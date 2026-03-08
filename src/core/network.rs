//! Full faithful Rust port of Arceliar/ironwood `network` + `encrypted` packages.
//!
//! Wire-compatible with yggdrasil-go / ironwood Go implementation.

#![allow(dead_code, unused_imports, unused_variables)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use blake2::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use crypto_box::{
    SalsaBox,
    PublicKey as BoxPublicKey,
    SecretKey as BoxSecretKey,
    aead::Aead,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature as Ed25519Sig};
use rand::rngs::OsRng;
use sha2::Sha512;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Mutex},
    time,
};
use tracing::{debug, info, warn};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519Public};

// ============================================================================
// Public API types (preserved from original)
// ============================================================================

pub type PublicKeyBytes = [u8; 32];
pub type BoxReader = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxWriter = Box<dyn AsyncWrite + Unpin + Send>;

pub struct InboundPacket {
    pub payload: Vec<u8>,
    pub from: PublicKeyBytes,
}

pub struct PeerStats {
    pub key: PublicKeyBytes,
    pub priority: u8,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime: Duration,
    pub latency: Duration,
}

// ============================================================================
// Internal types
// ============================================================================

type PublicKey = [u8; 32];
type PrivateKey = [u8; 64]; // ed25519: seed[32] + pub[32]
type Signature  = [u8; 64];
type PeerPort   = u64;
type PeerId     = u64;

// Box key types (x25519)
type BoxPub     = [u8; 32];
type BoxPriv    = [u8; 32];

// ============================================================================
// Constants
// ============================================================================

const WIRE_DUMMY:               u8 = 0;
const WIRE_KEEP_ALIVE:          u8 = 1;
const WIRE_PROTO_SIG_REQ:       u8 = 2;
const WIRE_PROTO_SIG_RES:       u8 = 3;
const WIRE_PROTO_ANNOUNCE:      u8 = 4;
const WIRE_PROTO_BLOOM_FILTER:  u8 = 5;
const WIRE_PROTO_PATH_LOOKUP:   u8 = 6;
const WIRE_PROTO_PATH_NOTIFY:   u8 = 7;
const WIRE_PROTO_PATH_BROKEN:   u8 = 8;
const WIRE_TRAFFIC:             u8 = 9;

// Bloom filter constants (must match bits-and-blooms/bloom v3 defaults)
const BLOOM_F: usize = 16;   // flag bytes = BLOOM_U / 8
const BLOOM_U: usize = 128;  // uint64 words
const BLOOM_M: u32   = 8192; // total bits
const BLOOM_K: usize = 8;    // hash functions

const ROUTER_REFRESH:         Duration = Duration::from_secs(240);  // 4 min
const ROUTER_TIMEOUT:         Duration = Duration::from_secs(300);  // 5 min
const PEER_KEEPALIVE_DELAY:   Duration = Duration::from_secs(1);
const PEER_TIMEOUT:           Duration = Duration::from_secs(3);
const PEER_MAX_MSG_SIZE:      usize    = 1_048_576; // 1 MB
const PATH_TIMEOUT:           Duration = Duration::from_secs(60);
const PATH_THROTTLE:          Duration = Duration::from_secs(1);

// session type bytes (encrypted package)
const SESSION_DUMMY:   u8 = 0;
const SESSION_INIT:    u8 = 1;
const SESSION_ACK:     u8 = 2;
const SESSION_TRAFFIC: u8 = 3;

const SESSION_INIT_SIZE: usize = 1 + 32 + 16 + 64 + 32 + 32 + 8 + 8; // 193
const BOX_OVERHEAD:      usize = 16; // Poly1305 tag

// ============================================================================
// Wire encoding / decoding
// ============================================================================

fn put_uvarint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        if v < 0x80 { buf.push(v as u8); return; }
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
}

fn get_uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if i == 10 { return None; }
        if b < 0x80 { return Some((x | (b as u64) << s, i + 1)); }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    None
}

fn size_uvarint(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 { v >>= 7; n += 1; }
    n
}

fn chop_uvarint(data: &mut &[u8]) -> Option<u64> {
    let (v, n) = get_uvarint(data)?;
    *data = &data[n..];
    Some(v)
}

fn chop_slice<'a>(data: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if data.len() < len { return None; }
    let s = &data[..len];
    *data = &data[len..];
    Some(s)
}

fn put_path(buf: &mut Vec<u8>, path: &[PeerPort]) {
    for &p in path { put_uvarint(buf, p); }
    put_uvarint(buf, 0); // terminator
}

fn size_path(path: &[PeerPort]) -> usize {
    let mut n = 0;
    for &p in path { n += size_uvarint(p); }
    n + size_uvarint(0)
}

fn chop_path(data: &mut &[u8]) -> Option<Vec<PeerPort>> {
    let mut path = Vec::new();
    loop {
        let v = chop_uvarint(data)?;
        if v == 0 { break; }
        path.push(v);
    }
    Some(path)
}

/// Encode a wire frame: uvarint(len) + type_byte + body
fn encode_frame(type_byte: u8, body: &[u8]) -> Vec<u8> {
    let frame_len = 1 + body.len();
    let mut out = Vec::with_capacity(size_uvarint(frame_len as u64) + frame_len);
    put_uvarint(&mut out, frame_len as u64);
    out.push(type_byte);
    out.extend_from_slice(body);
    out
}

// ============================================================================
// Crypto primitives
// ============================================================================

fn sign_msg(msg: &[u8], priv_key: &PrivateKey) -> Signature {
    let seed: [u8; 32] = priv_key[..32].try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    sk.sign(msg).to_bytes()
}

fn verify_sig(msg: &[u8], sig: &Signature, pub_key: &PublicKey) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pub_key) else { return false; };
    let Ok(s)  = Ed25519Sig::from_slice(sig)         else { return false; };
    vk.verify(msg, &s).is_ok()
}

fn pub_less(a: &PublicKey, b: &PublicKey) -> bool { a < b }

/// Convert ed25519 public key to x25519 public key (Curve25519 Montgomery form)
fn ed_pub_to_box_pub(ed_pub: &[u8; 32]) -> Option<BoxPub> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let point = compressed.decompress()?;
    let montgomery = point.to_montgomery();
    Some(montgomery.to_bytes())
}

/// Convert ed25519 private key (64 bytes: seed+pub) to x25519 secret key
fn ed_priv_to_box_priv(ed_priv: &PrivateKey) -> BoxPriv {
    use sha2::Digest;
    let seed = &ed_priv[..32];
    let mut h = Sha512::new();
    h.update(seed);
    let hash = h.finalize();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // Clamp as per RFC 7748
    scalar[0]  &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

// ============================================================================
// Box (NaCl XSalsa20Poly1305) operations
// ============================================================================

fn new_box_key_pair() -> (BoxPub, BoxPriv) {
    let priv_key = X25519Secret::random_from_rng(OsRng);
    let pub_key  = X25519Public::from(&priv_key);
    (*pub_key.as_bytes(), priv_key.to_bytes())
}

fn make_salsa_box(their_pub: &BoxPub, our_priv: &BoxPriv) -> SalsaBox {
    let pub_key  = BoxPublicKey::from(*their_pub);
    let priv_key = BoxSecretKey::from(*our_priv);
    SalsaBox::new(&pub_key, &priv_key)
}

fn nonce_for_u64(u: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(&u.to_be_bytes());
    n
}

fn box_seal(msg: &[u8], nonce_u64: u64, their_pub: &BoxPub, our_priv: &BoxPriv) -> Vec<u8> {
    use crypto_box::aead::generic_array::GenericArray;
    let b = make_salsa_box(their_pub, our_priv);
    let nonce_bytes = nonce_for_u64(nonce_u64);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    b.encrypt(nonce, msg).expect("salsa box encrypt")
}

fn box_open(ct: &[u8], nonce_u64: u64, their_pub: &BoxPub, our_priv: &BoxPriv) -> Option<Vec<u8>> {
    use crypto_box::aead::generic_array::GenericArray;
    let b = make_salsa_box(their_pub, our_priv);
    let nonce_bytes = nonce_for_u64(nonce_u64);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    b.decrypt(nonce, ct).ok()
}

// ============================================================================
// Bloom filter (wire-compatible with bits-and-blooms/bloom/v3 + murmur3)
// ============================================================================

#[derive(Clone)]
struct BloomFilter {
    bits: [u64; BLOOM_U], // 128 uint64 words = 8192 bits
}

impl BloomFilter {
    fn new() -> Self { BloomFilter { bits: [0u64; BLOOM_U] } }

    fn base_hashes(data: &[u8]) -> [u64; 4] {
        // Match Go's bits-and-blooms/bloom/v3 sum256():
        // hash1,hash2 = murmur128(data)
        // hash3,hash4 = murmur128(data + "\x01")
        let h12 = murmur3::murmur3_x64_128(&mut io::Cursor::new(data), 0).unwrap_or(0);
        let h1 = h12 as u64;
        let h2 = (h12 >> 64) as u64;
        let mut data_with_one = data.to_vec();
        data_with_one.push(1u8);
        let h34 = murmur3::murmur3_x64_128(&mut io::Cursor::new(&data_with_one), 0).unwrap_or(0);
        let h3 = h34 as u64;
        let h4 = (h34 >> 64) as u64;
        [h1, h2, h3, h4]
    }

    fn location(h: &[u64; 4], i: u64) -> usize {
        // Match Go's bits-and-blooms/bloom/v3 location():
        // return h[ii%2] + ii*h[2+(((ii+(ii%2))%4)/2)]
        let idx3 = (2 + (((i + (i % 2)) % 4) / 2)) as usize;
        let v = h[(i % 2) as usize].wrapping_add(i.wrapping_mul(h[idx3]));
        (v % (BLOOM_M as u64)) as usize
    }

    fn add(&mut self, data: &[u8]) {
        let h = Self::base_hashes(data);
        for i in 0..BLOOM_K as u64 {
            let loc = Self::location(&h, i);
            self.bits[loc / 64] |= 1u64 << (loc % 64);
        }
    }

    fn test(&self, data: &[u8]) -> bool {
        let h = Self::base_hashes(data);
        for i in 0..BLOOM_K as u64 {
            let loc = Self::location(&h, i);
            if self.bits[loc / 64] & (1u64 << (loc % 64)) == 0 { return false; }
        }
        true
    }

    fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_U { self.bits[i] |= other.bits[i]; }
    }

    fn equal(&self, other: &BloomFilter) -> bool {
        self.bits == other.bits
    }

    fn size(&self) -> usize {
        let mut kept = 0;
        for &u in &self.bits {
            if u != 0 && u != !0u64 { kept += 1; }
        }
        BLOOM_F + BLOOM_F + kept * 8
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let mut flags0 = [0u8; BLOOM_F];
        let mut flags1 = [0u8; BLOOM_F];
        let mut kept: Vec<u64> = Vec::new();
        for (idx, &u) in self.bits.iter().enumerate() {
            if u == 0 {
                flags0[idx / 8] |= 0x80u8 >> (idx % 8);
            } else if u == !0u64 {
                flags1[idx / 8] |= 0x80u8 >> (idx % 8);
            } else {
                kept.push(u);
            }
        }
        out.extend_from_slice(&flags0);
        out.extend_from_slice(&flags1);
        for u in kept {
            out.extend_from_slice(&u.to_be_bytes());
        }
    }

    fn decode(data: &[u8]) -> Option<BloomFilter> {
        if data.len() < BLOOM_F + BLOOM_F { return None; }
        let flags0 = &data[..BLOOM_F];
        let flags1 = &data[BLOOM_F..BLOOM_F*2];
        let mut rest = &data[BLOOM_F*2..];
        let mut bloom = BloomFilter::new();
        for idx in 0..BLOOM_U {
            let f0 = flags0[idx / 8] & (0x80u8 >> (idx % 8)) != 0;
            let f1 = flags1[idx / 8] & (0x80u8 >> (idx % 8)) != 0;
            if f0 && f1 { return None; }
            if f0 {
                bloom.bits[idx] = 0;
            } else if f1 {
                bloom.bits[idx] = !0u64;
            } else {
                if rest.len() < 8 { return None; }
                bloom.bits[idx] = u64::from_be_bytes(rest[..8].try_into().ok()?);
                rest = &rest[8..];
            }
        }
        if !rest.is_empty() { return None; }
        Some(bloom)
    }
}

// ============================================================================
// Packet queue (per-peer, priority queue by dest/source/age)
// ============================================================================

const MAX_QUEUE_BYTES: u64 = 4 * 1_048_576; // 4 MB per peer

struct QueuedPacket {
    pkt_type: u8,
    data: Vec<u8>,
    source: PublicKey,
    dest: PublicKey,
    size: u64,
    timestamp: Instant,
}

struct PacketQueue {
    packets: VecDeque<QueuedPacket>,
    total_bytes: u64,
}

impl PacketQueue {
    fn new() -> Self { PacketQueue { packets: VecDeque::new(), total_bytes: 0 } }

    fn push(&mut self, pkt: QueuedPacket) {
        self.total_bytes += pkt.size;
        self.packets.push_back(pkt);
        // Drop oldest if over limit (approximate - drop from oldest packet)
        while self.total_bytes > MAX_QUEUE_BYTES {
            if let Some(dropped) = self.packets.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(dropped.size);
            } else { break; }
        }
    }

    fn pop(&mut self) -> Option<QueuedPacket> {
        if let Some(pkt) = self.packets.pop_front() {
            self.total_bytes = self.total_bytes.saturating_sub(pkt.size);
            Some(pkt)
        } else { None }
    }

    fn is_empty(&self) -> bool { self.packets.is_empty() }
}

// ============================================================================
// Traffic struct
// ============================================================================

struct Traffic {
    path:      Vec<PeerPort>,
    from:      Vec<PeerPort>,
    source:    PublicKey,
    dest:      PublicKey,
    watermark: u64,
    payload:   Vec<u8>,
}

impl Traffic {
    fn new() -> Self {
        Traffic { path: vec![], from: vec![], source: [0u8; 32], dest: [0u8; 32],
                  watermark: 0, payload: vec![] }
    }

    fn size(&self) -> usize {
        size_path(&self.path) + size_path(&self.from)
            + 32 + 32 + size_uvarint(self.watermark) + self.payload.len()
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        put_path(&mut out, &self.path);
        put_path(&mut out, &self.from);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        put_uvarint(&mut out, self.watermark);
        out.extend_from_slice(&self.payload);
        out
    }

    fn decode(data: &[u8]) -> Option<Traffic> {
        let mut d = data;
        let path      = chop_path(&mut d)?;
        let from      = chop_path(&mut d)?;
        let source    = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest      = chop_slice(&mut d, 32)?.try_into().ok()?;
        let watermark = chop_uvarint(&mut d)?;
        let payload   = d.to_vec();
        Some(Traffic { path, from, source, dest, watermark, payload })
    }

    fn copy_from(&mut self, other: &Traffic) {
        self.path      = other.path.clone();
        self.from      = other.from.clone();
        self.source    = other.source;
        self.dest      = other.dest;
        self.watermark = other.watermark;
        self.payload   = other.payload.clone();
    }
}

// ============================================================================
// Router protocol: SigReq, SigRes, Announce, RouterInfo
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
struct SigReq {
    seq:   u64,
    nonce: u64,
}

impl SigReq {
    fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 16);
        out.extend_from_slice(node);
        out.extend_from_slice(parent);
        put_uvarint(&mut out, self.seq);
        put_uvarint(&mut out, self.nonce);
        out
    }

    fn size(&self) -> usize {
        size_uvarint(self.seq) + size_uvarint(self.nonce)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_uvarint(out, self.seq);
        put_uvarint(out, self.nonce);
    }

    fn decode(data: &[u8]) -> Option<SigReq> {
        let mut d = data;
        let seq   = chop_uvarint(&mut d)?;
        let nonce = chop_uvarint(&mut d)?;
        if !d.is_empty() { return None; }
        Some(SigReq { seq, nonce })
    }

    fn chop(d: &mut &[u8]) -> Option<SigReq> {
        let seq   = chop_uvarint(d)?;
        let nonce = chop_uvarint(d)?;
        Some(SigReq { seq, nonce })
    }
}

#[derive(Clone)]
struct SigRes {
    req:  SigReq,
    port: PeerPort,
    psig: Signature,
}

impl SigRes {
    fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
        let mut out = self.req.bytes_for_sig(node, parent);
        put_uvarint(&mut out, self.port);
        out
    }

    fn check(&self, node: &PublicKey, parent: &PublicKey) -> bool {
        let bs = self.bytes_for_sig(node, parent);
        verify_sig(&bs, &self.psig, parent)
    }

    fn size(&self) -> usize {
        self.req.size() + size_uvarint(self.port) + 64
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.req.encode(out);
        put_uvarint(out, self.port);
        out.extend_from_slice(&self.psig);
    }

    fn chop(d: &mut &[u8]) -> Option<SigRes> {
        let req  = SigReq::chop(d)?;
        let port = chop_uvarint(d)?;
        let psig: Signature = chop_slice(d, 64)?.try_into().ok()?;
        Some(SigRes { req, port, psig })
    }

    fn decode(data: &[u8]) -> Option<SigRes> {
        let mut d = data;
        let res = SigRes::chop(&mut d)?;
        if !d.is_empty() { return None; }
        Some(res)
    }
}

#[derive(Clone)]
struct Announce {
    key:    PublicKey,
    parent: PublicKey,
    res:    SigRes,
    sig:    Signature,
}

impl Announce {
    fn check(&self) -> bool {
        if self.res.port == 0 && self.key != self.parent { return false; }
        let bs = self.res.bytes_for_sig(&self.key, &self.parent);
        verify_sig(&bs, &self.sig, &self.key) && verify_sig(&bs, &self.res.psig, &self.parent)
    }

    fn size(&self) -> usize { 32 + 32 + self.res.size() + 64 }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.parent);
        self.res.encode(out);
        out.extend_from_slice(&self.sig);
    }

    fn decode(data: &[u8]) -> Option<Announce> {
        let mut d = data;
        let key:    PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let parent: PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let res = SigRes::chop(&mut d)?;
        let sig: Signature = chop_slice(&mut d, 64)?.try_into().ok()?;
        if !d.is_empty() { return None; }
        Some(Announce { key, parent, res, sig })
    }
}

#[derive(Clone)]
struct RouterInfo {
    parent: PublicKey,
    res:    SigRes,
    sig:    Signature,
}

impl RouterInfo {
    fn get_announce(&self, key: PublicKey) -> Announce {
        Announce { key, parent: self.parent, res: self.res.clone(), sig: self.sig }
    }
}

// ============================================================================
// Path protocol: PathLookup, PathNotifyInfo, PathNotify, PathBroken
// ============================================================================

#[derive(Clone)]
struct PathLookup {
    source: PublicKey,
    dest:   PublicKey,
    from:   Vec<PeerPort>,
}

impl PathLookup {
    fn size(&self) -> usize { 32 + 32 + size_path(&self.from) }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        put_path(out, &self.from);
    }

    fn decode(data: &[u8]) -> Option<PathLookup> {
        let mut d = data;
        let source: PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest:   PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let from = chop_path(&mut d)?;
        if !d.is_empty() { return None; }
        Some(PathLookup { source, dest, from })
    }
}

#[derive(Clone)]
struct PathNotifyInfo {
    seq:  u64,
    path: Vec<PeerPort>,
    sig:  Signature,
}

impl PathNotifyInfo {
    fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint(&mut out, self.seq);
        put_path(&mut out, &self.path);
        out
    }

    fn sign(&mut self, priv_key: &PrivateKey) {
        self.sig = sign_msg(&self.bytes_for_sig(), priv_key);
    }

    fn equal(&self, other: &PathNotifyInfo) -> bool {
        self.seq == other.seq && self.path == other.path
    }

    fn size(&self) -> usize {
        size_uvarint(self.seq) + size_path(&self.path) + 64
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_uvarint(out, self.seq);
        put_path(out, &self.path);
        out.extend_from_slice(&self.sig);
    }

    fn decode(data: &[u8]) -> Option<PathNotifyInfo> {
        let mut d = data;
        let seq  = chop_uvarint(&mut d)?;
        let path = chop_path(&mut d)?;
        let sig: Signature = chop_slice(&mut d, 64)?.try_into().ok()?;
        if !d.is_empty() { return None; }
        Some(PathNotifyInfo { seq, path, sig })
    }

    fn chop(d: &mut &[u8]) -> Option<PathNotifyInfo> {
        let seq  = chop_uvarint(d)?;
        let path = chop_path(d)?;
        let sig: Signature = chop_slice(d, 64)?.try_into().ok()?;
        Some(PathNotifyInfo { seq, path, sig })
    }
}

#[derive(Clone)]
struct PathNotify {
    path:      Vec<PeerPort>,
    watermark: u64,
    source:    PublicKey,
    dest:      PublicKey,
    info:      PathNotifyInfo,
}

impl PathNotify {
    fn check(&self) -> bool {
        verify_sig(&self.info.bytes_for_sig(), &self.info.sig, &self.source)
    }

    fn size(&self) -> usize {
        size_path(&self.path) + size_uvarint(self.watermark) + 32 + 32 + self.info.size()
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_path(out, &self.path);
        put_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        self.info.encode(out);
    }

    fn decode(data: &[u8]) -> Option<PathNotify> {
        let mut d = data;
        let path      = chop_path(&mut d)?;
        let watermark = chop_uvarint(&mut d)?;
        let source:   PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest:     PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let info = PathNotifyInfo::chop(&mut d)?;
        if !d.is_empty() { return None; }
        Some(PathNotify { path, watermark, source, dest, info })
    }
}

#[derive(Clone)]
struct PathBroken {
    path:      Vec<PeerPort>,
    watermark: u64,
    source:    PublicKey,
    dest:      PublicKey,
}

impl PathBroken {
    fn size(&self) -> usize {
        size_path(&self.path) + size_uvarint(self.watermark) + 32 + 32
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_path(out, &self.path);
        put_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
    }

    fn decode(data: &[u8]) -> Option<PathBroken> {
        let mut d = data;
        let path      = chop_path(&mut d)?;
        let watermark = chop_uvarint(&mut d)?;
        let source:   PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest:     PublicKey = chop_slice(&mut d, 32)?.try_into().ok()?;
        if !d.is_empty() { return None; }
        Some(PathBroken { path, watermark, source, dest })
    }
}

// ============================================================================
// Bloom info (per-peer bloom state)
// ============================================================================

struct BloomInfo {
    send:    BloomFilter,
    recv:    BloomFilter,
    seq:     u16,
    on_tree: bool,
    z_dirty: bool,
}

// ============================================================================
// Path info / rumor
// ============================================================================

struct PathInfo {
    path:     Vec<PeerPort>,
    seq:      u64,
    req_time: Instant,
    updated:  Instant,
    broken:   bool,
    traffic:  Option<Box<Traffic>>,
}

struct PathRumor {
    traffic:   Option<Box<Traffic>>,
    send_time: Instant,
    created:   Instant,
}

// ============================================================================
// Peer data (held inside RouterState)
// ============================================================================

struct PeerData {
    id:              PeerId,
    key:             PublicKey,
    port:            PeerPort,
    prio:            u8,
    order:           u64,
    write_tx:        mpsc::Sender<Vec<u8>>,
    req_send_time:   Option<Instant>,
    lag:             Duration,
    rx_bytes:        u64,
    tx_bytes:        u64,
    connected_at:    Instant,
    queue:           PacketQueue,
    ready:           bool,
}

impl PeerData {
    /// Send a raw pre-encoded frame to this peer (non-blocking, queues if not ready)
    fn send_raw(&mut self, data: Vec<u8>) {
        if self.write_tx.try_send(data).is_err() {
            // channel full, drop (backpressure)
        }
    }

    fn send_frame(&mut self, type_byte: u8, body: &[u8]) {
        let frame = encode_frame(type_byte, body);
        self.send_raw(frame);
    }

    fn send_sig_req(&mut self, req: &SigReq) {
        let mut body = Vec::with_capacity(req.size());
        req.encode(&mut body);
        self.req_send_time = Some(Instant::now());
        self.send_frame(WIRE_PROTO_SIG_REQ, &body);
    }

    fn send_sig_res(&mut self, res: &SigRes) {
        let mut body = Vec::with_capacity(res.size());
        res.encode(&mut body);
        self.send_frame(WIRE_PROTO_SIG_RES, &body);
    }

    fn send_announce(&mut self, ann: &Announce) {
        let mut body = Vec::with_capacity(ann.size());
        ann.encode(&mut body);
        self.send_frame(WIRE_PROTO_ANNOUNCE, &body);
    }

    fn send_bloom(&mut self, bloom: &BloomFilter) {
        let mut body = Vec::with_capacity(bloom.size());
        bloom.encode(&mut body);
        self.send_frame(WIRE_PROTO_BLOOM_FILTER, &body);
    }

    fn send_path_lookup(&mut self, lookup: &PathLookup) {
        let mut body = Vec::with_capacity(lookup.size());
        lookup.encode(&mut body);
        self.send_frame(WIRE_PROTO_PATH_LOOKUP, &body);
    }

    fn send_path_notify(&mut self, notify: &PathNotify) {
        let mut body = Vec::with_capacity(notify.size());
        notify.encode(&mut body);
        self.send_frame(WIRE_PROTO_PATH_NOTIFY, &body);
    }

    fn send_path_broken(&mut self, broken: &PathBroken) {
        let mut body = Vec::with_capacity(broken.size());
        broken.encode(&mut body);
        self.send_frame(WIRE_PROTO_PATH_BROKEN, &body);
    }

    fn send_traffic(&mut self, tr: &Traffic) {
        let mut body = Vec::with_capacity(tr.size());
        body.extend_from_slice(&tr.encode());
        self.tx_bytes += body.len() as u64;
        self.send_frame(WIRE_TRAFFIC, &body);
    }
}

// ============================================================================
// Router State
// ============================================================================

struct RouterState {
    // Crypto
    pub_key:  PublicKey,
    priv_key: PrivateKey,

    // Peers: key -> id -> PeerData
    peers:           HashMap<PublicKey, HashMap<PeerId, PeerData>>,
    ports:           HashMap<PeerPort, PublicKey>,
    next_peer_id:    PeerId,
    next_port:       PeerPort,
    peer_order_ctr:  u64,

    // Spanning tree
    infos:         HashMap<PublicKey, RouterInfo>,
    info_updated:  HashMap<PublicKey, Instant>,  // last update time (for timeout)
    sent:          HashMap<PublicKey, HashSet<PublicKey>>,
    ancs:          HashMap<PublicKey, Vec<PublicKey>>,
    cache:         HashMap<PublicKey, Vec<PeerPort>>,
    requests:      HashMap<PublicKey, SigReq>,
    responses:     HashMap<PublicKey, SigRes>,
    responded:     HashSet<PeerId>,
    res_seqs:      HashMap<PublicKey, u64>,
    res_seq_ctr:   u64,
    refresh:       bool,
    do_root1:      bool,
    do_root2:      bool,

    // Bloom filters (per peer)
    bloom_infos:  HashMap<PublicKey, BloomInfo>,

    // Pathfinder
    pf_info:  PathNotifyInfo,
    paths:    HashMap<PublicKey, PathInfo>,
    rumors:   HashMap<PublicKey, PathRumor>,

    // Application receive channel
    app_tx: mpsc::Sender<InboundPacket>,

    // Path notify callback
    path_notify_cb: Option<Box<dyn Fn(VerifyingKey) + Send + Sync>>,
}

impl RouterState {
    fn new(pub_key: PublicKey, priv_key: PrivateKey, app_tx: mpsc::Sender<InboundPacket>) -> Self {
        let mut pf_info = PathNotifyInfo { seq: 0, path: vec![], sig: [0u8; 64] };
        pf_info.sign(&priv_key);

        let mut s = RouterState {
            pub_key, priv_key,
            peers: HashMap::new(), ports: HashMap::new(),
            next_peer_id: 1, next_port: 1, peer_order_ctr: 0,
            infos: HashMap::new(), info_updated: HashMap::new(),
            sent: HashMap::new(), ancs: HashMap::new(), cache: HashMap::new(),
            requests: HashMap::new(), responses: HashMap::new(),
            responded: HashSet::new(), res_seqs: HashMap::new(), res_seq_ctr: 0,
            refresh: false, do_root1: false, do_root2: true,
            bloom_infos: HashMap::new(),
            pf_info, paths: HashMap::new(), rumors: HashMap::new(),
            app_tx,
            path_notify_cb: None,
        };
        s.become_root();
        s
    }

    // ---- Peer management ----

    fn add_peer(&mut self, key: PublicKey, port: PeerPort, prio: u8,
                write_tx: mpsc::Sender<Vec<u8>>) -> PeerId {
        let id = self.next_peer_id;
        self.next_peer_id += 1;
        self.peer_order_ctr += 1;
        let order = self.peer_order_ctr;

        let is_new_key = !self.peers.contains_key(&key);
        if is_new_key {
            self.sent.insert(key, HashSet::new());
            self.ports.insert(port, key);
            self.bloom_infos.insert(key, BloomInfo {
                send: BloomFilter::new(), recv: BloomFilter::new(),
                seq: 0, on_tree: false, z_dirty: false,
            });
        } else {
            // Send previously sent info to this new connection for the same key
            let already_sent: Vec<PublicKey> = self.sent.get(&key)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            // We'll send them after PeerData is inserted below
        }

        let peer = PeerData {
            id, key, port, prio, order, write_tx,
            req_send_time: None,
            lag: Duration::from_nanos(u32::MAX as u64), // unknown latency
            rx_bytes: 0, tx_bytes: 0,
            connected_at: Instant::now(),
            queue: PacketQueue::new(),
            ready: true,
        };
        self.peers.entry(key).or_default().insert(id, peer);

        // Send announces for previously-known keys to this peer
        if !is_new_key {
            let already_sent: Vec<PublicKey> = self.sent.get(&key)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            for k in already_sent {
                if let Some(info) = self.infos.get(&k) {
                    let ann = info.get_announce(k);
                    if let Some(peer_map) = self.peers.get_mut(&key) {
                        if let Some(p) = peer_map.get_mut(&id) {
                            p.send_announce(&ann);
                        }
                    }
                }
            }
        }

        // Send sigReq and bloom
        let req = self.new_req();
        self.requests.insert(key, req);
        self.responded.remove(&id);

        tracing::debug!("add_peer: sending SigReq+Bloom to {}", hex::encode(&key[..8]));
        if let Some(peer_map) = self.peers.get_mut(&key) {
            if let Some(p) = peer_map.get_mut(&id) {
                p.send_sig_req(&req);
                let bloom = self.bloom_infos.get(&key).map(|bi| bi.send.clone());
                if let Some(b) = bloom {
                    p.send_bloom(&b);
                }
            }
        }

        id
    }

    fn remove_peer(&mut self, key: &PublicKey, id: PeerId) {
        let is_empty = if let Some(peers_for_key) = self.peers.get_mut(key) {
            peers_for_key.remove(&id);
            self.responded.remove(&id);
            peers_for_key.is_empty()
        } else { false };

        if is_empty {
            self.peers.remove(key);
            self.sent.remove(key);
            self.ports.retain(|_, v| v != key);
            self.requests.remove(key);
            self.responses.remove(key);
            self.res_seqs.remove(key);
            self.ancs.remove(key);
            self.cache.remove(key);
            self.bloom_infos.remove(key);
        } else {
            // Resend bloom to remaining peers with this key
            let bloom = self.bloom_infos.get(key).map(|bi| bi.send.clone());
            if let (Some(b), Some(peers)) = (bloom, self.peers.get_mut(key)) {
                for p in peers.values_mut() { p.send_bloom(&b); }
            }
        }
    }

    // ---- Router maintenance ----

    fn do_maintenance(&mut self) {
        self.expire_infos();
        self.expire_paths();
        self.reset_cache();
        self.update_ancestries();
        self.fix();
        self.send_announces();
        self.bloom_do_maintenance();
    }

    fn expire_infos(&mut self) {
        let now = Instant::now();
        let timeout = ROUTER_TIMEOUT;
        let refresh_interval = ROUTER_REFRESH;
        let self_key = self.pub_key;

        let expired: Vec<PublicKey> = self.info_updated.iter()
            .filter(|(k, t)| {
                if **k == self_key { t.elapsed() > refresh_interval }
                else               { t.elapsed() > timeout }
            })
            .map(|(k, _)| *k)
            .collect();

        for k in &expired {
            if *k == self_key {
                self.refresh = true;
            } else {
                self.infos.remove(k);
                self.info_updated.remove(k);
                for sent in self.sent.values_mut() { sent.remove(k); }
                self.reset_cache();
            }
        }
    }

    fn expire_paths(&mut self) {
        let timeout = PATH_TIMEOUT;
        let expired_paths: Vec<PublicKey> = self.paths.iter()
            .filter(|(_, info)| info.updated.elapsed() > timeout)
            .map(|(k, _)| *k)
            .collect();
        for k in expired_paths { self.paths.remove(&k); }

        let expired_rumors: Vec<PublicKey> = self.rumors.iter()
            .filter(|(_, r)| r.created.elapsed() > timeout)
            .map(|(k, _)| *k)
            .collect();
        for k in expired_rumors { self.rumors.remove(&k); }
    }

    fn reset_cache(&mut self) { self.cache.clear(); }

    fn update_ancestries(&mut self) {
        let keys: Vec<PublicKey> = self.peers.keys().cloned().collect();
        for key in keys {
            let anc = self.get_ancestry(key);
            let old = self.ancs.entry(key).or_default();
            if *old != anc { *old = anc; }
        }
    }

    fn get_cost(&self, id: PeerId) -> u64 {
        // Find the peer with this id
        for peers in self.peers.values() {
            if let Some(p) = peers.get(&id) {
                let ms = p.lag.as_millis() as u64;
                return if ms == 0 { 1 } else { ms };
            }
        }
        1
    }

    fn fix(&mut self) {
        let self_key = self.pub_key;
        let mut best_root   = self_key;
        let mut best_parent = self_key;
        let mut best_cost   = u64::MAX;

        let self_info = self.infos.get(&self_key).cloned();
        let self_parent = self_info.as_ref().map(|i| i.parent).unwrap_or(self_key);

        // Check if current parent leads to a better root than self
        if let Some(_) = self.peers.get(&self_parent) {
            let (root, dists) = self.get_root_and_dists(self_key);
            if pub_less(&root, &best_root) {
                let mut cost = u64::MAX;
                if let Some(ps) = self.peers.get(&self_parent) {
                    for (id, _) in ps {
                        let c = dists.get(&root).unwrap_or(&u64::MAX)
                            .saturating_mul(self.get_cost(*id));
                        if c < cost { cost = c; }
                    }
                }
                best_root = root;
                best_parent = self_parent;
                best_cost = cost;
            }
        }

        // Check all peers with responses
        let response_keys: Vec<PublicKey> = self.responses.keys().cloned().collect();
        for pk in response_keys {
            if !self.infos.contains_key(&pk) { continue; }
            let (p_root, p_dists) = self.get_root_and_dists(pk);
            if p_dists.contains_key(&self_key) { continue; } // would loop through us

            let mut cost = u64::MAX;
            if let Some(ps) = self.peers.get(&pk) {
                for (id, _) in ps {
                    let c = p_dists.get(&p_root).unwrap_or(&u64::MAX)
                        .saturating_mul(self.get_cost(*id));
                    if c < cost { cost = c; }
                }
            }

            if pub_less(&p_root, &best_root) {
                best_root = p_root;
                best_parent = pk;
                best_cost = cost;
            } else if p_root == best_root {
                let refresh = self.refresh;
                if (refresh && cost.saturating_mul(2) < best_cost)
                    || (best_parent != self_parent && cost < best_cost)
                {
                    best_root = p_root;
                    best_parent = pk;
                    best_cost = cost;
                }
            }
        }

        if self.refresh || self.do_root1 || self.do_root2 || self_parent != best_parent {
            let res = self.responses.get(&best_parent).cloned();
            if let (Some(r), false) = (res, best_root == self_key) {
                if self.use_response(best_parent, &r.clone()) {
                    self.refresh = false;
                    self.do_root1 = false;
                    self.do_root2 = false;
                    self.send_reqs();
                    return;
                }
            }
            if self.do_root2 {
                self.become_root();
                self.refresh = false;
                self.do_root1 = false;
                self.do_root2 = false;
                self.send_reqs();
            } else if !self.do_root1 {
                self.do_root1 = true;
            }
        }
    }

    fn send_announces(&mut self) {
        let self_anc = self.get_ancestry(self.pub_key);
        let peer_keys: Vec<PublicKey> = self.peers.keys().cloned().collect();

        for peer_key in &peer_keys {
            let peer_anc = self.get_ancestry(*peer_key);
            let sent = self.sent.entry(*peer_key).or_default();

            let mut to_send: Vec<PublicKey> = Vec::new();
            for &k in &self_anc {
                if !sent.contains(&k) { to_send.push(k); sent.insert(k); }
            }
            for &k in &peer_anc {
                if !sent.contains(&k) { to_send.push(k); sent.insert(k); }
            }

            // Collect announcements
            let anns: Vec<Announce> = to_send.iter()
                .filter_map(|&k| self.infos.get(&k).map(|info| info.get_announce(k)))
                .collect();

            // Send to all peer connections
            if let Some(peers) = self.peers.get_mut(peer_key) {
                for p in peers.values_mut() {
                    for ann in &anns { p.send_announce(ann); }
                }
            }
        }
    }

    fn new_req(&self) -> SigReq {
        use rand::RngCore;
        let mut rng = OsRng;
        let seq = self.infos.get(&self.pub_key).map(|i| i.res.req.seq + 1).unwrap_or(1);
        let nonce = rng.next_u64();
        SigReq { seq, nonce }
    }

    fn become_root(&mut self) -> bool {
        let req = self.new_req();
        let mut res = SigRes { req, port: 0, psig: [0u8; 64] };
        let bs = res.bytes_for_sig(&self.pub_key, &self.pub_key);
        res.psig = sign_msg(&bs, &self.priv_key);
        let ann = Announce {
            key:    self.pub_key,
            parent: self.pub_key,
            res:    res.clone(),
            sig:    res.psig,
        };
        if !ann.check() { return false; }
        self.update(&ann)
    }

    fn handle_request(&mut self, peer_id: PeerId, peer_key: PublicKey, req: SigReq) {
        // Find the peer port for this peer_id
        let port = self.peers.get(&peer_key)
            .and_then(|ps| ps.get(&peer_id))
            .map(|p| p.port)
            .unwrap_or(0);
        let mut res = SigRes { req, port, psig: [0u8; 64] };
        let bs = res.bytes_for_sig(&peer_key, &self.pub_key);
        res.psig = sign_msg(&bs, &self.priv_key);
        if let Some(ps) = self.peers.get_mut(&peer_key) {
            if let Some(p) = ps.get_mut(&peer_id) {
                p.send_sig_res(&res);
            }
        }
    }

    fn handle_response(&mut self, peer_id: PeerId, peer_key: PublicKey,
                       res: SigRes, rtt: Duration) {
        let req = self.requests.get(&peer_key).cloned();
        if let Some(r) = req {
            if r == res.req {
                if !self.responses.contains_key(&peer_key) {
                    self.res_seq_ctr += 1;
                    self.res_seqs.insert(peer_key, self.res_seq_ctr);
                    self.responses.insert(peer_key, res);
                }
                if !self.responded.contains(&peer_id) {
                    self.responded.insert(peer_id);
                    let lag = if let Some(p) = self.peers.get_mut(&peer_key)
                        .and_then(|ps| ps.get_mut(&peer_id))
                    {
                        if p.lag == Duration::from_nanos(u32::MAX as u64) {
                            p.lag = rtt * 2;
                        } else {
                            let prev = p.lag;
                            p.lag = p.lag * 7 / 8 + rtt.min(prev * 2) / 8;
                        }
                        p.lag
                    } else { Duration::ZERO };
                }
            }
        }
    }

    fn use_response(&mut self, peer_key: PublicKey, res: &SigRes) -> bool {
        let bs = res.bytes_for_sig(&self.pub_key, &peer_key);
        let info = RouterInfo {
            parent: peer_key,
            res: res.clone(),
            sig: sign_msg(&bs, &self.priv_key),
        };
        let ann = info.get_announce(self.pub_key);
        self.update(&ann)
    }

    fn handle_announce(&mut self, peer_id: PeerId, peer_key: PublicKey, ann: Announce) {
        if self.update(&ann) {
            tracing::debug!("handle_announce: stored key={} parent={}", hex::encode(&ann.key[..8]), hex::encode(&ann.parent[..8]));
            if ann.key == self.pub_key { self.refresh = true; }
            if let Some(s) = self.sent.get_mut(&peer_key) { s.insert(ann.key); }
        } else {
            let old_info = self.infos.get(&ann.key).cloned();
            if let Some(old) = old_info {
                let have = RouterInfo { parent: ann.parent, res: ann.res.clone(), sig: ann.sig };
                // If different, tell this peer what we know
                if let Some(ps) = self.peers.get_mut(&peer_key) {
                    if let Some(p) = ps.get_mut(&peer_id) {
                        p.send_announce(&old.get_announce(ann.key));
                    }
                }
            }
            if let Some(s) = self.sent.get_mut(&peer_key) { s.insert(ann.key); }
        }
    }

    fn update(&mut self, ann: &Announce) -> bool {
        if !ann.check() { return false; }

        if let Some(info) = self.infos.get(&ann.key) {
            match ann.res.req.seq.cmp(&info.res.req.seq) {
                std::cmp::Ordering::Less    => return false,
                std::cmp::Ordering::Equal   => {
                    if pub_less(&info.parent, &ann.parent) { return false; }
                    if pub_less(&ann.parent, &info.parent) { /* better */ }
                    else if ann.res.req.nonce >= info.res.req.nonce { return false; }
                }
                std::cmp::Ordering::Greater => { /* newer seq */ }
            }
        }

        // Clean up sent tracking
        for sent in self.sent.values_mut() { sent.remove(&ann.key); }
        self.reset_cache();

        let info = RouterInfo {
            parent: ann.parent,
            res:    ann.res.clone(),
            sig:    ann.sig,
        };
        self.infos.insert(ann.key, info);
        self.info_updated.insert(ann.key, Instant::now());

        true
    }

    fn send_reqs(&mut self) {
        self.requests.clear();
        self.responses.clear();
        self.res_seqs.clear();
        self.res_seq_ctr = 0;

        let peer_keys: Vec<PublicKey> = self.peers.keys().cloned().collect();
        for pk in peer_keys {
            let req = self.new_req();
            self.requests.insert(pk, req);
            if let Some(ps) = self.peers.get_mut(&pk) {
                for (id, p) in ps.iter_mut() {
                    self.responded.remove(id);
                    p.send_sig_req(&req);
                }
            }
        }
    }

    // ---- Tree path computation ----

    fn get_root_and_dists(&self, dest: PublicKey) -> (PublicKey, HashMap<PublicKey, u64>) {
        let mut dists = HashMap::new();
        let mut next = dest;
        let mut root = dest;
        let mut dist = 0u64;
        loop {
            if dists.contains_key(&next) { break; }
            if let Some(info) = self.infos.get(&next) {
                root = next;
                dists.insert(next, dist);
                dist += 1;
                next = info.parent;
            } else { break; }
        }
        (root, dists)
    }

    fn get_root_and_path(&self, dest: PublicKey) -> (PublicKey, Vec<PeerPort>) {
        let mut ports: Vec<PeerPort> = Vec::new();
        let mut visited: HashSet<PublicKey> = HashSet::new();
        let mut root = dest;
        let mut next = dest;
        loop {
            if visited.contains(&next) { return (dest, vec![]); }
            if let Some(info) = self.infos.get(&next) {
                root = next;
                visited.insert(next);
                if next == info.parent { break; } // reached root
                ports.push(info.res.port);
                next = info.parent;
            } else { return (dest, vec![]); }
        }
        ports.reverse();
        (root, ports)
    }

    fn get_dist(&mut self, dest_path: &[PeerPort], key: PublicKey) -> u64 {
        let key_path = if let Some(cached) = self.cache.get(&key) {
            cached.clone()
        } else {
            let (_, path) = self.get_root_and_path(key);
            self.cache.insert(key, path.clone());
            path
        };

        let end = dest_path.len().min(key_path.len());
        let mut dist = (key_path.len() + dest_path.len()) as u64;
        for idx in 0..end {
            if key_path[idx] == dest_path[idx] { dist -= 2; } else { break; }
        }
        dist
    }

    fn lookup(&mut self, path: &[PeerPort], watermark: &mut u64) -> Option<(PublicKey, PeerId)> {
        let self_key = self.pub_key;
        let self_dist = self.get_dist(path, self_key);
        if self_dist >= *watermark { return None; }
        let mut best_dist = self_dist;
        *watermark = self_dist;

        // Gather candidates: all peers with dist < best_dist
        let mut candidates: Vec<(PublicKey, PeerId, u64)> = Vec::new();
        let peer_keys: Vec<PublicKey> = self.peers.keys().cloned().collect();
        for k in &peer_keys {
            let d = self.get_dist(path, *k);
            if d < best_dist {
                if let Some(ps) = self.peers.get(k) {
                    for &id in ps.keys() { candidates.push((*k, id, d)); }
                }
            }
        }

        let mut best_peer: Option<(PublicKey, PeerId)> = None;
        let mut best_cost = u64::MAX;
        best_dist = u64::MAX;

        for (k, id, dist) in candidates {
            let cost = self.get_cost(id);
            let prio = self.peers.get(&k).and_then(|ps| ps.get(&id)).map(|p| p.prio).unwrap_or(255);
            let order = self.peers.get(&k).and_then(|ps| ps.get(&id)).map(|p| p.order).unwrap_or(u64::MAX);

            if best_peer.is_none() {
                best_peer = Some((k, id));
                best_cost = cost;
                best_dist = dist;
                continue;
            }
            let (bk, bid) = best_peer.unwrap();
            let best_prio = self.peers.get(&bk).and_then(|ps| ps.get(&bid)).map(|p| p.prio).unwrap_or(255);
            let best_order = self.peers.get(&bk).and_then(|ps| ps.get(&bid)).map(|p| p.order).unwrap_or(u64::MAX);

            if k == bk {
                if prio < best_prio { best_peer = Some((k, id)); best_cost = cost; best_dist = dist; }
                continue;
            }

            let cv = cost.saturating_mul(dist);
            let bv = best_cost.saturating_mul(best_dist);
            if cv < bv { best_peer = Some((k, id)); best_cost = cost; best_dist = dist; }
            else if cv == bv {
                if dist < best_dist { best_peer = Some((k, id)); best_cost = cost; best_dist = dist; }
                else if dist == best_dist && cost < best_cost {
                    best_peer = Some((k, id)); best_cost = cost; best_dist = dist;
                } else if dist == best_dist && cost == best_cost && order < best_order {
                    best_peer = Some((k, id)); best_cost = cost; best_dist = dist;
                }
            }
        }
        best_peer
    }

    fn get_ancestry(&self, key: PublicKey) -> Vec<PublicKey> {
        let mut anc = self.backwards_ancestry(vec![], key);
        anc.reverse();
        anc
    }

    fn backwards_ancestry(&self, mut anc: Vec<PublicKey>, key: PublicKey) -> Vec<PublicKey> {
        let mut here = key;
        loop {
            if anc.contains(&here) { return anc; }
            if let Some(info) = self.infos.get(&here) {
                anc.push(here);
                here = info.parent;
            } else { return anc; }
        }
    }

    // ---- Bloom filter operations ----

    /// Transform a public key for bloom filter matching.
    ///
    /// Mirrors yggdrasil-go's `keyXform`:
    ///   `func(key) { return address.SubnetForKey(key).GetKey() }`
    ///
    /// This ensures that any full public key maps to the same "partial key"
    /// that is derived from the IPv6 address/subnet.  Lookup probes are sent
    /// with this partial key so that bloom-multicast can reach the right node
    /// and the node can recognise that the probe is meant for it.
    fn bloom_x_key(&self, key: &PublicKey) -> PublicKey {
        use crate::address;
        if let Some(snet) = address::subnet_for_key(key) {
            snet.get_key()
        } else {
            *key
        }
    }

    fn bloom_fix_on_tree(&mut self) {
        let self_key = self.pub_key;
        let self_parent = self.infos.get(&self_key).map(|i| i.parent).unwrap_or(self_key);
        tracing::debug!("bloom_fix_on_tree: self_parent={} infos_count={}", hex::encode(&self_parent[..8]), self.infos.len());

        let peer_keys: Vec<PublicKey> = self.bloom_infos.keys().cloned().collect();
        for pk in peer_keys {
            let info_parent = self.infos.get(&pk).map(|i| i.parent);
            let was_on = self.bloom_infos[&pk].on_tree;
            let on_tree = self_parent == pk || info_parent == Some(self_key);
            tracing::debug!("  peer={}: self_parent==pk={} info_parent={:?} on_tree={}", hex::encode(&pk[..8]), self_parent==pk, info_parent.map(|p| hex::encode(&p[..8])), on_tree);
            let bi = self.bloom_infos.get_mut(&pk).unwrap();
            bi.on_tree = on_tree;
            if was_on && !on_tree {
                // Dropped from tree, send empty bloom
                bi.send = BloomFilter::new();
                let empty = BloomFilter::new();
                if let Some(ps) = self.peers.get_mut(&pk) {
                    for p in ps.values_mut() { p.send_bloom(&empty); }
                }
            }
        }
    }

    fn bloom_get_for(&mut self, key: PublicKey, keep_ones: bool) -> (BloomFilter, bool) {
        let self_key = self.pub_key;
        let xform = self.bloom_x_key(&self_key);

        let mut b = BloomFilter::new();
        b.add(&xform);

        // Merge on-tree peers' recv blooms (except the target peer)
        let on_tree_peers: Vec<PublicKey> = self.bloom_infos.iter()
            .filter(|(k, bi)| bi.on_tree && **k != key)
            .map(|(k, _)| *k)
            .collect();
        for pk in on_tree_peers {
            let recv_bloom = self.bloom_infos[&pk].recv.clone();
            b.merge(&recv_bloom);
        }

        let bi = self.bloom_infos.entry(key).or_insert_with(|| BloomInfo {
            send: BloomFilter::new(), recv: BloomFilter::new(),
            seq: 0, on_tree: false, z_dirty: false,
        });

        let is_new = if keep_ones {
            if !bi.z_dirty {
                let mut c = b.clone();
                c.merge(&bi.send);
                if !c.equal(&b) { bi.z_dirty = true; b = c; }
            } else {
                b.merge(&bi.send);
            }
            !b.equal(&bi.send)
        } else {
            bi.z_dirty = false;
            !b.equal(&bi.send)
        };

        if is_new { bi.send = b.clone(); }
        (b, is_new)
    }

    fn bloom_do_maintenance(&mut self) {
        self.bloom_fix_on_tree();

        let on_tree_keys: Vec<PublicKey> = self.bloom_infos.iter()
            .filter(|(_, bi)| bi.on_tree)
            .map(|(k, _)| *k)
            .collect();

        for k in on_tree_keys {
            let z_dirty = self.bloom_infos[&k].z_dirty;
            let keep_ones = !z_dirty;
            let (b, is_new) = self.bloom_get_for(k, keep_ones);
            let bi = self.bloom_infos.get_mut(&k).unwrap();
            bi.seq = bi.seq.wrapping_add(1);
            if is_new || bi.seq >= 3600 {
                bi.seq = 0;
                if let Some(ps) = self.peers.get_mut(&k) {
                    for p in ps.values_mut() { p.send_bloom(&b); }
                }
            }
        }
    }

    fn bloom_handle(&mut self, peer_key: PublicKey, bloom: BloomFilter) {
        if let Some(bi) = self.bloom_infos.get_mut(&peer_key) {
            bi.recv = bloom;
        }
    }

    fn bloom_send_multicast(&mut self, packet_encoded: Vec<u8>, packet_type: u8,
                            from_key: PublicKey, to_key: PublicKey) {
        let xform = self.bloom_x_key(&to_key);

        // Debug: log bloom filter check for each on_tree peer
        for (k, bi) in self.bloom_infos.iter() {
            if bi.on_tree {
                let not_from = *k != from_key;
                let bloom_match = bi.recv.test(&xform);
                tracing::debug!("bloom_send_multicast: peer={} not_from={} bloom_match={} (to_xkey={})", hex::encode(&k[..8]), not_from, bloom_match, hex::encode(&xform[..8]));
            }
        }

        let target_peers: Vec<(PublicKey, PeerId)> = self.bloom_infos.iter()
            .filter(|(k, bi)| bi.on_tree && **k != from_key && bi.recv.test(&xform))
            .flat_map(|(k, _)| {
                self.peers.get(k).map(|ps| {
                    let best = ps.values().min_by_key(|p| p.prio);
                    best.map(|p| (*k, p.id))
                }).flatten()
            })
            .collect();

        tracing::debug!("bloom_send_multicast: sending to {} peers", target_peers.len());
        for (k, id) in target_peers {
            if let Some(ps) = self.peers.get_mut(&k) {
                if let Some(p) = ps.get_mut(&id) {
                    p.send_raw(encode_frame(packet_type, &packet_encoded));
                }
            }
        }
    }

    // ---- Pathfinder operations ----

    fn pf_send_lookup(&mut self, dest: PublicKey) {
        if let Some(info) = self.paths.get(&dest) {
            if info.req_time.elapsed() < PATH_THROTTLE { return; }
        }

        // Ensure a rumor entry exists so pf_handle_notify can accept the PathNotify response.
        // pf_rumor_send_lookup creates this before calling us; when called directly (e.g.
        // from send_lookup), we must create it here.
        tracing::debug!("pf_send_lookup: dest={}", hex::encode(&dest[..8]));
        let xform = self.bloom_x_key(&dest);
        if !self.rumors.contains_key(&xform) {
            self.rumors.insert(xform, PathRumor {
                traffic: None,
                send_time: Instant::now(),
                created: Instant::now(),
            });
        }

        let self_key = self.pub_key;
        let (root, from) = self.get_root_and_path(self_key);
        tracing::debug!("pf_send_lookup: root={} from_path={:?}", hex::encode(&root[..8]), from);
        let lookup = PathLookup { source: self_key, dest, from };

        let mut body = Vec::with_capacity(lookup.size());
        lookup.encode(&mut body);
        tracing::debug!("pf_send_lookup: PathLookup bytes ({} total): {}", body.len(), hex::encode(&body));
        self.pf_handle_lookup(self_key, lookup, body);
    }

    fn pf_handle_lookup(&mut self, from_key: PublicKey, lookup: PathLookup, body: Vec<u8>) {
        tracing::debug!("pf_handle_lookup: dest={} source={} from_peer={}", hex::encode(&lookup.dest[..8]), hex::encode(&lookup.source[..8]), hex::encode(&from_key[..8]));
        // Multicast
        self.bloom_send_multicast(body, WIRE_PROTO_PATH_LOOKUP, from_key, lookup.dest);

        // Check if we match
        let dx = self.bloom_x_key(&lookup.dest);
        let sx = self.bloom_x_key(&self.pub_key);
        tracing::debug!("pf_handle_lookup: dx={} sx={} match={}", hex::encode(&dx[..8]), hex::encode(&sx[..8]), dx==sx);
        if dx != sx { return; }
        tracing::debug!("pf_handle_lookup: MATCHED, sending PathNotify for source={}", hex::encode(&lookup.source[..8]));

        let self_key = self.pub_key;
        let (_, path) = self.get_root_and_path(self_key);
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut notify = PathNotify {
            path:      lookup.from.clone(),
            watermark: u64::MAX,
            source:    self_key,
            dest:      lookup.source,
            info:      PathNotifyInfo { seq, path: path.clone(), sig: [0u8; 64] },
        };

        let new_info = PathNotifyInfo { seq, path, sig: [0u8; 64] };
        if !self.pf_info.equal(&new_info) {
            let mut info = new_info;
            info.sign(&self.priv_key);
            self.pf_info = info.clone();
            notify.info = info;
        } else {
            notify.info = self.pf_info.clone();
        }

        let notify_clone = notify.clone();
        self.pf_handle_notify(self_key, notify_clone);
    }

    fn pf_handle_notify(&mut self, from_key: PublicKey, mut notify: PathNotify) {
        let mut wm = notify.watermark;
        if let Some((next_key, next_id)) = self.lookup(&notify.path.clone(), &mut wm) {
            notify.watermark = wm;
            if let Some(ps) = self.peers.get_mut(&next_key) {
                if let Some(p) = ps.get_mut(&next_id) {
                    p.send_path_notify(&notify);
                }
            }
            return;
        }

        if notify.dest != self.pub_key { return; }

        // Check rumors table
        let xform = self.bloom_x_key(&notify.source);
        tracing::debug!("pf_handle_notify: source={} xform={} rumors_has={} paths_has={}",
            hex::encode(&notify.source[..8]), hex::encode(&xform[..8]),
            self.rumors.contains_key(&xform), self.paths.contains_key(&notify.source));

        if let Some(info) = self.paths.get(&notify.source) {
            if notify.info.seq <= info.seq { return; }
            let nfo = PathNotifyInfo { seq: info.seq, path: info.path.clone(), sig: [0u8; 64] };
            if nfo.equal(&notify.info) { return; }
            if !notify.check() { return; }
            // valid update
        } else {
            if !self.rumors.contains_key(&xform) {
                tracing::warn!("pf_handle_notify: dropped, no rumor for xform={}", hex::encode(&xform[..8]));
                return;
            }
            if !notify.check() {
                tracing::warn!("pf_handle_notify: dropped, check() failed");
                return;
            }
            // new path
        }

        let path = notify.info.path.clone();
        let seq = notify.info.seq;
        let source = notify.source;

        // Move traffic from rumor if available
        let traffic = self.rumors.get_mut(&xform)
            .and_then(|r| r.traffic.take())
            .filter(|tr| tr.dest == source);

        let entry = self.paths.entry(source).or_insert_with(|| PathInfo {
            path: vec![], seq: 0, req_time: Instant::now(),
            updated: Instant::now(), broken: false, traffic: None,
        });
        entry.path = path;
        entry.seq = seq;
        entry.broken = false;
        entry.updated = Instant::now();

        // Fire path notify callback
        tracing::debug!("pf_handle_notify: ACCEPTED path to source={} path_len={}", hex::encode(&source[..8]), entry.path.len());
        if let Ok(vk) = VerifyingKey::from_bytes(&source) {
            if let Some(cb) = &self.path_notify_cb { cb(vk); }
        }

        if let Some(tr) = traffic {
            self.pf_handle_traffic(*tr);
        }
    }

    fn pf_handle_traffic(&mut self, mut tr: Traffic) {
        if let Some(info) = self.paths.get(&tr.dest) {
            if !info.broken {
                tracing::debug!("pf_handle_traffic: routing to dest={} path_len={}", hex::encode(&tr.dest[..8]), info.path.len());
                tr.path = info.path.clone();
                let (_, from) = self.get_root_and_path(self.pub_key);
                tr.from = from;
                self.handle_traffic(None, tr);
                return;
            }
        }
        tracing::debug!("pf_handle_traffic: no path for dest={}, initiating lookup", hex::encode(&tr.dest[..8]));
        // No path known, initiate lookup
        let dest = tr.dest;
        self.pf_rumor_send_lookup(dest, tr);
    }

    fn pf_rumor_send_lookup(&mut self, dest: PublicKey, tr: Traffic) {
        let xform = self.bloom_x_key(&dest);

        let should_send = if let Some(rumor) = self.rumors.get_mut(&xform) {
            let should = rumor.send_time.elapsed() >= PATH_THROTTLE;
            if should { rumor.send_time = Instant::now(); }
            rumor.traffic = Some(Box::new(tr));
            should
        } else {
            self.rumors.insert(xform, PathRumor {
                traffic: Some(Box::new(tr)),
                send_time: Instant::now(),
                created: Instant::now(),
            });
            true
        };

        if should_send { self.pf_send_lookup(dest); }
    }

    fn pf_do_broken(&mut self, tr: &Traffic) {
        let mut broken = PathBroken {
            path:      tr.from.clone(),
            watermark: u64::MAX,
            source:    tr.source,
            dest:      tr.dest,
        };
        self.pf_handle_broken(broken);
    }

    fn pf_handle_broken(&mut self, mut broken: PathBroken) {
        let mut wm = broken.watermark;
        if let Some((next_key, next_id)) = self.lookup(&broken.path.clone(), &mut wm) {
            broken.watermark = wm;
            if let Some(ps) = self.peers.get_mut(&next_key) {
                if let Some(p) = ps.get_mut(&next_id) {
                    p.send_path_broken(&broken);
                }
            }
            return;
        }

        if broken.source != self.pub_key { return; }

        if let Some(info) = self.paths.get_mut(&broken.dest) {
            info.broken = true;
        }
        let dest = broken.dest;
        self.pf_send_lookup(dest);
    }

    fn pf_reset_timeout(&mut self, key: PublicKey) {
        if let Some(info) = self.paths.get_mut(&key) {
            if !info.broken { info.updated = Instant::now(); }
        }
    }

    // ---- Traffic handling ----

    fn handle_traffic(&mut self, from_peer_id: Option<PeerId>, tr: Traffic) {
        let mut wm = tr.watermark;
        let path = tr.path.clone();
        if let Some((next_key, next_id)) = self.lookup(&path, &mut wm) {
            tracing::debug!("handle_traffic: forwarding to next_key={} id={}", hex::encode(&next_key[..8]), next_id);
            let mut tr2 = tr;
            tr2.watermark = wm;
            if let Some(ps) = self.peers.get_mut(&next_key) {
                if let Some(p) = ps.get_mut(&next_id) {
                    p.send_traffic(&tr2);
                }
            }
        } else if tr.dest == self.pub_key {
            if let Some(id) = from_peer_id { /* update rx stats */ }
            self.pf_reset_timeout(tr.source);
            // Deliver to application (session layer will decrypt)
            let _ = self.app_tx.try_send(InboundPacket {
                payload: tr.payload,
                from: tr.source,
            });
        } else {
            tracing::debug!("handle_traffic: no route for dest={} path_len={}", hex::encode(&tr.dest[..8]), path.len());
            self.pf_do_broken(&tr);
        }
    }
}

// ============================================================================
// Session encryption (ported from ironwood/encrypted)
// ============================================================================

struct SessionBuffer {
    data:         Vec<u8>,
    current_pub:  BoxPub,
    current_priv: BoxPriv,
    next_pub:     BoxPub,
    next_priv:    BoxPriv,
    created:      Instant,
}

/// Result returned by decrypt_traffic — tells caller what action to take.
enum DecryptResult {
    /// Decryption succeeded; contains plaintext payload.
    Ok(Vec<u8>),
    /// Keys out of sync; caller should send a SessionInit to recover.
    SendInit,
    /// Packet is invalid/replayed; drop silently.
    Drop,
}

struct SessionInfo {
    ed:             PublicKey, // remote ed25519 key
    seq:            u64,       // remote seq
    remote_key_seq: u64,
    current:        BoxPub,    // remote's current box pub
    next:           BoxPub,    // remote's next box pub
    local_key_seq:  u64,
    recv_priv:      BoxPriv,
    recv_pub:       BoxPub,
    recv_nonce:     u64,
    send_priv:      BoxPriv,
    send_pub:       BoxPub,
    send_nonce:     u64,
    next_priv:      BoxPriv,
    next_pub:       BoxPub,
    next_send_nonce: u64,
    next_recv_nonce: u64,
    rotated:        Option<Instant>, // last time we did key rotation (rate-limit: once/min)
    last_used:      Instant,
    rx_bytes:       u64,
    tx_bytes:       u64,
}

impl SessionInfo {
    fn new(ed: PublicKey, current: BoxPub, next: BoxPub, seq: u64) -> Self {
        let (recv_pub, recv_priv)   = new_box_key_pair();
        let (send_pub, send_priv)   = new_box_key_pair();
        let (next_pub, next_priv)   = new_box_key_pair();
        let mut s = SessionInfo {
            ed, seq: seq.wrapping_sub(1), remote_key_seq: 0,
            current, next, local_key_seq: 0,
            recv_priv, recv_pub, recv_nonce: 0,
            send_priv, send_pub, send_nonce: 0,
            next_priv, next_pub, next_send_nonce: 0, next_recv_nonce: 0,
            rotated: None, last_used: Instant::now(), rx_bytes: 0, tx_bytes: 0,
        };
        s
    }

    fn handle_update(&mut self, current: BoxPub, next: BoxPub, seq: u64, key_seq: u64) {
        self.current = current;
        self.next = next;
        self.seq = seq;
        self.remote_key_seq = key_seq;  // match Go: info.remoteKeySeq = init.keySeq
        // Advance our keys (match Go _handleUpdate)
        self.recv_pub  = self.send_pub;
        self.recv_priv = self.send_priv;
        self.send_pub  = self.next_pub;
        self.send_priv = self.next_priv;
        let (np, npr) = new_box_key_pair();
        self.next_pub  = np;
        self.next_priv = npr;
        self.local_key_seq += 1;
        self.recv_nonce = 0;
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.last_used = Instant::now();
    }

    fn encrypt_traffic(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.send_nonce = self.send_nonce.wrapping_add(1);
        if self.send_nonce == 0 {
            // Nonce overflow: rotate keys
            self.recv_pub  = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub  = self.next_pub;
            self.send_priv = self.next_priv;
            let (np, npr) = new_box_key_pair();
            self.next_pub  = np;
            self.next_priv = npr;
            self.local_key_seq += 1;
            // Match Go: _fixShared(0, 0) resets all nonces
            self.recv_nonce = 0;
            self.next_send_nonce = 0;
            self.next_recv_nonce = 0;
        }

        // Prepend nextPub inside encrypted payload
        let mut inner = Vec::with_capacity(32 + plaintext.len());
        inner.extend_from_slice(&self.next_pub);
        inner.extend_from_slice(plaintext);

        let mut out = Vec::new();
        out.push(SESSION_TRAFFIC);
        put_uvarint(&mut out, self.local_key_seq);
        put_uvarint(&mut out, self.remote_key_seq);
        put_uvarint(&mut out, self.send_nonce);

        let ct = box_seal(&inner, self.send_nonce, &self.current, &self.send_priv);
        out.extend_from_slice(&ct);
        self.tx_bytes += plaintext.len() as u64;
        self.last_used = Instant::now();
        out
    }

    fn decrypt_traffic(&mut self, msg: &[u8]) -> DecryptResult {
        if msg.is_empty() || msg[0] != SESSION_TRAFFIC { return DecryptResult::Drop; }
        let mut d = &msg[1..];
        let remote_key_seq = match chop_uvarint(&mut d) { Some(v) => v, None => return DecryptResult::Drop };
        let local_key_seq  = match chop_uvarint(&mut d) { Some(v) => v, None => return DecryptResult::Drop };
        let nonce          = match chop_uvarint(&mut d) { Some(v) => v, None => return DecryptResult::Drop };

        let from_current = remote_key_seq == self.remote_key_seq;
        let from_next    = remote_key_seq == self.remote_key_seq + 1;
        let to_recv      = local_key_seq + 1 == self.local_key_seq;
        let to_send      = local_key_seq == self.local_key_seq;

        // Select key for decryption (matches Go's doRecv switch)
        enum Case { CurrentToRecv, NextToSend, NextToRecv }
        let case = if from_current && to_recv {
            if nonce <= self.recv_nonce { return DecryptResult::Drop; }
            Case::CurrentToRecv
        } else if from_next && to_send {
            if nonce <= self.next_send_nonce { return DecryptResult::Drop; }
            Case::NextToSend
        } else if from_next && to_recv {
            if nonce <= self.next_recv_nonce { return DecryptResult::Drop; }
            Case::NextToRecv
        } else {
            // Can't make sense of the key seqs — send init to recover (matches Go default case)
            return DecryptResult::SendInit;
        };

        let (shared_pub, shared_priv) = match case {
            Case::CurrentToRecv => (self.current, self.recv_priv),
            Case::NextToSend    => (self.next,    self.send_priv),
            Case::NextToRecv    => (self.next,    self.recv_priv),
        };

        let decrypted = match box_open(d, nonce, &shared_pub, &shared_priv) {
            Some(d) => d,
            // Decryption failure = keys out of sync → send init to recover (matches Go else branch)
            None => return DecryptResult::SendInit,
        };

        if decrypted.len() < 32 { return DecryptResult::Drop; }
        let inner_key: BoxPub = match decrypted[..32].try_into() {
            Ok(k) => k,
            Err(_) => return DecryptResult::Drop,
        };
        let payload = decrypted[32..].to_vec();

        // Update nonces and potentially rotate keys (matches Go onSuccess callbacks)
        match case {
            Case::CurrentToRecv => {
                self.recv_nonce = nonce;
            }
            Case::NextToSend => {
                // Always update nonce to prevent replay even if rate-limited (matches Go)
                self.next_send_nonce = nonce;
                // Rate-limited key rotation: at most once per minute (matches Go rotated check)
                let should_rotate = self.rotated
                    .map(|t| t.elapsed() > Duration::from_secs(60))
                    .unwrap_or(true);
                if should_rotate {
                    self.current = self.next;
                    self.next = inner_key;
                    self.remote_key_seq += 1;
                    self.recv_pub  = self.send_pub;
                    self.recv_priv = self.send_priv;
                    self.send_pub  = self.next_pub;
                    self.send_priv = self.next_priv;
                    let (np, npr) = new_box_key_pair();
                    self.next_pub  = np;
                    self.next_priv = npr;
                    self.local_key_seq += 1;
                    // _fixShared(nonce, 0): recvNonce=nonce, sendNonce=0, next*=0
                    self.recv_nonce = nonce;
                    self.send_nonce = 0;
                    self.next_send_nonce = 0;
                    self.next_recv_nonce = 0;
                    self.rotated = Some(Instant::now());
                }
            }
            Case::NextToRecv => {
                // Always update nonce to prevent replay even if rate-limited (matches Go)
                self.next_recv_nonce = nonce;
                let should_rotate = self.rotated
                    .map(|t| t.elapsed() > Duration::from_secs(60))
                    .unwrap_or(true);
                if should_rotate {
                    self.current = self.next;
                    self.next = inner_key;
                    self.remote_key_seq += 1;
                    self.recv_pub  = self.send_pub;
                    self.recv_priv = self.send_priv;
                    self.send_pub  = self.next_pub;
                    self.send_priv = self.next_priv;
                    let (np, npr) = new_box_key_pair();
                    self.next_pub  = np;
                    self.next_priv = npr;
                    self.local_key_seq += 1;
                    // _fixShared(nonce, 0)
                    self.recv_nonce = nonce;
                    self.send_nonce = 0;
                    self.next_send_nonce = 0;
                    self.next_recv_nonce = 0;
                    self.rotated = Some(Instant::now());
                }
            }
        }

        self.rx_bytes += payload.len() as u64;
        self.last_used = Instant::now();
        DecryptResult::Ok(payload)
    }
}

// ============================================================================
// SessionInit wire format
// ============================================================================

struct SessionInitMsg {
    current: BoxPub,
    next:    BoxPub,
    key_seq: u64,
    seq:     u64,
}

impl SessionInitMsg {
    fn encrypt(&self, from_ed_priv: &PrivateKey, to_ed_pub: &PublicKey,
               type_byte: u8) -> Option<Vec<u8>> {
        let to_box_pub = ed_pub_to_box_pub(to_ed_pub)?;
        let (from_box_pub, from_box_priv) = new_box_key_pair();

        // Build signed bytes
        let mut sig_bytes = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        sig_bytes.extend_from_slice(&from_box_pub);
        sig_bytes.extend_from_slice(&self.current);
        sig_bytes.extend_from_slice(&self.next);
        sig_bytes.extend_from_slice(&self.key_seq.to_be_bytes());
        sig_bytes.extend_from_slice(&self.seq.to_be_bytes());

        let sig = sign_msg(&sig_bytes, from_ed_priv);

        // Payload to be encrypted: sig[64] + sigBytes[32..] (skip the fromBoxPub prefix)
        let mut payload = Vec::with_capacity(64 + sig_bytes.len() - 32);
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&sig_bytes[32..]); // current + next + key_seq + seq

        let ct = box_seal(&payload, 0, &to_box_pub, &from_box_priv);

        let mut out = vec![type_byte];
        out.extend_from_slice(&from_box_pub);
        out.extend_from_slice(&ct);
        if out.len() != SESSION_INIT_SIZE { return None; }
        Some(out)
    }

    fn decrypt(data: &[u8], our_ed_priv: &PrivateKey,
               from_ed_pub: &PublicKey) -> Option<SessionInitMsg> {
        if data.len() != SESSION_INIT_SIZE { return None; }
        // data[0] is type byte (already checked by caller)
        let from_box_pub: BoxPub = data[1..33].try_into().ok()?;
        let our_box_priv = ed_priv_to_box_priv(our_ed_priv);
        let ct = &data[33..];

        let payload = box_open(ct, 0, &from_box_pub, &our_box_priv)?;
        // payload: sig[64] + current[32] + next[32] + key_seq[8] + seq[8] = 144
        if payload.len() < 144 { return None; }

        let sig: Signature = payload[..64].try_into().ok()?;
        let current: BoxPub = payload[64..96].try_into().ok()?;
        let next:    BoxPub = payload[96..128].try_into().ok()?;
        let key_seq = u64::from_be_bytes(payload[128..136].try_into().ok()?);
        let seq     = u64::from_be_bytes(payload[136..144].try_into().ok()?);

        // Verify signature: sig covers fromBoxPub + current + next + key_seq + seq
        let mut sig_bytes = Vec::with_capacity(112);
        sig_bytes.extend_from_slice(&from_box_pub);
        sig_bytes.extend_from_slice(&payload[64..144]); // current+next+key_seq+seq
        if !verify_sig(&sig_bytes, &sig, from_ed_pub) { return None; }

        Some(SessionInitMsg { current, next, key_seq, seq })
    }
}

// ============================================================================
// Session manager
// ============================================================================

/// Action returned by handle_data, telling the caller what to do next.
enum SessionAction {
    /// Decrypted payload ready to deliver to the application.
    Plaintext(Vec<u8>),
    /// Keys out of sync on existing session — send init with session's own keys to recover.
    RecoveryInit,
    /// Traffic arrived for an unknown session — send throwaway init (random keys, no buffer).
    /// Matches Go's _handleTraffic else branch.
    ThrowawayInit,
    /// Nothing to do (handshake packet processed, or replay/invalid).
    Nothing,
}

struct SessionManager {
    sessions:   HashMap<PublicKey, SessionInfo>,
    buffers:    HashMap<PublicKey, SessionBuffer>,
    ed_priv:    PrivateKey,  // our ed25519 private key
    box_priv:   BoxPriv,     // our x25519 private key (from ed_priv)
    pending_tx: Vec<(PublicKey, Vec<u8>)>, // encrypted packets to route after session est.
}

impl SessionManager {
    fn new(ed_priv: PrivateKey) -> Self {
        let box_priv = ed_priv_to_box_priv(&ed_priv);
        SessionManager {
            sessions:   HashMap::new(),
            buffers:    HashMap::new(),
            ed_priv, box_priv,
            pending_tx: Vec::new(),
        }
    }

    fn handle_data(&mut self, from_pub: &PublicKey, data: Vec<u8>) -> SessionAction {
        if data.is_empty() { return SessionAction::Nothing; }
        match data[0] {
            SESSION_DUMMY => SessionAction::Nothing,
            SESSION_INIT => {
                if let Some(init) = SessionInitMsg::decrypt(&data, &self.ed_priv, from_pub) {
                    self.handle_init(from_pub, &init);
                }
                SessionAction::Nothing // ack sent separately
            }
            SESSION_ACK => {
                if let Some(ack) = SessionInitMsg::decrypt(&data, &self.ed_priv, from_pub) {
                    self.handle_ack(from_pub, &ack);
                }
                SessionAction::Nothing
            }
            SESSION_TRAFFIC => {
                if let Some(session) = self.sessions.get_mut(from_pub) {
                    match session.decrypt_traffic(&data) {
                        DecryptResult::Ok(payload) => SessionAction::Plaintext(payload),
                        // Keys out of sync: recover by sending init with existing session keys
                        DecryptResult::SendInit    => SessionAction::RecoveryInit,
                        DecryptResult::Drop        => SessionAction::Nothing,
                    }
                } else {
                    // Unknown session — could be spoofed/replay, don't create a buffer.
                    // Send a throwaway init (matches Go _handleTraffic else branch).
                    SessionAction::ThrowawayInit
                }
            }
            _ => SessionAction::Nothing,
        }
    }

    /// Build a SessionInit using the existing session's send_pub/next_pub.
    /// Used to recover from key desync (matches Go sessionInfo._sendInit).
    fn make_recovery_init(&self, pub_key: &PublicKey) -> Option<Vec<u8>> {
        let session = self.sessions.get(pub_key)?;
        let init = SessionInitMsg {
            current: session.send_pub,
            next:    session.next_pub,
            key_seq: session.local_key_seq,
            seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
        };
        init.encrypt(&self.ed_priv, pub_key, SESSION_INIT)
    }

    /// Build a SessionInit with throwaway random keys (no buffer created).
    /// Used when traffic arrives for an unknown session (matches Go _handleTraffic else branch).
    fn make_throwaway_init(&self, pub_key: &PublicKey) -> Option<Vec<u8>> {
        let (current, _) = new_box_key_pair();
        let (next, _)    = new_box_key_pair();
        let init = SessionInitMsg {
            current, next, key_seq: 0,
            seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
        };
        init.encrypt(&self.ed_priv, pub_key, SESSION_INIT)
    }

    fn handle_init(&mut self, pub_key: &PublicKey, init: &SessionInitMsg) {
        if let Some(info) = self.sessions.get_mut(pub_key) {
            if init.seq <= info.seq { return; }
            info.handle_update(init.current, init.next, init.seq, init.key_seq);
        } else {
            let mut info = SessionInfo::new(*pub_key, init.current, init.next, init.seq);
            // Absorb buffer keys if any (match Go _sessionForInit buffer absorption)
            if let Some(buf) = self.buffers.remove(pub_key) {
                info.send_pub  = buf.current_pub;
                info.send_priv = buf.current_priv;
                info.next_pub  = buf.next_pub;
                info.next_priv = buf.next_priv;
            }
            // Always advance keys like Go's handleInit → _handleUpdate
            // (seq was set to init.seq - 1 in new(), so this update always applies)
            info.handle_update(init.current, init.next, init.seq, init.key_seq);
            self.sessions.insert(*pub_key, info);
        }
    }

    fn handle_ack(&mut self, pub_key: &PublicKey, ack: &SessionInitMsg) {
        let already = self.sessions.contains_key(pub_key);
        if already {
            if let Some(info) = self.sessions.get_mut(pub_key) {
                if ack.seq <= info.seq { return; }
                info.handle_update(ack.current, ack.next, ack.seq, ack.key_seq);
            }
        } else {
            // Take buffered data BEFORE handle_init removes the buffer
            let buffered = self.buffers.get(pub_key)
                .filter(|b| !b.data.is_empty())
                .map(|b| b.data.clone());
            self.handle_init(pub_key, ack);
            // Now the session exists; encrypt and queue any buffered payload
            if let Some(data) = buffered {
                if let Some(info) = self.sessions.get_mut(pub_key) {
                    let enc = info.encrypt_traffic(&data);
                    tracing::debug!("handle_ack: flushing buffered {} bytes to {}", data.len(), hex::encode(&pub_key[..8]));
                    self.pending_tx.push((*pub_key, enc));
                }
            }
        }
    }

    /// Send an init packet bytes to the given destination (to be routed by caller).
    /// Payload is buffered so it can be flushed once a SessionAck is received.
    fn make_init(&mut self, to_pub: &PublicKey, payload: &[u8]) -> Option<Vec<u8>> {
        let buf = self.buffers.entry(*to_pub).or_insert_with(|| {
            let (cp, cpr) = new_box_key_pair();
            let (np, npr) = new_box_key_pair();
            SessionBuffer {
                data: vec![], current_pub: cp, current_priv: cpr,
                next_pub: np, next_priv: npr, created: Instant::now(),
            }
        });
        // Always update buffered data with the latest packet
        buf.data = payload.to_vec();

        let init = SessionInitMsg {
            current: buf.current_pub,
            next:    buf.next_pub,
            key_seq: 0,
            seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
        };
        init.encrypt(&self.ed_priv, to_pub, SESSION_INIT)
    }

    fn make_ack(&self, to_pub: &PublicKey, session: &SessionInfo) -> Option<Vec<u8>> {
        let init = SessionInitMsg {
            current: session.send_pub,
            next:    session.next_pub,
            key_seq: session.local_key_seq,
            seq: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
        };
        init.encrypt(&self.ed_priv, to_pub, SESSION_ACK)
    }

    /// Encrypt plaintext for sending to dest_pub. Returns encrypted bytes
    /// or None if no session (caller should then send init and buffer).
    fn write_to(&mut self, dest: &PublicKey, msg: &[u8]) -> Option<Vec<u8>> {
        if let Some(session) = self.sessions.get_mut(dest) {
            Some(session.encrypt_traffic(msg))
        } else {
            None
        }
    }

    fn expire_sessions(&mut self) {
        let timeout = Duration::from_secs(60);
        let expired: Vec<PublicKey> = self.sessions.iter()
            .filter(|(_, s)| s.last_used.elapsed() > timeout)
            .map(|(k, _)| *k)
            .collect();
        for k in expired { self.sessions.remove(&k); }

        let expired_bufs: Vec<PublicKey> = self.buffers.iter()
            .filter(|(_, b)| b.created.elapsed() > timeout)
            .map(|(k, _)| *k)
            .collect();
        for k in expired_bufs { self.buffers.remove(&k); }
    }
}

// ============================================================================
// NetworkCore — manages peer connections and owns RouterState + SessionManager
// ============================================================================

struct NetworkCore {
    router:   Arc<Mutex<RouterState>>,
    sessions: Arc<Mutex<SessionManager>>,
    pub_key:  PublicKey,
    priv_key: PrivateKey,
    app_rx:   Mutex<mpsc::Receiver<InboundPacket>>,
    // channel for packets that need a session ack to be sent back
    ack_tx:   mpsc::Sender<(PublicKey, Vec<u8>)>,
}

// ============================================================================
// PacketConn (public API)
// ============================================================================

pub struct PacketConn {
    inner: Arc<PacketConnInner>,
}

struct PacketConnInner {
    router:   Arc<Mutex<RouterState>>,
    sessions: Arc<Mutex<SessionManager>>,
    pub_key:  PublicKey,
    priv_key: PrivateKey,
    app_rx:   Mutex<mpsc::Receiver<InboundPacket>>,
    // pending acks: (dest_ed_pub, ack_bytes)
    ack_tx:   mpsc::Sender<(PublicKey, Vec<u8>)>,
    ack_rx:   Mutex<mpsc::Receiver<(PublicKey, Vec<u8>)>>,
}

impl PacketConn {
    pub fn new(signing_key: SigningKey) -> Self {
        let seed = signing_key.to_bytes();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        // Build private key (seed + pub, 64 bytes, like Go's ed25519.PrivateKey)
        let mut priv_key = [0u8; 64];
        priv_key[..32].copy_from_slice(&seed);
        priv_key[32..].copy_from_slice(&pub_bytes);

        let (app_tx, app_rx) = mpsc::channel(4096);
        let (ack_tx, ack_rx) = mpsc::channel(256);

        let router = Arc::new(Mutex::new(
            RouterState::new(pub_bytes, priv_key, app_tx)
        ));
        let sessions = Arc::new(Mutex::new(SessionManager::new(priv_key)));

        let inner = Arc::new(PacketConnInner {
            router: Arc::clone(&router),
            sessions: Arc::clone(&sessions),
            pub_key:  pub_bytes,
            priv_key,
            app_rx:   Mutex::new(app_rx),
            ack_tx,
            ack_rx:   Mutex::new(ack_rx),
        });

        // Spawn maintenance task
        {
            let r = Arc::clone(&router);
            let s = Arc::clone(&sessions);
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    r.lock().await.do_maintenance();
                    s.lock().await.expire_sessions();
                }
            });
        }

        // Spawn ack-sender task: consume pending SessionAck packets and route them.
        // This is necessary because acks must be routed via the router (which requires
        // async) but session handling happens inside sync mutex guards.
        {
            let inner2 = Arc::clone(&inner);
            tokio::spawn(async move {
                let mut rx = inner2.ack_rx.lock().await;
                while let Some((dest, ack_bytes)) = rx.recv().await {
                    let mut router = inner2.router.lock().await;
                    let self_key = router.pub_key;
                    let (_, path) = router.get_root_and_path(dest);
                    let (_, from) = router.get_root_and_path(self_key);
                    let tr = Traffic {
                        path, from, source: self_key, dest,
                        watermark: u64::MAX, payload: ack_bytes,
                    };
                    drop(router);
                    inner2.router.lock().await.pf_handle_traffic(tr);
                }
            });
        }

        PacketConn { inner }
    }

    pub fn public_key(&self) -> PublicKeyBytes { self.inner.pub_key }

    pub fn mtu(&self) -> u64 {
        // Approximate: peerMaxMsgSize - traffic overhead - session overhead
        let tr_overhead = size_path(&[]) * 2 + 32 + 32 + size_uvarint(u64::MAX) + 1;
        let sess_overhead = 1 + 9 + 9 + 9 + 32 + BOX_OVERHEAD;
        (PEER_MAX_MSG_SIZE - tr_overhead - sess_overhead) as u64
    }

    pub async fn set_path_notify<F>(&self, f: F)
    where F: Fn(VerifyingKey) + Send + Sync + 'static
    {
        self.inner.router.lock().await.path_notify_cb = Some(Box::new(f));
    }

    /// Called by link.rs after a successful yggdrasil handshake.
    /// Blocks until the peer session ends (mirrors ironwood HandleConn semantics).
    pub async fn handle_conn(
        &self,
        peer_pub_key: PublicKeyBytes,
        reader: BoxReader,
        writer: BoxWriter,
        priority: u8,
    ) -> Result<()> {
        if peer_pub_key == self.inner.pub_key {
            return Err(anyhow!("cannot connect to self"));
        }
        run_peer(Arc::clone(&self.inner), peer_pub_key, reader, writer, priority).await
    }

    /// Receives the next application-level packet (decrypted).
    pub async fn read_from(&self) -> Result<InboundPacket> {
        let mut rx = self.inner.app_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow!("PacketConn closed"))
    }

    /// Sends an encrypted application-level packet to dst.
    pub async fn write_to(&self, payload: &[u8], dst: &PublicKeyBytes) -> Result<()> {
        // Try to encrypt with existing session
        let encrypted = self.inner.sessions.lock().await.write_to(dst, payload);

        if let Some(enc) = encrypted {
            // Route encrypted bytes via the network layer
            self.send_via_router(*dst, enc).await;
        } else {
            // No session yet — buffer payload and send SessionInit
            let init_bytes = self.inner.sessions.lock().await.make_init(dst, payload);
            if let Some(init) = init_bytes {
                tracing::debug!("write_to: no session for {}, sending SessionInit + buffering {} bytes", hex::encode(&dst[..8]), payload.len());
                self.send_via_router(*dst, init).await;
            }
        }
        Ok(())
    }

    pub async fn send_lookup(&self, partial_key: &[u8]) {
        if partial_key.len() != 32 { return; }
        let mut key = [0u8; 32];
        key.copy_from_slice(partial_key);
        self.inner.router.lock().await.pf_send_lookup(key);
    }

    pub async fn close(&self) {
        // Drop all peers by clearing the router state
        self.inner.router.lock().await.peers.clear();
    }

    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        // Non-async version — use try_lock
        if let Ok(r) = self.inner.router.try_lock() {
            r.peers.iter().flat_map(|(key, peer_map)| {
                peer_map.values().map(|p| PeerStats {
                    key: p.key,
                    priority: p.prio,
                    rx_bytes: p.rx_bytes,
                    tx_bytes: p.tx_bytes,
                    uptime: p.connected_at.elapsed(),
                    latency: p.lag,
                }).collect::<Vec<_>>()
            }).collect()
        } else { vec![] }
    }

    async fn send_via_router(&self, dest: PublicKey, payload: Vec<u8>) {
        let mut router = self.inner.router.lock().await;
        let self_key = router.pub_key;
        let (_, path) = router.get_root_and_path(dest);
        let (_, from) = router.get_root_and_path(self_key);
        let tr = Traffic {
            path, from, source: self_key, dest,
            watermark: u64::MAX, payload,
        };
        drop(router); // release lock before recursive call
        self.inner.router.lock().await.pf_handle_traffic(tr);
    }
}

// ============================================================================
// Per-peer read/write tasks
// ============================================================================

async fn run_peer(
    inner: Arc<PacketConnInner>,
    peer_key: PublicKey,
    mut reader: BoxReader,
    writer: BoxWriter,
    priority: u8,
) -> Result<()> {
    // Channel for write task
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Register peer with router
    let (peer_id, port) = {
        let mut router = inner.router.lock().await;
        let port = router.next_port;
        router.next_port += 1;
        let id = router.add_peer(peer_key, port, priority, write_tx.clone());
        (id, port)
    };

    info!("peer connected: {} (id={}, port={})", hex::encode(&peer_key[..8]), peer_id, port);

    // Write task
    let write_task = tokio::spawn(async move {
        let mut w = writer;
        while let Some(data) = write_rx.recv().await {
            if w.write_all(&data).await.is_err() { break; }
        }
    });

    // Keepalive task: send a keepalive frame every PEER_KEEPALIVE_DELAY
    // to prevent the remote side from timing out the connection.
    let keepalive_task = {
        let ka_tx = write_tx.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(PEER_KEEPALIVE_DELAY);
            loop {
                interval.tick().await;
                let frame = encode_frame(WIRE_KEEP_ALIVE, &[]);
                if ka_tx.send(frame).await.is_err() {
                    break;
                }
            }
        })
    };

    // Read loop
    let result = peer_read_loop(&inner, peer_key, peer_id, &mut *reader).await;

    // Cleanup
    keepalive_task.abort();
    write_task.abort();
    inner.router.lock().await.remove_peer(&peer_key, peer_id);
    info!("peer disconnected: {}", hex::encode(&peer_key[..8]));
    result
}

async fn peer_read_loop<R: AsyncRead + Unpin + Send + ?Sized>(
    inner: &Arc<PacketConnInner>,
    peer_key: PublicKey,
    peer_id: PeerId,
    stream: &mut R,
) -> Result<()> {
    let self_key = inner.pub_key;

    loop {
        // Read uvarint frame length
        let frame_len = read_uvarint_from(stream).await?;

        if frame_len == 0 || frame_len > PEER_MAX_MSG_SIZE as u64 {
            return Err(anyhow!("invalid frame length: {}", frame_len));
        }

        let mut frame = vec![0u8; frame_len as usize];
        tokio::time::timeout(PEER_TIMEOUT, stream.read_exact(&mut frame)).await
            .map_err(|_| anyhow!("peer timeout"))?
            .map_err(|e| anyhow!("read error: {e}"))?;

        if frame.is_empty() { continue; }
        let pkt_type = frame[0];
        let body = &frame[1..];

        tracing::trace!("rx pkt_type={} len={} from={}", pkt_type, frame_len, hex::encode(&peer_key[..8]));

        let mut router = inner.router.lock().await;

        // Update rx stats
        if let Some(ps) = router.peers.get_mut(&peer_key) {
            if let Some(p) = ps.get_mut(&peer_id) {
                p.rx_bytes += frame.len() as u64;
            }
        }

        if !matches!(pkt_type, WIRE_DUMMY | WIRE_KEEP_ALIVE | WIRE_PROTO_ANNOUNCE | WIRE_PROTO_BLOOM_FILTER) {
            tracing::debug!("rx pkt_type={} from={} body_len={}", pkt_type, hex::encode(&peer_key[..8]), body.len());
        }
        match pkt_type {
            WIRE_DUMMY | WIRE_KEEP_ALIVE => {}

            WIRE_PROTO_SIG_REQ => {
                if let Some(req) = SigReq::decode(body) {
                    router.handle_request(peer_id, peer_key, req);
                }
            }

            WIRE_PROTO_SIG_RES => {
                if let Some(res) = SigRes::decode(body) {
                    let rtt = router.peers.get(&peer_key)
                        .and_then(|ps| ps.get(&peer_id))
                        .and_then(|p| p.req_send_time)
                        .map(|t| t.elapsed())
                        .unwrap_or(Duration::from_secs(1));
                    router.handle_response(peer_id, peer_key, res, rtt);
                }
            }

            WIRE_PROTO_ANNOUNCE => {
                if let Some(ann) = Announce::decode(body) {
                    tracing::debug!("rx ANNOUNCE key={} parent={} from={}",
                        hex::encode(&ann.key[..8]), hex::encode(&ann.parent[..8]),
                        hex::encode(&peer_key[..8]));
                    if ann.check() {
                        router.handle_announce(peer_id, peer_key, ann);
                    } else {
                        tracing::warn!("rx ANNOUNCE check FAILED from={}", hex::encode(&peer_key[..8]));
                    }
                } else {
                    tracing::warn!("rx ANNOUNCE decode FAILED from={} body_len={}", hex::encode(&peer_key[..8]), body.len());
                }
            }

            WIRE_PROTO_BLOOM_FILTER => {
                if let Some(bloom) = BloomFilter::decode(body) {
                    router.bloom_handle(peer_key, bloom);
                }
            }

            WIRE_PROTO_PATH_LOOKUP => {
                let on_tree = router.bloom_infos.get(&peer_key)
                    .map(|bi| bi.on_tree).unwrap_or(false);
                tracing::debug!("rx PATH_LOOKUP from={} on_tree={} body_len={}", hex::encode(&peer_key[..8]), on_tree, body.len());
                if on_tree {
                    if let Some(lookup) = PathLookup::decode(body) {
                        let body_clone = body.to_vec();
                        router.pf_handle_lookup(peer_key, lookup, body_clone);
                    } else {
                        tracing::warn!("rx PATH_LOOKUP decode FAILED from={}", hex::encode(&peer_key[..8]));
                    }
                }
            }

            WIRE_PROTO_PATH_NOTIFY => {
                tracing::debug!("rx PATH_NOTIFY from={} body_len={}", hex::encode(&peer_key[..8]), body.len());
                if let Some(notify) = PathNotify::decode(body) {
                    router.pf_handle_notify(peer_key, notify);
                } else {
                    tracing::warn!("rx PATH_NOTIFY decode FAILED from={}", hex::encode(&peer_key[..8]));
                }
            }

            WIRE_PROTO_PATH_BROKEN => {
                if let Some(broken) = PathBroken::decode(body) {
                    router.pf_handle_broken(broken);
                }
            }

            WIRE_TRAFFIC => {
                if let Some(mut tr) = Traffic::decode(body) {
                    let dest = tr.dest;
                    let source = tr.source;
                    let payload = tr.payload.clone();
                    tracing::debug!("rx TRAFFIC: dest={} source={} payload_len={} for_us={}",
                        hex::encode(&dest[..8]), hex::encode(&source[..8]), payload.len(), dest == self_key);
                    drop(router);

                    // If destined for us, pass to session layer
                    if dest == self_key {
                        let mut sessions = inner.sessions.lock().await;
                        let action = sessions.handle_data(&source, payload.clone());
                        // Flush any data queued by handle_ack (buffered payload after session est.)
                        let pending = std::mem::take(&mut sessions.pending_tx);
                        // Check if we need to send an ack (session init received)
                        if !payload.is_empty() && payload[0] == SESSION_INIT {
                            if let Some(sess) = sessions.sessions.get(&source) {
                                if let Some(ack) = sessions.make_ack(&source, sess) {
                                    drop(sessions);
                                    let _ = inner.ack_tx.try_send((source, ack));
                                }
                            } else {
                                drop(sessions);
                            }
                        } else {
                            // Handle recovery/throwaway init for session desync
                            let recovery_bytes = match &action {
                                SessionAction::RecoveryInit  => sessions.make_recovery_init(&source),
                                SessionAction::ThrowawayInit => sessions.make_throwaway_init(&source),
                                _ => None,
                            };
                            drop(sessions);
                            if let Some(init_bytes) = recovery_bytes {
                                tracing::debug!("session recovery: sending init to {}", hex::encode(&source[..8]));
                                let _ = inner.ack_tx.try_send((source, init_bytes));
                            }
                        }
                        // Route any pending (post-session-establishment) encrypted packets
                        for (dest_key, enc) in pending {
                            let _ = inner.ack_tx.try_send((dest_key, enc));
                        }
                        if let SessionAction::Plaintext(plaintext) = action {
                            // Deliver decrypted payload to application
                            let _ = inner.router.lock().await.app_tx.try_send(InboundPacket {
                                payload: plaintext,
                                from: source,
                            });
                        }
                    } else {
                        let mut r = inner.router.lock().await;
                        let mut wm = tr.watermark;
                        if let Some((next_key, next_id)) = r.lookup(&tr.path.clone(), &mut wm) {
                            tr.watermark = wm;
                            if let Some(ps) = r.peers.get_mut(&next_key) {
                                if let Some(p) = ps.get_mut(&next_id) {
                                    p.send_traffic(&tr);
                                }
                            }
                        } else {
                            r.pf_do_broken(&tr);
                        }
                    }
                } else {
                    return Err(anyhow!("malformed traffic packet"));
                }
            }

            _ => { warn!("unknown packet type: {}", pkt_type); }
        }
    }
}

/// Read a uvarint with no timeout (wait indefinitely for next frame to start).
/// The Go ironwood implementation only sets a read deadline after *sending*
/// a non-keepalive packet, so we match that by not timing out waiting for
/// the next frame.
async fn read_uvarint_from<R: AsyncRead + Unpin + ?Sized>(stream: &mut R) -> Result<u64> {
    let mut x = 0u64;
    let mut s = 0u32;
    for _i in 0..10usize {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await
            .map_err(|e| anyhow!("read error: {e}"))?;
        let byte = b[0];
        if byte < 0x80 {
            return Ok(x | (byte as u64) << s);
        }
        x |= ((byte & 0x7f) as u64) << s;
        s += 7;
    }
    Err(anyhow!("uvarint overflow"))
}
