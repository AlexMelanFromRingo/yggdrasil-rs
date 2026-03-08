//! Yggdrasil connection handshake — version metadata.
//!
//! Port of yggdrasil-go/src/core/version.go
//!
//! Wire format:
//!   4 bytes  "meta" magic
//!   2 bytes  remaining-length (big-endian u16) — covers TLV entries + signature
//!   TLV entries (each: 2-byte type, 2-byte length, N bytes value):
//!     type 0 — major version (u16 BE)
//!     type 1 — minor version (u16 BE)
//!     type 2 — ed25519 public key (32 bytes)
//!     type 3 — priority (u8)
//!   64 bytes  ed25519 signature over BLAKE2b-512(password)(public_key)

use anyhow::{anyhow, Result};
use blake2::Blake2b512;
use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const PROTOCOL_VERSION_MAJOR: u16 = 0;
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

const ED25519_PUBLIC_KEY_SIZE: usize = 32;
const ED25519_SIGNATURE_SIZE: usize = 64;

/// Metadata exchanged at the start of every peer connection.
#[derive(Debug, Clone, Default)]
pub struct VersionMetadata {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    pub priority: u8,
}

impl VersionMetadata {
    /// Returns a base metadata struct with the current protocol version.
    pub fn base() -> Self {
        VersionMetadata {
            major_ver: PROTOCOL_VERSION_MAJOR,
            minor_ver: PROTOCOL_VERSION_MINOR,
            public_key: [0u8; ED25519_PUBLIC_KEY_SIZE],
            priority: 0,
        }
    }

    /// Serialises the metadata to wire format and signs it.
    pub fn encode(&self, signing_key: &SigningKey, password: &[u8]) -> Result<Vec<u8>> {
        let mut bs: Vec<u8> = Vec::with_capacity(128);

        // Magic
        bs.extend_from_slice(b"meta");
        // Placeholder for remaining-length (filled in at the end)
        bs.extend_from_slice(&[0u8, 0u8]);

        // TLV: major version
        bs.extend_from_slice(&META_VERSION_MAJOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes());
        bs.extend_from_slice(&self.major_ver.to_be_bytes());

        // TLV: minor version
        bs.extend_from_slice(&META_VERSION_MINOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes());
        bs.extend_from_slice(&self.minor_ver.to_be_bytes());

        // TLV: public key
        bs.extend_from_slice(&META_PUBLIC_KEY.to_be_bytes());
        bs.extend_from_slice(&(ED25519_PUBLIC_KEY_SIZE as u16).to_be_bytes());
        bs.extend_from_slice(&self.public_key);

        // TLV: priority
        bs.extend_from_slice(&META_PRIORITY.to_be_bytes());
        bs.extend_from_slice(&1u16.to_be_bytes());
        bs.push(self.priority);

        // Compute hash: BLAKE2b-512 keyed with `password` over `public_key`
        let hash = blake2b_keyed_hash(&self.public_key, password)?;

        // Sign the hash
        let sig: Signature = signing_key.sign(&hash);
        bs.extend_from_slice(&sig.to_bytes());

        // Fill in remaining-length (everything after the 6-byte header)
        let remaining = (bs.len() - 6) as u16;
        bs[4] = (remaining >> 8) as u8;
        bs[5] = remaining as u8;

        Ok(bs)
    }

    /// Reads and verifies a metadata frame from an async reader.
    pub async fn decode<R: AsyncRead + Unpin>(
        reader: &mut R,
        password: &[u8],
    ) -> Result<Self> {
        // Read 6-byte header
        let mut header = [0u8; 6];
        reader.read_exact(&mut header).await?;

        if &header[..4] != b"meta" {
            return Err(anyhow!("invalid handshake: remote is not Yggdrasil"));
        }

        let remaining_len = u16::from_be_bytes([header[4], header[5]]) as usize;
        if remaining_len < ED25519_SIGNATURE_SIZE {
            return Err(anyhow!("invalid handshake length, possible version mismatch"));
        }

        let mut body = vec![0u8; remaining_len];
        reader.read_exact(&mut body).await?;

        let sig_bytes = &body[body.len() - ED25519_SIGNATURE_SIZE..];
        let tlv_bytes = &body[..body.len() - ED25519_SIGNATURE_SIZE];

        let mut meta = VersionMetadata::default();
        let mut rest = tlv_bytes;

        while rest.len() >= 4 {
            let op = u16::from_be_bytes([rest[0], rest[1]]);
            let oplen = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            rest = &rest[4..];
            if rest.len() < oplen {
                break;
            }
            match op {
                META_VERSION_MAJOR if oplen >= 2 => {
                    meta.major_ver = u16::from_be_bytes([rest[0], rest[1]]);
                }
                META_VERSION_MINOR if oplen >= 2 => {
                    meta.minor_ver = u16::from_be_bytes([rest[0], rest[1]]);
                }
                META_PUBLIC_KEY if oplen == ED25519_PUBLIC_KEY_SIZE => {
                    meta.public_key.copy_from_slice(&rest[..ED25519_PUBLIC_KEY_SIZE]);
                }
                META_PRIORITY if oplen >= 1 => {
                    meta.priority = rest[0];
                }
                _ => {}
            }
            rest = &rest[oplen..];
        }

        // Verify signature: must be a valid ed25519 sig over BLAKE2b(key) using their key
        let hash = blake2b_keyed_hash(&meta.public_key, password)
            .map_err(|_| anyhow!("invalid password supplied, check your config"))?;

        let vk = VerifyingKey::from_bytes(&meta.public_key)
            .map_err(|e| anyhow!("invalid remote public key: {e}"))?;

        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow!("invalid signature length"))?;
        let sig = Signature::from_bytes(&sig_arr);

        vk.verify(&hash, &sig)
            .map_err(|_| anyhow!("password does not match remote side"))?;

        Ok(meta)
    }

    /// Returns true if the version is compatible with ours.
    pub fn check(&self) -> bool {
        self.major_ver == PROTOCOL_VERSION_MAJOR
            && self.minor_ver == PROTOCOL_VERSION_MINOR
            && self.public_key != [0u8; 32]
    }
}

/// BLAKE2b-512 keyed with `password` over `data`.
fn blake2b_keyed_hash(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    if password.is_empty() {
        // Unkeyed BLAKE2b
        use blake2::Digest;
        let mut h = Blake2b512::new();
        Digest::update(&mut h, data);
        return Ok(Digest::finalize(h).to_vec());
    }

    // Keyed BLAKE2b (password acts as the key)
    use blake2::{Blake2bMac512, digest::{KeyInit, Mac}};
    let mut h = <Blake2bMac512 as KeyInit>::new_from_slice(password)
        .map_err(|e| anyhow!("BLAKE2b key error: {e}"))?;
    Mac::update(&mut h, data);
    Ok(Mac::finalize(h).into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_encode_decode_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();

        let mut meta = VersionMetadata::base();
        meta.public_key = pk;
        meta.priority = 3;

        let encoded = meta.encode(&sk, b"testpassword").unwrap();

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = VersionMetadata::decode(&mut cursor, b"testpassword")
            .await
            .unwrap();

        assert_eq!(decoded.major_ver, PROTOCOL_VERSION_MAJOR);
        assert_eq!(decoded.minor_ver, PROTOCOL_VERSION_MINOR);
        assert_eq!(decoded.public_key, pk);
        assert_eq!(decoded.priority, 3);
        assert!(decoded.check());
    }
}
