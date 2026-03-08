# yggdrasil-rs

A Rust port of [yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) v0.5.13 — a self-organizing, end-to-end encrypted mesh network daemon.

**Status: Working.** Wire-compatible with yggdrasil-go. Successfully exchanges encrypted traffic with the live Yggdrasil network (ping, HTTP, mesh routing all verified).

---

## What is Yggdrasil?

Yggdrasil is an encrypted IPv6 mesh network. Every node gets a stable `200::/7` IPv6 address derived from its ed25519 public key. Routing is fully decentralized — no servers, no registration, no central authority.

Key properties:
- **Self-organizing** — nodes form a spanning tree automatically
- **End-to-end encrypted** — NaCl box (X25519 + XSalsa20-Poly1305) with forward secrecy
- **Any-to-any routing** — every node can reach every other node
- **Stable addresses** — your IPv6 address is derived from your public key and never changes
- **Supports TCP, TLS, QUIC, WebSocket, UNIX socket, SOCKS5 peers**
- **Multicast peer discovery** on local networks

---

## Features

- [x] Full wire protocol compatibility with yggdrasil-go v0.5.13
- [x] Spanning tree routing with greedy path selection
- [x] Source routing via PathLookup/PathNotify/PathBroken
- [x] Bloom filter multicast for path discovery
- [x] Session encryption with double-ratchet key rotation + recovery
- [x] TUN interface — **Linux** (rtnetlink), **macOS** (ifconfig), **Windows** (wintun/netsh)
- [x] TCP, TLS, UNIX socket peer connections
- [x] SOCKS5 proxy support for outbound peers
- [x] Multicast peer discovery (UDP `ff02::114:9001`)
- [x] Admin socket (UNIX or TCP, JSON protocol)
- [x] HJSON and JSON config files
- [x] `yggdrasilctl` admin CLI
- [x] `genkeys` vanity key generator
- [x] Intermediate mesh routing (forwards traffic for other nodes)
- [x] **iOS / Android library mode** via C FFI (`--features mobile`)

---

## Quick Start

### Requirements

- Rust 1.85+ (edition 2024)
- Linux (for TUN support) — macOS untested but should work

### Build

```bash
git clone https://github.com/AlexMelanFromRingo/yggdrasil-rs
cd yggdrasil-rs

# Linux / macOS
cargo build --release --bin yggdrasil --features tun-support

# Windows (requires wintun.dll next to the binary — download from https://wintun.net)
cargo build --release --bin yggdrasil --features tun-support --target x86_64-pc-windows-gnu

# Android shared library (requires cargo-ndk and Android NDK)
cargo ndk --target aarch64-linux-android --platform 21 \
    -- build --release --features mobile

# iOS static library
cargo build --release --features mobile --target aarch64-apple-ios
```

### Generate a config

```bash
./target/release/yggdrasil --genconf > /etc/yggdrasil.conf
```

### Run

```bash
# Allow TUN creation without root
sudo setcap cap_net_admin+eip ./target/release/yggdrasil

./target/release/yggdrasil --useconffile /etc/yggdrasil.conf
```

### Config example

```json
{
  "PrivateKey": "<64-char hex>",
  "Peers": [
    "tls://ygg.mkg20001.io:443",
    "tcp://ygg.mkg20001.io:80"
  ],
  "Listen": [],
  "AdminListen": "unix:///tmp/ygg-admin.sock",
  "IfName": "auto",
  "IfMTU": 65535,
  "MulticastInterfaces": [],
  "AllowedPublicKeys": []
}
```

---

## Architecture

```
yggdrasil-rs/src/
├── bin/
│   ├── yggdrasil.rs      — Main daemon (CLI arg parsing, config loading)
│   ├── yggdrasilctl.rs   — Admin CLI (connects to admin socket)
│   └── genkeys.rs        — Vanity key generator (parallel threads)
├── core/
│   ├── mod.rs            — Core struct: lifecycle, API surface
│   ├── api.rs            — SelfInfo, PeerInfo, TreeEntryInfo, SessionInfo
│   ├── handshake.rs      — Peer handshake: version metadata wire format
│   ├── link.rs           — Link manager: dial/listen TCP/TLS/UNIX/SOCKS
│   ├── network.rs        — ★ Ironwood protocol (spanning tree, routing, sessions)
│   ├── nodeinfo.rs       — NodeInfo protocol handler
│   ├── options.rs        — SetupOption trait, peer/listen configuration types
│   ├── proto.rs          — ProtoHandler: nodeinfo + debug sub-protocol
│   └── types.rs          — Packet type constants
├── admin/
│   └── mod.rs            — Admin socket: UNIX/TCP, JSON-line protocol
├── ipv6rwc/
│   ├── mod.rs            — KeyStore, ReadWriteCloser (key ↔ IPv6 mapping)
│   └── icmpv6.rs         — ICMPv6 Packet Too Big builder
├── multicast/
│   ├── mod.rs            — Multicast peer discovery (UDP ff02::114:9001)
│   └── advertisement.rs  — Advertisement marshal/unmarshal
├── tun/
│   └── mod.rs            — TUN adapter (tun2 crate, feature-gated)
├── address.rs            — IPv6 address/subnet derivation from ed25519 keys
├── config.rs             — NodeConfig, TlsCertificate, PlatformDefaults
├── lib.rs                — Module declarations
└── version.rs            — build_name() / build_version()
```

### Data flow

```
TUN device
    │  raw IPv6 packets
    ▼
ipv6rwc::ReadWriteCloser   — maps IPv6 addresses to ed25519 public keys
    │  (dest_pub_key, payload)
    ▼
core::network::PacketConn::write_to()
    │
    ├─ SessionManager: encrypt with NaCl box + key rotation
    │      ↓ SessionInit/Ack handshake if new session
    │  SessionTraffic wire packet
    │
    ├─ PathfinderState: look up cached source route
    │      ↓ if no path: PathLookup flood via Bloom filter
    │  Traffic packet with embedded path
    │
    └─ RouterState::send_traffic() → per-peer mpsc channel → TCP write

TCP read → per-peer reader task
    │  uvarint-framed wire packets
    ▼
RouterState (dispatches by packet type)
    ├── ANNOUNCE      → spanning tree update → re-announce to peers
    ├── BLOOM_FILTER  → merge + propagate up tree
    ├── PATH_LOOKUP   → check if we match, propagate, or respond with PATH_NOTIFY
    ├── PATH_NOTIFY   → cache path, flush buffered traffic
    ├── PATH_BROKEN   → invalidate cached path, re-lookup
    ├── SIG_REQ/RES   → ed25519 spanning tree signature exchange
    └── TRAFFIC       → decrypt or forward
            ├── for us    → SessionManager::decrypt → TUN write
            └── not for us → lookup() → forward to next hop
```

---

## Protocol Details

The core routing protocol is [Ironwood](https://github.com/Arceliar/ironwood) by Arceliar. See [ironwood-rs](https://github.com/AlexMelanFromRingo/ironwood-rs) for a standalone documented Rust implementation of the protocol layer.

### Address derivation

Yggdrasil IPv6 addresses are derived from ed25519 public keys:

```
key = bitwise_invert(pubkey)
count leading_ones in key
address = [0x02] [leading_ones_count] [remaining_bits...]
```

Addresses fall in `200::/7`. Subnets are in `300::/7` (same derivation with `| 0x01` on the second byte).

### Peer handshake

When two nodes connect, they exchange a `VersionMetadata` frame:

```
[magic (8B)] [major (uvarint)] [minor (uvarint)] [metadata_key (uvarint)] [metadata_value ...]
```

Magic: `0x0bad1de` (little-endian). Major version mismatch closes the connection.

### Admin protocol

The admin socket accepts newline-delimited JSON:

```json
{"request": "getself"}
{"request": "getpeers"}
{"request": "gettree"}
{"request": "getsessions"}
{"request": "addpeer", "uri": "tcp://peer.example.com:9001"}
{"request": "removepeer", "uri": "tcp://peer.example.com:9001"}
```

---

## Differences from yggdrasil-go

| Aspect | yggdrasil-go | yggdrasil-rs |
|--------|-------------|--------------|
| Actor model | `phony.Inbox` actor | `Arc<Mutex<RouterState>>` |
| Timer model | `time.AfterFunc` | tokio `interval` task (1s) |
| Per-peer I/O | goroutine per peer | tokio task per peer + mpsc channel |
| QUIC | ✓ (quic-go) | ✓ (quinn) |
| WebSocket | ✓ | ✓ (tokio-tungstenite) |
| Linux TUN | ✓ (rtnetlink) | ✓ (rtnetlink) |
| macOS TUN | ✓ (utun) | ✓ (ifconfig) |
| Windows TUN | ✓ (wintun) | ✓ (wintun + netsh) |
| iOS/Android lib | ✓ (Go mobile) | ✓ (`--features mobile`, C FFI) |

### Windows notes

- Requires `wintun.dll` in the same directory as the binary (download from [wintun.net](https://wintun.net))
- Run as Administrator (or grant `SeNetworkAdminPrivilege`)
- Admin socket uses TCP (`tcp://localhost:9001`) instead of UNIX socket

### iOS / Android notes

Enable the `mobile` feature. This compiles the library without a TUN adapter.
Instead, the app feeds raw IPv6 packets via `ygg_write()` and reads decrypted
packets via `ygg_read()`, bridging the OS VPN interface to the overlay.

See `src/mobile/mod.rs` for the full C header, Swift example, and Kotlin/JNI example.

Wire format is 100% identical — a yggdrasil-rs node interoperates transparently with yggdrasil-go nodes.

---

## License

LGPL-3.0 — same as yggdrasil-go.

The Ironwood protocol is by [Arceliar](https://github.com/Arceliar/ironwood).
Yggdrasil is by the [Yggdrasil Network contributors](https://github.com/yggdrasil-network).
