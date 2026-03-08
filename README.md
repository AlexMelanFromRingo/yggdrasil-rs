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
- [x] TCP, TLS, QUIC (quinn), WebSocket, UNIX socket peer connections
- [x] SOCKS5 proxy support for outbound peers
- [x] Multicast peer discovery (UDP `ff02::114:9001`)
- [x] Admin socket (UNIX or TCP, JSON protocol)
- [x] HJSON and JSON config files (reads HJSON/JSON, writes pretty JSON)
- [x] `yggdrasilctl` admin CLI
- [x] `genkeys` vanity key generator
- [x] Intermediate mesh routing (forwards traffic for other nodes)
- [x] **iOS / Android library mode** via C FFI (`--features mobile`)

---

## Quick Start

### Requirements

- Rust 1.85+ (edition 2024)
- Linux / macOS / Windows

### Build

```bash
git clone https://github.com/AlexMelanFromRingo/yggdrasil-rs
cd yggdrasil-rs

# Linux / macOS
cargo build --release --bin yggdrasil --bin yggdrasilctl --features tun-support

# Windows
cargo build --release --bin yggdrasil --bin yggdrasilctl --features tun-support --target x86_64-pc-windows-msvc

# Android shared library (requires cargo-ndk and Android NDK)
cargo ndk --target aarch64-linux-android --platform 21 \
    -- build --release --features mobile

# iOS static library
cargo build --release --features mobile --target aarch64-apple-ios
```

### Install on Linux (systemd)

```bash
# 1. Build and copy binaries
cargo build --release --features tun-support
sudo cp target/release/yggdrasil /usr/local/bin/
sudo cp target/release/yggdrasilctl /usr/local/bin/

# 2. Generate config
sudo yggdrasil --genconf > /etc/yggdrasil.conf

# 3. Install systemd service
sudo cp contrib/systemd/yggdrasil.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now yggdrasil
```

The systemd service uses `AmbientCapabilities=CAP_NET_ADMIN` so the daemon
runs without root (no `setcap` required).

### Manage with yggdrasilctl

```bash
# Show our own address and public key
yggdrasilctl getself

# List connected peers
yggdrasilctl getpeers

# Show spanning tree
yggdrasilctl gettree

# Show active sessions
yggdrasilctl getsessions

# Add a peer at runtime
yggdrasilctl addpeer uri=tls://peer.example.com:443

# Remove a peer
yggdrasilctl removepeer uri=tls://peer.example.com:443
```

The admin socket path is configured via `AdminListen` in `yggdrasil.conf`
(default: `unix:///tmp/ygg-admin.sock` on Linux/macOS,
`tcp://localhost:9001` on Windows).

### Manual run (development)

```bash
# Allow TUN creation without root (alternative to systemd AmbientCapabilities)
sudo setcap cap_net_admin+eip ./target/release/yggdrasil

# Run in foreground (logs to stderr)
./target/release/yggdrasil --useconffile /etc/yggdrasil.conf

# Run in background (redirect logs)
./target/release/yggdrasil --useconffile /etc/yggdrasil.conf \
    2>/var/log/yggdrasil.log &
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
│   ├── link.rs           — Link manager: TCP/TLS/QUIC/WebSocket/UNIX/SOCKS5
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
├── mobile/
│   └── mod.rs            — C FFI layer for iOS/Android (--features mobile)
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
    └─ RouterState::send_traffic() → per-peer mpsc channel → TCP/TLS/QUIC write

TCP/TLS/QUIC read → per-peer reader task
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
4 bytes  "meta" magic (ASCII)
2 bytes  remaining-length (big-endian u16) — covers TLV entries + signature
TLV entries (each: 2-byte type, 2-byte length, N bytes value):
  type 0 — major version (u16 BE)
  type 1 — minor version (u16 BE)
  type 2 — ed25519 public key (32 bytes)
  type 3 — priority (u8)
64 bytes  ed25519 signature over BLAKE2b-512(password || public_key)
```

Major version mismatch closes the connection.

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

The wire protocol is **100% identical** — yggdrasil-rs and yggdrasil-go interoperate transparently. The differences below are internal implementation choices that have no effect on compatibility.

### Internal implementation

| Aspect | yggdrasil-go | yggdrasil-rs |
|--------|-------------|--------------|
| Concurrency model | `phony.Inbox` actor | `Arc<Mutex<RouterState>>` |
| Timer model | `time.AfterFunc` | tokio `interval` task (1 s) |
| Per-peer I/O | goroutine per peer | tokio task per peer + mpsc channel |

### Feature matrix

| Feature | yggdrasil-go | yggdrasil-rs |
|---------|-------------|--------------|
| QUIC | ✓ (quic-go) | ✓ (quinn) |
| WebSocket | ✓ | ✓ (tokio-tungstenite) |
| Linux TUN | ✓ (rtnetlink) | ✓ (rtnetlink) |
| macOS TUN | ✓ (utun) | ✓ (ifconfig) |
| Windows TUN | ✓ (wintun, DLL embedded) | ✓ (wintun, DLL embedded via `--features embedded-wintun`) |
| iOS/Android lib | ✓ (Go mobile) | ✓ (`--features mobile`, C FFI) |
| Config format | HJSON read + write | HJSON read, pretty JSON write |

### Windows notes

The TUN driver on Windows is [wintun](https://wintun.net), the same driver
used by WireGuard and yggdrasil-go.

**With `--features embedded-wintun`** (recommended): `wintun.dll` is
extracted from the binary into `%TEMP%\yggdrasil-rs\` at startup — no
manual DLL placement needed. Place `contrib/windows/wintun.dll` before
building:

```bash
cargo build --release --features tun-support,embedded-wintun --target x86_64-pc-windows-msvc
```

**Without `embedded-wintun`**: download `wintun.dll` from
[wintun.net](https://wintun.net) and place it next to `yggdrasil.exe`.

IPv6 address assignment uses the Windows IP Helper API
(`CreateUnicastIpAddressEntry`) — the same approach as yggdrasil-go's
`winipcfg`, not a `netsh` subprocess.

Other Windows notes:
- Run as Administrator (or grant `SeNetworkAdminPrivilege`)
- Admin socket defaults to TCP (`tcp://localhost:9001`) instead of UNIX socket

### iOS / Android notes

Enable the `mobile` feature. This compiles the library without a TUN adapter.
Instead, the app feeds raw IPv6 packets via `ygg_write()` and reads decrypted
packets via `ygg_read()`, bridging the OS VPN interface to the overlay.

See `src/mobile/mod.rs` for the full C header, Swift example, and Kotlin/JNI example.

---

## License

LGPL-3.0 — same as yggdrasil-go.

The Ironwood protocol is by [Arceliar](https://github.com/Arceliar/ironwood).
Yggdrasil is by the [Yggdrasil Network contributors](https://github.com/yggdrasil-network).
