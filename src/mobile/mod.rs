//! # Mobile library interface (iOS / Android)
//!
//! This module exposes a C-compatible FFI layer so that the Yggdrasil node can
//! be embedded inside iOS (Swift / Objective-C) and Android (Kotlin / JNI) apps.
//!
//! ## How mobile networking works
//!
//! On desktop the OS gives us a TUN file descriptor and we configure the
//! network interface ourselves (rtnetlink on Linux, ifconfig on macOS, netsh
//! on Windows).  On mobile the OS is in charge:
//!
//! - **Android**: `VpnService.Builder` creates the TUN fd and passes it to the
//!   app.  The app reads/writes raw IPv6 packets on that fd.
//! - **iOS**: `NEPacketTunnelProvider` provides `packetFlow` — the app reads
//!   and writes `NEPacket` objects (raw IP frames) through that interface.
//!
//! In both cases _Yggdrasil handles all routing and encryption_; the app glues
//! the OS packet flow to our [`ygg_write`] / [`ygg_read`] FFI calls.
//!
//! ## Build
//!
//! ```text
//! # Android (requires cargo-ndk and Android NDK)
//! cargo ndk --target aarch64-linux-android \
//!           --platform 21 \
//!           -- build --release --features mobile
//!
//! # iOS (requires Xcode command-line tools)
//! cargo build --release \
//!             --features mobile \
//!             --target aarch64-apple-ios
//! ```
//!
//! ## Swift example (iOS)
//!
//! ```swift
//! import Foundation
//!
//! // Start the node with a JSON config string
//! let config = """
//! { "PrivateKey": "...", "Peers": ["tls://peer.example.com:443"] }
//! """
//! config.withCString { ygg_start($0) }
//!
//! // Read a decrypted IPv6 packet from the overlay (call from VPN packet loop)
//! var buf = [UInt8](repeating: 0, count: 65535)
//! let n = ygg_read(&buf, Int32(buf.count))
//!
//! // Write a raw IPv6 packet captured from the OS tunnel interface
//! let packet: [UInt8] = /* from packetFlow.readPackets */ []
//! packet.withUnsafeBytes { ptr in
//!     ygg_write(ptr.baseAddress, Int32(packet.count))
//! }
//!
//! // Get our Yggdrasil address (e.g. "201:ce9b:33fc:31f6:...")
//! var addrBuf = [CChar](repeating: 0, count: 64)
//! ygg_get_address(&addrBuf, 64)
//! let addr = String(cString: addrBuf)
//! ```
//!
//! ## Kotlin / JNI example (Android)
//!
//! ```kotlin
//! // In your build.gradle: implementation 'com.github....:yggdrasil-android:...'
//! System.loadLibrary("yggdrasil_rs")
//!
//! external fun yggStart(configJson: String)
//! external fun yggStop()
//! external fun yggRead(buf: ByteArray): Int
//! external fun yggWrite(buf: ByteArray)
//! external fun yggGetAddress(): String
//! external fun yggGetPubkey(): String
//!
//! // In your VpnService implementation:
//! override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
//!     yggStart(loadConfig())
//!     startPacketLoop()
//!     return START_STICKY
//! }
//!
//! private fun startPacketLoop() = thread {
//!     val buf = ByteArray(65535)
//!     while (running) {
//!         yggWrite(readFromVpnInterface())        // OS → Yggdrasil
//!         val n = yggRead(buf)
//!         if (n > 0) writeToVpnInterface(buf, n) // Yggdrasil → OS
//!     }
//! }
//! ```
//!
//! ## C header (`yggdrasil_mobile.h`)
//!
//! Copy this into your Xcode / NDK project:
//!
//! ```c
//! #ifndef YGGDRASIL_MOBILE_H
//! #define YGGDRASIL_MOBILE_H
//! #include <stdint.h>
//!
//! /// Start the node. config_json = null-terminated UTF-8 JSON. Blocks until ready.
//! void ygg_start(const char *config_json);
//!
//! /// Stop the node and free all resources.
//! void ygg_stop(void);
//!
//! /// Inject a raw IPv6 packet from the OS VPN interface.
//! void ygg_write(const uint8_t *data, int32_t len);
//!
//! /// Read the next decrypted IPv6 packet into buf. Returns bytes written, or -1.
//! int32_t ygg_read(uint8_t *buf, int32_t buf_len);
//!
//! /// Copy our Yggdrasil IPv6 address (null-terminated) into buf (need >= 40 B).
//! void ygg_get_address(char *buf, int32_t buf_len);
//!
//! /// Copy our ed25519 public key as hex (null-terminated) into buf (need >= 65 B).
//! void ygg_get_pubkey(char *buf, int32_t buf_len);
//!
//! #endif
//! ```

#![cfg(feature = "mobile")]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::config::NodeConfig;
use crate::core::Core;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Global node state
// ---------------------------------------------------------------------------

struct MobileNode {
    runtime: tokio::runtime::Runtime,
    core:    Arc<Core>,
    /// Packets flowing from Yggdrasil overlay → OS VPN interface.
    pkt_rx:  Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

static NODE: OnceLock<MobileNode> = OnceLock::new();

// ---------------------------------------------------------------------------
// Public FFI exports
// ---------------------------------------------------------------------------

/// Start the Yggdrasil node.
///
/// `config_json` is a null-terminated UTF-8 JSON config (same format as the
/// desktop `yggdrasil.conf`).  Blocks until the node is fully started.
///
/// # Safety
/// `config_json` must be a valid non-null null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_start(config_json: *const c_char) {
    if config_json.is_null() {
        eprintln!("[yggdrasil] ygg_start: null config_json");
        return;
    }
    let json = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s.to_owned(),
        Err(e) => { eprintln!("[yggdrasil] ygg_start: invalid UTF-8: {e}"); return; }
    };
    if NODE.get().is_some() {
        eprintln!("[yggdrasil] ygg_start: node already running");
        return;
    }
    match start_node_inner(json) {
        Ok(node) => { let _ = NODE.set(node); }
        Err(e)   => { eprintln!("[yggdrasil] ygg_start failed: {e}"); }
    }
}

/// Stop the Yggdrasil node and release all resources.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_stop() {
    if let Some(node) = NODE.get() {
        node.runtime.block_on(async { node.core.stop().await });
    }
}

/// Inject a raw IPv6 packet from the OS VPN interface into the Yggdrasil overlay.
///
/// Call this every time you receive a packet from the OS tunnel fd.
///
/// # Safety
/// `data` must be valid and non-null for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_write(data: *const u8, len: c_int) {
    if data.is_null() || len <= 0 { return; }
    let node = match NODE.get() { Some(n) => n, None => return };
    let packet = std::slice::from_raw_parts(data, len as usize);

    // Resolve dest key from IPv6 src address, then encrypt+route.
    // We use the Core::write_to pathway via ipv6rwc address lookup.
    node.runtime.block_on(async {
        // The packet is a raw IPv6 frame; extract dst address from bytes 24..40.
        if packet.len() < 40 { return; }
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&packet[24..40]);
        // ipv6rwc will look up the ed25519 key for this IPv6 address internally.
        // We trigger it via the ReadWriteCloser path inside Core.
        // For mobile, Core exposes write_to(payload, dst_key) and read_from().
        // We skip the TUN layer: packet IS the payload for write_to.
        // The actual key lookup happens inside ipv6rwc when we call Core's internal path.
        // Here we use the same approach as ipv6rwc::ReadWriteCloser::write():
        // just call Core::write_to with the full IPv6 packet as payload —
        // the session layer wraps it and routing handles the rest.
        // Destination key is derived from the IPv6 dst address.
        use crate::address::addr_for_key;
        // Reconstruct destination ed25519 key from dst IPv6 address via reverse mapping.
        // (ipv6rwc keeps this map; we call the high-level Core write API directly.)
        let _ = node.core.write_packet(packet).await;
    });
}

/// Read the next decrypted IPv6 packet from the overlay into `buf`.
///
/// Blocks until a packet is available.  Returns number of bytes written into
/// `buf`, or `-1` if the buffer is too small or the node is not running.
///
/// # Safety
/// `buf` must be valid and non-null for `buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_read(buf: *mut u8, buf_len: c_int) -> c_int {
    if buf.is_null() || buf_len <= 0 { return -1; }
    let node = match NODE.get() { Some(n) => n, None => return -1 };

    let packet = node.runtime.block_on(async {
        node.pkt_rx.lock().ok()?.recv().await
    });

    match packet {
        Some(p) if p.len() <= buf_len as usize => {
            std::ptr::copy_nonoverlapping(p.as_ptr(), buf, p.len());
            p.len() as c_int
        }
        Some(_) => -1,
        None    => -1,
    }
}

/// Copy our Yggdrasil IPv6 address as a null-terminated ASCII string into `buf`.
///
/// The address has the form `"201:ce9b:33fc:31f6:dc16:7986:f61:b6d6"`.
/// `buf_len` must be at least 40 bytes.
///
/// # Safety
/// `buf` must be valid and non-null for `buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_get_address(buf: *mut c_char, buf_len: c_int) {
    if buf.is_null() || buf_len <= 0 { return; }
    let node = match NODE.get() { Some(n) => n, None => return };
    let addr = format!("{}", node.core.address());
    write_cstr(buf, buf_len, &addr);
}

/// Copy our ed25519 public key as lowercase hex (64 chars + NUL) into `buf`.
///
/// `buf_len` must be at least 65 bytes.
///
/// # Safety
/// `buf` must be valid and non-null for `buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_get_pubkey(buf: *mut c_char, buf_len: c_int) {
    if buf.is_null() || buf_len <= 0 { return; }
    let node = match NODE.get() { Some(n) => n, None => return };
    let key = hex::encode(node.core.public_key());
    write_cstr(buf, buf_len, &key);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn start_node_inner(config_json: String) -> anyhow::Result<MobileNode> {
    let cfg: NodeConfig = serde_json::from_str(&config_json)?;
    let cfg = Arc::new(cfg);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;

    // Channel: Core read loop → FFI ygg_read()
    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    // Start Core without TUN (mobile app provides its own packet flow)
    let core: Arc<Core> = rt.block_on(async { Core::new(cfg).await })?;

    // Background task: drain Core::read_from → pkt_tx
    {
        let core2 = Arc::clone(&core);
        let tx = pkt_tx;
        rt.spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match core2.read_from(&mut buf).await {
                    Ok((n, _from)) if n > 0 => {
                        let _ = tx.send(buf[..n].to_vec()).await;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    // Connect configured peers
    rt.block_on(async {
        for peer in &core.config_ref().peers {
            let _ = core.add_peer(peer, "").await;
        }
    });

    Ok(MobileNode {
        runtime: rt,
        core,
        pkt_rx: Mutex::new(pkt_rx),
    })
}

/// Write `s` as null-terminated C string into `buf`, truncated to `buf_len - 1`.
unsafe fn write_cstr(buf: *mut c_char, buf_len: c_int, s: &str) {
    let max = (buf_len as usize).saturating_sub(1);
    let bytes = s.as_bytes();
    let n = bytes.len().min(max);
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, n);
    *buf.add(n) = 0;
}
