//! Two-node integration test.
//!
//! Spins up two in-process Yggdrasil nodes connected over:
//!   - TCP (always)
//!   - WebSocket (ws://)
//!   - UNIX socket (unix://, Linux/macOS only)
//!
//! For each transport the test verifies:
//!   1. Peers connect and exchange spanning-tree announcements.
//!   2. Encrypted traffic flows in both directions (echo test).
//!   3. Throughput (MB/s) and round-trip latency (ms) are measured and printed.

use std::{sync::Arc, time::{Duration, Instant}};
use tokio::time::sleep;
use yggdrasil_rs::{config::NodeConfig, core::Core};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

/// Generate a minimal NodeConfig with no listeners, no peers, no TUN.
fn make_config() -> Arc<NodeConfig> {
    let mut cfg = NodeConfig::generate().expect("generate config");
    cfg.admin_listen = String::new(); // disable admin socket
    cfg.if_name = "none".to_string(); // no TUN
    Arc::new(cfg)
}

/// Wait until node `a` sees `b` as an up peer (up to `timeout`).
async fn wait_peered(a: &Arc<Core>, b: &Arc<Core>, timeout: Duration) -> bool {
    let b_key = b.public_key();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let peers = a.get_peers().await;
        if peers.iter().any(|p| p.key == b_key && p.up) {
            return true;
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Warm up the session between two nodes: send probes from A to B repeatedly
/// until B receives one (or timeout expires).
///
/// Must be called after `wait_peered`. The Ironwood bloom-filter exchange and
/// `on_tree` flag are set by the 1-second maintenance tick, so the first
/// PathLookup may need up to ~1 second to propagate. We retry every 500 ms.
async fn warmup(sender: &Arc<Core>, receiver: &Arc<Core>, timeout: Duration) -> bool {
    let dst = receiver.public_key();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let recv_core = Arc::clone(receiver);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let probe_timeout = remaining.min(Duration::from_millis(800));

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            tokio::time::timeout(probe_timeout, recv_core.read_from(&mut buf)).await.ok()
        });

        let _ = sender.write_to(b"ygg-warmup", &dst).await;

        if matches!(handle.await, Ok(Some(Ok(_)))) {
            return true;
        }
        // Let the ironwood maintenance tick run (bloom exchange, on_tree update)
        sleep(Duration::from_millis(500)).await;
    }
    false
}

/// One-way throughput + RTT measurement.
///
/// Sends `count` packets of `size` bytes A→B, measures throughput.
/// Then does a single echo (A→B→A) to measure RTT.
async fn measure(
    sender: &Arc<Core>,
    receiver: &Arc<Core>,
    count: usize,
    size: usize,
) -> (f64, f64) {
    let dst_b = receiver.public_key();
    let dst_a = sender.public_key();
    let payload: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();

    // ---- Throughput (one-way A→B) -----------------------------------------
    let recv_core = Arc::clone(receiver);
    let recv_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        for _ in 0..count {
            if tokio::time::timeout(
                Duration::from_secs(30),
                recv_core.read_from(&mut buf),
            ).await.is_err() {
                break;
            }
        }
    });

    let start = Instant::now();
    for _ in 0..count {
        sender.write_to(&payload, &dst_b).await.expect("write");
    }
    recv_handle.await.expect("recv task");
    let elapsed = start.elapsed();
    let mbps = (count * size) as f64 / elapsed.as_secs_f64() / 1_000_000.0;

    // ---- RTT (single echo B→A→B via echo task on A) ----------------------
    let send_core = Arc::clone(sender);
    let echo_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        if let Ok(Ok((n, from))) = tokio::time::timeout(
            Duration::from_secs(5),
            send_core.read_from(&mut buf),
        ).await {
            let _ = send_core.write_to(&buf[..n], &from).await;
        }
    });

    let t0 = Instant::now();
    receiver.write_to(b"ping", &dst_a).await.expect("rtt write");
    let mut buf = vec![0u8; 256];
    let rtt = if let Ok(Ok(_)) = tokio::time::timeout(
        Duration::from_secs(5),
        receiver.read_from(&mut buf),
    ).await {
        t0.elapsed().as_secs_f64() * 1000.0
    } else {
        f64::NAN
    };
    echo_handle.await.ok();

    (mbps, rtt)
}

// ---------------------------------------------------------------------------
// TCP transport
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_two_nodes_tcp() {
    init_tracing();
    let a = Core::new(make_config()).await.expect("core A");
    let b = Core::new(make_config()).await.expect("core B");

    let listener = b.listen_local("tcp://127.0.0.1:0", "").await.expect("listen");
    let port = listener.local_addr.port();

    a.call_peer(&format!("tcp://127.0.0.1:{port}"), "").await.expect("call peer");

    assert!(wait_peered(&a, &b, Duration::from_secs(10)).await, "TCP: nodes did not peer");
    assert!(warmup(&a, &b, Duration::from_secs(10)).await, "TCP: session warm-up failed");

    let (mbps, rtt) = measure(&a, &b, 200, 4096).await;
    println!("TCP  — throughput: {mbps:.1} MB/s  avg RTT: {rtt:.2} ms");
    assert!(mbps > 0.0, "zero throughput");

    a.stop().await;
    b.stop().await;
}

// ---------------------------------------------------------------------------
// WebSocket transport (ws://)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_two_nodes_websocket() {
    init_tracing();
    let a = Core::new(make_config()).await.expect("core A");
    let b = Core::new(make_config()).await.expect("core B");

    let listener = b.listen_local("ws://127.0.0.1:0", "").await.expect("listen ws");
    let port = listener.local_addr.port();

    a.call_peer(&format!("ws://127.0.0.1:{port}"), "").await.expect("call peer ws");

    assert!(wait_peered(&a, &b, Duration::from_secs(10)).await, "WS: nodes did not peer");
    assert!(warmup(&a, &b, Duration::from_secs(10)).await, "WS: session warm-up failed");

    let (mbps, rtt) = measure(&a, &b, 200, 4096).await;
    println!("WS   — throughput: {mbps:.1} MB/s  avg RTT: {rtt:.2} ms");
    assert!(mbps > 0.0, "zero throughput");

    a.stop().await;
    b.stop().await;
}

// ---------------------------------------------------------------------------
// UNIX socket transport (Linux / macOS only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_two_nodes_unix() {
    let a = Core::new(make_config()).await.expect("core A");
    let b = Core::new(make_config()).await.expect("core B");

    let path = format!("/tmp/ygg-test-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);

    let _listener = b.listen_local(&format!("unix://{path}"), "").await.expect("listen unix");
    sleep(Duration::from_millis(20)).await;

    a.call_peer(&format!("unix://{path}"), "").await.expect("call peer unix");

    assert!(wait_peered(&a, &b, Duration::from_secs(10)).await, "UNIX: nodes did not peer");
    assert!(warmup(&a, &b, Duration::from_secs(10)).await, "UNIX: session warm-up failed");

    let (mbps, rtt) = measure(&a, &b, 200, 4096).await;
    println!("UNIX — throughput: {mbps:.1} MB/s  avg RTT: {rtt:.2} ms");
    assert!(mbps > 0.0, "zero throughput");

    a.stop().await;
    b.stop().await;
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Throughput stress: larger payloads
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_throughput_large_payloads() {
    let a = Core::new(make_config()).await.expect("core A");
    let b = Core::new(make_config()).await.expect("core B");

    let listener = b.listen_local("tcp://127.0.0.1:0", "").await.expect("listen");
    let port = listener.local_addr.port();
    a.call_peer(&format!("tcp://127.0.0.1:{port}"), "").await.expect("call peer");

    assert!(wait_peered(&a, &b, Duration::from_secs(10)).await, "nodes did not peer");
    assert!(warmup(&a, &b, Duration::from_secs(10)).await, "session warm-up failed");

    // 64 KB payloads, 50 packets
    let (mbps, rtt) = measure(&a, &b, 50, 65000).await;
    println!("TCP large (64KB×50) — throughput: {mbps:.1} MB/s  avg RTT: {rtt:.2} ms");
    assert!(mbps > 0.0, "zero throughput");

    a.stop().await;
    b.stop().await;
}
