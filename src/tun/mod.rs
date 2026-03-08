/// TUN adapter — reads/writes IPv6 packets to/from the OS network stack.
///
/// Port of yggdrasil-go/src/tun/tun.go + tun_linux.go

use crate::{
    address::{self, Address, Subnet},
    config::get_defaults,
    ipv6rwc::ReadWriteCloser,
};
use anyhow::{anyhow, Result};
use std::{
    net::Ipv6Addr,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Setup options
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InterfaceName(pub String);

#[derive(Debug, Clone, Copy)]
pub struct InterfaceMTU(pub u64);

impl Default for InterfaceName {
    fn default() -> Self {
        InterfaceName(get_defaults().default_if_name.to_string())
    }
}

impl Default for InterfaceMTU {
    fn default() -> Self {
        InterfaceMTU(get_defaults().default_if_mtu)
    }
}

// ---------------------------------------------------------------------------
// Platform MTU limits
// ---------------------------------------------------------------------------

pub fn default_name() -> String {
    get_defaults().default_if_name.to_string()
}

pub fn default_mtu() -> u64 {
    get_defaults().default_if_mtu
}

pub fn maximum_mtu() -> u64 {
    get_defaults().maximum_if_mtu
}

fn supported_mtu(mtu: u64) -> u64 {
    mtu.clamp(1280, maximum_mtu())
}

// ---------------------------------------------------------------------------
// TUN adapter
// ---------------------------------------------------------------------------

pub struct TunAdapter {
    rwc: Arc<ReadWriteCloser>,
    addr: Address,
    subnet: Subnet,
    mtu: u64,
    name: String,
    is_open: AtomicBool,
    is_enabled: AtomicBool,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    // channel from overlay-read to TUN-write
    ch_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ch_rx: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl TunAdapter {
    /// Creates and starts the TUN adapter.
    pub async fn new(
        rwc: Arc<ReadWriteCloser>,
        name: InterfaceName,
        mtu: InterfaceMTU,
    ) -> Result<Arc<Self>> {
        let addr = rwc.address();
        let subnet = rwc.subnet();

        let (ch_tx, ch_rx) = tokio::sync::mpsc::channel(4096);

        let tun = Arc::new(TunAdapter {
            rwc: Arc::clone(&rwc),
            addr,
            subnet,
            mtu: mtu.0,
            name: name.0.clone(),
            is_open: AtomicBool::new(false),
            is_enabled: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            ch_tx,
            ch_rx: Mutex::new(ch_rx),
        });

        tun.start(name.0, mtu.0).await?;
        Ok(tun)
    }

    async fn start(self: &Arc<Self>, if_name: String, desired_mtu: u64) -> Result<()> {
        if if_name == "none" || if_name == "dummy" {
            debug!("Not starting TUN: ifname is {if_name}");
            self.is_enabled.store(false, Ordering::SeqCst);
            // Still run the queue goroutine so the underlying layers don't block
            self.spawn_queue_task().await;
            return Ok(());
        }

        let actual_mtu = supported_mtu(self.rwc.max_mtu().min(desired_mtu));
        self.rwc.set_mtu(actual_mtu);

        #[cfg(any(
            all(feature = "tun-support", target_os = "linux"),
            all(feature = "tun-support", target_os = "macos"),
            all(feature = "tun-support", target_os = "windows"),
        ))]
        self.setup_tun(if_name, actual_mtu).await?;

        #[cfg(not(any(
            all(feature = "tun-support", target_os = "linux"),
            all(feature = "tun-support", target_os = "macos"),
            all(feature = "tun-support", target_os = "windows"),
        )))]
        {
            warn!("TUN support not compiled in (missing 'tun-support' feature)");
            return Err(anyhow!("TUN not supported on this build"));
        }

        self.is_open.store(true, Ordering::SeqCst);
        self.is_enabled.store(true, Ordering::SeqCst);

        self.spawn_queue_task().await;
        self.spawn_read_task().await;
        self.spawn_write_task().await;

        Ok(())
    }

    /// Shared TUN read/write task spawner — used by all platforms after device creation.
    #[cfg(feature = "tun-support")]
    async fn spawn_tun_io_tasks(self: &Arc<Self>, device: tun2::AsyncDevice) {
        let dev = Arc::new(device);

        // TUN read task: OS → overlay
        let dev_r = Arc::clone(&dev);
        let rwc_r = Arc::clone(&self.rwc);
        let is_open_r = Arc::clone(self);
        let h_read = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match dev_r.recv(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if let Err(e) = rwc_r.write(&buf[..n]).await {
                            debug!("TUN→overlay error: {e}");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if is_open_r.is_open.load(Ordering::SeqCst) {
                            error!("TUN read error: {e}");
                        }
                        break;
                    }
                }
            }
        });

        // TUN write task: overlay → OS
        let dev_w = Arc::clone(&dev);
        let this_w = Arc::clone(self);
        let h_write = tokio::spawn(async move {
            loop {
                let packet = {
                    let mut rx = this_w.ch_rx.lock().await;
                    match rx.recv().await {
                        Some(p) => p,
                        None => break,
                    }
                };
                if !this_w.is_enabled.load(Ordering::SeqCst) {
                    continue;
                }
                if let Err(e) = dev_w.send(&packet).await {
                    if this_w.is_open.load(Ordering::SeqCst) {
                        error!("TUN write error: {e}");
                    }
                }
            }
        });

        let mut tasks = self.tasks.lock().await;
        tasks.push(h_read);
        tasks.push(h_write);
    }

    /// Linux TUN setup: create device, assign IPv6 via rtnetlink, bring link up.
    #[cfg(all(feature = "tun-support", target_os = "linux"))]
    async fn setup_tun(self: &Arc<Self>, if_name: String, mtu: u64) -> Result<()> {
        use futures::TryStreamExt;
        use std::net::IpAddr;

        let actual_name = if if_name == "auto" { "ygg0".to_string() } else { if_name };
        let ipv6_addr = Ipv6Addr::from(self.addr.0);

        // Create TUN device. Do NOT call config.address() with IPv6 — EINVAL.
        // IPv6 address is assigned separately via rtnetlink below.
        let mut config = tun2::Configuration::default();
        config.name(actual_name.clone());
        config.mtu(mtu.min(65535) as u16);

        let device = tun2::create_as_async(&config)
            .map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

        // Assign IPv6 address and bring interface up via rtnetlink.
        {
            let (conn, handle, _) = rtnetlink::new_connection()
                .map_err(|e| anyhow!("rtnetlink connect failed: {e}"))?;
            tokio::spawn(conn);

            let mut links = handle.link().get().match_name(actual_name.clone()).execute();
            let link = links.try_next().await
                .map_err(|e| anyhow!("rtnetlink get link: {e}"))?
                .ok_or_else(|| anyhow!("interface {actual_name} not found"))?;
            let link_index = link.header.index;

            handle.address()
                .add(link_index, IpAddr::V6(ipv6_addr), 7)
                .execute()
                .await
                .map_err(|e| anyhow!("add IPv6 address: {e}"))?;

            handle.link().set(link_index).up().execute().await
                .map_err(|e| anyhow!("bring {actual_name} up: {e}"))?;
        }

        info!("Interface name: {actual_name}");
        info!("Interface IPv6: {ipv6_addr}");
        info!("Interface MTU: {mtu}");

        self.spawn_tun_io_tasks(device).await;
        Ok(())
    }

    /// macOS TUN setup: create utun device, assign IPv6 via ifconfig.
    #[cfg(all(feature = "tun-support", target_os = "macos"))]
    async fn setup_tun(self: &Arc<Self>, if_name: String, mtu: u64) -> Result<()> {
        let actual_name = if if_name == "auto" { "utun9".to_string() } else { if_name };
        let ipv6_addr = Ipv6Addr::from(self.addr.0);

        let mut config = tun2::Configuration::default();
        config.name(actual_name.clone());
        config.mtu(mtu.min(65535) as u16);

        let device = tun2::create_as_async(&config)
            .map_err(|e| anyhow!("failed to create TUN device: {e}"))?;

        // macOS: assign IPv6 address via ifconfig
        let addr_str = format!("{ipv6_addr}");
        let status = std::process::Command::new("ifconfig")
            .args([&actual_name, "inet6", &addr_str, "prefixlen", "7", "alias"])
            .status()
            .map_err(|e| anyhow!("ifconfig failed: {e}"))?;
        if !status.success() {
            return Err(anyhow!("ifconfig inet6 failed for {actual_name}"));
        }

        // Set MTU
        let _ = std::process::Command::new("ifconfig")
            .args([&actual_name, "mtu", &mtu.to_string()])
            .status();

        // Bring up
        let _ = std::process::Command::new("ifconfig")
            .args([&actual_name, "up"])
            .status();

        info!("Interface name: {actual_name}");
        info!("Interface IPv6: {ipv6_addr}");
        info!("Interface MTU: {mtu}");

        self.spawn_tun_io_tasks(device).await;
        Ok(())
    }

    /// Windows TUN setup via wintun driver.
    ///
    /// **Requirement**: `wintun.dll` must be placed in the same directory as the
    /// binary. Download from <https://wintun.net>.
    ///
    /// The process must be run as Administrator (or have SeNetworkAdminPrivilege).
    /// IPv6 address is configured via `netsh interface ipv6`.
    #[cfg(all(feature = "tun-support", target_os = "windows"))]
    async fn setup_tun(self: &Arc<Self>, if_name: String, mtu: u64) -> Result<()> {
        let actual_name = if if_name == "auto" { "Yggdrasil".to_string() } else { if_name };
        let ipv6_addr = Ipv6Addr::from(self.addr.0);

        // tun2 on Windows uses the wintun driver automatically.
        let mut config = tun2::Configuration::default();
        config.name(actual_name.clone());
        config.mtu(mtu.min(65535) as u16);

        let device = tun2::create_as_async(&config)
            .map_err(|e| anyhow!("failed to create TUN device (is wintun.dll present?): {e}"))?;

        // Assign IPv6 address via netsh
        let addr_str = format!("{ipv6_addr}");
        let output = std::process::Command::new("netsh")
            .args([
                "interface", "ipv6", "add", "address",
                &actual_name,
                &format!("{addr_str}/7"),
            ])
            .output()
            .map_err(|e| anyhow!("netsh failed: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("netsh add address failed: {stderr}"));
        }

        // Set MTU via netsh
        let _ = std::process::Command::new("netsh")
            .args([
                "interface", "ipv6", "set", "subinterface",
                &actual_name,
                &format!("mtu={mtu}"),
                "store=active",
            ])
            .output();

        info!("Interface name: {actual_name}");
        info!("Interface IPv6: {ipv6_addr}");
        info!("Interface MTU: {mtu}");

        self.spawn_tun_io_tasks(device).await;
        Ok(())
    }

    /// Fallback for unsupported platforms (e.g. FreeBSD without explicit support).
    #[cfg(all(
        feature = "tun-support",
        not(target_os = "linux"),
        not(target_os = "macos"),
        not(target_os = "windows"),
    ))]
    async fn setup_tun(self: &Arc<Self>, if_name: String, mtu: u64) -> Result<()> {
        Err(anyhow!("TUN setup is not implemented for this platform. Contributions welcome!"))
    }

    /// Spawns a task that reads IPv6 packets from the overlay and queues them
    /// for writing to the TUN device.
    async fn spawn_queue_task(self: &Arc<Self>) {
        let rwc = Arc::clone(&self.rwc);
        let tx = self.ch_tx.clone();
        let handle = tokio::spawn(async move {
            let mut buf = Vec::with_capacity(65535);
            loop {
                buf.clear();
                match rwc.read(&mut buf).await {
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("TUN queue read error: {e}");
                        break;
                    }
                }
            }
        });
        self.tasks.lock().await.push(handle);
    }

    async fn spawn_read_task(self: &Arc<Self>) {}
    async fn spawn_write_task(self: &Arc<Self>) {}

    pub fn is_started(&self) -> bool {
        self.is_open.load(Ordering::SeqCst)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u64 {
        supported_mtu(self.mtu)
    }

    pub async fn stop(&self) -> Result<()> {
        self.is_open.store(false, Ordering::SeqCst);
        let mut tasks = self.tasks.lock().await;
        for t in tasks.drain(..) {
            t.abort();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GetTUN admin response
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
pub struct GetTUNResponse {
    pub enabled: bool,
    pub name: String,
    pub mtu: u64,
}
