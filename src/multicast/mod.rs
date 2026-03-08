/// Multicast peer discovery.
///
/// Port of yggdrasil-go/src/multicast/multicast.go

pub mod advertisement;

use crate::{
    core::Core,
    core::handshake::{PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR},
};
use advertisement::MulticastAdvertisement;
use anyhow::{anyhow, Result};
use blake2::Blake2b512;
use hex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    time::sleep,
};
use tracing::{debug, info, warn};
use url::Url;

// Multicast group address used by Yggdrasil
const MULTICAST_GROUP: &str = "[ff02::114]:9001";

// ---------------------------------------------------------------------------
// Setup options
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MulticastInterface {
    pub regex: Regex,
    pub beacon: bool,
    pub listen: bool,
    pub port: u16,
    pub priority: u8,
    pub password: String,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct InterfaceInfo {
    iface_name: String,
    addrs: Vec<Ipv6Addr>,
    beacon: bool,
    listen: bool,
    port: u16,
    priority: u8,
    password: Vec<u8>,
    hash: Vec<u8>,
}

struct ListenerInfo {
    port: u16,
    started_at: Instant,
    interval: Duration,
    cancel: tokio::sync::oneshot::Sender<()>,
}

// ---------------------------------------------------------------------------
// Multicast module
// ---------------------------------------------------------------------------

pub struct Multicast {
    core: Arc<Core>,
    interfaces: Vec<MulticastInterface>,
    running: AtomicBool,
    group_addr: SocketAddr,
    active_listeners: Mutex<HashMap<String, ListenerInfo>>,
}

impl Multicast {
    pub async fn new(core: Arc<Core>, interfaces: Vec<MulticastInterface>) -> Result<Arc<Self>> {
        let group_addr: SocketAddr = MULTICAST_GROUP.parse()
            .map_err(|e| anyhow!("invalid multicast group address: {e}"))?;

        let m = Arc::new(Multicast {
            core,
            interfaces,
            running: AtomicBool::new(false),
            group_addr,
            active_listeners: Mutex::new(HashMap::new()),
        });

        if !m.interfaces.is_empty() && m.interfaces.iter().any(|i| i.beacon || i.listen) {
            m.start().await?;
        }

        Ok(m)
    }

    async fn start(self: &Arc<Self>) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(anyhow!("multicast module is already started"));
        }

        info!("Starting multicast module");

        let group_addr = match self.group_addr {
            SocketAddr::V6(a) => a,
            _ => return Err(anyhow!("expected IPv6 multicast group")),
        };

        // Create socket with SO_REUSEADDR + SO_REUSEPORT set BEFORE binding.
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::SocketAddr as StdSocketAddr;

        let sock2 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| anyhow!("socket create: {e}"))?;
        sock2.set_reuse_address(true)
            .map_err(|e| anyhow!("SO_REUSEADDR: {e}"))?;
        #[cfg(target_os = "linux")]
        sock2.set_reuse_port(true)
            .map_err(|e| anyhow!("SO_REUSEPORT: {e}"))?;

        // Bind to [::]:port
        let bind_addr: StdSocketAddr = format!("[::]:{}", group_addr.port())
            .parse()
            .map_err(|e| anyhow!("parse bind addr: {e}"))?;
        sock2.bind(&bind_addr.into())
            .map_err(|e| anyhow!("bind multicast socket: {e}"))?;
        sock2.set_nonblocking(true)
            .map_err(|e| anyhow!("set_nonblocking: {e}"))?;

        let std_socket: std::net::UdpSocket = sock2.into();
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| anyhow!("tokio UdpSocket from_std: {e}"))?;

        // Join the multicast group on every relevant interface so we
        // actually receive multicast announcements from peers.
        let multicast_ip: Ipv6Addr = *group_addr.ip();
        for iface in pnet_datalink::interfaces() {
            if !iface.is_up() || iface.is_loopback() {
                continue;
            }
            let has_v6_link_local = iface.ips.iter().any(|ip| {
                if let IpAddr::V6(v6) = ip.ip() { v6.is_unicast_link_local() } else { false }
            });
            if !has_v6_link_local {
                continue;
            }
            let idx = interface_index(&iface.name);
            if idx == 0 {
                continue;
            }
            if let Err(e) = socket.join_multicast_v6(&multicast_ip, idx) {
                debug!("join multicast on {}: {e}", iface.name);
            }
        }

        let socket = Arc::new(socket);
        let this = Arc::clone(self);
        let sock_recv = Arc::clone(&socket);
        let sock_send = Arc::clone(&socket);

        // Receive loop
        tokio::spawn(async move {
            this.listen_loop(sock_recv, group_addr).await;
        });

        // Announce loop
        let this2 = Arc::clone(self);
        tokio::spawn(async move {
            this2.announce_loop(sock_send, group_addr).await;
        });

        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        info!("Stopped multicast module");
        Ok(())
    }

    pub fn is_started(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    async fn listen_loop(&self, socket: Arc<UdpSocket>, group_addr: SocketAddrV6) {
        let pk = self.core.public_key();
        let mut buf = vec![0u8; 2048];

        loop {
            if !self.running.load(Ordering::SeqCst) {
                return;
            }

            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    if !self.running.load(Ordering::SeqCst) {
                        return;
                    }
                    warn!("multicast recv error: {e}");
                    continue;
                }
            };

            let adv = match MulticastAdvertisement::unmarshal_binary(&buf[..n]) {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Version check
            if adv.major_version != PROTOCOL_VERSION_MAJOR
                || adv.minor_version != PROTOCOL_VERSION_MINOR
            {
                continue;
            }
            // Skip our own beacons
            if adv.public_key == pk {
                continue;
            }

            let from_addr = match from {
                SocketAddr::V6(a) => a,
                _ => continue,
            };

            // Find matching interface config
            for iface in &self.interfaces {
                if !iface.listen {
                    continue;
                }

                // Verify hash
                let expected_hash = compute_hash(&iface.password, &adv.public_key);
                if expected_hash != adv.hash {
                    continue;
                }

                // Dial the peer
                let peer_port = adv.port;
                let peer_ip = from_addr.ip();
                let peer_zone = from_addr.scope_id().to_string();

                let mut peer_addr = from_addr;
                peer_addr.set_port(peer_port);

                let priority = iface.priority;
                let password = iface.password.clone();
                let public_key_hex = hex::encode(adv.public_key);

                let peer_uri = format!(
                    "tls://[{}%{}]:{peer_port}?key={public_key_hex}&priority={priority}&password={}",
                    peer_ip,
                    peer_zone,
                    urlencoding(&password),
                );

                let core = Arc::clone(&self.core);
                tokio::spawn(async move {
                    if let Err(e) = core.call_peer(&peer_uri, &peer_zone).await {
                        debug!("multicast dial failed: {e}");
                    }
                });

                break;
            }
        }
    }

    async fn announce_loop(&self, socket: Arc<UdpSocket>, group_addr: SocketAddrV6) {
        let pk = self.core.public_key();

        loop {
            if !self.running.load(Ordering::SeqCst) {
                return;
            }

            let ifaces = self.get_allowed_interfaces().await;

            for (name, info) in &ifaces {
                if !info.beacon {
                    continue;
                }

                // Ensure we have a listener for this interface
                let listener_port = self.ensure_listener(name, info).await;

                for addr in &info.addrs {
                    let adv = MulticastAdvertisement {
                        major_version: PROTOCOL_VERSION_MAJOR,
                        minor_version: PROTOCOL_VERSION_MINOR,
                        public_key: pk,
                        port: listener_port,
                        hash: info.hash.clone(),
                    };
                    let payload = adv.marshal_binary();
                    let dst = SocketAddrV6::new(
                        group_addr.ip().clone(),
                        group_addr.port(),
                        0,
                        // Use the interface index as scope_id
                        0,
                    );
                    if let Err(e) = socket.send_to(&payload, SocketAddr::V6(dst)).await {
                        debug!("multicast send error on {name}: {e}");
                    }
                }
            }

            // Randomize interval ~1s
            let millis = rand::random::<u64>() % 1024;
            sleep(Duration::from_millis(1000 + millis)).await;
        }
    }

    async fn ensure_listener(&self, iface_name: &str, info: &InterfaceInfo) -> u16 {
        // Check if we already have a listener for this interface
        if let Some(li) = self.active_listeners.lock().await.get(iface_name) {
            return li.port;
        }

        // Start a new TLS listener on a random port
        let bind = format!("[::]:{}", info.port);
        let uri = format!("tls://{bind}?priority={}&password={}", info.priority, urlencoding(std::str::from_utf8(&info.password).unwrap_or("")));

        let core = Arc::clone(&self.core);
        let port = info.port;
        let iface_name_owned = iface_name.to_string();

        match core.listen_local(&uri, &iface_name_owned).await {
            Ok(listener) => {
                let actual_port = listener.local_addr.port();
                // Take ownership of the cancel sender so the listener stays alive.
                self.active_listeners.lock().await.insert(
                    iface_name.to_string(),
                    ListenerInfo {
                        port: actual_port,
                        started_at: Instant::now(),
                        interval: Duration::ZERO,
                        cancel: listener.cancel,
                    },
                );
                actual_port
            }
            Err(e) => {
                warn!("Failed to start multicast listener on {iface_name}: {e}");
                port
            }
        }
    }

    async fn get_allowed_interfaces(&self) -> HashMap<String, InterfaceInfo> {
        let pk = self.core.public_key();
        let mut result = HashMap::new();

        // Enumerate system interfaces
        let ifaces = match get_network_interfaces() {
            Ok(i) => i,
            Err(e) => {
                debug!("Failed to get interfaces: {e}");
                return result;
            }
        };

        for (name, addrs) in ifaces {
            for cfg in &self.interfaces {
                if !cfg.beacon && !cfg.listen {
                    continue;
                }
                if !cfg.regex.is_match(&name) {
                    continue;
                }

                let hash = compute_hash(&cfg.password, &pk);
                result.insert(
                    name.clone(),
                    InterfaceInfo {
                        iface_name: name.clone(),
                        addrs: addrs.clone(),
                        beacon: cfg.beacon,
                        listen: cfg.listen,
                        port: cfg.port,
                        priority: cfg.priority,
                        password: cfg.password.as_bytes().to_vec(),
                        hash,
                    },
                );
                break;
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Platform interface enumeration
// ---------------------------------------------------------------------------

fn get_network_interfaces() -> Result<HashMap<String, Vec<Ipv6Addr>>> {
    let mut result = HashMap::new();
    for iface in pnet_datalink::interfaces() {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        let addrs: Vec<Ipv6Addr> = iface
            .ips
            .iter()
            .filter_map(|ip| {
                if let IpAddr::V6(v6) = ip.ip() {
                    if v6.is_unicast_link_local() {
                        Some(v6)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        if !addrs.is_empty() {
            result.insert(iface.name, addrs);
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compute_hash(password: &str, pk: &[u8; 32]) -> Vec<u8> {
    if password.is_empty() {
        use blake2::Digest;
        let mut h = Blake2b512::new();
        Digest::update(&mut h, pk);
        return Digest::finalize(h).to_vec();
    }
    use blake2::{Blake2bMac512, digest::{KeyInit, Mac}};
    match <Blake2bMac512 as KeyInit>::new_from_slice(password.as_bytes()) {
        Ok(mut h) => {
            Mac::update(&mut h, pk);
            Mac::finalize(h).into_bytes().to_vec()
        }
        Err(_) => vec![],
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Returns the OS network interface index for the given name, or 0 on error.
fn interface_index(name: &str) -> u32 {
    use std::ffi::CString;
    let c_name = match CString::new(name) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    idx as u32
}
