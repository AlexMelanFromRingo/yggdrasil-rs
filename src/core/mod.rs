/// Core — Yggdrasil node lifecycle.
///
/// Port of yggdrasil-go/src/core/core.go + api.go

pub mod api;
pub mod handshake;
pub mod link;
pub mod nodeinfo;
pub mod options;
pub mod proto;
pub mod types;

use crate::{address, config::NodeConfig, version};
use anyhow::{anyhow, Result};
use api::*;
use ed25519_dalek::SigningKey;
use ironwood_rs::{InboundPacket, PacketConn};
use nodeinfo::NodeInfoHandler;
use proto::ProtoHandler;
use std::{
    collections::HashSet,
    net::Ipv6Addr,
    sync::Arc,
};
use tokio::{sync::{Mutex, RwLock, mpsc}, task::JoinHandle};
use tracing::info;
use url::Url;

/// The Yggdrasil node — manages the full lifecycle.
pub struct Core {
    packet_conn: Arc<PacketConn>,
    proto: Arc<ProtoHandler>,
    signing_key: SigningKey,
    public_key: [u8; 32],
    config: Arc<NodeConfig>,
    allowed_public_keys: RwLock<HashSet<[u8; 32]>>,
    listeners: Mutex<Vec<link::Listener>>,
    background_tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Traffic packets dispatched from the background read loop.
    traffic_tx: mpsc::Sender<InboundPacket>,
    traffic_rx: Mutex<mpsc::Receiver<InboundPacket>>,
}

impl Core {
    /// Creates and starts a new Yggdrasil node.
    pub async fn new(node_config: Arc<NodeConfig>) -> Result<Arc<Self>> {
        let signing_key = node_config.signing_key()?;
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        if let Some(name) = {
            let n = version::build_name();
            if n != "unknown" { Some(n) } else { None }
        } {
            info!("Build name: {name}");
        }
        if let Some(ver) = {
            let v = version::build_version();
            if v != "unknown" { Some(v) } else { None }
        } {
            info!("Build version: {ver}");
        }

        // Build the overlay network conn (ironwood equivalent)
        let packet_conn = Arc::new(PacketConn::new(signing_key.clone()));

        // Build node info handler
        let nodeinfo_handler = NodeInfoHandler::new();

        // Build protocol handler
        let proto = ProtoHandler::new(Arc::clone(&nodeinfo_handler));

        let (traffic_tx, traffic_rx) = mpsc::channel::<InboundPacket>(4096);

        let core = Arc::new(Core {
            packet_conn: Arc::clone(&packet_conn),
            proto: Arc::clone(&proto),
            signing_key: signing_key.clone(),
            public_key,
            config: Arc::clone(&node_config),
            allowed_public_keys: RwLock::new(HashSet::new()),
            listeners: Mutex::new(Vec::new()),
            background_tasks: Mutex::new(Vec::new()),
            traffic_tx,
            traffic_rx: Mutex::new(traffic_rx),
        });

        // Wire up protocol callbacks
        {
            let pc = Arc::clone(&packet_conn);
            let core2 = Arc::clone(&core);
            let pc_send = Arc::clone(&packet_conn);
            proto
                .set_core_callbacks(
                    move |payload, dst| {
                        let pc = Arc::clone(&pc_send);
                        tokio::spawn(async move {
                            let _ = pc.write_to(&payload, &dst).await;
                        });
                    },
                    {
                        let c = Arc::clone(&core2);
                        move || {
                            let si = c.get_self();
                            (si.key, si.routing_entries)
                        }
                    },
                    {
                        let c = Arc::clone(&core2);
                        move || {
                            tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current()
                                    .block_on(async {
                                        c.get_peers().await.iter().map(|p| p.key).collect()
                                    })
                            })
                        }
                    },
                    {
                        let c = Arc::clone(&core2);
                        move || {
                            tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current()
                                    .block_on(async {
                                        c.get_tree().await.iter().map(|t| t.key).collect()
                                    })
                            })
                        }
                    },
                    {
                        let c = Arc::clone(&core2);
                        move || c.mtu()
                    },
                )
                .await;
        }

        // Spawn background read loop
        {
            let pc = Arc::clone(&packet_conn);
            let proto_clone = Arc::clone(&proto);
            let core_weak = Arc::downgrade(&core);
            let handle = tokio::spawn(async move {
                loop {
                    match pc.read_from().await {
                        Ok(pkt) => {
                            if pkt.payload.is_empty() {
                                continue;
                            }
                            match pkt.payload[0] {
                                types::TYPE_SESSION_TRAFFIC => {
                                    // Forward to ipv6rwc / application
                                    // (application calls Core::read_from())
                                    if let Some(c) = core_weak.upgrade() {
                                        c.deliver_packet(pkt).await;
                                    }
                                }
                                types::TYPE_SESSION_PROTO => {
                                    proto_clone
                                        .handle_proto(pkt.from, &pkt.payload[1..])
                                        .await;
                                }
                                _ => {}
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            core.background_tasks.lock().await.push(handle);
        }

        Ok(core)
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Applies configuration options (listeners, peers, allowed keys, etc.).
    pub async fn apply_config(&self, node_config: &NodeConfig) -> Result<()> {
        // Allowed public keys
        let mut allowed = self.allowed_public_keys.write().await;
        for hex_key in &node_config.allowed_public_keys {
            let bytes = hex::decode(hex_key)
                .map_err(|e| anyhow!("invalid allowed key: {e}"))?;
            if bytes.len() != 32 {
                return Err(anyhow!("allowed key must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            allowed.insert(arr);
        }
        Ok(())
    }

    pub fn mtu(&self) -> u64 {
        let session_overhead = 1u64;
        let mtu = self.packet_conn.mtu() - session_overhead;
        mtu.min(65535)
    }

    /// Returns the node's IPv6 address.
    pub fn address(&self) -> Ipv6Addr {
        let addr = address::addr_for_key(&self.public_key).expect("valid key");
        Ipv6Addr::from(addr.0)
    }

    /// Returns the node's /64 subnet.
    pub fn subnet(&self) -> (Ipv6Addr, u8) {
        let snet = address::subnet_for_key(&self.public_key).expect("valid key");
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&snet.0);
        (Ipv6Addr::from(bytes), 64)
    }

    /// Returns the node's ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns info about this node.
    pub fn get_self(&self) -> SelfInfo {
        // routing entries = number of known peers (simplified)
        let peers = self.packet_conn.get_peer_stats();
        SelfInfo {
            key: self.public_key,
            routing_entries: peers.len() as u64,
        }
    }

    /// Returns info about all connected peers.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.packet_conn
            .get_peer_stats()
            .into_iter()
            .map(|s| PeerInfo {
                uri: String::new(),
                up: true,
                inbound: false,
                last_error: None,
                last_error_time: None,
                key: s.key,
                root: [0u8; 32],
                coords: vec![],
                port: 0,
                priority: s.priority,
                cost: 0,
                rx_bytes: s.rx_bytes,
                tx_bytes: s.tx_bytes,
                rx_rate: 0,
                tx_rate: 0,
                uptime: s.uptime,
                latency: s.latency,
            })
            .collect()
    }

    /// Returns the spanning-tree entries.
    pub async fn get_tree(&self) -> Vec<TreeEntryInfo> {
        // Simplified: return peers as tree entries
        self.packet_conn
            .get_peer_stats()
            .into_iter()
            .map(|s| TreeEntryInfo {
                key: s.key,
                parent: self.public_key,
                sequence: 0,
            })
            .collect()
    }

    /// Returns known routing paths.
    pub async fn get_paths(&self) -> Vec<PathEntryInfo> {
        vec![]
    }

    /// Returns active application sessions.
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
        self.packet_conn
            .get_peer_stats()
            .into_iter()
            .map(|s| SessionInfo {
                key: s.key,
                rx_bytes: s.rx_bytes,
                tx_bytes: s.tx_bytes,
                uptime: s.uptime,
            })
            .collect()
    }

    /// Adds a persistent outbound peer.
    pub async fn add_peer(self: &Arc<Self>, uri: &str, sintf: &str) -> Result<()> {
        let links = link::Links::new(
            Arc::clone(&self.packet_conn),
            Arc::clone(&self.config),
        );
        links.add(uri, sintf, link::LinkType::Persistent).await
    }

    /// Adds an ephemeral (one-shot) outbound peer.
    pub async fn call_peer(self: &Arc<Self>, uri: &str, sintf: &str) -> Result<()> {
        let links = link::Links::new(
            Arc::clone(&self.packet_conn),
            Arc::clone(&self.config),
        );
        links.add(uri, sintf, link::LinkType::Ephemeral).await
    }

    /// Starts a listener.
    pub async fn listen(self: &Arc<Self>, uri: &str, sintf: &str) -> Result<link::Listener> {
        let links = link::Links::new(
            Arc::clone(&self.packet_conn),
            Arc::clone(&self.config),
        );
        links.listen(uri, sintf, false).await
    }

    /// Starts a local (multicast) listener that bypasses AllowedPublicKeys.
    pub async fn listen_local(self: &Arc<Self>, uri: &str, sintf: &str) -> Result<link::Listener> {
        let links = link::Links::new(
            Arc::clone(&self.packet_conn),
            Arc::clone(&self.config),
        );
        links.listen(uri, sintf, true).await
    }

    /// Sends a packet to the given destination public key.
    pub async fn write_to(&self, payload: &[u8], dst: &[u8; 32]) -> Result<usize> {
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(types::TYPE_SESSION_TRAFFIC);
        buf.extend_from_slice(payload);
        self.packet_conn.write_to(&buf, dst).await?;
        Ok(payload.len())
    }

    /// Reads the next application-level IPv6 packet.
    /// Blocks until one is available from the background dispatch loop.
    pub async fn read_from(&self, out: &mut [u8]) -> Result<(usize, [u8; 32])> {
        let pkt = self.traffic_rx.lock().await
            .recv().await
            .ok_or_else(|| anyhow!("Core traffic channel closed"))?;
        if pkt.payload.is_empty() || pkt.payload[0] != types::TYPE_SESSION_TRAFFIC {
            return Err(anyhow!("not a traffic packet"));
        }
        let data = &pkt.payload[1..];
        let n = out.len().min(data.len());
        out[..n].copy_from_slice(&data[..n]);
        Ok((n, pkt.from))
    }

    /// Sends a path lookup for a partial key.
    pub async fn send_lookup(&self, partial: &[u8]) {
        self.packet_conn.send_lookup(partial).await;
    }

    /// Registers a callback for when a new path to a key is discovered.
    pub async fn set_path_notify<F>(&self, f: F)
    where
        F: Fn([u8; 32]) + Send + Sync + 'static,
    {
        self.packet_conn
            .set_path_notify(move |vk| f(vk.to_bytes()))
            .await;
    }

    /// Returns a reference to the node's config (for mobile FFI and other consumers).
    pub fn config_ref(&self) -> &NodeConfig {
        &self.config
    }

    /// Inject a raw IPv6 packet from an external source (e.g. mobile VPN interface).
    ///
    /// The destination ed25519 key is derived from the IPv6 destination address
    /// using the yggdrasil address reverse-mapping (`Address::get_key`).
    /// Packets destined outside `200::/7` are silently dropped.
    pub async fn write_packet(&self, raw_ipv6: &[u8]) -> Result<()> {
        if raw_ipv6.len() < 40 { return Ok(()); }
        let dst_ip: [u8; 16] = raw_ipv6[24..40].try_into()
            .map_err(|_| anyhow!("bad packet"))?;
        let addr = crate::address::Address(dst_ip);
        if !addr.is_valid() { return Ok(()); } // not a yggdrasil address
        let key = addr.get_key();
        self.write_to(raw_ipv6, &key).await?;
        Ok(())
    }

    /// Shuts down the node.
    pub async fn stop(&self) {
        info!("Stopping...");
        self.packet_conn.close().await;
        let mut tasks = self.background_tasks.lock().await;
        for t in tasks.drain(..) {
            t.abort();
        }
        info!("Stopped");
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Internal: delivers a traffic packet to the application-level queue.
    async fn deliver_packet(&self, pkt: InboundPacket) {
        let _ = self.traffic_tx.send(pkt).await;
    }
}

/// Logging interface compatible with the Go Logger interface.
pub trait Logger: Send + Sync + 'static {
    fn info(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn error(&self, msg: &str);
    fn debug(&self, msg: &str);
}

/// A logger that uses the `tracing` crate.
pub struct TracingLogger;

impl Logger for TracingLogger {
    fn info(&self, msg: &str) { tracing::info!("{msg}"); }
    fn warn(&self, msg: &str) { tracing::warn!("{msg}"); }
    fn error(&self, msg: &str) { tracing::error!("{msg}"); }
    fn debug(&self, msg: &str) { tracing::debug!("{msg}"); }
}

/// Handler function type for admin socket endpoints.
pub type AddHandlerFunc =
    Box<dyn Fn(serde_json::Value) -> Result<serde_json::Value> + Send + Sync + 'static>;
