//! Setup options passed to `Core::new()`.
//!
//! Port of yggdrasil-go/src/core/options.go

use std::net::IpAddr;

/// A listener URI string (e.g. "tls://0.0.0.0:0").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenAddress(pub String);

/// An outbound peer connection.
#[derive(Debug, Clone)]
pub struct Peer {
    pub uri: String,
    pub source_interface: String,
}

/// Arbitrary node info key-value map (JSON object).
pub type NodeInfo = Option<serde_json::Value>;

/// Whether to hide platform/version from NodeInfo responses.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeInfoPrivacy(pub bool);

/// A single allowed public key (hex-decoded 32 bytes).
#[derive(Debug, Clone)]
pub struct AllowedPublicKey(pub [u8; 32]);

/// A filter function for peer IP addresses.
/// If set, peers whose resolved IPs do not pass the filter are skipped.
pub type PeerFilterFn = Box<dyn Fn(&IpAddr) -> bool + Send + Sync + 'static>;

/// Sealed trait for setup options.
pub trait SetupOption: sealed::Sealed + Send + Sync {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ListenAddress {}
    impl Sealed for super::Peer {}
    impl Sealed for Option<serde_json::Value> {}
    impl Sealed for super::NodeInfoPrivacy {}
    impl Sealed for super::AllowedPublicKey {}
}

impl SetupOption for ListenAddress {}
impl SetupOption for Peer {}
impl SetupOption for NodeInfo {}
impl SetupOption for NodeInfoPrivacy {}
impl SetupOption for AllowedPublicKey {}

/// Convenience builder that collects typed options.
#[derive(Default)]
pub struct OptionsBuilder {
    pub listen: Vec<ListenAddress>,
    pub peers: Vec<Peer>,
    pub node_info: NodeInfo,
    pub node_info_privacy: bool,
    pub allowed_keys: Vec<[u8; 32]>,
    pub peer_filter: Option<PeerFilterFn>,
}

impl OptionsBuilder {
    pub fn apply_listen(&mut self, addr: ListenAddress) {
        self.listen.push(addr);
    }
    pub fn apply_peer(&mut self, peer: Peer) {
        self.peers.push(peer);
    }
    pub fn apply_node_info(&mut self, info: NodeInfo) {
        self.node_info = info;
    }
    pub fn apply_node_info_privacy(&mut self, v: NodeInfoPrivacy) {
        self.node_info_privacy = v.0;
    }
    pub fn apply_allowed_key(&mut self, k: AllowedPublicKey) {
        self.allowed_keys.push(k.0);
    }
    pub fn apply_peer_filter(&mut self, f: PeerFilterFn) {
        self.peer_filter = Some(f);
    }
}
