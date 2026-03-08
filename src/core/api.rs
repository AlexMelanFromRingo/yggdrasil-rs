/// Public API types returned by Core.
///
/// Port of yggdrasil-go/src/core/api.go

use std::time::Duration;

pub type PublicKeyBytes = [u8; 32];

/// Information about this node.
#[derive(Debug, Clone)]
pub struct SelfInfo {
    pub key: PublicKeyBytes,
    pub routing_entries: u64,
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub uri: String,
    pub up: bool,
    pub inbound: bool,
    pub last_error: Option<String>,
    pub last_error_time: Option<std::time::SystemTime>,
    pub key: PublicKeyBytes,
    pub root: PublicKeyBytes,
    pub coords: Vec<u64>,
    pub port: u64,
    pub priority: u8,
    pub cost: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub uptime: Duration,
    pub latency: Duration,
}

/// A spanning-tree entry.
#[derive(Debug, Clone)]
pub struct TreeEntryInfo {
    pub key: PublicKeyBytes,
    pub parent: PublicKeyBytes,
    pub sequence: u64,
}

/// A known path through the overlay.
#[derive(Debug, Clone)]
pub struct PathEntryInfo {
    pub key: PublicKeyBytes,
    pub path: Vec<u64>,
    pub sequence: u64,
}

/// An active application session with a remote node.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub key: PublicKeyBytes,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime: Duration,
}
