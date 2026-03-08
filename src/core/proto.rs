/// Protocol handler — nodeinfo + debug sub-protocol.
///
/// Port of yggdrasil-go/src/core/proto.go (and debug.go / nodeinfo.go)

use crate::core::{types::*, nodeinfo::NodeInfoHandler};
use anyhow::Result;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

type KeyArray = [u8; 32];

/// Callback stored for a pending debug request.
struct ReqInfo {
    callback: Box<dyn FnOnce(Vec<u8>) + Send>,
    deadline: Instant,
}

/// Handles all in-band protocol packets (nodeinfo requests/responses, debug).
pub struct ProtoHandler {
    pub nodeinfo: Arc<NodeInfoHandler>,
    self_requests: Mutex<HashMap<KeyArray, ReqInfo>>,
    peers_requests: Mutex<HashMap<KeyArray, ReqInfo>>,
    tree_requests: Mutex<HashMap<KeyArray, ReqInfo>>,
    // Injected by Core after construction
    send_fn: Mutex<Option<Box<dyn Fn(Vec<u8>, KeyArray) + Send + Sync>>>,
    get_self_fn: Mutex<Option<Box<dyn Fn() -> (KeyArray, u64) + Send + Sync>>>,
    get_peers_fn: Mutex<Option<Box<dyn Fn() -> Vec<KeyArray> + Send + Sync>>>,
    get_tree_fn: Mutex<Option<Box<dyn Fn() -> Vec<KeyArray> + Send + Sync>>>,
    mtu_fn: Mutex<Option<Box<dyn Fn() -> u64 + Send + Sync>>>,
}

impl ProtoHandler {
    pub fn new(nodeinfo: Arc<NodeInfoHandler>) -> Arc<Self> {
        Arc::new(ProtoHandler {
            nodeinfo,
            self_requests: Mutex::new(HashMap::new()),
            peers_requests: Mutex::new(HashMap::new()),
            tree_requests: Mutex::new(HashMap::new()),
            send_fn: Mutex::new(None),
            get_self_fn: Mutex::new(None),
            get_peers_fn: Mutex::new(None),
            get_tree_fn: Mutex::new(None),
            mtu_fn: Mutex::new(None),
        })
    }

    /// Wires up callbacks from Core so the proto handler can query/send.
    pub async fn set_core_callbacks(
        &self,
        send: impl Fn(Vec<u8>, KeyArray) + Send + Sync + 'static,
        get_self: impl Fn() -> (KeyArray, u64) + Send + Sync + 'static,
        get_peers: impl Fn() -> Vec<KeyArray> + Send + Sync + 'static,
        get_tree: impl Fn() -> Vec<KeyArray> + Send + Sync + 'static,
        mtu: impl Fn() -> u64 + Send + Sync + 'static,
    ) {
        *self.send_fn.lock().await = Some(Box::new(send));
        *self.get_self_fn.lock().await = Some(Box::new(get_self));
        *self.get_peers_fn.lock().await = Some(Box::new(get_peers));
        *self.get_tree_fn.lock().await = Some(Box::new(get_tree));
        *self.mtu_fn.lock().await = Some(Box::new(mtu));
    }

    /// Dispatches an incoming protocol packet.
    pub async fn handle_proto(&self, from: KeyArray, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match data[0] {
            TYPE_PROTO_DUMMY => {}
            TYPE_PROTO_NODE_INFO_REQUEST => {
                self.handle_nodeinfo_request(from).await;
            }
            TYPE_PROTO_NODE_INFO_RESPONSE => {
                self.nodeinfo.fire_callback(from, data[1..].to_vec()).await;
            }
            TYPE_PROTO_DEBUG => {
                self.handle_debug(from, &data[1..]).await;
            }
            _ => {}
        }
    }

    async fn handle_nodeinfo_request(&self, from: KeyArray) {
        let info = self.nodeinfo.get_node_info().await;
        let mut payload = vec![TYPE_SESSION_PROTO, TYPE_PROTO_NODE_INFO_RESPONSE];
        payload.extend_from_slice(&info);
        self.send(payload, from).await;
    }

    async fn handle_debug(&self, from: KeyArray, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match data[0] {
            TYPE_DEBUG_DUMMY => {}
            TYPE_DEBUG_GET_SELF_REQUEST => self.handle_get_self_request(from).await,
            TYPE_DEBUG_GET_SELF_RESPONSE => self.handle_get_self_response(from, &data[1..]).await,
            TYPE_DEBUG_GET_PEERS_REQUEST => self.handle_get_peers_request(from).await,
            TYPE_DEBUG_GET_PEERS_RESPONSE => {
                self.handle_get_peers_response(from, &data[1..]).await
            }
            TYPE_DEBUG_GET_TREE_REQUEST => self.handle_get_tree_request(from).await,
            TYPE_DEBUG_GET_TREE_RESPONSE => {
                self.handle_get_tree_response(from, &data[1..]).await
            }
            _ => {}
        }
    }

    async fn handle_get_self_request(&self, from: KeyArray) {
        let (key, routing_entries) = match self.get_self_fn.lock().await.as_ref() {
            Some(f) => f(),
            None => return,
        };
        let res = serde_json::json!({
            "key": hex::encode(key),
            "routing_entries": routing_entries.to_string(),
        });
        let bs = serde_json::to_vec(&res).unwrap_or_default();
        self.send_debug(TYPE_DEBUG_GET_SELF_RESPONSE, &bs, from).await;
    }

    async fn handle_get_self_response(&self, from: KeyArray, data: &[u8]) {
        if let Some(info) = self.self_requests.lock().await.remove(&from) {
            (info.callback)(data.to_vec());
        }
    }

    async fn handle_get_peers_request(&self, from: KeyArray) {
        let peers = match self.get_peers_fn.lock().await.as_ref() {
            Some(f) => f(),
            None => return,
        };
        let mtu = match self.mtu_fn.lock().await.as_ref() {
            Some(f) => f(),
            None => u64::MAX,
        };
        let mut bs: Vec<u8> = Vec::new();
        for pk in &peers {
            let candidate = [bs.as_slice(), pk.as_slice()].concat();
            const OVERHEAD: u64 = 2;
            if (candidate.len() as u64) + OVERHEAD > mtu {
                break;
            }
            bs.extend_from_slice(pk);
        }
        self.send_debug(TYPE_DEBUG_GET_PEERS_RESPONSE, &bs, from).await;
    }

    async fn handle_get_peers_response(&self, from: KeyArray, data: &[u8]) {
        if let Some(info) = self.peers_requests.lock().await.remove(&from) {
            (info.callback)(data.to_vec());
        }
    }

    async fn handle_get_tree_request(&self, from: KeyArray) {
        let tree = match self.get_tree_fn.lock().await.as_ref() {
            Some(f) => f(),
            None => return,
        };
        let mtu = match self.mtu_fn.lock().await.as_ref() {
            Some(f) => f(),
            None => u64::MAX,
        };
        let mut bs: Vec<u8> = Vec::new();
        for pk in &tree {
            let candidate = [bs.as_slice(), pk.as_slice()].concat();
            const OVERHEAD: u64 = 2;
            if (candidate.len() as u64) + OVERHEAD > mtu {
                break;
            }
            bs.extend_from_slice(pk);
        }
        self.send_debug(TYPE_DEBUG_GET_TREE_RESPONSE, &bs, from).await;
    }

    async fn handle_get_tree_response(&self, from: KeyArray, data: &[u8]) {
        if let Some(info) = self.tree_requests.lock().await.remove(&from) {
            (info.callback)(data.to_vec());
        }
    }

    /// Sends a debug sub-packet.
    async fn send_debug(&self, dtype: u8, data: &[u8], to: KeyArray) {
        let mut payload = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, dtype];
        payload.extend_from_slice(data);
        self.send(payload, to).await;
    }

    async fn send(&self, payload: Vec<u8>, to: KeyArray) {
        if let Some(f) = self.send_fn.lock().await.as_ref() {
            f(payload, to);
        }
    }

    // ---- Admin-socket handler helpers -----------------------------------

    pub async fn send_get_self_request(
        &self,
        key: KeyArray,
        cb: impl FnOnce(Vec<u8>) + Send + 'static,
    ) {
        {
            let mut reqs = self.self_requests.lock().await;
            reqs.insert(
                key,
                ReqInfo {
                    callback: Box::new(cb),
                    deadline: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let mut payload = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_SELF_REQUEST];
        self.send(payload, key).await;
    }

    pub async fn send_get_peers_request(
        &self,
        key: KeyArray,
        cb: impl FnOnce(Vec<u8>) + Send + 'static,
    ) {
        {
            let mut reqs = self.peers_requests.lock().await;
            reqs.insert(
                key,
                ReqInfo {
                    callback: Box::new(cb),
                    deadline: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let mut payload = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_PEERS_REQUEST];
        self.send(payload, key).await;
    }

    pub async fn send_get_tree_request(
        &self,
        key: KeyArray,
        cb: impl FnOnce(Vec<u8>) + Send + 'static,
    ) {
        {
            let mut reqs = self.tree_requests.lock().await;
            reqs.insert(
                key,
                ReqInfo {
                    callback: Box::new(cb),
                    deadline: Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let mut payload = vec![TYPE_SESSION_PROTO, TYPE_PROTO_DEBUG, TYPE_DEBUG_GET_TREE_REQUEST];
        self.send(payload, key).await;
    }
}
