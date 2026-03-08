//! NodeInfo — fetching and caching node metadata from remote nodes.
//!
//! Port of yggdrasil-go/src/core/nodeinfo.go

use anyhow::Result;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

use crate::version;

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

type NodeInfoCallback = Box<dyn FnOnce(Vec<u8>) + Send + 'static>;

struct CallbackEntry {
    callback: NodeInfoCallback,
    created: Instant,
}

type KeyArray = [u8; 32];

/// Manages this node's outgoing NodeInfo and incoming NodeInfo request callbacks.
pub struct NodeInfoHandler {
    my_node_info: Mutex<Vec<u8>>,          // JSON bytes
    callbacks: Mutex<HashMap<KeyArray, CallbackEntry>>,
}

impl NodeInfoHandler {
    pub fn new() -> Arc<Self> {
        let handler = Arc::new(NodeInfoHandler {
            my_node_info: Mutex::new(Vec::new()),
            callbacks: Mutex::new(HashMap::new()),
        });
        let h = Arc::clone(&handler);
        tokio::spawn(async move {
            h.cleanup_loop().await;
        });
        handler
    }

    /// Sets this node's NodeInfo from a JSON value and optional privacy mode.
    pub async fn set_node_info(
        &self,
        given: Option<&Value>,
        privacy: bool,
    ) -> Result<()> {
        let mut info: HashMap<String, Value> = HashMap::new();
        if let Some(Value::Object(m)) = given {
            for (k, v) in m {
                info.insert(k.clone(), v.clone());
            }
        }
        if !privacy {
            info.insert("buildname".into(), Value::String(version::build_name().to_string()));
            info.insert("buildversion".into(), Value::String(version::build_version().to_string()));
            info.insert("buildplatform".into(), Value::String(std::env::consts::OS.to_string()));
            info.insert("buildarch".into(), Value::String(std::env::consts::ARCH.to_string()));
        }
        let json = serde_json::to_vec(&info)?;
        if json.len() > 16384 {
            return Err(anyhow::anyhow!("NodeInfo exceeds max length of 16384 bytes"));
        }
        *self.my_node_info.lock().await = json;
        Ok(())
    }

    /// Returns our own raw NodeInfo JSON bytes.
    pub async fn get_node_info(&self) -> Vec<u8> {
        self.my_node_info.lock().await.clone()
    }

    /// Registers a callback for a NodeInfo response from `key`.
    pub async fn add_callback(&self, key: KeyArray, cb: NodeInfoCallback) {
        let entry = CallbackEntry {
            callback: cb,
            created: Instant::now(),
        };
        self.callbacks.lock().await.insert(key, entry);
    }

    /// Fires the callback for `key` with the received NodeInfo, if one exists.
    pub async fn fire_callback(&self, key: KeyArray, info: Vec<u8>) {
        if let Some(entry) = self.callbacks.lock().await.remove(&key) {
            (entry.callback)(info);
        }
    }

    async fn cleanup_loop(&self) {
        loop {
            tokio::time::sleep(CLEANUP_INTERVAL).await;
            let mut cbs = self.callbacks.lock().await;
            cbs.retain(|_, v| v.created.elapsed() < CALLBACK_TIMEOUT);
        }
    }
}
