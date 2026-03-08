//! Admin socket — JSON-over-TCP/UNIX API.
//!
//! Port of yggdrasil-go/src/admin/admin.go and the handler files.

use crate::core::{Core, AddHandlerFunc};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixListener},
    sync::{Mutex, RwLock},
};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminSocketRequest {
    #[serde(rename = "request")]
    pub name: String,
    #[serde(rename = "arguments", default)]
    pub arguments: Value,
    #[serde(rename = "keepalive", default)]
    pub keep_alive: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminSocketResponse {
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub response: Value,
}

#[derive(Debug, Serialize)]
pub struct ListEntry {
    pub command: String,
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub list: Vec<ListEntry>,
}

// ---------------------------------------------------------------------------
// GetSelf
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct GetSelfResponse {
    #[serde(rename = "build_name")]
    pub build_name: String,
    #[serde(rename = "build_version")]
    pub build_version: String,
    #[serde(rename = "public_key")]
    pub public_key: String,
    #[serde(rename = "ip_address")]
    pub ip_address: String,
    #[serde(rename = "subnet")]
    pub subnet: String,
    #[serde(rename = "routing_entries")]
    pub routing_entries: u64,
}

// ---------------------------------------------------------------------------
// GetPeers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GetPeersRequest {
    #[serde(default)]
    pub sort: String,
}

#[derive(Debug, Serialize)]
pub struct GetPeerEntry {
    pub uri: String,
    pub up: bool,
    pub inbound: bool,
    pub ip_address: String,
    pub public_key: String,
    pub priority: u8,
    pub rx_bytes: DataUnit,
    pub tx_bytes: DataUnit,
    pub rx_rate: DataUnit,
    pub tx_rate: DataUnit,
    pub uptime: u64,
    pub latency: f64,
    pub last_error: String,
    pub last_error_time: String,
}

#[derive(Debug, Serialize)]
pub struct GetPeersResponse {
    pub peers: Vec<GetPeerEntry>,
}

// ---------------------------------------------------------------------------
// GetTree
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct GetTreeEntry {
    pub public_key: String,
    pub ip_address: String,
    pub parent: String,
    pub sequence: u64,
}

#[derive(Debug, Serialize)]
pub struct GetTreeResponse {
    pub tree: Vec<GetTreeEntry>,
}

// ---------------------------------------------------------------------------
// GetPaths
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct GetPathsEntry {
    pub public_key: String,
    pub ip_address: String,
    pub path: Vec<u64>,
    pub sequence: u64,
}

#[derive(Debug, Serialize)]
pub struct GetPathsResponse {
    pub paths: Vec<GetPathsEntry>,
}

// ---------------------------------------------------------------------------
// GetSessions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct GetSessionEntry {
    pub public_key: String,
    pub ip_address: String,
    pub rx_bytes: DataUnit,
    pub tx_bytes: DataUnit,
    pub uptime: u64,
}

#[derive(Debug, Serialize)]
pub struct GetSessionsResponse {
    pub sessions: Vec<GetSessionEntry>,
}

// ---------------------------------------------------------------------------
// AddPeer / RemovePeer
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub uri: String,
    #[serde(rename = "interface", default)]
    pub interface: String,
}

#[derive(Debug, Serialize)]
pub struct AddPeerResponse {}

#[derive(Debug, Deserialize)]
pub struct RemovePeerRequest {
    pub uri: String,
    #[serde(rename = "interface", default)]
    pub interface: String,
}

#[derive(Debug, Serialize)]
pub struct RemovePeerResponse {}

// ---------------------------------------------------------------------------
// DataUnit — human-readable byte count
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct DataUnit(pub u64);

impl DataUnit {
    pub fn format(&self) -> String {
        let v = self.0;
        if v >= 1024 * 1024 * 1024 * 1024 {
            format!("{:.1}TB", v as f64 / 1024.0 / 1024.0 / 1024.0 / 1024.0)
        } else if v >= 1024 * 1024 * 1024 {
            format!("{:.1}GB", v as f64 / 1024.0 / 1024.0 / 1024.0)
        } else if v >= 1024 * 1024 {
            format!("{:.1}MB", v as f64 / 1024.0 / 1024.0)
        } else if v >= 100 {
            format!("{:.1}KB", v as f64 / 1024.0)
        } else {
            format!("{v}B")
        }
    }
}

// ---------------------------------------------------------------------------
// AdminSocket
// ---------------------------------------------------------------------------

struct Handler {
    desc: String,
    args: Vec<String>,
    func: AddHandlerFunc,
}

pub struct AdminSocket {
    core: Arc<Core>,
    handlers: RwLock<HashMap<String, Handler>>,
    done: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl AdminSocket {
    /// Creates an admin socket, starts listening, and returns the handle.
    ///
    /// Returns `Ok(None)` if `listen_addr` is `"none"` or empty.
    pub async fn new(
        core: Arc<Core>,
        listen_addr: &str,
    ) -> Result<Option<Arc<Self>>> {
        if listen_addr.is_empty() || listen_addr == "none" {
            return Ok(None);
        }

        let socket = Arc::new(AdminSocket {
            core: Arc::clone(&core),
            handlers: RwLock::new(HashMap::new()),
            done: Mutex::new(None),
        });

        socket.register_builtin_handlers().await;

        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
        *socket.done.lock().await = Some(done_tx);

        let sock_clone = Arc::clone(&socket);
        let addr = listen_addr.to_string();

        tokio::spawn(async move {
            if let Err(e) = AdminSocket::listen_loop(sock_clone, addr, &mut done_rx).await {
                warn!("Admin socket error: {e}");
            }
        });

        Ok(Some(socket))
    }

    async fn listen_loop(
        this: Arc<Self>,
        addr: String,
        done: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        use url::Url;
        if let Ok(u) = Url::parse(&addr) {
            match u.scheme() {
                "unix" => {
                    let path = u.path().to_string();
                    let _ = std::fs::remove_file(&path);
                    let listener = UnixListener::bind(&path)?;
                    info!("UNIX admin socket listening on {path}");
                    loop {
                        tokio::select! {
                            accept = listener.accept() => {
                                if let Ok((stream, _)) = accept {
                                    let (r, w) = tokio::io::split(stream);
                                    let s = Arc::clone(&this);
                                    tokio::spawn(async move {
                                        if let Err(e) = s.handle_connection(r, w).await {
                                            debug!("admin connection error: {e}");
                                        }
                                    });
                                }
                            }
                            _ = &mut *done => break,
                        }
                    }
                    return Ok(());
                }
                "tcp" => {
                    let host = u.host_str().unwrap_or("127.0.0.1").to_string();
                    let port = u.port().unwrap_or(9001);
                    let listener = TcpListener::bind(format!("{host}:{port}")).await?;
                    info!("TCP admin socket listening on {host}:{port}");
                    loop {
                        tokio::select! {
                            accept = listener.accept() => {
                                if let Ok((stream, _)) = accept {
                                    let (r, w) = stream.into_split();
                                    let s = Arc::clone(&this);
                                    tokio::spawn(async move {
                                        if let Err(e) = s.handle_connection(r, w).await {
                                            debug!("admin connection error: {e}");
                                        }
                                    });
                                }
                            }
                            _ = &mut *done => break,
                        }
                    }
                    return Ok(());
                }
                _ => {}
            }
        }

        // Fallback: try TCP directly
        let listener = TcpListener::bind(&addr).await?;
        info!("TCP admin socket listening on {addr}");
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    if let Ok((stream, _)) = accept {
                        let (r, w) = stream.into_split();
                        let s = Arc::clone(&this);
                        tokio::spawn(async move {
                            if let Err(e) = s.handle_connection(r, w).await {
                                debug!("admin connection error: {e}");
                            }
                        });
                    }
                }
                _ = &mut *done => break,
            }
        }
        Ok(())
    }

    async fn handle_connection<R, W>(&self, r: R, mut w: W) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(r);
        let mut line = String::new();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }

            let resp = match serde_json::from_str::<AdminSocketRequest>(&line) {
                Err(e) => AdminSocketResponse {
                    status: "error".into(),
                    error: format!("failed to parse request: {e}"),
                    request: Value::Null,
                    response: Value::Null,
                },
                Ok(req) => {
                    let req_val = serde_json::to_value(&req).unwrap_or(Value::Null);
                    let keep_alive = req.keep_alive;
                    let result = self.dispatch(&req.name, req.arguments).await;
                    let resp = match result {
                        Ok(v) => AdminSocketResponse {
                            status: "success".into(),
                            error: String::new(),
                            request: req_val,
                            response: v,
                        },
                        Err(e) => AdminSocketResponse {
                            status: "error".into(),
                            error: e.to_string(),
                            request: req_val,
                            response: Value::Null,
                        },
                    };
                    if !keep_alive {
                        let json = serde_json::to_string(&resp)? + "\n";
                        w.write_all(json.as_bytes()).await?;
                        break;
                    }
                    resp
                }
            };

            let json = serde_json::to_string(&resp)? + "\n";
            w.write_all(json.as_bytes()).await?;
        }

        Ok(())
    }

    async fn dispatch(&self, name: &str, args: Value) -> Result<Value> {
        let key = name.to_lowercase();
        let handlers = self.handlers.read().await;
        let handler = handlers
            .get(&key)
            .ok_or_else(|| anyhow!("unknown action '{}', try 'list' for help", name))?;
        (handler.func)(args)
    }

    /// Registers a handler for an admin endpoint.
    pub async fn add_handler(
        &self,
        name: &str,
        desc: &str,
        args: Vec<&str>,
        f: impl Fn(Value) -> Result<Value> + Send + Sync + 'static,
    ) -> Result<()> {
        let mut handlers = self.handlers.write().await;
        let key = name.to_lowercase();
        if handlers.contains_key(&key) {
            return Err(anyhow!("handler already exists for '{name}'"));
        }
        handlers.insert(
            key,
            Handler {
                desc: desc.to_string(),
                args: args.into_iter().map(String::from).collect(),
                func: Box::new(f),
            },
        );
        Ok(())
    }

    pub async fn stop(&self) {
        if let Some(tx) = self.done.lock().await.take() {
            let _ = tx.send(());
        }
    }

    // -----------------------------------------------------------------------
    // Built-in handlers
    // -----------------------------------------------------------------------

    async fn register_builtin_handlers(self: &Arc<Self>) {
        let this = Arc::clone(self);

        // list
        {
            let s = Arc::clone(&this);
            this.add_handler("list", "List available commands", vec![], move |_| {
                let handlers = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(s.handlers.read())
                });
                let mut entries: Vec<ListEntry> = handlers
                    .iter()
                    .map(|(name, h)| ListEntry {
                        command: name.clone(),
                        description: h.desc.clone(),
                        fields: h.args.clone(),
                    })
                    .collect();
                entries.sort_by(|a, b| a.command.cmp(&b.command));
                Ok(serde_json::to_value(ListResponse { list: entries })?)
            })
            .await
            .ok();
        }

        // getSelf
        {
            let core = Arc::clone(&self.core);
            this.add_handler("getSelf", "Show details about this node", vec![], move |_| {
                let si = core.get_self();
                let addr = core.address();
                let (snet_ip, snet_prefix) = core.subnet();
                let resp = GetSelfResponse {
                    build_name: crate::version::build_name().to_string(),
                    build_version: crate::version::build_version().to_string(),
                    public_key: hex::encode(si.key),
                    ip_address: addr.to_string(),
                    subnet: format!("{snet_ip}/{snet_prefix}"),
                    routing_entries: si.routing_entries,
                };
                Ok(serde_json::to_value(resp)?)
            })
            .await
            .ok();
        }

        // getPeers
        {
            let core = Arc::clone(&self.core);
            this.add_handler("getPeers", "Show directly connected peers", vec!["sort"], move |_args| {
                let peers = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(core.get_peers())
                });
                let entries: Vec<GetPeerEntry> = peers
                    .into_iter()
                    .map(|p| {
                        let ip = crate::address::addr_for_key(&p.key)
                            .map(|a| std::net::Ipv6Addr::from(a.0).to_string())
                            .unwrap_or_default();
                        GetPeerEntry {
                            uri: p.uri,
                            up: p.up,
                            inbound: p.inbound,
                            ip_address: ip,
                            public_key: hex::encode(p.key),
                            priority: p.priority,
                            rx_bytes: DataUnit(p.rx_bytes),
                            tx_bytes: DataUnit(p.tx_bytes),
                            rx_rate: DataUnit(p.rx_rate),
                            tx_rate: DataUnit(p.tx_rate),
                            uptime: p.uptime.as_secs(),
                            latency: p.latency.as_secs_f64() * 1000.0,
                            last_error: p.last_error.unwrap_or_default(),
                            last_error_time: String::new(),
                        }
                    })
                    .collect();
                Ok(serde_json::to_value(GetPeersResponse { peers: entries })?)
            })
            .await
            .ok();
        }

        // getTree
        {
            let core = Arc::clone(&self.core);
            this.add_handler("getTree", "Show known tree entries", vec![], move |_| {
                let tree = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(core.get_tree())
                });
                let entries: Vec<GetTreeEntry> = tree
                    .into_iter()
                    .map(|t| {
                        let ip = crate::address::addr_for_key(&t.key)
                            .map(|a| std::net::Ipv6Addr::from(a.0).to_string())
                            .unwrap_or_default();
                        GetTreeEntry {
                            public_key: hex::encode(t.key),
                            ip_address: ip,
                            parent: hex::encode(t.parent),
                            sequence: t.sequence,
                        }
                    })
                    .collect();
                Ok(serde_json::to_value(GetTreeResponse { tree: entries })?)
            })
            .await
            .ok();
        }

        // getPaths
        {
            let core = Arc::clone(&self.core);
            this.add_handler("getPaths", "Show established paths", vec![], move |_| {
                let paths = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(core.get_paths())
                });
                let entries: Vec<GetPathsEntry> = paths
                    .into_iter()
                    .map(|p| {
                        let ip = crate::address::addr_for_key(&p.key)
                            .map(|a| std::net::Ipv6Addr::from(a.0).to_string())
                            .unwrap_or_default();
                        GetPathsEntry {
                            public_key: hex::encode(p.key),
                            ip_address: ip,
                            path: p.path,
                            sequence: p.sequence,
                        }
                    })
                    .collect();
                Ok(serde_json::to_value(GetPathsResponse { paths: entries })?)
            })
            .await
            .ok();
        }

        // getSessions
        {
            let core = Arc::clone(&self.core);
            this.add_handler("getSessions", "Show active sessions", vec![], move |_| {
                let sessions = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(core.get_sessions())
                });
                let entries: Vec<GetSessionEntry> = sessions
                    .into_iter()
                    .map(|s| {
                        let ip = crate::address::addr_for_key(&s.key)
                            .map(|a| std::net::Ipv6Addr::from(a.0).to_string())
                            .unwrap_or_default();
                        GetSessionEntry {
                            public_key: hex::encode(s.key),
                            ip_address: ip,
                            rx_bytes: DataUnit(s.rx_bytes),
                            tx_bytes: DataUnit(s.tx_bytes),
                            uptime: s.uptime.as_secs(),
                        }
                    })
                    .collect();
                Ok(serde_json::to_value(GetSessionsResponse { sessions: entries })?)
            })
            .await
            .ok();
        }

        // addPeer
        {
            let core = Arc::clone(&self.core);
            this.add_handler(
                "addPeer",
                "Add a peer to the peer list",
                vec!["uri", "interface"],
                move |args| {
                    let req: AddPeerRequest = serde_json::from_value(args)?;
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(core.add_peer(&req.uri, &req.interface))
                    })?;
                    Ok(serde_json::to_value(AddPeerResponse {})?)
                },
            )
            .await
            .ok();
        }
    }
}

