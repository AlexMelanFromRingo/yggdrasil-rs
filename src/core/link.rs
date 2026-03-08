/// Link management — dial and listen for peer connections.
///
/// Port of yggdrasil-go/src/core/link.go + link_tcp.go / link_tls.go /
/// link_quic.go / link_ws.go / link_wss.go / link_socks.go / link_unix.go

use crate::core::handshake::VersionMetadata;
use crate::core::network::{BoxReader, BoxWriter, PacketConn, PublicKeyBytes};
use crate::config::NodeConfig;
use anyhow::{anyhow, Result};
use hex;
use rustls_pki_types::ServerName;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
    sync::{RwLock, mpsc, oneshot},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};
use url::Url;

pub const DEFAULT_BACKOFF_LIMIT: Duration = Duration::from_secs(4096); // ~1h8m
pub const MINIMUM_BACKOFF_LIMIT: Duration = Duration::from_secs(5);

/// How a link was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Statically configured peer.
    Persistent,
    /// Discovered via multicast.
    Ephemeral,
    /// Accepted incoming connection.
    Incoming,
}

/// Options parsed from the peer URI query string.
#[derive(Debug, Clone, Default)]
pub struct LinkOptions {
    pub pinned_keys: Vec<PublicKeyBytes>,
    pub priority: u8,
    pub tls_sni: String,
    pub password: Vec<u8>,
    pub max_backoff: Duration,
}

/// A handle to a running listener.
pub struct Listener {
    pub local_addr: SocketAddr,
    pub cancel: oneshot::Sender<()>,
}

impl Listener {
    pub fn stop(self) {
        let _ = self.cancel.send(());
    }
}

/// Internal state for a persistent outbound link.
#[derive(Debug)]
struct LinkState {
    link_type: LinkType,
    // URI without query string
    uri: String,
    last_error: Option<String>,
    connected: bool,
    // Signal to abort backoff and reconnect immediately
    kick_tx: mpsc::Sender<()>,
    // Signal to stop the connection loop entirely
    cancel_tx: oneshot::Sender<()>,
}

/// Manages all peer links (outbound + inbound listeners).
pub struct Links {
    packet_conn: Arc<PacketConn>,
    node_config: Arc<NodeConfig>,
    links: RwLock<HashMap<String, LinkState>>,
}

impl Links {
    pub fn new(packet_conn: Arc<PacketConn>, node_config: Arc<NodeConfig>) -> Arc<Self> {
        Arc::new(Links {
            packet_conn,
            node_config,
            links: RwLock::new(HashMap::new()),
        })
    }

    // -----------------------------------------------------------------------
    // Add / remove outbound peers
    // -----------------------------------------------------------------------

    /// Adds a persistent or ephemeral outbound peer.
    pub async fn add(self: &Arc<Self>, uri: &str, sintf: &str, link_type: LinkType) -> Result<()> {
        let u = Url::parse(uri)?;
        let options = parse_link_options(&u)?;
        let link_uri = strip_query(uri);

        let mut links = self.links.write().await;
        if links.contains_key(&link_uri) {
            return Err(anyhow!("peer is already configured"));
        }

        let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        links.insert(
            link_uri.clone(),
            LinkState {
                link_type,
                uri: link_uri.clone(),
                last_error: None,
                connected: false,
                kick_tx,
                cancel_tx,
            },
        );
        drop(links);

        let this = Arc::clone(self);
        let sintf = sintf.to_string();
        let u2 = u.clone();

        tokio::spawn(async move {
            let mut backoff: i32 = 0;
            let mut cancel = cancel_rx;

            loop {
                // Check for cancellation
                match cancel.try_recv() {
                    Ok(_) | Err(oneshot::error::TryRecvError::Closed) => break,
                    Err(_) => {}
                }

                match timeout(
                    Duration::from_secs(30),
                    this.dial_any(&u2, &sintf, &options),
                )
                .await
                {
                    Ok(Ok((reader, writer))) => {
                        backoff = 0;
                        {
                            let mut ls = this.links.write().await;
                            if let Some(s) = ls.get_mut(&link_uri) {
                                s.connected = true;
                                s.last_error = None;
                            }
                        }
                        // Run handler
                        if let Err(e) = this.handle_stream(link_type, &options, reader, writer, false).await {
                            debug!("link handler error: {e}");
                        }
                        {
                            let mut ls = this.links.write().await;
                            if let Some(s) = ls.get_mut(&link_uri) {
                                s.connected = false;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        let err_str = format!("{e}");
                        debug!("dial {}: {err_str}", link_uri);
                        {
                            let mut ls = this.links.write().await;
                            if let Some(s) = ls.get_mut(&link_uri) {
                                s.last_error = Some(err_str);
                                s.connected = false;
                            }
                        }
                    }
                    Err(_elapsed) => {
                        let err_str = "connection timeout".to_string();
                        debug!("dial {}: timeout", link_uri);
                        {
                            let mut ls = this.links.write().await;
                            if let Some(s) = ls.get_mut(&link_uri) {
                                s.last_error = Some(err_str);
                                s.connected = false;
                            }
                        }
                    }
                }

                if link_type != LinkType::Persistent {
                    break;
                }

                // Exponential backoff
                if backoff < 32 {
                    backoff += 1;
                }
                let wait = Duration::from_secs(1u64 << backoff.min(12))
                    .min(options.max_backoff)
                    .max(MINIMUM_BACKOFF_LIMIT);

                tokio::select! {
                    _ = sleep(wait) => {}
                    _ = kick_rx.recv() => {}
                    _ = &mut cancel => break,
                }
            }

            // Clean up
            let mut ls = this.links.write().await;
            ls.remove(&link_uri);
        });

        Ok(())
    }

    /// Removes a persistent peer.
    pub async fn remove(&self, uri: &str) -> Result<()> {
        let link_uri = strip_query(uri);
        let mut links = self.links.write().await;
        if links.remove(&link_uri).is_none() {
            return Err(anyhow!("peer is not configured"));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Listen
    // -----------------------------------------------------------------------

    /// Starts a listener for the given URI scheme.
    pub async fn listen(self: &Arc<Self>, uri: &str, sintf: &str, local: bool) -> Result<Listener> {
        let u = Url::parse(uri)?;
        let options = parse_link_options(&u)?;

        match u.scheme().to_lowercase().as_str() {
            "tcp" => self.listen_tcp(&u, sintf, &options, local).await,
            "tls" => self.listen_tls(&u, sintf, &options, local).await,
            "unix" => self.listen_unix(&u, &options, local).await,
            s => Err(anyhow!("unknown link scheme: {s}")),
        }
    }

    async fn listen_tcp(
        self: &Arc<Self>,
        u: &Url,
        sintf: &str,
        options: &LinkOptions,
        local: bool,
    ) -> Result<Listener> {
        let addr = resolve_host_port(u)?;
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        info!("TCP listener started on {local_addr}");

        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let this = Arc::clone(self);
        let opts = options.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, remote)) => {
                                debug!("TCP inbound from {remote}");
                                let this2 = Arc::clone(&this);
                                let opts2 = opts.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = this2.handler(LinkType::Incoming, &opts2, stream, local).await {
                                        debug!("inbound handler error: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("TCP accept error: {e}");
                                break;
                            }
                        }
                    }
                    _ = &mut cancel_rx => break,
                }
            }
            info!("TCP listener stopped on {local_addr}");
        });

        Ok(Listener { local_addr, cancel: cancel_tx })
    }

    async fn listen_tls(
        self: &Arc<Self>,
        u: &Url,
        sintf: &str,
        options: &LinkOptions,
        local: bool,
    ) -> Result<Listener> {
        let addr = resolve_host_port(u)?;
        let tcp_listener = TcpListener::bind(addr).await?;
        let local_addr = tcp_listener.local_addr()?;
        info!("TLS listener started on {local_addr}");

        let tls_config = self.node_config.build_rustls_config()
            .map_err(|e| anyhow!("TLS config error: {e}"))?;
        let acceptor = TlsAcceptor::from(tls_config);

        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let this = Arc::clone(self);
        let opts = options.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = tcp_listener.accept() => {
                        match accept {
                            Ok((tcp_stream, remote)) => {
                                debug!("TLS inbound from {remote}");
                                let acceptor2 = acceptor.clone();
                                let this2 = Arc::clone(&this);
                                let opts2 = opts.clone();
                                tokio::spawn(async move {
                                    match acceptor2.accept(tcp_stream).await {
                                        Ok(tls_stream) => {
                                            let (r, w) = tokio::io::split(tls_stream);
                                            let stream = RwStream { r, w };
                                            if let Err(e) = this2.handler_rw(LinkType::Incoming, &opts2, stream, local).await {
                                                debug!("TLS inbound handler error: {e}");
                                            }
                                        }
                                        Err(e) => debug!("TLS accept error: {e}"),
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("TLS TCP accept error: {e}");
                                break;
                            }
                        }
                    }
                    _ = &mut cancel_rx => break,
                }
            }
            info!("TLS listener stopped on {local_addr}");
        });

        Ok(Listener { local_addr, cancel: cancel_tx })
    }

    async fn listen_unix(
        self: &Arc<Self>,
        u: &Url,
        options: &LinkOptions,
        local: bool,
    ) -> Result<Listener> {
        let path = u.path();
        // Remove stale socket file if it exists
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        // Use a dummy local addr for the Listener struct
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        info!("UNIX listener started on {path}");

        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let this = Arc::clone(self);
        let opts = options.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _)) => {
                                let this2 = Arc::clone(&this);
                                let opts2 = opts.clone();
                                tokio::spawn(async move {
                                    let (r, w) = tokio::io::split(stream);
                                    let rws = RwStream { r, w };
                                    if let Err(e) = this2.handler_rw(LinkType::Incoming, &opts2, rws, local).await {
                                        debug!("UNIX inbound handler error: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("UNIX accept error: {e}");
                                break;
                            }
                        }
                    }
                    _ = &mut cancel_rx => break,
                }
            }
        });

        Ok(Listener { local_addr, cancel: cancel_tx })
    }

    // -----------------------------------------------------------------------
    // Dialing — returns generic boxed reader/writer (handles TLS upgrade)
    // -----------------------------------------------------------------------

    async fn dial_any(
        &self,
        u: &Url,
        _sintf: &str,
        options: &LinkOptions,
    ) -> Result<(BoxReader, BoxWriter)> {
        match u.scheme().to_lowercase().as_str() {
            "tcp" => {
                let stream = TcpStream::connect(resolve_host_port(u)?).await?;
                let (r, w) = tokio::io::split(stream);
                Ok((Box::new(r), Box::new(w)))
            }
            "tls" => {
                let tcp = TcpStream::connect(resolve_host_port(u)?).await?;
                let tls = self.upgrade_tls_client(tcp, options).await?;
                let (r, w) = tokio::io::split(tls);
                Ok((Box::new(r), Box::new(w)))
            }
            "socks" => {
                use tokio_socks::tcp::Socks5Stream;
                let proxy_host = u.host_str().unwrap_or("127.0.0.1");
                let proxy_port = u.port().unwrap_or(1080);
                let proxy_addr: SocketAddr = format!("{proxy_host}:{proxy_port}")
                    .parse()
                    .map_err(|e| anyhow!("invalid proxy addr: {e}"))?;
                let target = u.path().trim_start_matches('/');
                let stream = Socks5Stream::connect(proxy_addr, target).await
                    .map_err(|e| anyhow!("SOCKS5 error: {e}"))?;
                let (r, w) = tokio::io::split(stream.into_inner());
                Ok((Box::new(r), Box::new(w)))
            }
            "sockstls" => {
                use tokio_socks::tcp::Socks5Stream;
                let proxy_host = u.host_str().unwrap_or("127.0.0.1");
                let proxy_port = u.port().unwrap_or(1080);
                let proxy_addr: SocketAddr = format!("{proxy_host}:{proxy_port}")
                    .parse()
                    .map_err(|e| anyhow!("invalid proxy addr: {e}"))?;
                let target = u.path().trim_start_matches('/');
                let tcp = Socks5Stream::connect(proxy_addr, target).await
                    .map_err(|e| anyhow!("SOCKS5 error: {e}"))?
                    .into_inner();
                let tls = self.upgrade_tls_client(tcp, options).await?;
                let (r, w) = tokio::io::split(tls);
                Ok((Box::new(r), Box::new(w)))
            }
            "unix" => Err(anyhow!("unix dial not supported for outbound")),
            s => Err(anyhow!("unknown scheme: {s}")),
        }
    }

    async fn upgrade_tls_client(
        &self,
        tcp: TcpStream,
        options: &LinkOptions,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tls_config = self.node_config.build_rustls_client_config()
            .map_err(|e| anyhow!("TLS client config error: {e}"))?;
        let connector = TlsConnector::from(tls_config);
        let sni_str = if options.tls_sni.is_empty() { "localhost" } else { &options.tls_sni };
        let sni = ServerName::try_from(sni_str.to_owned())
            .map_err(|e| anyhow!("invalid SNI: {e}"))?;
        let stream = connector.connect(sni, tcp).await
            .map_err(|e| anyhow!("TLS handshake error: {e}"))?;
        Ok(stream)
    }

    // -----------------------------------------------------------------------
    // Connection handlers
    // -----------------------------------------------------------------------

    /// Unified handler: performs yggdrasil handshake then hands off to network layer.
    async fn handle_stream(
        &self,
        link_type: LinkType,
        options: &LinkOptions,
        mut reader: BoxReader,
        mut writer: BoxWriter,
        local: bool,
    ) -> Result<()> {
        let meta = self.send_recv_handshake(options, &mut reader, &mut writer).await?;
        self.post_handshake(link_type, options, meta, reader, writer, local).await
    }

    /// Handler for inbound TCP streams.
    async fn handler(
        &self,
        link_type: LinkType,
        options: &LinkOptions,
        stream: TcpStream,
        local: bool,
    ) -> Result<()> {
        let (r, w) = tokio::io::split(stream);
        self.handle_stream(link_type, options, Box::new(r), Box::new(w), local).await
    }

    /// Handler for inbound TLS / UNIX streams.
    async fn handler_rw<R, W>(
        &self,
        link_type: LinkType,
        options: &LinkOptions,
        stream: RwStream<R, W>,
        local: bool,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let RwStream { r, w } = stream;
        self.handle_stream(link_type, options, Box::new(r), Box::new(w), local).await
    }

    async fn send_recv_handshake<R, W>(
        &self,
        options: &LinkOptions,
        r: &mut R,
        w: &mut W,
    ) -> Result<VersionMetadata>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let signing_key = self.node_config.signing_key()
            .map_err(|e| anyhow!("no signing key: {e}"))?;
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let mut meta_out = VersionMetadata::base();
        meta_out.public_key = public_key;
        meta_out.priority = options.priority;

        let encoded = meta_out.encode(&signing_key, &options.password)?;

        // Send our metadata, receive theirs — with a 6-second deadline
        let handshake_result = timeout(Duration::from_secs(6), async {
            w.write_all(&encoded).await?;
            VersionMetadata::decode(r, &options.password).await
        }).await
        .map_err(|_| anyhow!("handshake timeout"))?;

        let meta_in = handshake_result?;

        if !meta_in.check() {
            return Err(anyhow!(
                "remote node incompatible version ({}.{} vs {}.{})",
                VersionMetadata::base().major_ver,
                VersionMetadata::base().minor_ver,
                meta_in.major_ver,
                meta_in.minor_ver,
            ));
        }

        // Reject self-connections
        if meta_in.public_key == public_key {
            return Err(anyhow!("node cannot connect to self"));
        }

        // Check pinned keys
        if !options.pinned_keys.is_empty() {
            if !options.pinned_keys.contains(&meta_in.public_key) {
                return Err(anyhow!("remote public key not in pinned key list"));
            }
        }

        Ok(meta_in)
    }

    async fn post_handshake(
        &self,
        link_type: LinkType,
        options: &LinkOptions,
        meta: VersionMetadata,
        reader: BoxReader,
        writer: BoxWriter,
        local: bool,
    ) -> Result<()> {
        // Check AllowedPublicKeys
        if !local {
            let allowed = &self.node_config.allowed_public_keys;
            if !allowed.is_empty() {
                let hex_key = hex::encode(&meta.public_key);
                if !allowed.iter().any(|k| k == &hex_key) {
                    return Err(anyhow!(
                        "public key {} not in AllowedPublicKeys",
                        hex_key
                    ));
                }
            }
        }

        let priority = options.priority.max(meta.priority);
        let dir = if link_type == LinkType::Incoming { "inbound" } else { "outbound" };
        let remote_ip = crate::address::addr_for_key(&meta.public_key)
            .map(|a| std::net::Ipv6Addr::from(a.0).to_string())
            .unwrap_or_default();
        info!("Connected {dir}: {remote_ip}");

        self.packet_conn
            .handle_conn(meta.public_key, reader, writer, priority)
            .await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A combined Read+Write wrapper used for non-TcpStream connections.
struct RwStream<R, W> {
    r: R,
    w: W,
}

fn resolve_host_port(u: &Url) -> Result<SocketAddr> {
    let host = u.host_str().ok_or_else(|| anyhow!("missing host in URI"))?;
    let port = u.port().ok_or_else(|| anyhow!("missing port in URI"))?;
    let addr_str = format!("{host}:{port}");
    addr_str
        .to_socket_addrs()
        .map_err(|e| anyhow!("resolve {addr_str}: {e}"))?
        .next()
        .ok_or_else(|| anyhow!("no address resolved for {addr_str}"))
}

fn strip_query(uri: &str) -> String {
    if let Ok(mut u) = Url::parse(uri) {
        u.set_query(None);
        u.to_string()
    } else {
        uri.to_string()
    }
}

fn parse_link_options(u: &Url) -> Result<LinkOptions> {
    let mut opts = LinkOptions {
        max_backoff: DEFAULT_BACKOFF_LIMIT,
        ..Default::default()
    };

    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "key" => {
                let bytes = hex::decode(v.as_ref())
                    .map_err(|_| anyhow!("pinned public key is invalid"))?;
                if bytes.len() != 32 {
                    return Err(anyhow!("pinned public key is invalid"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                opts.pinned_keys.push(arr);
            }
            "priority" => {
                opts.priority = v.parse::<u8>()
                    .map_err(|_| anyhow!("priority value is invalid"))?;
            }
            "password" => {
                if v.len() > 64 {
                    return Err(anyhow!("invalid password supplied"));
                }
                opts.password = v.as_bytes().to_vec();
            }
            "sni" => {
                // Only use as SNI if it's not an IP literal
                if v.parse::<IpAddr>().is_err() {
                    opts.tls_sni = v.into_owned();
                }
            }
            "maxbackoff" => {
                let secs: u64 = v.parse().map_err(|_| anyhow!("max backoff duration invalid"))?;
                let d = Duration::from_secs(secs);
                if d < MINIMUM_BACKOFF_LIMIT {
                    return Err(anyhow!("max backoff duration invalid"));
                }
                opts.max_backoff = d;
            }
            _ => {}
        }
    }

    // If no explicit SNI, use the URI host if it's not an IP
    if opts.tls_sni.is_empty() {
        if let Some(host) = u.host_str() {
            if host.parse::<IpAddr>().is_err() {
                opts.tls_sni = host.to_string();
            }
        }
    }

    Ok(opts)
}
