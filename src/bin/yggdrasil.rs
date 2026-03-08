//! Yggdrasil node daemon.
//!
//! Port of yggdrasil-go/cmd/yggdrasil/main.go

use anyhow::{anyhow, Result};
use clap::Parser;
use std::{
    io::Read,
    net::Ipv6Addr,
    path::PathBuf,
    sync::Arc,
};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};
use yggdrasil_rs::{
    address,
    admin::AdminSocket,
    config::NodeConfig,
    core::Core,
    ipv6rwc::ReadWriteCloser,
    multicast::{Multicast, MulticastInterface},
    tun::{InterfaceMTU, InterfaceName, TunAdapter},
    version,
};

#[derive(Parser, Debug)]
#[command(
    name = "yggdrasil",
    about = "Yggdrasil network node daemon",
    disable_version_flag = true,
)]
struct Args {
    /// Print a new config to stdout
    #[arg(long)]
    genconf: bool,

    /// Read HJSON/JSON config from stdin
    #[arg(long)]
    useconf: bool,

    /// Read HJSON/JSON config from the specified file
    #[arg(long, value_name = "FILE")]
    useconffile: Option<PathBuf>,

    /// Output normalised config (use with --useconf or --useconffile)
    #[arg(long)]
    normaliseconf: bool,

    /// Output private key in PEM format (use with --useconf or --useconffile)
    #[arg(long)]
    exportkey: bool,

    /// Output config as JSON instead of HJSON
    #[arg(long)]
    json: bool,

    /// Automatic mode: random keys, peer with IPv6 neighbours
    #[arg(long)]
    autoconf: bool,

    /// Print the build version
    #[arg(long = "buildversion")]
    version: bool,

    /// Log destination: "stdout", "syslog", or a file path
    #[arg(long, default_value = "stdout")]
    logto: String,

    /// Output the IPv6 address (use with --useconf or --useconffile)
    #[arg(long)]
    address: bool,

    /// Output the IPv6 subnet (use with --useconf or --useconffile)
    #[arg(long)]
    subnet: bool,

    /// Output the public key hex (use with --useconf or --useconffile)
    #[arg(long)]
    publickey: bool,

    /// Log level: error, warn, info, debug, trace
    #[arg(long, default_value = "info")]
    loglevel: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (ring) before any TLS operations.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    // --version
    if args.version {
        println!("Build name:    {}", version::build_name());
        println!("Build version: {}", version::build_version());
        return Ok(());
    }

    // Set up logging — include both the library crate (yggdrasil_rs) and
    // this binary crate (yggdrasil) so all info!() calls are visible.
    let filter = EnvFilter::try_new(format!(
        "yggdrasil_rs={0},yggdrasil={0}",
        args.loglevel
    ))
    .unwrap_or_else(|_| EnvFilter::new("info"));
    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Generate / load config
    let mut cfg = if args.genconf || args.autoconf {
        NodeConfig::generate()?
    } else if args.useconf {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        NodeConfig::from_hjson(buf.as_bytes())?
    } else if let Some(ref path) = args.useconffile {
        let data = std::fs::read(path)?;
        NodeConfig::from_hjson(&data)?
    } else {
        eprintln!("Usage: yggdrasil [OPTIONS]\nRun with --help for help.");
        return Ok(());
    };

    // --genconf
    if args.genconf {
        cfg.admin_listen = String::new();
        let out = cfg.to_json()?;
        println!("{out}");
        return Ok(());
    }

    let signing_key = cfg.signing_key()?;
    let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

    // --address
    if args.address {
        let addr = address::addr_for_key(&public_key)
            .ok_or_else(|| anyhow!("address derivation failed"))?;
        println!("{}", Ipv6Addr::from(addr.0));
        return Ok(());
    }

    // --subnet
    if args.subnet {
        let snet = address::subnet_for_key(&public_key)
            .ok_or_else(|| anyhow!("subnet derivation failed"))?;
        let mut ip_bytes = [0u8; 16];
        ip_bytes[..8].copy_from_slice(&snet.0);
        println!("{}/64", Ipv6Addr::from(ip_bytes));
        return Ok(());
    }

    // --publickey
    if args.publickey {
        println!("{}", hex::encode(public_key));
        return Ok(());
    }

    // --normaliseconf
    if args.normaliseconf {
        cfg.admin_listen = String::new();
        if !cfg.private_key_path.is_empty() {
            cfg.private_key = None;
        }
        println!("{}", cfg.to_json()?);
        return Ok(());
    }

    // --exportkey
    if args.exportkey {
        let pem = cfg.marshal_pem_private_key()?;
        println!("{}", String::from_utf8(pem)?);
        return Ok(());
    }

    // ---- Start the node -----------------------------------------------
    let cfg = Arc::new(cfg);

    info!("Your public key is {}", hex::encode(public_key));

    let core = Core::new(Arc::clone(&cfg)).await?;

    info!("Your IPv6 address is {}", core.address());
    let (snet, prefix) = core.subnet();
    info!("Your IPv6 subnet is {snet}/{prefix}");

    // Apply configuration
    core.apply_config(&cfg).await?;

    // Start listeners
    for addr in &cfg.listen {
        match core.listen(addr, "").await {
            Ok(_) => info!("Listener started: {addr}"),
            Err(e) => error!("Failed to start listener {addr}: {e}"),
        }
    }

    // Connect to peers
    for peer in &cfg.peers {
        if let Err(e) = core.add_peer(peer, "").await {
            error!("Failed to add peer {peer}: {e}");
        }
    }
    for (intf, peers) in &cfg.interface_peers {
        for peer in peers {
            if let Err(e) = core.add_peer(peer, intf).await {
                error!("Failed to add peer {peer} on {intf}: {e}");
            }
        }
    }

    // Admin socket
    let admin = AdminSocket::new(Arc::clone(&core), &cfg.admin_listen).await?;

    // Multicast
    let mc_ifaces: Vec<MulticastInterface> = cfg.multicast_interfaces
        .iter()
        .filter_map(|mc| {
            regex::Regex::new(&mc.regex).ok().map(|re| MulticastInterface {
                regex: re,
                beacon: mc.beacon,
                listen: mc.listen,
                port: mc.port,
                priority: mc.priority as u8,
                password: mc.password.clone(),
            })
        })
        .collect();
    let multicast = Multicast::new(Arc::clone(&core), mc_ifaces).await?;

    // TUN adapter
    let rwc = Arc::new(ReadWriteCloser::new(Arc::clone(&core)));
    let tun = TunAdapter::new(
        Arc::clone(&rwc),
        InterfaceName(cfg.if_name.clone()),
        InterfaceMTU(cfg.if_mtu),
    )
    .await
    .map_err(|e| {
        error!("TUN setup failed: {e}");
        e
    })
    .ok();

    info!("Yggdrasil node is running");

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Shutting down...");

    if let Some(ref t) = tun && let Err(e) = t.stop().await {
        error!("TUN stop error: {e}");
    }
    if let Some(ref a) = admin {
        a.stop().await;
    }
    if let Err(e) = multicast.stop().await {
        error!("Multicast stop error: {e}");
    }
    core.stop().await;

    Ok(())
}
