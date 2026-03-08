//! Yggdrasil admin CLI tool.
//!
//! Port of yggdrasil-go/cmd/yggdrasilctl/main.go

use anyhow::{anyhow, Result};
use clap::Parser;
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    net::TcpStream,
    os::unix::net::UnixStream,
    time::Duration,
};
use yggdrasil_rs::{
    admin::{AdminSocketRequest, AdminSocketResponse},
    config::get_defaults,
    version,
};

#[derive(Parser, Debug)]
#[command(name = "yggdrasilctl", about = "Yggdrasil admin control tool")]
struct Args {
    /// Admin socket endpoint (e.g. unix:///var/run/yggdrasil.sock or tcp://localhost:9001)
    #[arg(long, value_name = "ENDPOINT")]
    endpoint: Option<String>,

    /// Print the version
    #[arg(long)]
    ver: bool,

    /// Output raw JSON
    #[arg(long)]
    json: bool,

    /// Show table borders
    #[arg(long)]
    borders: bool,

    /// Command and optional key=value arguments
    args: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.ver {
        println!("Build name:    {}", version::build_name());
        println!("Build version: {}", version::build_version());
        return Ok(());
    }

    if args.args.is_empty() {
        eprintln!("Usage: yggdrasilctl [--endpoint=...] <command> [key=value ...]");
        eprintln!("Run 'yggdrasilctl list' to see available commands.");
        return Ok(());
    }

    // Determine endpoint
    let endpoint = args.endpoint.unwrap_or_else(|| {
        get_defaults().default_admin_listen.to_string()
    });

    // Parse command + arguments
    let command = args.args[0].clone();
    let mut kv_args: HashMap<String, String> = HashMap::new();
    for arg in &args.args[1..] {
        let parts: Vec<&str> = arg.splitn(2, '=').collect();
        if parts.len() == 2 {
            kv_args.insert(parts[0].to_string(), parts[1].to_string());
        } else {
            eprintln!("Ignoring invalid argument: {arg}");
        }
    }

    // Connect
    let (response, request_name) = dispatch(&endpoint, &command, kv_args)?;

    if response.status == "error" {
        eprintln!("Admin socket returned an error: {}", response.error);
        std::process::exit(1);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    // Pretty-print the response
    print_response(&request_name, &response.response, args.borders)?;
    Ok(())
}

fn dispatch(
    endpoint: &str,
    command: &str,
    kv_args: HashMap<String, String>,
) -> Result<(AdminSocketResponse, String)> {
    let req = AdminSocketRequest {
        name: command.to_string(),
        arguments: serde_json::to_value(kv_args)?,
        keep_alive: false,
    };

    use url::Url;
    if let Ok(u) = Url::parse(endpoint) {
        match u.scheme() {
            "unix" => {
                let path = u.path();
                eprintln!("Connecting to UNIX socket {path}");
                let stream = UnixStream::connect(path)?;
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                return rpc_via_stream(stream, req);
            }
            "tcp" => {
                let host = u.host_str().unwrap_or("localhost");
                let port = u.port().unwrap_or(9001);
                eprintln!("Connecting to TCP socket {host}:{port}");
                let stream = TcpStream::connect(format!("{host}:{port}"))?;
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                return rpc_via_stream(stream, req);
            }
            _ => {}
        }
    }

    // Fallback: TCP
    eprintln!("Connecting to {endpoint}");
    let stream = TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    rpc_via_stream(stream, req)
}

fn rpc_via_stream<S>(mut stream: S, req: AdminSocketRequest) -> Result<(AdminSocketResponse, String)>
where
    S: std::io::Read + std::io::Write,
{
    let name = req.name.clone();
    let json_req = serde_json::to_string(&req)? + "\n";
    stream.write_all(json_req.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let resp: AdminSocketResponse = serde_json::from_str(&line)
        .map_err(|e| anyhow!("failed to parse response: {e}\nraw: {line}"))?;
    Ok((resp, name))
}

fn print_response(command: &str, resp: &Value, _borders: bool) -> Result<()> {
    match command.to_lowercase().as_str() {
        "getself" => {
            if let Some(obj) = resp.as_object() {
                for (k, v) in obj {
                    let val_owned = v.to_string();
                    let val = v.as_str().unwrap_or(&val_owned);
                    println!("{k:30} {val}");
                }
            }
        }
        "getpeers" => {
            if let Some(peers) = resp.get("peers").and_then(|p| p.as_array()) {
                if peers.is_empty() {
                    println!("No peers connected.");
                    return Ok(());
                }
                println!("{:<50} {:<5} {:<4} {:<10} {:<10} Error", "URI", "State", "Dir", "RX", "TX");
                for peer in peers {
                    let uri = peer.get("uri").and_then(|v| v.as_str()).unwrap_or("-");
                    let up = peer.get("up").and_then(|v| v.as_bool()).unwrap_or(false);
                    let inbound = peer.get("inbound").and_then(|v| v.as_bool()).unwrap_or(false);
                    let rx = peer.get("rx_bytes").and_then(|v| v.as_object())
                        .map(|_| "?".to_string()).unwrap_or("0B".to_string());
                    let tx = peer.get("tx_bytes").and_then(|v| v.as_object())
                        .map(|_| "?".to_string()).unwrap_or("0B".to_string());
                    let err = peer.get("last_error").and_then(|v| v.as_str()).unwrap_or("-");
                    let state = if up { "Up" } else { "Down" };
                    let dir = if inbound { "In" } else { "Out" };
                    println!("{uri:<50} {state:<5} {dir:<4} {rx:<10} {tx:<10} {err}");
                }
            }
        }
        "gettree" => {
            if let Some(tree) = resp.get("tree").and_then(|t| t.as_array()) {
                println!("{:<66} {:<42} Sequence", "Public Key", "IP Address");
                for entry in tree {
                    let pk = entry.get("public_key").and_then(|v| v.as_str()).unwrap_or("-");
                    let ip = entry.get("ip_address").and_then(|v| v.as_str()).unwrap_or("-");
                    let seq = entry.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!("{pk:<66} {ip:<42} {seq}");
                }
            }
        }
        "getsessions" => {
            if let Some(sessions) = resp.get("sessions").and_then(|s| s.as_array()) {
                println!("{:<66} {:<42} {:<10} {:<10}", "Public Key", "IP Address", "RX", "TX");
                for s in sessions {
                    let pk = s.get("public_key").and_then(|v| v.as_str()).unwrap_or("-");
                    let ip = s.get("ip_address").and_then(|v| v.as_str()).unwrap_or("-");
                    println!("{pk:<66} {ip:<42}");
                }
            }
        }
        "list" => {
            if let Some(list) = resp.get("list").and_then(|l| l.as_array()) {
                println!("{:<30} {:<40} Fields", "Command", "Description");
                println!("{}", "-".repeat(100));
                for entry in list {
                    let cmd = entry.get("command").and_then(|v| v.as_str()).unwrap_or("-");
                    let desc = entry.get("description").and_then(|v| v.as_str()).unwrap_or("-");
                    let fields = entry.get("fields").and_then(|v| v.as_array())
                        .map(|a| a.iter().map(|f| f.as_str().unwrap_or("")).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default();
                    println!("{cmd:<30} {desc:<40} {fields}");
                }
            }
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(resp)?);
        }
    }
    Ok(())
}
