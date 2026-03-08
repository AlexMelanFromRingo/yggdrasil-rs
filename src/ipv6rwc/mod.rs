//! IPv6 ReadWriteCloser — maps Yggdrasil public keys to IPv6 addresses.
//!
//! Port of yggdrasil-go/src/ipv6rwc/ipv6rwc.go

pub mod icmpv6;

use crate::{
    address::{self, Address, Subnet},
    core::Core,
};
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::{
    net::Ipv6Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::debug;

#[allow(dead_code)]
const KEY_STORE_TIMEOUT: Duration = Duration::from_secs(120);

type KeyArray = [u8; 32];

struct KeyInfo {
    key: KeyArray,
    address: Address,
    subnet: Subnet,
    last_seen: Mutex<Instant>,
}

#[allow(dead_code)]
struct BufferedPacket {
    data: Vec<u8>,
    queued_at: Instant,
}

struct KeyStore {
    core: Arc<Core>,
    our_address: Address,
    our_subnet: Subnet,
    mtu: AtomicU64,
    key_to_info: DashMap<KeyArray, Arc<KeyInfo>>,
    addr_to_info: DashMap<Address, Arc<KeyInfo>>,
    subnet_to_info: DashMap<Subnet, Arc<KeyInfo>>,
    addr_buffer: DashMap<Address, BufferedPacket>,
    subnet_buffer: DashMap<Subnet, BufferedPacket>,
}

impl KeyStore {
    fn new(core: Arc<Core>) -> Arc<Self> {
        let pk = core.public_key();
        let our_address = address::addr_for_key(&pk).expect("valid key");
        let our_subnet = address::subnet_for_key(&pk).expect("valid key");

        Arc::new(KeyStore {
            core,
            our_address,
            our_subnet,
            mtu: AtomicU64::new(1280),
            key_to_info: DashMap::new(),
            addr_to_info: DashMap::new(),
            subnet_to_info: DashMap::new(),
            addr_buffer: DashMap::new(),
            subnet_buffer: DashMap::new(),
        })
    }

    fn max_mtu(&self) -> u64 {
        self.core.mtu()
    }

    fn set_mtu(&self, mut mtu: u64) {
        if mtu > self.max_mtu() {
            mtu = self.max_mtu();
        }
        if mtu < 1280 {
            mtu = 1280;
        }
        self.mtu.store(mtu, Ordering::Relaxed);
    }

    fn mtu(&self) -> u64 {
        self.mtu.load(Ordering::Relaxed)
    }

    async fn update(&self, key: &KeyArray) -> Arc<KeyInfo> {
        if let Some(info) = self.key_to_info.get(key) {
            *info.last_seen.lock().await = Instant::now();
            return Arc::clone(&info);
        }

        let _key_pub = ed25519_dalek::VerifyingKey::from_bytes(key).ok();
        let addr = address::addr_for_key(key).unwrap_or(Address([0u8; 16]));
        let subnet = address::subnet_for_key(key).unwrap_or(Subnet([0u8; 8]));

        let info = Arc::new(KeyInfo {
            key: *key,
            address: addr,
            subnet,
            last_seen: Mutex::new(Instant::now()),
        });

        self.key_to_info.insert(*key, Arc::clone(&info));
        self.addr_to_info.insert(addr, Arc::clone(&info));
        self.subnet_to_info.insert(subnet, Arc::clone(&info));

        // Flush any buffered packets
        if let Some((_, buf)) = self.addr_buffer.remove(&addr) {
            let core = Arc::clone(&self.core);
            let k = *key;
            let data = buf.data;
            tokio::spawn(async move {
                let _ = core.write_to(&data, &k).await;
            });
        }
        if let Some((_, buf)) = self.subnet_buffer.remove(&subnet) {
            let core = Arc::clone(&self.core);
            let k = *key;
            let data = buf.data;
            tokio::spawn(async move {
                let _ = core.write_to(&data, &k).await;
            });
        }

        info
    }

    /// Sends an IPv6 packet to a destination address, looking up the key.
    async fn send_to_address(&self, addr: &Address, data: &[u8]) {
        if let Some(info) = self.addr_to_info.get(addr) {
            *info.last_seen.lock().await = Instant::now();
            debug!("send_to_address: known key, sending {} bytes", data.len());
            let _ = self.core.write_to(data, &info.key).await;
        } else {
            debug!("send_to_address: no key, buffering + lookup for addr {:?}", std::net::Ipv6Addr::from(addr.0));
            self.addr_buffer.insert(
                *addr,
                BufferedPacket {
                    data: data.to_vec(),
                    queued_at: Instant::now(),
                },
            );
            self.send_key_lookup(&addr.get_key()).await;
        }
    }

    async fn send_to_subnet(&self, subnet: &Subnet, data: &[u8]) {
        if let Some(info) = self.subnet_to_info.get(subnet) {
            *info.last_seen.lock().await = Instant::now();
            let _ = self.core.write_to(data, &info.key).await;
        } else {
            self.subnet_buffer.insert(
                *subnet,
                BufferedPacket {
                    data: data.to_vec(),
                    queued_at: Instant::now(),
                },
            );
            self.send_key_lookup(&subnet.get_key()).await;
        }
    }

    async fn send_key_lookup(&self, partial_key: &[u8; 32]) {
        self.core.send_lookup(partial_key).await;
    }

    /// Reads the next IPv6 packet from the overlay network.
    async fn read_packet(&self, out: &mut Vec<u8>) -> Result<usize> {
        let mtu = self.mtu() as usize;
        let mut buf = vec![0u8; 65535];

        loop {
            let (n, from) = self.core.read_from(&mut buf).await?;
            if n == 0 {
                continue;
            }
            let packet = &buf[..n];

            // Must be IPv6 (first nibble = 6)
            if packet[0] & 0xf0 != 0x60 {
                continue;
            }
            if packet.len() < 40 {
                continue;
            }

            // Check if oversized → send ICMPv6 PTB back
            if packet.len() > mtu {
                let src_bytes: [u8; 16] = packet[8..24].try_into().unwrap();
                let dst_bytes: [u8; 16] = packet[24..40].try_into().unwrap();
                let ptb = icmpv6::create_icmpv6_packet_too_big(
                    &src_bytes,
                    &dst_bytes,
                    mtu as u32,
                    packet,
                );
                self.write_packet(&ptb).await.ok();
                continue;
            }

            let mut src_addr = Address([0u8; 16]);
            let mut dst_addr = Address([0u8; 16]);
            let mut src_subnet = Subnet([0u8; 8]);
            let mut dst_subnet = Subnet([0u8; 8]);

            src_addr.0.copy_from_slice(&packet[8..24]);
            dst_addr.0.copy_from_slice(&packet[24..40]);
            src_subnet.0.copy_from_slice(&packet[8..16]);
            dst_subnet.0.copy_from_slice(&packet[24..32]);

            // Packet must be addressed to us
            if dst_addr != self.our_address && dst_subnet != self.our_subnet {
                continue;
            }

            // Update key info for the sender
            let info = self.update(&from).await;

            // Verify source address matches sender's key
            if src_addr != info.address && src_subnet != info.subnet {
                continue;
            }

            out.resize(n, 0);
            out.copy_from_slice(packet);
            return Ok(n);
        }
    }

    /// Writes an IPv6 packet into the overlay network.
    async fn write_packet(&self, data: &[u8]) -> Result<usize> {
        if data[0] & 0xf0 != 0x60 {
            return Err(anyhow!("not an IPv6 packet"));
        }
        if data.len() < 40 {
            return Err(anyhow!("undersized IPv6 packet"));
        }

        let mut src_addr = Address([0u8; 16]);
        let mut dst_addr = Address([0u8; 16]);
        let mut src_subnet = Subnet([0u8; 8]);
        let mut dst_subnet = Subnet([0u8; 8]);

        src_addr.0.copy_from_slice(&data[8..24]);
        dst_addr.0.copy_from_slice(&data[24..40]);
        src_subnet.0.copy_from_slice(&data[8..16]);
        dst_subnet.0.copy_from_slice(&data[24..32]);

        // Source must be our address or subnet
        if src_addr != self.our_address && src_subnet != self.our_subnet {
            return Err(anyhow!("incorrect source address: {}", Ipv6Addr::from(src_addr.0)));
        }

        if dst_addr.is_valid() {
            self.send_to_address(&dst_addr, data).await;
        } else if dst_subnet.is_valid() {
            self.send_to_subnet(&dst_subnet, data).await;
        } else {
            return Err(anyhow!("invalid destination address"));
        }

        Ok(data.len())
    }
}

// ---------------------------------------------------------------------------
// Public ReadWriteCloser
// ---------------------------------------------------------------------------

pub struct ReadWriteCloser {
    store: Arc<KeyStore>,
    /// Buffered inbound packet queue (reserved for future buffered-read API).
    #[allow(dead_code)]
    rx_buf: Mutex<Vec<u8>>,
}

impl ReadWriteCloser {
    pub fn new(core: Arc<Core>) -> Self {
        let store = KeyStore::new(core);

        // Register path-notify callback
        {
            let s = Arc::clone(&store);
            tokio::spawn(async move {
                let s_cb = Arc::clone(&s);
                s.core
                    .set_path_notify(move |key| {
                        let s2 = Arc::clone(&s_cb);
                        tokio::spawn(async move {
                            s2.update(&key).await;
                        });
                    })
                    .await;
            });
        }

        ReadWriteCloser {
            store,
            rx_buf: Mutex::new(Vec::new()),
        }
    }

    pub fn address(&self) -> Address {
        self.store.our_address
    }

    pub fn subnet(&self) -> Subnet {
        self.store.our_subnet
    }

    pub fn max_mtu(&self) -> u64 {
        self.store.max_mtu()
    }

    pub fn set_mtu(&self, mtu: u64) {
        self.store.set_mtu(mtu);
    }

    pub fn mtu(&self) -> u64 {
        self.store.mtu()
    }

    pub async fn read(&self, buf: &mut Vec<u8>) -> Result<usize> {
        self.store.read_packet(buf).await
    }

    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        self.store.write_packet(data).await
    }

    pub async fn close(&self) -> Result<()> {
        self.store.core.stop().await;
        Ok(())
    }
}
