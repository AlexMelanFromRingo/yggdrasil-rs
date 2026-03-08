//! Yggdrasil vanity key generator.
//!
//! Port of yggdrasil-go/cmd/genkeys/main.go
//!
//! Generates ed25519 keys in parallel; prints each new "better" key found.
//! "Better" means a lower raw public key (more leading 0-bits) which yields
//! a higher NodeID (more leading 1-bits in inverted key) → higher IP address.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    net::Ipv6Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Instant,
};
use yggdrasil_rs::address;

struct KeySet {
    priv_key: [u8; 32],
    pub_key: [u8; 32],
    count: u64,
}

fn is_better(old_pub: &[u8; 32], new_pub: &[u8; 32]) -> bool {
    for idx in 0..32 {
        if new_pub[idx] < old_pub[idx] {
            return true;
        }
        if new_pub[idx] > old_pub[idx] {
            break;
        }
    }
    false
}

fn do_keys(tx: mpsc::SyncSender<KeySet>, running: Arc<AtomicBool>) {
    let mut best_key = [0xffu8; 32];
    let mut count: u64 = 0;
    let mut rng = OsRng;

    while running.load(Ordering::Relaxed) {
        let signing_key = SigningKey::generate(&mut rng);
        let pub_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        count += 1;

        if !is_better(&best_key, &pub_bytes) {
            continue;
        }

        best_key = pub_bytes;
        let priv_bytes: [u8; 32] = signing_key.to_bytes();

        let _ = tx.try_send(KeySet {
            priv_key: priv_bytes,
            pub_key: pub_bytes,
            count,
        });
        count = 0;
    }
}

fn main() {
    let threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("Threads: {threads}");

    let start = Instant::now();
    let mut total_keys: u64 = 0;
    let mut current_best = [0xffu8; 32];
    let mut first = true;

    let running = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::sync_channel::<KeySet>(threads * 2);

    for _ in 0..threads {
        let tx2 = tx.clone();
        let running2 = Arc::clone(&running);
        thread::spawn(move || do_keys(tx2, running2));
    }
    drop(tx);

    while let Ok(key) = rx.recv() {
        if first || is_better(&current_best, &key.pub_key) {
            total_keys += key.count;
            current_best = key.pub_key;
            first = false;

            let elapsed = start.elapsed();
            println!("-----  {elapsed:.2?}  ---  {total_keys} keys tried");
            println!("Priv:  {}", hex::encode(key.priv_key));
            println!("Pub:   {}", hex::encode(key.pub_key));

            if let Some(addr) = address::addr_for_key(&key.pub_key) {
                println!("IP:    {}", Ipv6Addr::from(addr.0));
            }
        }
    }
}
