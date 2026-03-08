/// Multicast beacon advertisement — binary encoding/decoding.
///
/// Port of yggdrasil-go/src/multicast/advertisement.go

use anyhow::{anyhow, Result};

const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Multicast advertisement packet broadcast on the LAN.
#[derive(Debug, Clone)]
pub struct MulticastAdvertisement {
    pub major_version: u16,
    pub minor_version: u16,
    pub public_key: [u8; ED25519_PUBLIC_KEY_SIZE],
    pub port: u16,
    pub hash: Vec<u8>,
}

impl MulticastAdvertisement {
    /// Serialises to the on-wire binary format.
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(ED25519_PUBLIC_KEY_SIZE + 8 + self.hash.len());
        b.extend_from_slice(&self.major_version.to_be_bytes());
        b.extend_from_slice(&self.minor_version.to_be_bytes());
        b.extend_from_slice(&self.public_key);
        b.extend_from_slice(&self.port.to_be_bytes());
        b.extend_from_slice(&(self.hash.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.hash);
        b
    }

    /// Deserialises from the on-wire binary format.
    pub fn unmarshal_binary(b: &[u8]) -> Result<Self> {
        if b.len() < ED25519_PUBLIC_KEY_SIZE + 8 {
            return Err(anyhow!("invalid multicast beacon: too short"));
        }
        let major_version = u16::from_be_bytes([b[0], b[1]]);
        let minor_version = u16::from_be_bytes([b[2], b[3]]);
        let mut public_key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&b[4..4 + ED25519_PUBLIC_KEY_SIZE]);
        let port = u16::from_be_bytes([
            b[4 + ED25519_PUBLIC_KEY_SIZE],
            b[5 + ED25519_PUBLIC_KEY_SIZE],
        ]);
        let hash_len =
            u16::from_be_bytes([b[6 + ED25519_PUBLIC_KEY_SIZE], b[7 + ED25519_PUBLIC_KEY_SIZE]])
                as usize;
        let hash_start = 8 + ED25519_PUBLIC_KEY_SIZE;
        if b.len() < hash_start + hash_len {
            return Err(anyhow!("invalid multicast beacon: truncated hash"));
        }
        let hash = b[hash_start..hash_start + hash_len].to_vec();
        Ok(MulticastAdvertisement {
            major_version,
            minor_version,
            public_key,
            port,
            hash,
        })
    }
}
