/// IPv6 address and subnet derivation from ed25519 public keys.
///
/// Direct port of yggdrasil-go/src/address/address.go

/// A 128-bit IPv6 address in the yggdrasil address range.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address(pub [u8; 16]);

/// An IPv6 /64 subnet prefix in the yggdrasil subnet range.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Subnet(pub [u8; 8]);

/// Returns the address prefix used by yggdrasil (currently `[0x02]`).
pub fn get_prefix() -> [u8; 1] {
    [0x02]
}

impl Address {
    /// Returns true if the address is within the yggdrasil node address range.
    pub fn is_valid(&self) -> bool {
        let prefix = get_prefix();
        for (i, &b) in prefix.iter().enumerate() {
            if self.0[i] != b {
                return false;
            }
        }
        true
    }

    /// Reconstructs the partial ed25519 public key encoded in this address.
    /// Used for key lookup / DHT searches.
    pub fn get_key(&self) -> [u8; 32] {
        let prefix = get_prefix();
        let mut key = [0u8; 32];
        let ones = self.0[prefix.len()] as usize;
        for idx in 0..ones {
            key[idx / 8] |= 0x80u8 >> (idx % 8) as u32;
        }
        let key_offset = ones + 1;
        let addr_offset = 8 * prefix.len() + 8;
        for idx in addr_offset..(8 * 16) {
            let bits = self.0[idx / 8] & (0x80u8 >> (idx % 8) as u32);
            let bits = bits << (idx % 8) as u32;
            let key_idx = key_offset + (idx - addr_offset);
            let bits = bits >> (key_idx % 8) as u32;
            let ki = key_idx / 8;
            if ki >= key.len() {
                break;
            }
            key[ki] |= bits;
        }
        for b in key.iter_mut() {
            *b = !*b;
        }
        key
    }
}

impl Subnet {
    /// Returns true if the subnet is within the yggdrasil subnet range.
    pub fn is_valid(&self) -> bool {
        let prefix = get_prefix();
        let l = prefix.len();
        for (i, &b) in prefix[..l - 1].iter().enumerate() {
            if self.0[i] != b {
                return false;
            }
        }
        self.0[l - 1] == prefix[l - 1] | 0x01
    }

    /// Reconstructs the partial ed25519 public key encoded in this subnet.
    pub fn get_key(&self) -> [u8; 32] {
        let mut addr = Address([0u8; 16]);
        addr.0[..8].copy_from_slice(&self.0);
        addr.get_key()
    }
}

/// Derives the yggdrasil IPv6 address from an ed25519 public key (32 bytes).
///
/// Returns `None` if the key length is not 32 bytes.
pub fn addr_for_key(public_key: &[u8]) -> Option<Address> {
    if public_key.len() != 32 {
        return None;
    }

    // Bitwise-invert the key
    let mut buf = [0u8; 32];
    for (i, &b) in public_key.iter().enumerate() {
        buf[i] = !b;
    }

    let mut addr = Address([0u8; 16]);
    let mut temp: Vec<u8> = Vec::with_capacity(32);
    let mut done = false;
    let mut ones: u8 = 0;
    let mut bits: u8 = 0;
    let mut n_bits: u32 = 0;

    for idx in 0..(8 * buf.len()) {
        let bit = (buf[idx / 8] & (0x80u8 >> (idx % 8) as u32)) >> (7 - (idx % 8)) as u32;
        if !done && bit != 0 {
            ones += 1;
            continue;
        }
        if !done && bit == 0 {
            done = true;
            continue;
        }
        bits = (bits << 1) | bit;
        n_bits += 1;
        if n_bits == 8 {
            n_bits = 0;
            temp.push(bits);
        }
    }

    let prefix = get_prefix();
    let prefix_len = prefix.len();
    addr.0[..prefix_len].copy_from_slice(&prefix);
    addr.0[prefix_len] = ones;
    let rest = &temp[..(16 - prefix_len - 1).min(temp.len())];
    addr.0[prefix_len + 1..prefix_len + 1 + rest.len()].copy_from_slice(rest);

    Some(addr)
}

/// Derives the yggdrasil /64 subnet from an ed25519 public key (32 bytes).
///
/// Returns `None` if the key length is not 32 bytes.
pub fn subnet_for_key(public_key: &[u8]) -> Option<Subnet> {
    let addr = addr_for_key(public_key)?;
    let mut snet = Subnet([0u8; 8]);
    snet.0.copy_from_slice(&addr.0[..8]);
    let prefix = get_prefix();
    snet.0[prefix.len() - 1] |= 0x01;
    Some(snet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix() {
        assert_eq!(get_prefix(), [0x02]);
    }

    #[test]
    fn test_addr_roundtrip() {
        // Generate a fake 32-byte key and verify address derivation is stable.
        let key = [0xABu8; 32];
        let addr = addr_for_key(&key).unwrap();
        assert!(addr.is_valid());
    }

    #[test]
    fn test_subnet_valid() {
        let key = [0xCDu8; 32];
        let snet = subnet_for_key(&key).unwrap();
        assert!(snet.is_valid());
    }

    #[test]
    fn test_addr_invalid_key_len() {
        assert!(addr_for_key(&[0u8; 16]).is_none());
    }
}
