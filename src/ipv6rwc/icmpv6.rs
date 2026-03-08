/// ICMPv6 packet construction helpers.
///
/// Port of yggdrasil-go/src/ipv6rwc/icmpv6.go

use std::net::Ipv6Addr;

/// Creates an ICMPv6 "Packet Too Big" packet, including the IPv6 header.
///
/// `dst` and `src` are the destination and source IPv6 addresses (16 bytes each).
/// Returns the complete IPv6 + ICMPv6 packet bytes.
pub fn create_icmpv6_packet_too_big(dst: &[u8; 16], src: &[u8; 16], mtu: u32, original_packet: &[u8]) -> Vec<u8> {
    // Truncate original packet to 512 bytes for the PTB body
    let truncated = &original_packet[..original_packet.len().min(512)];

    // ICMPv6 PTB body: 4-byte MTU field + truncated original packet
    let icmp_body_len = 4 + truncated.len();

    // Compute checksum over pseudo-header + ICMPv6
    let icmp_type: u8 = 2; // Packet Too Big
    let icmp_code: u8 = 0;

    let mut icmp_payload = Vec::with_capacity(4 + icmp_body_len);
    icmp_payload.push(icmp_type);
    icmp_payload.push(icmp_code);
    icmp_payload.extend_from_slice(&[0u8, 0u8]); // checksum placeholder
    icmp_payload.extend_from_slice(&mtu.to_be_bytes());
    icmp_payload.extend_from_slice(truncated);

    // Compute ICMPv6 checksum using IPv6 pseudo-header
    let checksum = icmpv6_checksum(src, dst, &icmp_payload);
    icmp_payload[2] = (checksum >> 8) as u8;
    icmp_payload[3] = checksum as u8;

    // Build IPv6 header (40 bytes)
    let payload_len = icmp_payload.len() as u16;
    let mut pkt = Vec::with_capacity(40 + icmp_payload.len());
    // Version (6) + Traffic Class (0) + Flow Label (0)
    pkt.push(0x60u8);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    // Payload length
    pkt.extend_from_slice(&payload_len.to_be_bytes());
    // Next header: ICMPv6 = 58
    pkt.push(58u8);
    // Hop limit
    pkt.push(255u8);
    // Source address
    pkt.extend_from_slice(src);
    // Destination address
    pkt.extend_from_slice(dst);
    // ICMPv6 payload
    pkt.extend_from_slice(&icmp_payload);
    pkt
}

/// Computes the ICMPv6 checksum using the IPv6 pseudo-header.
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src + dst + ICMPv6 payload length (u32 BE) + zeros (3 bytes) + next header (58)
    let pseudo: Vec<u8> = {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(src);
        p.extend_from_slice(dst);
        p.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
        p.extend_from_slice(&[0u8, 0u8, 0u8, 58u8]);
        p
    };

    for chunk in pseudo.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    for chunk in icmp.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}
