use std::net::IpAddr;

/// The layer-4 protocol carried in an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    /// Any protocol number not explicitly recognised.
    Other(u8),
}

impl IpProtocol {
    fn from_u8(value: u8) -> Self {
        match value {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            other => IpProtocol::Other(other),
        }
    }
}

/// Parsed fields extracted from an IPv4 or IPv6 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHeader {
    /// IP version: 4 or 6.
    pub version: u8,
    /// Layer-4 protocol.
    pub protocol: IpProtocol,
    /// Source address.
    pub src_addr: IpAddr,
    /// Destination address.
    pub dst_addr: IpAddr,
    /// Byte offset within `packet` where the layer-4 payload begins.
    pub payload_offset: usize,
    /// Total length of the IP datagram in bytes (header + payload).
    pub total_length: usize,
}

/// Parses an IP header from the beginning of `packet`.
///
/// Returns `None` if the packet is too short, malformed, or carries an
/// unrecognised IP version.
///
/// # Examples
///
/// ```
/// use packet_engine::ip::{parse_ip_header, IpProtocol};
///
/// // Minimal valid IPv4 TCP packet (20-byte header, no payload).
/// let mut pkt = [0u8; 20];
/// pkt[0] = 0x45; // version=4, IHL=5
/// pkt[9] = 6;    // protocol=TCP
/// // total length = 20
/// pkt[2] = 0x00;
/// pkt[3] = 0x14;
///
/// let hdr = parse_ip_header(&pkt).expect("should parse");
/// assert_eq!(hdr.version, 4);
/// assert_eq!(hdr.protocol, IpProtocol::Tcp);
/// assert_eq!(hdr.payload_offset, 20);
/// ```
#[must_use]
pub fn parse_ip_header(packet: &[u8]) -> Option<IpHeader> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

/// Parses an IPv4 header.
///
/// Handles variable Internet Header Length (IHL ≥ 5). Requires at least
/// `ihl * 4` bytes to be present in `packet`.
fn parse_ipv4(packet: &[u8]) -> Option<IpHeader> {
    // Minimum IPv4 header is 20 bytes.
    if packet.len() < 20 {
        return None;
    }

    let ihl = (packet[0] & 0x0F) as usize;
    if ihl < 5 {
        // IHL values below 5 are invalid per RFC 791.
        return None;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len {
        return None;
    }

    // Total length field (bytes 2-3). Reject truncated packets and packets
    // where total_length is smaller than the header itself (malformed).
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_length > packet.len() || total_length < header_len {
        return None;
    }

    // Protocol (byte 9).
    let protocol = IpProtocol::from_u8(packet[9]);

    // Source address (bytes 12-15).
    let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    // Destination address (bytes 16-19).
    let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Some(IpHeader {
        version: 4,
        protocol,
        src_addr: IpAddr::V4(src),
        dst_addr: IpAddr::V4(dst),
        payload_offset: header_len,
        total_length,
    })
}

/// Well-known IPv6 extension header Next Header values.
///
/// These are protocol numbers that indicate another extension header follows
/// rather than a transport-layer payload.
const IPV6_EXT_HOP_BY_HOP: u8 = 0;
const IPV6_EXT_ROUTING: u8 = 43;
const IPV6_EXT_FRAGMENT: u8 = 44;
const IPV6_EXT_ESP: u8 = 50;
const IPV6_EXT_AH: u8 = 51;
const IPV6_EXT_DESTINATION: u8 = 60;

/// Returns `true` if `next_header` is a recognised IPv6 extension header that
/// must be skipped to reach the transport-layer payload.
#[inline]
fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        IPV6_EXT_HOP_BY_HOP
            | IPV6_EXT_ROUTING
            | IPV6_EXT_FRAGMENT
            | IPV6_EXT_ESP
            | IPV6_EXT_AH
            | IPV6_EXT_DESTINATION
    )
}

/// Parses an IPv6 header, walking any extension headers to find the real
/// transport-layer protocol.
///
/// IPv6 has a fixed 40-byte base header followed by zero or more extension
/// headers.  Each extension header (except Fragment, which is always 8 bytes)
/// carries a `hdr_ext_len` field that gives its length in 8-byte units
/// *excluding* the first 8 bytes.  The walk is capped at 10 iterations to
/// guard against malformed packets with circular or excessively long chains.
fn parse_ipv6(packet: &[u8]) -> Option<IpHeader> {
    // Fixed 40-byte IPv6 base header.
    if packet.len() < 40 {
        return None;
    }

    // Payload length field (bytes 4-5) — does NOT include the 40-byte header.
    let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_length = 40 + payload_length;

    // Source address (bytes 8-23).
    let src_bytes: [u8; 16] = packet[8..24].try_into().ok()?;
    let src = std::net::Ipv6Addr::from(src_bytes);

    // Destination address (bytes 24-39).
    let dst_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
    let dst = std::net::Ipv6Addr::from(dst_bytes);

    // Walk extension headers to find the actual transport protocol.
    let mut next_header = packet[6];
    let mut payload_offset: usize = 40;
    const MAX_EXT_ITERATIONS: usize = 10;

    for _ in 0..MAX_EXT_ITERATIONS {
        if !is_ipv6_extension_header(next_header) {
            // Reached a transport-layer protocol (or unknown).
            break;
        }

        // Fragment header (44) is always exactly 8 bytes; the hdr_ext_len
        // field is reserved and must not be used to compute the size.
        let ext_len_bytes: usize = if next_header == IPV6_EXT_FRAGMENT {
            8
        } else {
            // Each non-fragment extension header has:
            //   byte 0: next header
            //   byte 1: hdr_ext_len (length in 8-byte units, not counting the
            //            first 8 bytes)
            if payload_offset + 2 > packet.len() {
                return None;
            }
            let hdr_ext_len = packet[payload_offset + 1] as usize;
            (hdr_ext_len + 1) * 8
        };

        if payload_offset + ext_len_bytes > packet.len() {
            return None;
        }

        // Advance to the next header.
        next_header = packet[payload_offset];
        payload_offset += ext_len_bytes;
    }

    let protocol = IpProtocol::from_u8(next_header);

    Some(IpHeader {
        version: 6,
        protocol,
        src_addr: IpAddr::V6(src),
        dst_addr: IpAddr::V6(dst),
        payload_offset,
        total_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Builds a minimal 20-byte IPv4 header with no payload.
    fn build_ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2] = 0x00; // total length = 20
        pkt[3] = 0x14;
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt
    }

    /// Builds a minimal 40-byte IPv6 header with no payload.
    fn build_ipv6(next_header: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version=6
        pkt[4] = 0x00; // payload length = 0
        pkt[5] = 0x00;
        pkt[6] = next_header;
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt
    }

    #[test]
    fn valid_ipv4_tcp_packet() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let pkt = build_ipv4(6, src, dst);

        let hdr = parse_ip_header(&pkt).expect("should parse");
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.protocol, IpProtocol::Tcp);
        assert_eq!(hdr.src_addr, IpAddr::V4(Ipv4Addr::from(src)));
        assert_eq!(hdr.dst_addr, IpAddr::V4(Ipv4Addr::from(dst)));
        assert_eq!(hdr.payload_offset, 20);
        assert_eq!(hdr.total_length, 20);
    }

    #[test]
    fn ipv4_with_options_ihl_greater_than_5() {
        // IHL=6 -> 24-byte header; pad to 24 bytes.
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x46; // version=4, IHL=6
        pkt[2] = 0x00; // total length = 24
        pkt[3] = 0x18;
        pkt[9] = 17; // UDP
        pkt[12] = 172;
        pkt[13] = 16;
        pkt[14] = 0;
        pkt[15] = 1; // src 172.16.0.1
        pkt[16] = 172;
        pkt[17] = 16;
        pkt[18] = 0;
        pkt[19] = 2; // dst 172.16.0.2

        let hdr = parse_ip_header(&pkt).expect("should parse");
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.protocol, IpProtocol::Udp);
        assert_eq!(hdr.payload_offset, 24);
        assert_eq!(hdr.total_length, 24);
        assert_eq!(hdr.src_addr, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(hdr.dst_addr, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)));
    }

    #[test]
    fn valid_ipv6_packet() {
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        let pkt = build_ipv6(6, src, dst);

        let hdr = parse_ip_header(&pkt).expect("should parse");
        assert_eq!(hdr.version, 6);
        assert_eq!(hdr.protocol, IpProtocol::Tcp);
        assert_eq!(hdr.src_addr, IpAddr::V6(Ipv6Addr::from(src)));
        assert_eq!(hdr.dst_addr, IpAddr::V6(Ipv6Addr::from(dst)));
        assert_eq!(hdr.payload_offset, 40);
        assert_eq!(hdr.total_length, 40); // payload length = 0
    }

    #[test]
    fn truncated_packet_returns_none() {
        // Only 10 bytes — too short for any valid IP header.
        let pkt = [0x45u8; 10];
        assert!(parse_ip_header(&pkt).is_none());
    }

    #[test]
    fn empty_packet_returns_none() {
        assert!(parse_ip_header(&[]).is_none());
    }

    #[test]
    fn unknown_ip_version_returns_none() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x55; // version=5 (reserved / ST)
        assert!(parse_ip_header(&pkt).is_none());
    }

    #[test]
    fn ipv4_invalid_ihl_returns_none() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x44; // IHL=4 — below minimum of 5
        assert!(parse_ip_header(&pkt).is_none());
    }

    #[test]
    fn ipv4_truncated_options_returns_none() {
        // IHL=7 means 28-byte header, but we only provide 20 bytes.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x47; // IHL=7
        assert!(parse_ip_header(&pkt).is_none());
    }

    /// Builds an IPv6 packet with a Hop-by-Hop extension header (next_header=0)
    /// followed by TCP.
    ///
    /// Layout:
    ///   [0..40)   IPv6 base header  (next_header = 0 = Hop-by-Hop)
    ///   [40..48)  Hop-by-Hop ext header: next_header=6 (TCP), hdr_ext_len=0
    ///             (meaning total ext header length = 8 bytes)
    ///             followed by 6 option bytes (padding)
    ///   [48..)    TCP payload
    #[test]
    fn ipv6_with_hop_by_hop_extension_header_finds_tcp() {
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];

        // Payload = 8-byte Hop-by-Hop header + 20-byte TCP pseudo-payload.
        let payload_len: u16 = 8 + 20;

        let mut pkt = vec![0u8; 40 + payload_len as usize];
        // IPv6 base header.
        pkt[0] = 0x60; // version=6, traffic class=0, flow label=0
        pkt[4] = (payload_len >> 8) as u8;
        pkt[5] = (payload_len & 0xFF) as u8;
        pkt[6] = 0; // next_header = Hop-by-Hop (0)
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);

        // Hop-by-Hop extension header at offset 40.
        // byte 0: next_header = 6 (TCP)
        // byte 1: hdr_ext_len = 0 (total length = (0+1)*8 = 8 bytes)
        // bytes 2-7: padding options
        pkt[40] = 6; // next_header = TCP
        pkt[41] = 0; // hdr_ext_len = 0
        // bytes 42-47 are already zero (padding)

        // bytes 48-67: mock TCP segment (all zeros, just needs to be present)

        let hdr = parse_ip_header(&pkt).expect("should parse IPv6 + Hop-by-Hop + TCP");
        assert_eq!(hdr.version, 6);
        assert_eq!(hdr.protocol, IpProtocol::Tcp);
        assert_eq!(
            hdr.payload_offset, 48,
            "payload_offset must skip both IPv6 base header (40) and Hop-by-Hop ext (8)"
        );
        assert_eq!(hdr.src_addr, IpAddr::V6(Ipv6Addr::from(src)));
        assert_eq!(hdr.dst_addr, IpAddr::V6(Ipv6Addr::from(dst)));
    }

    #[test]
    fn ipv6_with_no_extension_headers_payload_offset_is_40() {
        let src = [0u8; 16];
        let dst = [0u8; 16];
        // next_header=17 (UDP) — no extension headers.
        let pkt = build_ipv6(17, src, dst);
        let hdr = parse_ip_header(&pkt).expect("should parse");
        assert_eq!(hdr.payload_offset, 40);
        assert_eq!(hdr.protocol, IpProtocol::Udp);
    }

    #[test]
    fn ipv6_truncated_extension_header_returns_none() {
        // next_header=43 (Routing) but the packet is only 41 bytes — not
        // enough room for even 2 bytes of the extension header.
        let mut pkt = vec![0u8; 41];
        pkt[0] = 0x60;
        pkt[6] = 43; // Routing extension header
        assert!(parse_ip_header(&pkt).is_none());
    }
}
