use std::net::IpAddr;

use crate::constants::{DNS_HEADER_SIZE, MAX_DNS_NAME_LENGTH};
use crate::domain::DomainRecord;

/// Parses the DNS question section from a raw UDP payload.
///
/// Only standard queries (QR=0) are processed.  For each question with a type
/// of A (1) or AAAA (28) the name is passed through [`DomainRecord::from_raw_name`]
/// so that noise, IP literals, and bare hostnames are all filtered out.
///
/// Returns an empty `Vec` on any structural error instead of panicking.
///
/// # Examples
///
/// ```
/// use packet_engine::dns::parse_dns_query;
///
/// // A one-question query for "example.com" type A.
/// let pkt = build_a_query(b"\x07example\x03com\x00", 1);
/// let records = parse_dns_query(&pkt);
/// // "example.com" is not a noise domain, so we should get one record.
/// assert_eq!(records.len(), 1);
/// assert_eq!(records[0].domain, "example.com");
///
/// fn build_a_query(name: &[u8], qtype: u16) -> Vec<u8> {
///     let mut pkt = vec![
///         0x12, 0x34, // ID
///         0x01, 0x00, // flags: QR=0, RD=1
///         0x00, 0x01, // QDCOUNT=1
///         0x00, 0x00, // ANCOUNT=0
///         0x00, 0x00, // NSCOUNT=0
///         0x00, 0x00, // ARCOUNT=0
///     ];
///     pkt.extend_from_slice(name);
///     pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
///     pkt.extend_from_slice(&[0x00, 0x01]);         // QCLASS=IN
///     pkt
/// }
/// ```
#[must_use]
pub fn parse_dns_query(udp_payload: &[u8]) -> Vec<DomainRecord> {
    if udp_payload.len() < DNS_HEADER_SIZE {
        return Vec::new();
    }

    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);

    // Only process queries (QR bit = 0).
    if flags & 0x8000 != 0 {
        return Vec::new();
    }

    let qd_count = u16::from_be_bytes([udp_payload[4], udp_payload[5]]) as usize;
    if qd_count == 0 || qd_count > 10 {
        return Vec::new();
    }

    let mut offset = DNS_HEADER_SIZE;
    let mut records = Vec::with_capacity(qd_count);

    for _ in 0..qd_count {
        let name = match parse_dns_name(udp_payload, &mut offset) {
            Some(n) => n,
            None => return records,
        };

        // Need at least 4 bytes for QTYPE + QCLASS.
        if offset + 4 > udp_payload.len() {
            return records;
        }

        let qtype = u16::from_be_bytes([udp_payload[offset], udp_payload[offset + 1]]);
        offset += 4; // skip QTYPE (2) + QCLASS (2)

        // Only record A and AAAA queries.
        if qtype != 1 && qtype != 28 {
            continue;
        }

        if let Some(record) = DomainRecord::from_raw_name(&name) {
            records.push(record);
        }
    }

    records
}

/// Parses a DNS wire-format name starting at `*offset` inside `data`.
///
/// Handles both length-prefixed labels and compression pointers (0xC0 prefix).
/// At most 10 pointer jumps are followed to guard against loops.  The offset
/// is advanced past the name in the *original* position (i.e. the byte after
/// the first zero-length label or the two-byte pointer that ends the name
/// there).
///
/// Returns `None` if the data is malformed, truncated, or the resulting name
/// exceeds [`MAX_DNS_NAME_LENGTH`].
#[must_use]
pub fn parse_dns_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;
    const MAX_JUMPS: usize = 10;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len_byte = data[pos];

        if len_byte == 0 {
            // End-of-name marker.
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }

        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            if !jumped {
                *offset = pos + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
            pos = ptr;
            continue;
        }

        // Reject reserved label types (0x40 and 0x80) per RFC 1035.
        // Only the top two bits being 0x00 indicates a regular length label.
        if (len_byte & 0xC0) != 0x00 {
            return None;
        }

        // Regular label.
        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[pos..pos + label_len])
            .ok()?
            .to_lowercase();
        labels.push(label);
        pos += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    let name = labels.join(".");
    if name.len() > MAX_DNS_NAME_LENGTH {
        return None;
    }

    Some(name)
}

/// Parses a DNS response packet and extracts A / AAAA answer records.
///
/// Only response packets (QR=1) are processed.  The question section is
/// skipped and the answer section is walked for type A (1) and AAAA (28)
/// resource records.  Each such record yields a `(domain, ip)` pair.
///
/// Returns an empty `Vec` on any structural error instead of panicking.
#[must_use]
pub fn parse_dns_response(udp_payload: &[u8]) -> Vec<(String, IpAddr)> {
    if udp_payload.len() < DNS_HEADER_SIZE {
        return Vec::new();
    }

    let flags = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);

    // Only process responses (QR bit = 1).
    if flags & 0x8000 == 0 {
        return Vec::new();
    }

    let qd_count = u16::from_be_bytes([udp_payload[4], udp_payload[5]]) as usize;
    let an_count = u16::from_be_bytes([udp_payload[6], udp_payload[7]]) as usize;

    let mut offset = DNS_HEADER_SIZE;

    // Skip question section.
    for _ in 0..qd_count {
        if parse_dns_name(udp_payload, &mut offset).is_none() {
            return Vec::new();
        }
        // Skip QTYPE + QCLASS.
        if offset + 4 > udp_payload.len() {
            return Vec::new();
        }
        offset += 4;
    }

    // Parse answer section.
    let mut results = Vec::new();

    for _ in 0..an_count {
        // Owner name (may be compressed).
        let name = match parse_dns_name(udp_payload, &mut offset) {
            Some(n) => n,
            None => return results,
        };

        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes.
        if offset + 10 > udp_payload.len() {
            return results;
        }

        let rr_type = u16::from_be_bytes([udp_payload[offset], udp_payload[offset + 1]]);
        // Skip TYPE + CLASS + TTL.
        offset += 8;
        let rd_length = u16::from_be_bytes([udp_payload[offset], udp_payload[offset + 1]]) as usize;
        offset += 2;

        if offset + rd_length > udp_payload.len() {
            return results;
        }

        let rdata = &udp_payload[offset..offset + rd_length];

        match rr_type {
            1 => {
                // A record — 4 bytes.
                if rd_length == 4 {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
                    results.push((name, ip));
                }
            }
            28 => {
                // AAAA record — 16 bytes.
                if rd_length == 16 {
                    if let Ok(bytes) = <[u8; 16]>::try_from(rdata) {
                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
                        results.push((name, ip));
                    }
                }
            }
            _ => {}
        }

        offset += rd_length;
    }

    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Wire-format helpers
    // -----------------------------------------------------------------------

    /// Encodes a dotted domain name into DNS wire format (length-prefixed labels
    /// terminated by a zero byte).
    fn encode_name(domain: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in domain.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0x00); // root label
        out
    }

    /// Builds a minimal DNS query packet for the given name and QTYPE.
    fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: QR=0 (query), RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        pkt.extend_from_slice(&encode_name(domain));
        pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        pkt
    }

    /// Builds a minimal DNS response with one A record in the answer section.
    fn build_a_response(domain: &str, ip: [u8; 4]) -> Vec<u8> {
        let encoded = encode_name(domain);
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // flags: QR=1 (response), AA=0, RD=1, RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // Question section
        pkt.extend_from_slice(&encoded);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

        // Answer: use compression pointer back to the question name (offset 12).
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        pkt.extend_from_slice(&ip); // RDATA
        pkt
    }

    /// Builds a minimal DNS response with one AAAA record.
    fn build_aaaa_response(domain: &str, ip: [u8; 16]) -> Vec<u8> {
        let encoded = encode_name(domain);
        let mut pkt = vec![
            0x12, 0x34,
            0x81, 0x80,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
        ];
        pkt.extend_from_slice(&encoded);
        pkt.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // QTYPE=AAAA, QCLASS=IN
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer
        pkt.extend_from_slice(&[0x00, 0x1C]); // TYPE=AAAA
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        pkt.extend_from_slice(&[0x00, 0x10]); // RDLENGTH=16
        pkt.extend_from_slice(&ip); // RDATA
        pkt
    }

    // -----------------------------------------------------------------------
    // parse_dns_query tests
    // -----------------------------------------------------------------------

    #[test]
    fn query_type_a_google_com_is_extracted() {
        let pkt = build_query("google.com", 1);
        let records = parse_dns_query(&pkt);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "google.com");
    }

    #[test]
    fn query_type_aaaa_is_extracted() {
        let pkt = build_query("google.com", 28);
        let records = parse_dns_query(&pkt);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "google.com");
    }

    #[test]
    fn response_packet_yields_empty_vec_from_query_parser() {
        // QR=1 means it is a response — parse_dns_query must reject it.
        let pkt = build_a_response("google.com", [8, 8, 8, 8]);
        let records = parse_dns_query(&pkt);
        assert!(records.is_empty(), "parse_dns_query must ignore responses");
    }

    #[test]
    fn query_type_mx_is_not_recorded() {
        // QTYPE=MX (15) should be silently skipped.
        let pkt = build_query("google.com", 15);
        let records = parse_dns_query(&pkt);
        assert!(records.is_empty());
    }

    #[test]
    fn noise_domain_is_accepted_by_query_parser() {
        // Noise filtering is the engine's responsibility, not the parser's.
        let pkt = build_query("apple.com", 1);
        let records = parse_dns_query(&pkt);
        assert_eq!(records.len(), 1, "parser must accept noise domains");
        assert_eq!(records[0].domain, "apple.com");
    }

    #[test]
    fn truncated_query_packet_does_not_panic() {
        // Feed truncated packets of increasing lengths; none should panic.
        let full = build_query("google.com", 1);
        for len in 0..full.len() {
            let _ = parse_dns_query(&full[..len]);
        }
    }

    // -----------------------------------------------------------------------
    // parse_dns_name tests
    // -----------------------------------------------------------------------

    #[test]
    fn compressed_name_is_resolved() {
        // Build a packet where the answer name is a pointer to offset 12.
        // Layout:
        //   [0..12)  = DNS header
        //   [12..)   = encoded "google.com" in the question section
        //   then a pointer [0xC0, 0x0C] pointing back to offset 12
        let mut data = vec![
            0x00, 0x00, // ID (unused)
            0x01, 0x00, // flags
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        data.extend_from_slice(&encode_name("google.com"));

        // Place the pointer right after the header (for testing purposes).
        let ptr_offset = data.len();
        data.push(0xC0);
        data.push(0x0C); // points to offset 12 = start of question name

        let mut offset = ptr_offset;
        let name = parse_dns_name(&data, &mut offset).expect("should resolve");
        assert_eq!(name, "google.com");
        // After following the pointer, offset must point past the 2-byte pointer.
        assert_eq!(offset, ptr_offset + 2);
    }

    #[test]
    fn name_is_lowercased_by_parser() {
        let mut data = vec![0u8; DNS_HEADER_SIZE];
        data.extend_from_slice(b"\x06GOOGLE\x03COM\x00");
        let mut offset = DNS_HEADER_SIZE;
        let name = parse_dns_name(&data, &mut offset).expect("should parse");
        assert_eq!(name, "google.com");
    }

    #[test]
    fn empty_name_returns_none() {
        // A single 0x00 byte is the root label, which represents an empty name
        // after joining — should return None.
        let data = [0x00u8];
        let mut offset = 0;
        assert!(parse_dns_name(&data, &mut offset).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_dns_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn a_record_response_is_extracted() {
        let pkt = build_a_response("example.com", [93, 184, 216, 34]);
        let results = parse_dns_response(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "example.com");
        assert_eq!(
            results[0].1,
            IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn aaaa_record_response_is_extracted() {
        let ip_bytes = [
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
        ];
        let pkt = build_aaaa_response("example.com", ip_bytes);
        let results = parse_dns_response(&pkt);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "example.com");
        assert_eq!(
            results[0].1,
            IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes))
        );
    }

    #[test]
    fn query_packet_yields_empty_vec_from_response_parser() {
        let pkt = build_query("example.com", 1);
        let results = parse_dns_response(&pkt);
        assert!(results.is_empty(), "parse_dns_response must ignore queries");
    }

    #[test]
    fn truncated_response_packet_does_not_panic() {
        let full = build_a_response("example.com", [1, 2, 3, 4]);
        for len in 0..full.len() {
            let _ = parse_dns_response(&full[..len]);
        }
    }
}
