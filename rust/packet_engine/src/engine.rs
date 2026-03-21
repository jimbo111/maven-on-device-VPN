use crate::ip::{self, IpProtocol};

const _: () = assert!(
    crate::constants::BATCH_FLUSH_INTERVAL_MS <= i64::MAX as u64,
    "BATCH_FLUSH_INTERVAL_MS must fit in i64"
);
use crate::dns;
use crate::domain::{DomainRecord, DetectionSource};
use crate::storage::DomainStorage;
use crate::errors::EngineError;
use crate::constants::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of processing a packet.
pub enum ProcessResult {
    /// Forward the original packet unchanged (the common case)
    Forward,
    /// Replace the original packet with this modified version
    Replace(Vec<u8>),
}

/// The main packet processing engine.
///
/// Owns all mutable state and is NOT thread-safe.
pub struct PacketEngine {
    storage: DomainStorage,
    pending_domains: Vec<DomainRecord>,
    last_flush_ms: i64,
    stats: EngineStats,
    pub noise_filter_enabled: bool,
}

#[derive(Debug, Default)]
pub struct EngineStats {
    pub packets_processed: u64,
    pub dns_domains_found: u64,
    pub packets_skipped: u64,
    pub flush_errors: u64,
}

impl PacketEngine {
    pub fn new(db_path: &str) -> Result<Self, EngineError> {
        let storage = DomainStorage::new(db_path)?;

        Ok(PacketEngine {
            storage,
            pending_domains: Vec::with_capacity(BATCH_INSERT_SIZE),
            last_flush_ms: Self::now_millis(),
            stats: EngineStats::default(),
            noise_filter_enabled: true,
        })
    }

    pub fn process_packet(&mut self, packet: &[u8]) -> ProcessResult {
        self.stats.packets_processed += 1;

        let ip_header = match ip::parse_ip_header(packet) {
            Some(h) => h,
            None => {
                self.stats.packets_skipped += 1;
                return ProcessResult::Forward;
            }
        };

        if ip_header.payload_offset >= packet.len() {
            self.stats.packets_skipped += 1;
            return ProcessResult::Forward;
        }

        let transport_data = &packet[ip_header.payload_offset..];

        match ip_header.protocol {
            IpProtocol::Udp => self.handle_udp(transport_data),
            _ => {
                self.stats.packets_skipped += 1;
            }
        };

        self.maybe_flush();
        ProcessResult::Forward
    }

    fn handle_udp(&mut self, transport_data: &[u8]) {
        if transport_data.len() < 8 {
            return;
        }

        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
        let udp_payload = &transport_data[8..];

        // Outbound DNS query (to port 53)
        if dst_port == DNS_PORT {
            let records = dns::parse_dns_query(udp_payload);
            for record in records {
                if self.noise_filter_enabled && crate::domain::is_noise_domain(&record.domain) {
                    continue;
                }
                self.stats.dns_domains_found += 1;
                self.pending_domains
                    .push(record.with_source(DetectionSource::Dns));
            }
        }
    }

    fn maybe_flush(&mut self) {
        if self.pending_domains.is_empty() {
            return;
        }

        let now = Self::now_millis();
        let elapsed = now.saturating_sub(self.last_flush_ms);

        let should_flush = self.pending_domains.len() >= BATCH_INSERT_SIZE
            || elapsed >= BATCH_FLUSH_INTERVAL_MS as i64;

        if should_flush {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        if self.pending_domains.is_empty() {
            return;
        }

        let domains: Vec<DomainRecord> = self.pending_domains.drain(..).collect();

        if let Err(e) = self.storage.batch_insert(&domains) {
            log::error!("Failed to flush domains to SQLite: {}", e);
            self.stats.flush_errors += 1;
        }

        self.last_flush_ms = Self::now_millis();
    }

    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64
    }
}

impl Drop for PacketEngine {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_query_packet(domain: &str) -> Vec<u8> {
        let mut udp_payload = Vec::new();
        udp_payload.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        for label in domain.split('.') {
            udp_payload.push(label.len() as u8);
            udp_payload.extend_from_slice(label.as_bytes());
        }
        udp_payload.push(0x00);
        udp_payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let udp_len = (8 + udp_payload.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&[0xAB, 0xCD]);
        udp.extend_from_slice(&[0x00, 0x35]);
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]);
        udp.extend_from_slice(&udp_payload);

        let total_len = (20 + udp.len()) as u16;
        let mut packet = vec![
            0x45, 0x00,
            (total_len >> 8) as u8, (total_len & 0xFF) as u8,
            0x00, 0x00, 0x00, 0x00, 0x40, 17,
            0x00, 0x00, 10, 0, 0, 1, 8, 8, 8, 8,
        ];
        packet.extend_from_slice(&udp);
        packet
    }

    #[test]
    fn engine_processes_dns_query() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let packet = build_dns_query_packet("github.com");
        let result = engine.process_packet(&packet);
        assert!(matches!(result, ProcessResult::Forward));
        engine.flush();
        assert_eq!(engine.storage.domain_count().unwrap(), 1);
        assert_eq!(engine.stats.dns_domains_found, 1);
    }

    #[test]
    fn engine_skips_non_ip_packets() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let garbage = vec![0xFF; 20];
        let result = engine.process_packet(&garbage);
        assert!(matches!(result, ProcessResult::Forward));
        assert_eq!(engine.stats.packets_skipped, 1);
    }

    #[test]
    fn engine_has_pending_domains_before_flush() {
        let mut engine = PacketEngine::new(":memory:").unwrap();
        let packet = build_dns_query_packet("droptest.com");
        engine.process_packet(&packet);
        assert_eq!(engine.pending_domains.len(), 1);
        engine.flush();
        assert_eq!(engine.pending_domains.len(), 0);
        assert_eq!(engine.storage.domain_count().unwrap(), 1);
    }
}
