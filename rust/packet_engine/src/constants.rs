/// Batch insert threshold.
pub const BATCH_INSERT_SIZE: usize = 50;

/// Batch flush interval in milliseconds.
pub const BATCH_FLUSH_INTERVAL_MS: u64 = 500;

/// DNS standard port
pub const DNS_PORT: u16 = 53;

/// Maximum DNS query name length (per RFC 1035)
pub const MAX_DNS_NAME_LENGTH: usize = 253;

/// DNS header size in bytes
pub const DNS_HEADER_SIZE: usize = 12;
