use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::MAX_DNS_NAME_LENGTH;

/// Indicates how a domain name was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSource {
    /// Observed in a plaintext DNS query or response.
    Dns,
    /// Observed in a TLS ClientHello SNI extension.
    Sni,
    /// Inferred by correlating a prior DNS answer with a connection destination.
    DnsCorrelation,
}

impl DetectionSource {
    /// Returns a short, stable string identifier for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::domain::DetectionSource;
    ///
    /// assert_eq!(DetectionSource::Dns.as_str(), "dns");
    /// assert_eq!(DetectionSource::Sni.as_str(), "sni");
    /// assert_eq!(DetectionSource::DnsCorrelation.as_str(), "dns_correlation");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DetectionSource::Dns => "dns",
            DetectionSource::Sni => "sni",
            DetectionSource::DnsCorrelation => "dns_correlation",
        }
    }
}

/// A validated, normalised domain name observed on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    /// The normalised domain name (lowercase, no trailing dot).
    pub domain: String,
    /// Unix timestamp in milliseconds at which this record was created.
    pub timestamp_ms: i64,
    /// The detection mechanism that produced this record.
    pub source: DetectionSource,
}

impl DomainRecord {
    /// Attempts to build a [`DomainRecord`] from a raw DNS wire-format name.
    ///
    /// Normalisation steps applied in order:
    /// 1. Trim leading/trailing ASCII whitespace.
    /// 2. Convert to lowercase.
    /// 3. Strip a single trailing dot (root label).
    ///
    /// The candidate is then rejected if any of the following hold:
    /// - It contains no dot (e.g. bare hostnames like `localhost`).
    /// - It parses as an IP address literal.
    /// - It exceeds [`MAX_DNS_NAME_LENGTH`] (253) bytes.
    /// - [`is_noise_domain`] returns `true`.
    ///
    /// On success the timestamp is captured from [`SystemTime::now`] and the
    /// source defaults to [`DetectionSource::Dns`].
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::domain::DomainRecord;
    ///
    /// assert!(DomainRecord::from_raw_name("google.com.").is_some());
    /// assert!(DomainRecord::from_raw_name("localhost").is_none());
    /// assert!(DomainRecord::from_raw_name("192.168.1.1").is_none());
    /// // Noise domains are accepted — filtering is the engine's job.
    /// assert!(DomainRecord::from_raw_name("apple.com").is_some());
    /// ```
    #[must_use]
    pub fn from_raw_name(name: &str) -> Option<Self> {
        let trimmed = name.trim();
        let lower = trimmed.to_lowercase();
        let normalised = lower.strip_suffix('.').unwrap_or(&lower);

        // Reject bare hostnames (no dot present after normalisation).
        if !normalised.contains('.') {
            return None;
        }

        // Reject IP address literals.
        if normalised.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        // Reject names exceeding the RFC 1035 limit.
        if normalised.len() > MAX_DNS_NAME_LENGTH {
            return None;
        }

        // NOTE: Noise domain filtering is intentionally NOT done here.
        // It is a policy decision handled by PacketEngine based on a
        // runtime-configurable flag (noise_filter_enabled). This function
        // only performs structural validation and normalisation.

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        Some(Self {
            domain: normalised.to_owned(),
            timestamp_ms,
            source: DetectionSource::Dns,
        })
    }

    /// Overrides the detection source on this record.
    ///
    /// Follows the builder pattern and consumes `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use packet_engine::domain::{DomainRecord, DetectionSource};
    ///
    /// let record = DomainRecord::from_raw_name("example.com")
    ///     .unwrap()
    ///     .with_source(DetectionSource::Sni);
    ///
    /// assert_eq!(record.source, DetectionSource::Sni);
    /// ```
    #[must_use]
    pub fn with_source(mut self, source: DetectionSource) -> Self {
        self.source = source;
        self
    }
}

/// Returns `true` if `domain` is a suffix match for any well-known noise
/// domain that should never be stored (Apple infrastructure, Akamai CDN, mDNS
/// local names, reverse-DNS arpa zones, etc.).
///
/// The match is intentionally suffix-based: `sub.apple.com` is treated as
/// noise in the same way as `apple.com` itself.
///
/// # Examples
///
/// ```
/// use packet_engine::domain::is_noise_domain;
///
/// assert!(is_noise_domain("apple.com"));
/// assert!(is_noise_domain("time.apple.com"));
/// assert!(!is_noise_domain("example.com"));
/// ```
#[must_use]
pub fn is_noise_domain(domain: &str) -> bool {
    const NOISE_SUFFIXES: &[&str] = &[
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "apple-dns.net",
        "cloudfront.net",
        "akamaiedge.net",
        "akadns.net",
        "in-addr.arpa",
        "ip6.arpa",
        "local",
    ];

    for suffix in NOISE_SUFFIXES {
        if domain == *suffix {
            return true;
        }
        // Check for a proper subdomain match without allocating:
        // domain must end with suffix AND the character immediately before
        // the suffix must be a dot (e.g. "sub.apple.com" matches "apple.com").
        let slen = suffix.len();
        if domain.len() > slen
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - slen - 1] == b'.'
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_dot_is_stripped() {
        let record = DomainRecord::from_raw_name("google.com.").expect("should be valid");
        assert_eq!(record.domain, "google.com");
    }

    #[test]
    fn name_is_lowercased() {
        let record = DomainRecord::from_raw_name("AMAZON.COM").expect("should be valid");
        assert_eq!(record.domain, "amazon.com");
    }

    #[test]
    fn noise_domain_passes_from_raw_name() {
        // from_raw_name no longer filters noise — that is the engine's job.
        assert!(
            DomainRecord::from_raw_name("apple.com").is_some(),
            "from_raw_name must accept noise domains (filtering is engine-level)"
        );
    }

    #[test]
    fn is_noise_domain_detects_noise() {
        assert!(is_noise_domain("apple.com"));
        assert!(is_noise_domain("mask.icloud.com"));
        assert!(!is_noise_domain("example.com"));
    }

    #[test]
    fn ip_literal_is_rejected() {
        assert!(
            DomainRecord::from_raw_name("192.168.1.1").is_none(),
            "IPv4 literals must be rejected"
        );
        assert!(
            DomainRecord::from_raw_name("::1").is_none(),
            "IPv6 literals must be rejected"
        );
    }

    #[test]
    fn bare_hostname_without_dot_is_rejected() {
        assert!(
            DomainRecord::from_raw_name("localhost").is_none(),
            "bare hostnames must be rejected"
        );
    }

    #[test]
    fn name_exceeding_max_length_is_rejected() {
        // Build a name that is 254 bytes, one over the 253-byte limit.
        let long_label = "a".repeat(50);
        let candidate = format!(
            "{}.{}.{}.{}.{}.com",
            long_label, long_label, long_label, long_label, long_label
        );
        assert!(
            candidate.len() > MAX_DNS_NAME_LENGTH,
            "test prerequisite: candidate must exceed limit"
        );
        assert!(DomainRecord::from_raw_name(&candidate).is_none());
    }

    #[test]
    fn with_source_overrides_default() {
        let record = DomainRecord::from_raw_name("example.com")
            .expect("should be valid")
            .with_source(DetectionSource::Sni);
        assert_eq!(record.source, DetectionSource::Sni);
    }

    #[test]
    fn default_source_is_dns() {
        let record = DomainRecord::from_raw_name("example.com").expect("should be valid");
        assert_eq!(record.source, DetectionSource::Dns);
    }

    #[test]
    fn detection_source_as_str() {
        assert_eq!(DetectionSource::Dns.as_str(), "dns");
        assert_eq!(DetectionSource::Sni.as_str(), "sni");
        assert_eq!(DetectionSource::DnsCorrelation.as_str(), "dns_correlation");
    }

    #[test]
    fn timestamp_is_positive() {
        let record = DomainRecord::from_raw_name("example.com").expect("should be valid");
        assert!(record.timestamp_ms > 0, "timestamp must be a positive Unix ms value");
    }
}
