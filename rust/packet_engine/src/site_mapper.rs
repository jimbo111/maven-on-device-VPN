use std::borrow::Cow;

/// Known CDN / supporting domain → parent site associations.
///
/// Suffix-matched: `domain == suffix` OR `domain` ends with `".<suffix>"`.
/// Registrable domains (e.g. `google.com`) are absent — eTLD+1 handles them.
const KNOWN_ASSOCIATIONS: &[(&str, &str)] = &[
    // YouTube
    ("ytimg.com", "youtube.com"),
    ("googlevideo.com", "youtube.com"),
    // Meta
    ("fbcdn.net", "facebook.com"),
    ("cdninstagram.com", "instagram.com"),
    // Twitter / X
    ("twimg.com", "x.com"),
    // Netflix
    ("nflxvideo.net", "netflix.com"),
    ("nflximg.net", "netflix.com"),
    // TikTok
    ("tiktokcdn.com", "tiktok.com"),
    // Reddit
    ("redditmedia.com", "reddit.com"),
    ("redditstatic.com", "reddit.com"),
    // Discord
    ("discordapp.com", "discord.com"),
    ("discordapp.net", "discord.com"),
    // Spotify
    ("scdn.co", "spotify.com"),
    // GitHub
    ("githubusercontent.com", "github.com"),
    ("githubassets.com", "github.com"),
    // Twitch
    ("twitchcdn.net", "twitch.tv"),
    // Apple
    ("icloud.com", "apple.com"),
    ("mzstatic.com", "apple.com"),
    // Microsoft
    ("live.com", "microsoft.com"),
    ("microsoftonline.com", "microsoft.com"),
];

/// Shared CDN / analytics infrastructure — mapped to `"_infra"`.
const INFRA_DOMAINS: &[&str] = &[
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "doubleclick.net",
    "cloudfront.net",
    "akamaiedge.net",
    "cloudflare.com",
    "fastly.net",
];

/// Two-part TLD suffixes requiring three labels for a registrable domain.
const MULTI_PART_TLDS: &[&str] = &[
    ".co.uk",
    ".co.kr",
    ".co.jp",
    ".com.au",
    ".com.br",
    ".com.cn",
];

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn suffix_matches(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    let slen = suffix.len();
    domain.len() > slen
        && domain.ends_with(suffix)
        && domain.as_bytes()[domain.len() - slen - 1] == b'.'
}

/// Extracts the registrable domain (eTLD+1) from a fully qualified domain.
/// Zero allocation — returns a slice of the input.
fn extract_etld_plus_one(domain: &str) -> &str {
    if domain.is_empty() {
        return domain;
    }

    let labels_needed: usize = if MULTI_PART_TLDS
        .iter()
        .any(|tld| domain.ends_with(tld))
    {
        3
    } else {
        2
    };

    let bytes = domain.as_bytes();
    let mut dots_seen: usize = 0;
    let mut i = bytes.len();

    while i > 0 {
        i -= 1;
        if bytes[i] == b'.' {
            dots_seen += 1;
            if dots_seen == labels_needed {
                return &domain[i + 1..];
            }
        }
    }

    domain
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Maps a domain name to its canonical site using a three-layer lookup:
///
/// 1. Known CDN associations (suffix match)
/// 2. Shared infrastructure → `"_infra"`
/// 3. eTLD+1 fallback (zero allocation)
#[must_use]
pub fn map_to_site(domain: &str) -> Cow<'_, str> {
    for (suffix, parent) in KNOWN_ASSOCIATIONS {
        if suffix_matches(domain, suffix) {
            return Cow::Borrowed(parent);
        }
    }

    for infra in INFRA_DOMAINS {
        if suffix_matches(domain, infra) {
            return Cow::Borrowed("_infra");
        }
    }

    Cow::Borrowed(extract_etld_plus_one(domain))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Layer 1: known associations

    #[test]
    fn ytimg_maps_to_youtube() {
        assert_eq!(map_to_site("i.ytimg.com"), "youtube.com");
        assert_eq!(map_to_site("ytimg.com"), "youtube.com");
    }

    #[test]
    fn fbcdn_maps_to_facebook() {
        assert_eq!(map_to_site("static.fbcdn.net"), "facebook.com");
    }

    #[test]
    fn twimg_maps_to_x() {
        assert_eq!(map_to_site("video.twimg.com"), "x.com");
    }

    #[test]
    fn nflxvideo_maps_to_netflix() {
        assert_eq!(map_to_site("cdn.nflxvideo.net"), "netflix.com");
    }

    #[test]
    fn discord_variants() {
        assert_eq!(map_to_site("cdn.discordapp.com"), "discord.com");
        assert_eq!(map_to_site("gateway.discordapp.net"), "discord.com");
    }

    #[test]
    fn githubusercontent_maps_to_github() {
        assert_eq!(map_to_site("raw.githubusercontent.com"), "github.com");
    }

    // Layer 2: infrastructure

    #[test]
    fn cloudfront_maps_to_infra() {
        assert_eq!(map_to_site("d123.cloudfront.net"), "_infra");
    }

    #[test]
    fn googleapis_maps_to_infra() {
        assert_eq!(map_to_site("fonts.googleapis.com"), "_infra");
    }

    // Layer 3: eTLD+1 fallback

    #[test]
    fn www_example_com() {
        assert_eq!(map_to_site("www.example.com"), "example.com");
    }

    #[test]
    fn deep_subdomain() {
        assert_eq!(map_to_site("api.v2.stripe.com"), "stripe.com");
    }

    #[test]
    fn already_registrable() {
        let result = map_to_site("example.com");
        assert_eq!(result, "example.com");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // Multi-part TLDs

    #[test]
    fn co_uk_three_labels() {
        assert_eq!(map_to_site("www.bbc.co.uk"), "bbc.co.uk");
    }

    #[test]
    fn co_kr_three_labels() {
        assert_eq!(map_to_site("news.naver.co.kr"), "naver.co.kr");
    }

    // Edge cases

    #[test]
    fn single_label() {
        assert_eq!(map_to_site("localhost"), "localhost");
    }

    #[test]
    fn empty_string() {
        assert_eq!(map_to_site(""), "");
    }

    #[test]
    fn suffix_not_confused_with_partial() {
        assert_eq!(map_to_site("notytimg.com"), "notytimg.com");
    }
}
