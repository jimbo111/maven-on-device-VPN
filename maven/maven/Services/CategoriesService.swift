import Foundation

final class CategoriesService {
    static let shared = CategoriesService()

    private var domainToCategory: [String: (key: String, label: String, icon: String)] = [:]

    private init() {
        for cat in Self.categories {
            for domain in cat.domains {
                domainToCategory[domain] = (key: cat.key, label: cat.label, icon: cat.icon)
            }
        }
    }

    private static let categories: [(key: String, label: String, icon: String, domains: [String])] = [
        ("social", "Social Media", "person.2.fill", [
            "facebook.com", "instagram.com", "x.com", "tiktok.com", "reddit.com"
        ]),
        ("entertainment", "Entertainment", "play.circle.fill", [
            "youtube.com", "netflix.com", "spotify.com", "twitch.tv"
        ]),
        ("shopping", "Shopping", "cart.fill", [
            "amazon.com", "ebay.com", "walmart.com"
        ]),
        ("communication", "Communication", "bubble.left.and.bubble.right.fill", [
            "whatsapp.com", "discord.com", "slack.com", "zoom.us"
        ]),
        ("search", "Search", "magnifyingglass", [
            "google.com", "bing.com", "duckduckgo.com"
        ]),
        ("productivity", "Productivity", "hammer.fill", [
            "github.com", "notion.so", "figma.com"
        ]),
        ("news", "News", "newspaper.fill", [
            "cnn.com", "bbc.com", "nytimes.com"
        ]),
        ("gaming", "Gaming", "gamecontroller.fill", [
            "steampowered.com", "epicgames.com", "roblox.com"
        ]),
    ]

    /// Look up the category for a site domain. Returns nil if uncategorized.
    func categorize(_ siteDomain: String) -> (key: String, label: String, icon: String)? {
        domainToCategory[siteDomain]
    }
}
