import Foundation

struct DomainRecord: Identifiable, Hashable, Sendable {
    let id: Int64
    let domain: String
    let firstSeenMs: Int64
    let lastSeenMs: Int64
    let visitCount: Int
    let source: String
    let siteDomain: String

    var firstSeenDate: Date {
        Date(timeIntervalSince1970: TimeInterval(firstSeenMs) / 1000)
    }

    var lastSeenDate: Date {
        Date(timeIntervalSince1970: TimeInterval(lastSeenMs) / 1000)
    }

    private static let relativeDateFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()

    private static let mediumDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    var relativeTimeString: String {
        Self.relativeDateFormatter.localizedString(for: lastSeenDate, relativeTo: Date())
    }

    var firstSeenFormatted: String {
        Self.mediumDateFormatter.string(from: firstSeenDate)
    }

    var lastSeenFormatted: String {
        Self.mediumDateFormatter.string(from: lastSeenDate)
    }
}
