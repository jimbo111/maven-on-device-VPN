import Foundation
import Combine

struct DailyDomainCount: Identifiable {
    let id = UUID()
    let date: Date
    let count: Int

    private static let dayFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "EEE"
        return formatter
    }()

    var dayLabel: String {
        Self.dayFormatter.string(from: date)
    }
}

struct TopDomain: Identifiable {
    let id = UUID()
    let domain: String
    let visitCount: Int
}

@MainActor
class StatsViewModel: ObservableObject {
    @Published var totalDomains: Int = 0
    @Published var totalVisits: Int = 0
    @Published var domainsToday: Int = 0
    @Published var dailyDomainCounts: [DailyDomainCount] = []
    @Published var topDomains: [TopDomain] = []

    private let notificationListener = DarwinNotificationListener(
        name: AppGroupConfig.newDomainsNotification
    )
    private var lastRefreshTime: CFAbsoluteTime = 0
    private static let refreshThrottleSeconds: CFAbsoluteTime = 3.0

    var formattedVisits: String {
        if totalVisits >= 1_000_000 {
            return String(format: "%.1fM", Double(totalVisits) / 1_000_000)
        } else if totalVisits >= 1_000 {
            return String(format: "%.1fK", Double(totalVisits) / 1_000)
        }
        return "\(totalVisits)"
    }

    init() {
        refresh()

        // Refresh stats when the tunnel writes new rows, throttled to avoid
        // excessive DB queries during active browsing.
        notificationListener.startListening { [weak self] in
            self?.throttledRefresh()
        }
    }

    private func throttledRefresh() {
        let now = CFAbsoluteTimeGetCurrent()
        guard now - lastRefreshTime >= Self.refreshThrottleSeconds else { return }
        lastRefreshTime = now
        refresh()
    }

    func refresh() {
        Task {
            let (dbStats, dailyCounts, top) = await Task.detached(priority: .userInitiated) {
                let dbStats = DatabaseReader.shared.stats()
                let dailyCounts = DatabaseReader.shared.dailyDomainCounts(days: 7)
                let top = DatabaseReader.shared.topDomains(limit: 5)
                return (dbStats, dailyCounts, top)
            }.value

            self.totalDomains = dbStats.totalDomains
            self.totalVisits = dbStats.totalVisits
            self.domainsToday = dbStats.domainsToday
            self.dailyDomainCounts = dailyCounts.map { DailyDomainCount(date: $0.date, count: $0.count) }
            self.topDomains = top.map { TopDomain(domain: $0.domain, visitCount: $0.visitCount) }
        }
    }
}
