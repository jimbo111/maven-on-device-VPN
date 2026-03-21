import Foundation
import Combine

@MainActor
class DomainListViewModel: ObservableObject {

    enum SortOption: String, CaseIterable, Identifiable {
        case recent = "Recent"
        case visitCount = "Most Visited"
        case alphabetical = "Alphabetical"

        var id: String { rawValue }
    }

    struct DomainGroup: Identifiable {
        let key: String
        let domains: [DomainRecord]
        var id: String { key }
    }

    @Published var allDomains: [DomainRecord] = []
    @Published var groupedDomains: [DomainGroup] = []
    @Published var searchText: String = ""
    @Published var sortOption: SortOption = .recent

    private var cancellables = Set<AnyCancellable>()
    private let notificationListener = DarwinNotificationListener(
        name: AppGroupConfig.newDomainsNotification
    )
    private var lastFetchTime: CFAbsoluteTime = 0
    private static let fetchThrottleSeconds: CFAbsoluteTime = 1.0

    init() {
        fetchDomains()

        // Re-filter when the user types or changes sort.
        Publishers.CombineLatest($searchText, $sortOption)
            .debounce(for: .milliseconds(200), scheduler: RunLoop.main)
            .sink { [weak self] _, _ in
                self?.applyFilters()
            }
            .store(in: &cancellables)

        // Listen for Darwin notifications from the packet tunnel extension.
        // Throttled to at most once per second to avoid excessive DB reads.
        // The callback fires on DispatchQueue.main; hop to @MainActor via Task
        // so the compiler can verify isolation.
        notificationListener.startListening { [weak self] in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                let now = CFAbsoluteTimeGetCurrent()
                guard now - self.lastFetchTime >= Self.fetchThrottleSeconds else { return }
                self.lastFetchTime = now
                self.fetchDomains()
            }
        }
    }

    // MARK: - Public

    func sortBy(_ option: SortOption) {
        sortOption = option
    }

    func refresh() {
        fetchDomains()
    }

    // MARK: - Data Fetching

    private func fetchDomains() {
        // Capture searchText and sortOption before dispatching so the
        // callback uses the same values the query used, preventing
        // stale-data glitches when the user types quickly.
        let capturedSearch = self.searchText
        let capturedSort = self.sortOption

        Task {
            let domains = await Task.detached(priority: .userInitiated) {
                if capturedSearch.isEmpty {
                    return DatabaseReader.shared.recentDomains()
                } else {
                    return DatabaseReader.shared.searchDomains(query: capturedSearch)
                }
            }.value

            // Discard the result if the user has already changed the
            // query or sort since this fetch started.
            guard self.searchText == capturedSearch,
                  self.sortOption == capturedSort else { return }
            self.allDomains = domains
            self.applyFilters()
        }
    }

    // MARK: - Filtering & Grouping

    private func applyFilters() {
        var filtered = allDomains

        // Local search filter (already fetched matching rows from DB, but
        // the debounced pipeline may run on stale data so double-filter).
        if !searchText.isEmpty {
            filtered = filtered.filter { $0.domain.localizedCaseInsensitiveContains(searchText) }
        }

        // Sort
        switch sortOption {
        case .recent:
            filtered.sort { $0.lastSeenMs > $1.lastSeenMs }
        case .visitCount:
            filtered.sort { $0.visitCount > $1.visitCount }
        case .alphabetical:
            filtered.sort { $0.domain.localizedCaseInsensitiveCompare($1.domain) == .orderedAscending }
        }

        // Group by date
        groupedDomains = groupByDate(filtered)
    }

    private func groupByDate(_ domains: [DomainRecord]) -> [DomainGroup] {
        let calendar = Calendar.current

        var todayDomains: [DomainRecord] = []
        var yesterdayDomains: [DomainRecord] = []
        var earlierDomains: [DomainRecord] = []

        for domain in domains {
            if calendar.isDateInToday(domain.lastSeenDate) {
                todayDomains.append(domain)
            } else if calendar.isDateInYesterday(domain.lastSeenDate) {
                yesterdayDomains.append(domain)
            } else {
                earlierDomains.append(domain)
            }
        }

        var groups: [DomainGroup] = []
        if !todayDomains.isEmpty {
            groups.append(DomainGroup(key: "Today", domains: todayDomains))
        }
        if !yesterdayDomains.isEmpty {
            groups.append(DomainGroup(key: "Yesterday", domains: yesterdayDomains))
        }
        if !earlierDomains.isEmpty {
            groups.append(DomainGroup(key: "Earlier", domains: earlierDomains))
        }

        return groups
    }
}
