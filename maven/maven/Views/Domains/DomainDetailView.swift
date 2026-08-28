import SwiftUI

struct DomainDetailView: View {
    let domain: DomainRecord

    @State private var visits: [VisitRecord] = []
    @State private var isLoading = true

    var body: some View {
        List {
            // Domain header
            Section {
                VStack(spacing: 8) {
                    Image(systemName: "globe")
                        .font(.system(size: 40))
                        .foregroundColor(.accentColor)

                    Text(domain.domain)
                        .font(.title2.bold())
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .listRowBackground(Color.clear)
            }

            // Stats
            Section("Overview") {
                if !domain.siteDomain.isEmpty && domain.siteDomain != domain.domain {
                    DetailRow(label: "Site", value: domain.siteDomain)
                }
                if let cat = CategoriesService.shared.categorize(domain.siteDomain.isEmpty ? domain.domain : domain.siteDomain) {
                    HStack {
                        Text("Category")
                            .foregroundColor(.secondary)
                        Spacer()
                        Label(cat.label, systemImage: cat.icon)
                            .font(.body)
                            .fontWeight(.medium)
                    }
                }
                DetailRow(label: "Total Visits", value: "\(domain.visitCount)")
                DetailRow(label: "First Seen", value: domain.firstSeenFormatted)
                DetailRow(label: "Last Seen", value: domain.lastSeenFormatted)
                DetailRow(label: "Detection Source", value: domain.sourceLabel)
            }

            // Recent visits from database
            Section("Recent Visits") {
                if isLoading {
                    HStack {
                        Spacer()
                        ProgressView()
                        Spacer()
                    }
                } else if visits.isEmpty {
                    Text("No visit history recorded yet.")
                        .foregroundColor(.secondary)
                        .font(.subheadline)
                } else {
                    ForEach(visits) { visit in
                        HStack {
                            Image(systemName: "clock")
                                .foregroundColor(.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(formattedDate(visit.date))
                                    .font(.subheadline)
                            }
                            Spacer()
                            Text(visit.source)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
        }
        .navigationTitle(domain.domain)
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await loadVisits()
        }
    }

    // MARK: - Data Loading

    private func loadVisits() async {
        let fetched = await Task.detached(priority: .userInitiated) {
            DatabaseReader.shared.visits(forDomainId: domain.id)
        }.value

        visits = fetched
        isLoading = false
    }

    // MARK: - Formatting

    private static let visitDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private func formattedDate(_ date: Date) -> String {
        Self.visitDateFormatter.string(from: date)
    }
}

// MARK: - Detail Row

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
    }
}

#Preview {
    NavigationStack {
        DomainDetailView(domain: DomainRecord(
            id: 1,
            domain: "i.ytimg.com",
            firstSeenMs: Int64((Date().timeIntervalSince1970 - 86400 * 5) * 1000),
            lastSeenMs: Int64((Date().timeIntervalSince1970 - 3600) * 1000),
            visitCount: 42,
            source: "dns",
            siteDomain: "youtube.com"
        ))
    }
}
