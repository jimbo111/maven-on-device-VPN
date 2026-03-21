import Foundation
import Combine
import UniformTypeIdentifiers

class SettingsViewModel: ObservableObject {
    @Published var settings: UserSettings
    @Published var showClearConfirmation: Bool = false
    @Published var showExportSheet: Bool = false
    @Published var csvFileURL: URL?
    @Published var isExporting: Bool = false
    @Published var exportError: String?

    var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(version) (\(build))"
    }

    init(settings: UserSettings = UserSettings()) {
        self.settings = settings
    }

    func exportCSV() {
        guard !isExporting else { return }
        isExporting = true
        exportError = nil

        Task.detached(priority: .userInitiated) { [weak self] in
            let domains = DatabaseReader.shared.recentDomains(limit: 10000)
            guard !domains.isEmpty else {
                await MainActor.run { self?.isExporting = false }
                return
            }

            var csv = "domain,visit_count,first_seen,last_seen,source\n"
            let formatter = ISO8601DateFormatter()

            for d in domains {
                // Escape embedded quotes for CSV safety
                let escaped = d.domain.replacingOccurrences(of: "\"", with: "\"\"")
                let firstSeen = formatter.string(from: d.firstSeenDate)
                let lastSeen = formatter.string(from: d.lastSeenDate)
                csv += "\"\(escaped)\",\(d.visitCount),\(firstSeen),\(lastSeen),\(d.source)\n"
            }

            // Use a unique filename to avoid collisions with prior exports
            let filename = "maven_domains_\(UUID().uuidString).csv"
            let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(filename)

            do {
                try csv.write(to: tempURL, atomically: true, encoding: .utf8)
                await MainActor.run {
                    self?.csvFileURL = tempURL
                    self?.showExportSheet = true
                    self?.isExporting = false
                }
            } catch {
                await MainActor.run {
                    self?.exportError = "Export failed: \(error.localizedDescription)"
                    self?.isExporting = false
                }
            }
        }
    }

    /// Call when the share sheet is dismissed to clean up the temporary file.
    func cleanupExportFile() {
        guard let url = csvFileURL else { return }
        try? FileManager.default.removeItem(at: url)
        csvFileURL = nil
    }

    /// Push the filterNoise setting to the running tunnel extension via IPC.
    func syncNoiseFilter(enabled: Bool) {
        Task {
            _ = await VPNManager.shared.sendMessage(Data([0x04, enabled ? 0x01 : 0x00]))
        }
    }

    func clearAllData() {
        // Truncate tables via SQL instead of deleting the file.
        // The Rust engine in the extension may have the DB open; deleting
        // the file would leave it writing to a ghost inode.
        DatabaseReader.shared.truncateAllData()

        // Post the same Darwin notification the extension uses so that all
        // views (DomainListView, StatsView) re-query and show empty state.
        let name = CFNotificationName(AppGroupConfig.newDomainsNotification as CFString)
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            name, nil, nil, true
        )

        showClearConfirmation = false
    }
}
