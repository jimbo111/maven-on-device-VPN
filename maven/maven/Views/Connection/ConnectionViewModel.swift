import Foundation
import Combine
import NetworkExtension

@MainActor
class ConnectionViewModel: ObservableObject {
    @Published var status: NEVPNStatus = .disconnected
    @Published var sessionStart: Date?
    @Published var elapsedSeconds: TimeInterval = 0
    @Published var stats: EngineStats?
    @Published var dbStats: DatabaseStats?
    /// Non-nil when the last `toggleConnection()` call failed. Cleared
    /// automatically when the user dismisses the alert (H9).
    @Published var connectionError: String?
    @Published var tunnelDebugStatus: String = ""

    private var cancellables = Set<AnyCancellable>()
    private var timer: AnyCancellable?
    private var statsTimer: AnyCancellable?
    private static let statsPollingInterval: TimeInterval = 5

    init() {
        let vpnManager = VPNManager.shared
        vpnManager.$status
            .receive(on: RunLoop.main)
            .sink { [weak self] newStatus in
                self?.status = newStatus
                self?.handleStatusChange(newStatus)
            }
            .store(in: &cancellables)
    }

    // MARK: - Formatted values

    var formattedDuration: String {
        let total = Int(elapsedSeconds)
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60
        if hours > 0 {
            return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
        }
        return String(format: "%02d:%02d", minutes, seconds)
    }

    var formattedDomainsToday: String {
        guard let s = dbStats else { return "0" }
        return "\(s.domainsToday)"
    }

    var formattedPacketsScanned: String {
        guard let s = stats else { return "0" }
        let count = Int(s.packetsProcessed)
        if count >= 1_000_000 {
            return String(format: "%.1fM", Double(count) / 1_000_000)
        } else if count >= 1_000 {
            return String(format: "%.1fK", Double(count) / 1_000)
        }
        return "\(count)"
    }

    var formattedDNSQueries: String {
        guard let s = stats else { return "0" }
        return "\(s.dnsDomainsFound)"
    }

    // MARK: - Actions

    func toggleConnection() {
        Task {
            do {
                try await VPNManager.shared.toggle()
            } catch {
                connectionError = error.localizedDescription
            }
        }
    }

    func refreshStats() {
        Task {
            let result = await VPNManager.shared.requestStats()
            stats = result
            let db = await Task.detached(priority: .userInitiated) {
                DatabaseReader.shared.stats()
            }.value
            dbStats = db
            #if DEBUG
            tunnelDebugStatus = VPNManager.shared.readTunnelDebugStatus()
            if let s = result {
                print("[Maven Stats] pkts=\(s.packetsProcessed) dns=\(s.dnsDomainsFound) skip=\(s.packetsSkipped)")
            } else {
                print("[Maven Stats] requestStats returned nil")
            }
            #endif
        }
    }

    // MARK: - Private

    private func handleStatusChange(_ newStatus: NEVPNStatus) {
        if newStatus == .connected {
            // Duplicate .connected emissions (replayed initial value, repeated
            // NEVPNStatusDidChange posts) must not reset the session clock.
            // Prefer the system's connectedDate so a relaunched app shows the
            // real session duration, not time-since-app-open.
            if sessionStart == nil {
                sessionStart = VPNManager.shared.connectedDate ?? Date()
            }
            startTimer()
        } else {
            stopTimer()
            if newStatus == .disconnected {
                elapsedSeconds = 0
                sessionStart = nil
                stats = nil
            }
        }
    }

    private func startTimer() {
        timer?.cancel()
        statsTimer?.cancel()

        // 1-second timer for elapsed time display only.
        timer = Timer.publish(every: 1, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self, let start = self.sessionStart else { return }
                self.elapsedSeconds = Date().timeIntervalSince(start)
            }

        // 5-second timer for stats polling to reduce IPC overhead. (audit fix)
        refreshStats() // fetch immediately on connect
        statsTimer = Timer.publish(every: Self.statsPollingInterval, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.refreshStats()
            }
    }

    private func stopTimer() {
        timer?.cancel()
        timer = nil
        statsTimer?.cancel()
        statsTimer = nil
    }

    deinit {
        timer?.cancel()
        statsTimer?.cancel()
    }
}
