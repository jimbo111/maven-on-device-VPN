import Foundation
import Combine
import NetworkExtension
import os.log

// MARK: - Supporting types

/// Errors that VPNManager can throw to its callers.
enum VPNManagerError: Error, LocalizedError {
    case noConfiguration
    case managerLoadFailed(Error)
    case saveFailed(Error)
    case connectFailed(Error)
    case messageFailed

    var errorDescription: String? {
        switch self {
        case .noConfiguration:
            return "No VPN configuration found. Call saveConfiguration() first."
        case .managerLoadFailed(let err):
            return "Failed to load VPN preferences: \(err.localizedDescription)"
        case .saveFailed(let err):
            return "Failed to save VPN configuration: \(err.localizedDescription)"
        case .connectFailed(let err):
            return "Failed to start tunnel: \(err.localizedDescription)"
        case .messageFailed:
            return "Failed to deliver message to tunnel extension."
        }
    }
}

/// A decoded snapshot of the engine counters sent over the IPC channel.
struct EngineStats: Sendable {
    var packetsProcessed: UInt64
    var dnsDomainsFound: UInt64
    var packetsSkipped: UInt64
}

// MARK: - VPNManager

/// Manages the lifecycle of the Maven NETunnelProviderManager and provides a
/// high-level async API to the SwiftUI layer.
///
/// All published state is updated on the main actor; the class itself is
/// `@MainActor` so every method runs on the main thread unless annotated
/// otherwise.
@MainActor
final class VPNManager: ObservableObject {

    static let shared = VPNManager()

    @Published var status: NEVPNStatus = .disconnected
    @Published var isLoading = false

    /// The system-reported time the tunnel connected, if currently connected.
    var connectedDate: Date? {
        manager?.connection.connectedDate
    }

    private var manager: NETunnelProviderManager?
    private var statusObserver: Any?
    private let log = OSLog(subsystem: "com.jimmykim.maven", category: "VPNManager")

    // MARK: Init

    private init() {
        // NotificationCenter subscription must be set up from a nonisolated
        // context so we can bridge into @MainActor via Task.
        setupStatusObserver()
        Task { await loadManager() }
    }

    // MARK: - Configuration

    /// Loads the first saved NETunnelProviderManager from system preferences.
    func loadManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            os_log("loadManager: found %d saved configurations", log: log, type: .info, managers.count)
            self.manager = managers.first
            if let connection = manager?.connection {
                self.status = connection.status
                os_log("loadManager: restored status=%d", log: log, type: .info, connection.status.rawValue)
            }
        } catch {
            os_log("loadManager failed: %{public}@", log: log, type: .error, error.localizedDescription)
        }
    }

    /// Creates and persists a new NETunnelProviderManager pointed at the
    /// packet-tunnel extension.
    func createNewManager() async throws {
        let newManager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "jimmy.maven.tunnel"
        proto.serverAddress = "localhost"
        newManager.protocolConfiguration = proto
        newManager.localizedDescription = "Maven"
        newManager.isEnabled = true
        self.manager = newManager
    }

    /// Saves the current manager configuration to system preferences.
    func saveConfiguration() async throws {
        if manager == nil {
            os_log("saveConfiguration: no existing manager, creating new one", log: log, type: .info)
            try await createNewManager()
        }
        guard let manager = manager else { throw VPNManagerError.noConfiguration }
        do {
            os_log("saveConfiguration: saving to preferences...", log: log, type: .info)
            try await manager.saveToPreferences()
            os_log("saveConfiguration: reloading from preferences...", log: log, type: .info)
            try await manager.loadFromPreferences()
            os_log("saveConfiguration: success", log: log, type: .info)
        } catch {
            os_log("saveConfiguration failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw VPNManagerError.saveFailed(error)
        }
    }

    // MARK: - Connection control

    /// Starts the VPN tunnel, creating a configuration if one does not yet exist.
    func connect() async throws {
        isLoading = true
        defer { isLoading = false }

        if manager == nil {
            os_log("connect: no manager, loading...", log: log, type: .info)
            await loadManager()
        }
        if manager == nil {
            os_log("connect: still no manager, creating + saving...", log: log, type: .info)
            try await saveConfiguration()
        }
        guard let manager = manager else {
            throw VPNManagerError.noConfiguration
        }
        do {
            os_log("connect: starting VPN tunnel...", log: log, type: .info)
            try manager.connection.startVPNTunnel()
        } catch {
            os_log("connect failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw VPNManagerError.connectFailed(error)
        }
    }

    /// Stops the VPN tunnel.
    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Connects if currently disconnected, disconnects if currently connected.
    func toggle() async throws {
        switch status {
        case .disconnected, .invalid:
            try await connect()
        case .connected, .connecting, .reasserting:
            disconnect()
        case .disconnecting:
            break // Already on the way out.
        @unknown default:
            break
        }
    }

    // MARK: - IPC messaging

    /// Sends a raw message to the tunnel extension and returns the response.
    ///
    /// - Parameter data: The message payload.
    /// - Returns: The response data, or `nil` if the extension returned nothing.
    func sendMessage(_ data: Data) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            os_log("sendMessage: no NETunnelProviderSession (manager=%{public}@, connection=%{public}@)", log: log, type: .error,
                   manager == nil ? "nil" : "exists",
                   manager?.connection == nil ? "nil" : String(describing: type(of: manager!.connection)))
            return nil
        }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { responseData in
                    continuation.resume(returning: responseData)
                }
            } catch {
                os_log("sendMessage failed: %{public}@", log: self.log, type: .error, error.localizedDescription)
                continuation.resume(returning: nil)
            }
        }
    }

    /// Asks the tunnel extension to flush pending database writes.
    func requestFlush() async {
        _ = await sendMessage(Data([0x01]))
    }

    /// Fetches the current engine statistics from the tunnel extension.
    ///
    /// - Returns: A decoded `EngineStats` struct, or `nil` if the request
    ///   failed or the extension is not running.
    func requestStats() async -> EngineStats? {
        guard let response = await sendMessage(Data([0x02])) else {
            os_log("requestStats: sendMessage returned nil (extension not responding)", log: log, type: .error)
            return nil
        }
        guard response.count == 24 else {
            os_log("requestStats: unexpected response size %d (expected 24)", log: log, type: .error, response.count)
            return nil
        }

        func readUInt64(at offset: Int) -> UInt64 {
            var value: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &value) { dest in
                response.copyBytes(to: dest, from: offset..<(offset + 8))
            }
            return value
        }

        return EngineStats(
            packetsProcessed: readUInt64(at: 0),
            dnsDomainsFound:  readUInt64(at: 8),
            packetsSkipped:   readUInt64(at: 16)
        )
    }

    // MARK: - Debug

    /// Read the extension's debug status breadcrumbs.
    func readTunnelDebugStatus() -> String {
        let statusPath = AppGroupConfig.containerURL.appendingPathComponent("tunnel_status.txt").path
        return (try? String(contentsOfFile: statusPath, encoding: .utf8)) ?? "No tunnel status file found"
    }

    // MARK: - Status observation

    /// Wires up the NEVPNStatusDidChange notification on a nonisolated path so
    /// that the @MainActor class can safely call this from its `init`.
    nonisolated private func setupStatusObserver() {
        let observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let self else { return }
            guard let connection = notification.object as? NEVPNConnection else { return }
            let newStatus = connection.status
            Task { @MainActor in
                self.status = newStatus
            }
        }
        // Store the token; because we are nonisolated we cannot assign to the
        // @MainActor-isolated `statusObserver` directly — use a Task to hop
        // back onto the main actor.
        Task { @MainActor in
            self.statusObserver = observer
        }
    }

}
