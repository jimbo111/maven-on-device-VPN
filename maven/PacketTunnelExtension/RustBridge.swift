import Foundation

// MARK: - Errors

/// Errors thrown by RustPacketEngine.
enum RustEngineError: Error, LocalizedError {
    case initFailed(String)
    case processingFailed(String)

    var errorDescription: String? {
        switch self {
        case .initFailed(let msg):      return "Rust engine init failed: \(msg)"
        case .processingFailed(let msg): return "Rust engine processing failed: \(msg)"
        }
    }
}

// MARK: - Supporting types

extension RustPacketEngine {

    /// The outcome of processing a single packet.
    enum ProcessResult {
        /// Forward the original packet unchanged.
        case forward
        /// Replace the packet with the provided data.
        case replace(Data)
    }

    /// A snapshot of engine counters returned by `packet_engine_get_stats`.
    struct Stats {
        var packetsProcessed: UInt64
        var dnsDomainsFound: UInt64
        var packetsSkipped: UInt64
    }
}

// MARK: - RustPacketEngine

/// Swift wrapper around the C FFI exposed by the Rust packet_engine crate.
///
/// - Important: This class is **not** thread-safe. Use it exclusively from the
///   packet-loop thread inside the Network Extension, which is inherently
///   single-threaded.
final class RustPacketEngine {

    // The opaque pointer returned by `packet_engine_init`.
    // Optional so that `shutdown()` can nil it out, preventing a double-free
    // in `deinit` (C1/C2).
    private var handle: OpaquePointer?

    // A reusable output buffer sized for the maximum expected packet.
    // Avoids a heap allocation on every call to `processPacket`.
    private var outputBuffer: [UInt8]

    private static let maxPacketSize = 65_536

    // MARK: Lifecycle

    /// Initialises the Rust engine, opening or creating the SQLite database at
    /// `dbPath`.
    ///
    /// - Parameter dbPath: Absolute path to the shared-group SQLite file.
    /// - Throws: `RustEngineError.initFailed` when the C layer returns nil.
    init(dbPath: String) throws {
        guard let ptr = packet_engine_init(dbPath) else {
            let message = RustPacketEngine.consumeLastError() ?? "unknown error"
            throw RustEngineError.initFailed(message)
        }
        handle = ptr
        outputBuffer = [UInt8](repeating: 0, count: RustPacketEngine.maxPacketSize)
    }

    deinit {
        // Only destroy if shutdown() was not already called (prevents double-free).
        if let h = handle {
            packet_engine_destroy(h)
        }
    }

    // MARK: Public API

    /// Shuts the engine down and releases its resources.
    ///
    /// After calling this method the instance must not be used again.
    /// Sets `handle` to nil so `deinit` does not double-free.
    func shutdown() {
        guard let h = handle else { return }
        packet_engine_destroy(h)
        handle = nil
    }

    /// Processes a single network packet through the Rust engine.
    ///
    /// - Parameter packetData: The raw IP packet bytes read from `packetFlow`.
    /// - Returns: `.forward` to pass the original packet on, or
    ///   `.replace(Data)` to substitute a modified version.
    ///   Returns `.forward` immediately if the engine has been shut down.
    func processPacket(_ packetData: Data) -> ProcessResult {
        guard let handle = self.handle else { return .forward }

        var outLen: UInt = 0

        let result: Int32 = packetData.withUnsafeBytes { rawBuf in
            guard let baseAddress = rawBuf.baseAddress else { return -1 }
            let packetPtr = baseAddress.assumingMemoryBound(to: UInt8.self)
            return outputBuffer.withUnsafeMutableBufferPointer { outBuf in
                packet_engine_process(
                    handle,
                    packetPtr,
                    UInt(packetData.count),
                    outBuf.baseAddress,
                    UInt(outBuf.count),
                    &outLen
                )
            }
        }

        switch result {
        case 0:
            // Engine signals: forward the original packet.
            return .forward
        case 1:
            // Engine signals: use the modified packet in outputBuffer[0..<outLen].
            let replaced = Data(outputBuffer[0..<Int(outLen)])
            return .replace(replaced)
        default:
            // An error occurred; forward the original to avoid dropping traffic.
            return .forward
        }
    }

    /// Flushes any pending batch-insert operations to the SQLite database.
    func flush() {
        guard let handle = self.handle else { return }
        packet_engine_flush(handle)
    }

    /// Enables or disables noise domain filtering inside the engine.
    ///
    /// When enabled (the default), well-known noise domains (Apple
    /// infrastructure, CDNs, mDNS, etc.) are silently dropped before
    /// being written to SQLite.
    func setNoiseFilter(enabled: Bool) {
        guard let handle = self.handle else { return }
        packet_engine_set_noise_filter(handle, enabled)
    }

    /// Returns a snapshot of the engine's internal counters.
    func getStats() -> Stats {
        guard let handle = self.handle else {
            return Stats(packetsProcessed: 0, dnsDomainsFound: 0, packetsSkipped: 0)
        }
        let ffi = packet_engine_get_stats(handle)
        return Stats(
            packetsProcessed: ffi.packets_processed,
            dnsDomainsFound: ffi.dns_domains_found,
            packetsSkipped: ffi.packets_skipped
        )
    }

    // MARK: Private helpers

    /// Drains the thread-local last-error string set by the C layer.
    ///
    /// The returned string is owned by Swift; the underlying C allocation is
    /// freed by `packet_engine_free_string`.
    private static func consumeLastError() -> String? {
        guard let ptr = packet_engine_last_error() else { return nil }
        let message = String(cString: ptr)
        packet_engine_free_string(ptr)
        return message
    }
}
