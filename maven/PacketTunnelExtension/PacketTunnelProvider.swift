import NetworkExtension
import Network
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "com.jimmykim.maven.tunnel", category: "PacketTunnel")

    /// Single serial queue that protects ALL mutable state in this class.
    /// Every access to rustEngine, dnsForwarder, isProcessing, isStopping,
    /// and lastNotificationTime MUST happen on this queue.  (H4+M3+M4)
    private let queue = DispatchQueue(label: "com.jimmykim.maven.tunnel.state")

    /// Serializes ALL calls into the RustPacketEngine instance.
    /// The engine is not thread-safe — every call to processPacket, flush,
    /// getStats, setNoiseFilter, and setEchDowngrade MUST run on this queue.
    private let engineQueue = DispatchQueue(label: "com.jimmykim.maven.tunnel.engine")

    // -- Protected by `queue` --
    private var rustEngine: RustPacketEngine?
    private var dnsForwarder: DNSForwarder?
    private var tcpDNSForwarder: TCPDNSForwarder?
    private var icmpForwarder: ICMPForwarder?
    private var isProcessing = false
    private var isStopping = false
    private var lastNotificationTime: CFAbsoluteTime = 0 // (M2) protected by queue

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        #if DEBUG
        NSLog("[Maven Tunnel] startTunnel called")
        #endif
        os_log("Starting tunnel", log: log, type: .default)

        // Clear old debug status file so we only see fresh breadcrumbs
        let statusPath = AppGroupConfig.containerURL.appendingPathComponent("tunnel_status.txt").path
        try? FileManager.default.removeItem(atPath: statusPath)

        // (L4) Reset isStopping at the top of startTunnel so a previous
        // stop-then-start cycle doesn't leave stale state.
        queue.sync { isStopping = false }

        let settings = createTunnelSettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }

            // Check on the state queue whether we've been stopped in the meantime.
            let stopping = self.queue.sync { self.isStopping }
            if stopping {
                os_log("startTunnel callback fired after stopTunnel; aborting.", log: self.log, type: .default)
                completionHandler(NEVPNError(.configurationDisabled))
                return
            }

            if let error = error {
                os_log("Failed to set tunnel settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }

            // Initialize Rust engine
            do {
                let dbPath = AppGroupConfig.databasePath
                self.writeDebugStatus("init_start: dbPath=\(dbPath)")

                let engine = try RustPacketEngine(dbPath: dbPath)
                self.writeDebugStatus("engine_ok: Rust engine initialized")

                // Verify DB file was created
                let dbExists = FileManager.default.fileExists(atPath: dbPath)
                self.writeDebugStatus("db_exists=\(dbExists) at \(dbPath)")

                // Initialize DNS forwarders (UDP fast path + TCP fallback)
                let forwarder = DNSForwarder(packetFlow: self.packetFlow, log: self.log)
                let tcpForwarder = TCPDNSForwarder(packetFlow: self.packetFlow, log: self.log)
                let icmpForwarder = ICMPForwarder(packetFlow: self.packetFlow, log: self.log)

                // Apply user settings from shared UserDefaults.
                let filterNoise = AppGroupConfig.sharedDefaults.object(forKey: "filterNoise") as? Bool ?? true
                engine.setNoiseFilter(enabled: filterNoise)

                self.queue.sync {
                    self.rustEngine = engine
                    self.dnsForwarder = forwarder
                    self.tcpDNSForwarder = tcpForwarder
                    self.icmpForwarder = icmpForwarder
                    self.isProcessing = true
                }

                self.startPacketProcessing()
                completionHandler(nil)
                self.writeDebugStatus("tunnel_started: processing packets")
                #if DEBUG
                NSLog("[Maven Tunnel] Tunnel started successfully, processing packets")
                #endif
            } catch {
                self.writeDebugStatus("engine_FAILED: \(error.localizedDescription)")
                os_log("Failed to init Rust engine: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel, reason: %d", log: log, type: .default, reason.rawValue)

        queue.sync {
            isStopping = true
            isProcessing = false
        }

        // Grab references then nil them out under the lock.
        let (engine, forwarder, tcpForwarder, icmp) = queue.sync { () -> (RustPacketEngine?, DNSForwarder?, TCPDNSForwarder?, ICMPForwarder?) in
            let e = rustEngine
            let f = dnsForwarder
            let t = tcpDNSForwarder
            let i = icmpForwarder
            dnsForwarder = nil
            tcpDNSForwarder = nil
            icmpForwarder = nil
            rustEngine = nil
            return (e, f, t, i)
        }

        forwarder?.shutdown()
        tcpForwarder?.shutdown()
        icmp?.shutdown()
        // Dispatch flush + shutdown through engineQueue so they cannot overlap
        // with any in-flight processPacket calls from DNS response callbacks.
        engineQueue.sync { engine?.flush() }
        notifyAppOfNewDomains()
        engineQueue.sync { engine?.shutdown() }

        os_log("Tunnel stopped", log: log, type: .default)
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let command = messageData.first else {
            completionHandler?(nil)
            return
        }

        switch command {
        case 0x01:
            let engine = queue.sync { rustEngine }
            engineQueue.sync { engine?.flush() }
            notifyAppOfNewDomains()
            completionHandler?(Data([0x00]))
        case 0x02:
            let engine = queue.sync { rustEngine }
            if let engine = engine {
                // The app polls stats every few seconds while foregrounded.
                // Flush here too, so domains pending in the engine's batch
                // buffer reach SQLite even when traffic has gone quiet
                // (maybe_flush only runs while packets are arriving).
                engineQueue.sync { engine.flush() }
                notifyAppOfNewDomains()
                let stats = engineQueue.sync { engine.getStats() }
                writeDebugStatus("ipc_stats: pkts=\(stats.packetsProcessed) dns=\(stats.dnsDomainsFound)")
                var response = Data(capacity: 24)
                withUnsafeBytes(of: stats.packetsProcessed) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.dnsDomainsFound)  { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.packetsSkipped)   { response.append(contentsOf: $0) }
                completionHandler?(response)
            } else {
                completionHandler?(nil)
            }
        case 0x04: // Set noise filter
            if messageData.count >= 2 {
                let engine = queue.sync { rustEngine }
                engineQueue.sync { engine?.setNoiseFilter(enabled: messageData[1] == 0x01) }
            }
            completionHandler?(Data([0x00]))
        default:
            completionHandler?(nil)
        }
    }

    // MARK: - Tunnel Configuration

    /// Creates IPv4-only tunnel settings. (C1) IPv6 removed entirely to avoid
    /// the need for a proper UDP checksum in IPv6 response packets.
    private func createTunnelSettings() -> NEPacketTunnelNetworkSettings {
        // CGNAT-range addresses (RFC 6598) with a host mask: never collide with
        // home/office LANs (192.168.x.x would), and the /32 mask keeps the
        // interface from claiming an entire subnet as a connected route.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "100.64.0.1")

        // IPv4: route ONLY DNS server traffic through tunnel.
        let ipv4 = NEIPv4Settings(addresses: ["100.64.0.2"], subnetMasks: ["255.255.255.255"])
        let dns1Route = NEIPv4Route(destinationAddress: "8.8.8.8", subnetMask: "255.255.255.255")
        let dns2Route = NEIPv4Route(destinationAddress: "8.8.4.4", subnetMask: "255.255.255.255")
        ipv4.includedRoutes = [dns1Route, dns2Route]
        settings.ipv4Settings = ipv4

        // (C1) No IPv6 settings — all DNS goes through IPv4.

        // Force ALL system DNS through our tunnel.
        // matchDomains = [""] (empty string) is the special value meaning
        // "match all domains" — without this, iOS may bypass the tunnel's
        // DNS settings in a split-tunnel configuration.
        let dns = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: 1500)

        return settings
    }

    // MARK: - Debug Status (writes breadcrumbs to App Group for main app to read)

    private func writeDebugStatus(_ message: String) {
        let statusPath = AppGroupConfig.containerURL.appendingPathComponent("tunnel_status.txt").path
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "[\(timestamp)] \(message)\n"
        if FileManager.default.fileExists(atPath: statusPath) {
            if let handle = FileHandle(forWritingAtPath: statusPath) {
                handle.seekToEndOfFile()
                handle.write(Data(line.utf8))
                handle.closeFile()
            }
        } else {
            try? line.write(toFile: statusPath, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Darwin Notifications

    private func notifyAppOfNewDomains() {
        let name = CFNotificationName(AppGroupConfig.newDomainsNotification as CFString)
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            name,
            nil,
            nil,
            true
        )
    }

    /// Throttled notification — at most once per second. Must be called on `queue`.
    private func maybeNotifyApp() {
        let now = CFAbsoluteTimeGetCurrent()
        if now - lastNotificationTime >= 1.0 {
            lastNotificationTime = now
            notifyAppOfNewDomains()
        }
    }

    // MARK: - Packet Processing

    private var totalPacketsReceived: Int = 0 // protected by `queue`

    private func startPacketProcessing() {
        readPacketsFromTunnel()
    }

    private func readPacketsFromTunnel() {
        let processing = queue.sync { isProcessing }
        guard processing else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }

            // Snapshot state under the lock once per batch.
            let (engine, forwarder, tcpForwarder, icmpForwarder, active) = self.queue.sync {
                (self.rustEngine, self.dnsForwarder, self.tcpDNSForwarder, self.icmpForwarder, self.isProcessing)
            }
            guard active else { return }

            // Log first batch and every 100 packets for debugging.
            // totalPacketsReceived is protected by queue.
            let totalSoFar = self.queue.sync { () -> Int in
                self.totalPacketsReceived += packets.count
                return self.totalPacketsReceived
            }
            if totalSoFar <= packets.count || totalSoFar % 100 < packets.count {
                self.writeDebugStatus("packets_received: batch=\(packets.count) total=\(totalSoFar)")
            }

            let engineQueue = self.engineQueue
            for (i, packetData) in packets.enumerated() {
                // Run through Rust engine for domain extraction + ECH downgrade.
                // All engine calls are serialized on engineQueue (engine is NOT thread-safe).
                var outPacket = packetData
                if let engine = engine {
                    let result = engineQueue.sync { engine.processPacket(packetData) }
                    if case .replace(let modified) = result {
                        outPacket = modified
                    }
                }

                // Route to the matching forwarder: TCP port 53 goes through the
                // userspace TCP relay (DNS-over-TCP fallback after a truncated
                // UDP response), ICMP echo through the ping proxy, everything
                // else through the UDP fast path.
                // The processResponse closure serializes the response-path engine
                // call on the same engineQueue, preventing concurrent access.
                if outPacket.count > 9, outPacket[0] >> 4 == 4, outPacket[9] == 6 {
                    tcpForwarder?.handlePacket(outPacket, protocolFamily: protocols[i])
                } else if outPacket.count > 9, outPacket[0] >> 4 == 4, outPacket[9] == 1 {
                    icmpForwarder?.handlePacket(outPacket, protocolFamily: protocols[i])
                } else {
                    forwarder?.forwardDNSPacket(outPacket, protocolFamily: protocols[i]) { responsePacket in
                        guard let engine = engine else { return responsePacket }
                        return engineQueue.sync {
                            let result = engine.processPacket(responsePacket)
                            if case .replace(let modified) = result {
                                return modified
                            }
                            return responsePacket
                        }
                    }
                }
            }

            self.queue.async { self.maybeNotifyApp() }
            self.readPacketsFromTunnel()
        }
    }
}

// MARK: - DNS Forwarder

/// Forwards DNS packets from the TUN to real DNS servers and writes responses back.
///
/// Uses a single persistent UDP connection to 8.8.8.8:53, multiplexing queries
/// by DNS transaction ID (first 2 bytes of the DNS payload). This eliminates the
/// per-query overhead of creating/tearing down NWConnection objects (socket alloc,
/// bind, teardown, closure allocations).
///
/// If the connection fails, all pending queries are dropped and the connection is
/// lazily recreated on the next incoming query.
class DNSForwarder {
    private let packetFlow: NEPacketTunnelFlow
    private let log: OSLog

    /// Serial queue protecting ALL mutable state.
    private let queue: DispatchQueue

    /// The single long-lived UDP connection to 8.8.8.8:53.
    /// nil when not yet created or after a failure (lazy reconnect on next query).
    private var connection: NWConnection?

    /// In-flight queries keyed by DNS transaction ID.
    private var pendingQueries: [UInt16: PendingQuery] = [:]

    /// Back-pressure cap on in-flight queries.
    private static let maxPendingQueries = 64

    /// Per-query timeout in seconds.
    private static let queryTimeoutSeconds: Double = 5.0

    /// Set to true on shutdown to reject new queries.
    private var isShutdown = false

    /// A DNS query waiting for its response.
    ///
    /// Keyed in `pendingQueries` by the *upstream* transaction ID, which may
    /// have been rewritten to avoid collisions between concurrent clients.
    /// `originalTxnID` is restored into the response before writing it back.
    private struct PendingQuery {
        let originalPacket: Data
        let ipHeaderLen: Int
        let srcPort: UInt16
        let originalTxnID: UInt16
        let protocolFamily: NSNumber
        let processResponse: (Data) -> Data
        let deadline: DispatchWorkItem
    }

    init(packetFlow: NEPacketTunnelFlow, log: OSLog) {
        self.packetFlow = packetFlow
        self.log = log
        self.queue = DispatchQueue(label: "com.jimmykim.maven.dnsforwarder")
        os_log("DNS forwarder initialized", log: log, type: .default)
    }

    func shutdown() {
        queue.sync {
            isShutdown = true
            for (_, pending) in pendingQueries {
                pending.deadline.cancel()
            }
            pendingQueries.removeAll()
            connection?.cancel()
            connection = nil
        }
        os_log("DNS forwarder shut down", log: log, type: .default)
    }

    // MARK: - Public

    /// Forward a raw IPv4+UDP DNS packet to 8.8.8.8 and write the response back.
    func forwardDNSPacket(_ packet: Data, protocolFamily: NSNumber, processResponse: @escaping (Data) -> Data) {
        // IPv4 only — validate packet structure.
        guard packet.count >= 28 else { return }
        let version = packet[0] >> 4
        guard version == 4 else { return }

        let ipHeaderLen = Int(packet[0] & 0x0F) * 4
        guard ipHeaderLen >= 20, packet.count >= ipHeaderLen + 8 else { return }
        guard packet[9] == 17 else { return } // UDP

        let udpOffset = ipHeaderLen
        let dstPort = UInt16(packet[udpOffset + 2]) << 8 | UInt16(packet[udpOffset + 3])
        guard dstPort == 53 else { return }

        let srcPort = UInt16(packet[udpOffset]) << 8 | UInt16(packet[udpOffset + 1])
        let dnsPayload = packet[(udpOffset + 8)...]
        guard dnsPayload.count >= 12 else { return }

        // DNS transaction ID — first 2 bytes of the DNS payload.
        let txnID = UInt16(dnsPayload[dnsPayload.startIndex]) << 8
                  | UInt16(dnsPayload[dnsPayload.startIndex + 1])

        #if DEBUG
        if let domain = Self.extractDomainFromDNS(dnsPayload) {
            NSLog("[Maven DNS] Forwarding txn 0x%04x: %@", txnID, domain)
        }
        #endif

        queue.async { [weak self] in
            self?.sendQuery(
                packet: packet,
                ipHeaderLen: ipHeaderLen,
                srcPort: srcPort,
                dnsPayload: Data(dnsPayload),
                txnID: txnID,
                protocolFamily: protocolFamily,
                processResponse: processResponse
            )
        }
    }

    // MARK: - Connection Management

    /// Returns the current connection or creates a new one. Must be called on `queue`.
    private func ensureConnection() -> NWConnection {
        if let existing = connection {
            return existing
        }

        let conn = NWConnection(
            host: NWEndpoint.Host("8.8.8.8"),
            port: NWEndpoint.Port(integerLiteral: 53),
            using: .udp
        )

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            self.queue.async { self.handleConnectionStateChange(state) }
        }

        conn.start(queue: queue)
        self.connection = conn
        startReceiveLoop(on: conn)
        os_log("DNS connection created", log: log, type: .default)
        return conn
    }

    /// Continuous receive loop — re-arms after each datagram.
    private func startReceiveLoop(on conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self = self else { return }

            if let error = error {
                os_log("DNS receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                return // stateUpdateHandler will handle reconnection
            }

            if let data = data, data.count >= 2 {
                let txnID = UInt16(data[0]) << 8 | UInt16(data[1])
                self.handleResponse(data: data, txnID: txnID)
            }

            // Re-arm for next datagram (only if this is still the active connection).
            if self.connection === conn && !self.isShutdown {
                self.startReceiveLoop(on: conn)
            }
        }
    }

    private func handleConnectionStateChange(_ state: NWConnection.State) {
        switch state {
        case .ready:
            os_log("DNS connection ready", log: log, type: .default)
        case .failed(let error):
            os_log("DNS connection failed: %{public}@", log: log, type: .error, error.localizedDescription)
            failAllPendingQueries()
            connection?.cancel()
            connection = nil
        case .cancelled:
            os_log("DNS connection cancelled", log: log, type: .debug)
        case .waiting(let error):
            os_log("DNS connection waiting: %{public}@", log: log, type: .default, error.localizedDescription)
        default:
            break
        }
    }

    private func failAllPendingQueries() {
        for (_, pending) in pendingQueries {
            pending.deadline.cancel()
        }
        pendingQueries.removeAll()
    }

    // MARK: - Query Lifecycle

    /// Sends a DNS query on the shared connection. Must be called on `queue`.
    private func sendQuery(
        packet: Data,
        ipHeaderLen: Int,
        srcPort: UInt16,
        dnsPayload: Data,
        txnID: UInt16,
        protocolFamily: NSNumber,
        processResponse: @escaping (Data) -> Data
    ) {
        guard !isShutdown else { return }

        guard pendingQueries.count < Self.maxPendingQueries else {
            os_log("DNS query limit reached (%d), dropping", log: log, type: .error, Self.maxPendingQueries)
            return
        }

        // All queries share one upstream socket and responses only carry the
        // 16-bit transaction ID, so concurrent clients that pick the same ID
        // would be indistinguishable. Rewrite to a free upstream ID and restore
        // the original in the response.
        var upstreamID = txnID
        while pendingQueries[upstreamID] != nil {
            upstreamID &+= 1
        }
        var outgoingPayload = dnsPayload
        if upstreamID != txnID {
            outgoingPayload[outgoingPayload.startIndex] = UInt8(upstreamID >> 8)
            outgoingPayload[outgoingPayload.startIndex + 1] = UInt8(upstreamID & 0xFF)
        }

        let conn = ensureConnection()

        // Per-query timeout.
        let timeoutWork = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            if self.pendingQueries.removeValue(forKey: upstreamID) != nil {
                os_log("DNS query timed out for txn 0x%04x", log: self.log, type: .error, txnID)
            }
        }
        queue.asyncAfter(deadline: .now() + Self.queryTimeoutSeconds, execute: timeoutWork)

        pendingQueries[upstreamID] = PendingQuery(
            originalPacket: packet,
            ipHeaderLen: ipHeaderLen,
            srcPort: srcPort,
            originalTxnID: txnID,
            protocolFamily: protocolFamily,
            processResponse: processResponse,
            deadline: timeoutWork
        )

        conn.send(content: outgoingPayload, completion: .contentProcessed { [weak self] error in
            guard let self = self, let error = error else { return }
            os_log("DNS send error for txn 0x%04x: %{public}@", log: self.log, type: .error, txnID, error.localizedDescription)
            self.queue.async {
                if let pending = self.pendingQueries.removeValue(forKey: upstreamID) {
                    pending.deadline.cancel()
                }
            }
        })
    }

    /// Dispatches a DNS response to its matching pending query. Runs on `queue`.
    private func handleResponse(data: Data, txnID: UInt16) {
        guard let pending = pendingQueries.removeValue(forKey: txnID) else {
            os_log("DNS response for unknown txn 0x%04x, ignoring", log: log, type: .debug, txnID)
            return
        }
        pending.deadline.cancel()

        // The response must fit in a single IPv4 packet (total length is 16-bit).
        guard data.count <= 65_535 - pending.ipHeaderLen - 8 else {
            os_log("DNS response too large (%d bytes), dropping", log: log, type: .error, data.count)
            return
        }

        // Restore the client's original transaction ID if it was rewritten.
        var dnsResponse = data
        if pending.originalTxnID != txnID {
            dnsResponse[dnsResponse.startIndex] = UInt8(pending.originalTxnID >> 8)
            dnsResponse[dnsResponse.startIndex + 1] = UInt8(pending.originalTxnID & 0xFF)
        }

        var responsePacket = buildIPv4UDPResponse(
            origPacket: pending.originalPacket,
            ipHeaderLen: pending.ipHeaderLen,
            dnsResponse: dnsResponse,
            srcPort: pending.srcPort
        )

        // Pass through Rust engine (serialized on engineQueue via the closure).
        responsePacket = pending.processResponse(responsePacket)

        packetFlow.writePackets([responsePacket], withProtocols: [pending.protocolFamily])
    }

    // MARK: - Packet Construction

    /// Build an IPv4+UDP response packet by swapping src/dst in the original request.
    private func buildIPv4UDPResponse(origPacket: Data, ipHeaderLen: Int, dnsResponse: Data, srcPort: UInt16) -> Data {
        let udpLen = UInt16(8 + dnsResponse.count)
        let totalLen = UInt16(ipHeaderLen) + udpLen
        var pkt = Data(count: Int(totalLen))

        pkt[0] = origPacket[0]
        pkt[1] = 0
        pkt[2] = UInt8(totalLen >> 8)
        pkt[3] = UInt8(totalLen & 0xFF)
        pkt[4...5] = origPacket[4...5]
        pkt[6] = 0; pkt[7] = 0
        pkt[8] = 64
        pkt[9] = 17
        pkt[10] = 0; pkt[11] = 0
        pkt[12..<16] = origPacket[16..<20]
        pkt[16..<20] = origPacket[12..<16]

        var sum: UInt32 = 0
        for i in stride(from: 0, to: ipHeaderLen, by: 2) {
            sum += UInt32(pkt[i]) << 8 | UInt32(pkt[i + 1])
        }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let cksum = ~UInt16(sum & 0xFFFF)
        pkt[10] = UInt8(cksum >> 8)
        pkt[11] = UInt8(cksum & 0xFF)

        let uo = ipHeaderLen
        pkt[uo] = 0; pkt[uo + 1] = 53
        pkt[uo + 2] = UInt8(srcPort >> 8); pkt[uo + 3] = UInt8(srcPort & 0xFF)
        pkt[uo + 4] = UInt8(udpLen >> 8); pkt[uo + 5] = UInt8(udpLen & 0xFF)
        pkt[uo + 6] = 0; pkt[uo + 7] = 0

        pkt[(uo + 8)...] = dnsResponse[...]

        return pkt
    }

    // MARK: - DNS Parsing Helpers

    /// Extracts the queried domain name from a DNS payload for logging.
    private static func extractDomainFromDNS(_ payload: Data) -> String? {
        guard payload.count > 12 else { return nil }
        var parts: [String] = []
        var offset = payload.startIndex + 12

        while offset < payload.endIndex {
            let labelLen = Int(payload[offset])
            if labelLen == 0 { break }
            offset += 1
            let labelEnd = offset + labelLen
            guard labelEnd <= payload.endIndex else { return nil }
            if let label = String(bytes: payload[offset..<labelEnd], encoding: .utf8) {
                parts.append(label)
            }
            offset = labelEnd
        }
        return parts.isEmpty ? nil : parts.joined(separator: ".")
    }
}
