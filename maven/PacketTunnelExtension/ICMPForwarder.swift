import NetworkExtension
import Network
import os.log

/// Proxies ICMP echo (ping) through the tunnel to the DNS server IPs.
///
/// The tunnel routes the resolver IPs, so an app pinging 8.8.8.8 (a common
/// connectivity check) lands on the TUN as a raw ICMP packet with nothing to
/// answer it. This class forwards echo requests through an unprivileged
/// ICMP datagram socket (`SOCK_DGRAM`/`IPPROTO_ICMP`, the darwin "ping
/// socket") — the extension's own traffic bypasses its tunnel — and writes
/// the real replies back to the client, so reachability and latency stay
/// genuine instead of being faked locally.
///
/// The ICMP message bytes are relayed verbatim in both directions (their
/// checksums remain valid); only the outer IPv4 header is rebuilt. Requests
/// are matched to replies by (identifier, resolver IP). Only echo request /
/// reply are handled; other ICMP types are dropped as before.
///
/// IPv4 only, matching the tunnel configuration.
final class ICMPForwarder {

    // MARK: - Tunables

    private static let maxPending = 32
    private static let pendingTimeoutSeconds: CFAbsoluteTime = 30

    // MARK: - Pending echo state

    private struct PendingKey: Hashable {
        let identifier: UInt16
        let serverIP: Data
    }

    private struct Pending {
        let clientIP: Data
        let protocolFamily: NSNumber
        var lastSeen: CFAbsoluteTime
    }

    // MARK: - Properties

    /// Writes response packets back to the TUN. Injected for testability.
    private let writeBack: ([Data], [NSNumber]) -> Void
    private let log: OSLog
    /// Serial queue protecting ALL mutable state, including the socket.
    private let queue = DispatchQueue(label: "com.jimmykim.maven.icmp")
    private var socketFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var pending: [PendingKey: Pending] = [:]
    private var isShutdown = false

    convenience init(packetFlow: NEPacketTunnelFlow, log: OSLog) {
        self.init(log: log) { packets, protocols in
            packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    init(log: OSLog, writeBack: @escaping ([Data], [NSNumber]) -> Void) {
        self.log = log
        self.writeBack = writeBack
    }

    func shutdown() {
        queue.sync {
            isShutdown = true
            closeSocket()
            pending.removeAll()
        }
    }

    // MARK: - Entry point

    /// Handles a raw IPv4 packet carrying ICMP. Anything but an echo request
    /// is ignored (dropped, as before).
    func handlePacket(_ packet: Data, protocolFamily: NSNumber) {
        guard packet.count >= 28 else { return } // 20 IP + 8 ICMP header
        let bytes = [UInt8](packet)
        guard bytes[0] >> 4 == 4 else { return }
        let ipHeaderLen = Int(bytes[0] & 0x0F) * 4
        guard ipHeaderLen >= 20, bytes[9] == 1,
              packet.count >= ipHeaderLen + 8 else { return }

        let totalLength = Int(bytes[2]) << 8 | Int(bytes[3])
        guard totalLength >= ipHeaderLen + 8, totalLength <= packet.count else { return }

        // Echo request only: type 8, code 0.
        guard bytes[ipHeaderLen] == 8, bytes[ipHeaderLen + 1] == 0 else { return }

        let clientIP = packet.subdata(in: 12..<16)
        let serverIP = packet.subdata(in: 16..<20)
        let icmpMessage = packet.subdata(in: ipHeaderLen..<totalLength)
        let identifier = UInt16(bytes[ipHeaderLen + 4]) << 8 | UInt16(bytes[ipHeaderLen + 5])

        queue.async { [weak self] in
            self?.forward(icmpMessage, identifier: identifier, clientIP: clientIP,
                          serverIP: serverIP, protocolFamily: protocolFamily)
        }
    }

    // MARK: - Forwarding (runs on `queue`)

    private func forward(_ icmpMessage: Data, identifier: UInt16, clientIP: Data,
                         serverIP: Data, protocolFamily: NSNumber) {
        guard !isShutdown, ensureSocket() else { return }

        purgeStale()
        let key = PendingKey(identifier: identifier, serverIP: serverIP)
        if pending[key] == nil && pending.count >= Self.maxPending {
            os_log("ICMP pending limit reached, dropping", log: log, type: .error)
            return
        }
        pending[key] = Pending(clientIP: clientIP, protocolFamily: protocolFamily,
                               lastSeen: CFAbsoluteTimeGetCurrent())

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = serverIP.withUnsafeBytes { $0.load(as: in_addr_t.self) }

        let sent = icmpMessage.withUnsafeBytes { msgBuf -> Int in
            withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(socketFD, msgBuf.baseAddress, icmpMessage.count, 0,
                           sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if sent < 0 {
            os_log("ICMP sendto failed: errno=%d", log: log, type: .error, errno)
        }
    }

    /// Removes entries that have not seen traffic recently.
    private func purgeStale() {
        let cutoff = CFAbsoluteTimeGetCurrent() - Self.pendingTimeoutSeconds
        pending = pending.filter { $0.value.lastSeen >= cutoff }
    }

    // MARK: - Socket lifecycle (runs on `queue`)

    private func ensureSocket() -> Bool {
        if socketFD >= 0 { return true }

        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else {
            os_log("ICMP socket unavailable: errno=%d", log: log, type: .error, errno)
            return false
        }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        socketFD = fd

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainSocket()
        }
        source.setCancelHandler {
            close(fd)
        }
        source.resume()
        readSource = source
        return true
    }

    private func closeSocket() {
        readSource?.cancel() // cancel handler closes the fd
        readSource = nil
        socketFD = -1
    }

    private func drainSocket() {
        guard socketFD >= 0 else { return }
        var buffer = [UInt8](repeating: 0, count: 65_535)
        while true {
            var from = sockaddr_in()
            var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) { fromPtr in
                fromPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(socketFD, &buffer, buffer.count, 0, sa, &fromLen)
                }
            }
            guard n > 0 else { return } // EWOULDBLOCK or error: stop draining

            let senderIP = withUnsafeBytes(of: from.sin_addr.s_addr) { Data($0) }
            handleReply(Data(buffer[0..<n]), senderIP: senderIP)
        }
    }

    // MARK: - Replies (runs on `queue`)

    private func handleReply(_ raw: Data, senderIP: Data) {
        // Darwin ICMP datagram sockets deliver the full IP header ahead of
        // the ICMP message; strip it if present.
        var icmp = raw
        let bytes = [UInt8](raw)
        if !bytes.isEmpty && bytes[0] >> 4 == 4 {
            let ihl = Int(bytes[0] & 0x0F) * 4
            guard raw.count > ihl else { return }
            icmp = raw.subdata(in: ihl..<raw.count)
        }
        guard icmp.count >= 8 else { return }

        // Echo reply only: type 0, code 0.
        guard icmp[icmp.startIndex] == 0, icmp[icmp.startIndex + 1] == 0 else { return }

        let identifier = UInt16(icmp[icmp.startIndex + 4]) << 8
                       | UInt16(icmp[icmp.startIndex + 5])
        let key = PendingKey(identifier: identifier, serverIP: senderIP)
        guard var entry = pending[key] else { return }
        entry.lastSeen = CFAbsoluteTimeGetCurrent()
        pending[key] = entry

        let pkt = Self.makeICMPPacket(srcIP: senderIP, dstIP: entry.clientIP, icmpMessage: icmp)
        writeBack([pkt], [entry.protocolFamily])
    }

    // MARK: - Packet construction (pure, static for testability)

    /// Wraps an ICMP message in a fresh IPv4 header. The ICMP message is
    /// relayed verbatim, so its own checksum is untouched.
    static func makeICMPPacket(srcIP: Data, dstIP: Data, icmpMessage: Data) -> Data {
        let totalLen = 20 + icmpMessage.count
        var pkt = [UInt8](repeating: 0, count: totalLen)

        pkt[0] = 0x45
        pkt[2] = UInt8(totalLen >> 8)
        pkt[3] = UInt8(totalLen & 0xFF)
        pkt[8] = 64 // TTL
        pkt[9] = 1  // ICMP
        pkt[12] = srcIP[srcIP.startIndex]
        pkt[13] = srcIP[srcIP.startIndex + 1]
        pkt[14] = srcIP[srcIP.startIndex + 2]
        pkt[15] = srcIP[srcIP.startIndex + 3]
        pkt[16] = dstIP[dstIP.startIndex]
        pkt[17] = dstIP[dstIP.startIndex + 1]
        pkt[18] = dstIP[dstIP.startIndex + 2]
        pkt[19] = dstIP[dstIP.startIndex + 3]

        let ipCksum = TCPDNSForwarder.checksum(pkt[0..<20])
        pkt[10] = UInt8(ipCksum >> 8)
        pkt[11] = UInt8(ipCksum & 0xFF)

        for (i, byte) in icmpMessage.enumerated() {
            pkt[20 + i] = byte
        }
        return Data(pkt)
    }
}
