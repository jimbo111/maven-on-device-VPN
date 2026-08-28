import NetworkExtension
import Network
import os.log

/// Userspace TCP relay for DNS-over-TCP (RFC 7766) fallback.
///
/// The tunnel routes the DNS server IPs, so when a UDP response is truncated
/// (TC bit) the client retries over TCP to port 53 — and those raw TCP
/// segments arrive on the TUN with nothing to terminate them. This class
/// answers the client's handshake locally and relays the byte stream to the
/// real resolver over an outbound `NWConnection`, which handles real-network
/// loss and retransmission.
///
/// Deliberately minimal, relying on the TUN being an in-memory, lossless
/// link: segments to the client are never retransmitted, out-of-order
/// segments from the client are dropped (a duplicate ACK triggers the
/// client's own retransmit), and window scaling/SACK/timestamps are not
/// negotiated. DNS exchanges are a few KB at most, so none of that is needed.
///
/// IPv4 only, matching the tunnel configuration.
final class TCPDNSForwarder {

    // MARK: - Tunables

    private static let maxConnections = 16
    private static let idleTimeoutSeconds: Double = 60
    private static let advertisedWindow: UInt16 = 65_535
    private static let mss: UInt16 = 1_400
    /// Payload bytes per segment written to the client. Comfortably below the
    /// tunnel MTU (1500) after 40 bytes of headers.
    private static let chunkSize = 1_200

    // MARK: - TCP flag bits

    private struct TCPFlags {
        static let fin: UInt8 = 0x01
        static let syn: UInt8 = 0x02
        static let rst: UInt8 = 0x04
        static let psh: UInt8 = 0x08
        static let ack: UInt8 = 0x10
    }

    // MARK: - Parsed segment

    /// Fields extracted from a raw IPv4+TCP packet.
    struct Segment {
        let srcIP: Data     // 4 bytes
        let dstIP: Data     // 4 bytes
        let srcPort: UInt16
        let dstPort: UInt16
        let seq: UInt32
        let ack: UInt32
        let flags: UInt8
        let window: UInt16
        let payload: Data

        /// Parses an IPv4 packet carrying TCP. Returns nil for anything else
        /// or for structurally invalid packets.
        static func parse(_ packet: Data) -> Segment? {
            guard packet.count >= 40 else { return nil }
            let bytes = [UInt8](packet)
            guard bytes[0] >> 4 == 4 else { return nil }
            let ipHeaderLen = Int(bytes[0] & 0x0F) * 4
            guard ipHeaderLen >= 20, bytes[9] == 6,
                  packet.count >= ipHeaderLen + 20 else { return nil }

            let o = ipHeaderLen
            let dataOffset = Int(bytes[o + 12] >> 4) * 4
            guard dataOffset >= 20, packet.count >= o + dataOffset else { return nil }

            // The IP total-length field bounds the payload; readPackets can
            // hand us buffers with trailing slack in theory.
            let totalLength = Int(bytes[2]) << 8 | Int(bytes[3])
            guard totalLength >= o + dataOffset, totalLength <= packet.count else { return nil }

            return Segment(
                srcIP: packet.subdata(in: 12..<16),
                dstIP: packet.subdata(in: 16..<20),
                srcPort: UInt16(bytes[o]) << 8 | UInt16(bytes[o + 1]),
                dstPort: UInt16(bytes[o + 2]) << 8 | UInt16(bytes[o + 3]),
                seq: UInt32(bytes[o + 4]) << 24 | UInt32(bytes[o + 5]) << 16
                   | UInt32(bytes[o + 6]) << 8 | UInt32(bytes[o + 7]),
                ack: UInt32(bytes[o + 8]) << 24 | UInt32(bytes[o + 9]) << 16
                   | UInt32(bytes[o + 10]) << 8 | UInt32(bytes[o + 11]),
                flags: bytes[o + 13],
                window: UInt16(bytes[o + 14]) << 8 | UInt16(bytes[o + 15]),
                payload: packet.subdata(in: (o + dataOffset)..<totalLength)
            )
        }
    }

    // MARK: - Per-connection state

    private enum RelayState {
        case synReceived
        case established
        /// The upstream closed and our FIN has been sent; waiting for its ACK.
        case finSent
    }

    private final class Relay {
        var state: RelayState = .synReceived
        /// Next sequence number expected from the client.
        var rcvNxt: UInt32
        /// Next sequence number we will send.
        var sndNxt: UInt32
        /// Our initial send sequence, kept to rebuild a lost SYN-ACK.
        let iss: UInt32
        var clientClosed = false
        var upstream: NWConnection?
        var upstreamReady = false
        /// Client bytes queued while the upstream connection is still opening.
        var pendingOut = Data()
        /// The client's addresses, kept to build response segments.
        let clientIP: Data
        let serverIP: Data
        let clientPort: UInt16
        let protocolFamily: NSNumber
        var idleTimer: DispatchWorkItem?

        init(clientISN: UInt32, clientIP: Data, serverIP: Data, clientPort: UInt16, protocolFamily: NSNumber) {
            self.rcvNxt = clientISN &+ 1
            self.iss = UInt32.random(in: 0...UInt32.max)
            self.sndNxt = self.iss &+ 1
            self.clientIP = clientIP
            self.serverIP = serverIP
            self.clientPort = clientPort
            self.protocolFamily = protocolFamily
        }
    }

    private struct ConnectionKey: Hashable {
        let clientPort: UInt16
        let serverIP: Data
    }

    // MARK: - Properties

    /// Writes response packets back to the TUN. Injected so the state machine
    /// can be exercised without a real NEPacketTunnelFlow.
    private let writeBack: ([Data], [NSNumber]) -> Void
    private let log: OSLog
    /// Upstream resolver port — 53 in production, overridable for tests.
    let upstreamPort: UInt16
    /// Serial queue protecting ALL mutable state; upstream connections are
    /// started on it so their callbacks run here too.
    private let queue = DispatchQueue(label: "com.jimmykim.maven.tcpdns")
    private var relays: [ConnectionKey: Relay] = [:]
    private var isShutdown = false

    convenience init(packetFlow: NEPacketTunnelFlow, log: OSLog) {
        self.init(log: log, upstreamPort: 53) { packets, protocols in
            packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    init(log: OSLog, upstreamPort: UInt16, writeBack: @escaping ([Data], [NSNumber]) -> Void) {
        self.log = log
        self.upstreamPort = upstreamPort
        self.writeBack = writeBack
    }

    func shutdown() {
        queue.sync {
            isShutdown = true
            for (_, relay) in relays {
                relay.idleTimer?.cancel()
                relay.upstream?.cancel()
            }
            relays.removeAll()
        }
    }

    // MARK: - Entry point

    /// Handles a raw IPv4 TCP packet addressed to a DNS server. Packets that
    /// are not TCP port 53 are ignored (dropped, as before).
    func handlePacket(_ packet: Data, protocolFamily: NSNumber) {
        guard let segment = Segment.parse(packet), segment.dstPort == 53 else { return }
        queue.async { [weak self] in
            self?.process(segment, protocolFamily: protocolFamily)
        }
    }

    // MARK: - State machine (runs on `queue`)

    private func process(_ seg: Segment, protocolFamily: NSNumber) {
        guard !isShutdown else { return }

        let key = ConnectionKey(clientPort: seg.srcPort, serverIP: seg.dstIP)

        if seg.flags & TCPFlags.rst != 0 {
            teardown(key)
            return
        }

        if seg.flags & TCPFlags.syn != 0 && seg.flags & TCPFlags.ack == 0 {
            handleSYN(seg, key: key, protocolFamily: protocolFamily)
            return
        }

        guard let relay = relays[key] else {
            // Segment for a connection we don't know — tell the client.
            sendRST(for: seg, protocolFamily: protocolFamily)
            return
        }
        touch(relay, key: key)

        if relay.state == .synReceived && seg.flags & TCPFlags.ack != 0 {
            relay.state = .established
        }

        // In-order data from the client.
        if !seg.payload.isEmpty {
            let delta = seg.seq &- relay.rcvNxt
            if delta == 0 {
                relay.rcvNxt = relay.rcvNxt &+ UInt32(seg.payload.count)
                forwardToUpstream(seg.payload, relay: relay, key: key)
            }
            // delta >= 0x8000_0000: old retransmission — just re-ACK below.
            // 0 < delta < 0x8000_0000: a gap; the dup ACK below makes the
            // client retransmit. Either way the ACK we send is correct.
            sendACK(relay)
        }

        if seg.flags & TCPFlags.fin != 0 {
            let finSeq = seg.seq &+ UInt32(seg.payload.count)
            if finSeq == relay.rcvNxt && !relay.clientClosed {
                relay.clientClosed = true
                relay.rcvNxt = relay.rcvNxt &+ 1
                sendACK(relay)
                // Half-close toward the resolver; its EOF will trigger our FIN.
                relay.upstream?.send(content: nil, contentContext: .finalMessage,
                                     isComplete: true, completion: .contentProcessed { _ in })
            } else {
                sendACK(relay)
            }
        }

        // Client acknowledged our FIN — the connection is fully closed.
        if relay.state == .finSent && seg.flags & TCPFlags.ack != 0 && seg.ack == relay.sndNxt {
            teardown(key)
        }
    }

    private func handleSYN(_ seg: Segment, key: ConnectionKey, protocolFamily: NSNumber) {
        if let existing = relays[key] {
            if existing.state == .synReceived {
                // Our SYN-ACK was lost or delayed — resend it.
                sendSYNACK(existing)
            }
            // A SYN on an established relay is a stale duplicate; ignore.
            return
        }

        guard relays.count < Self.maxConnections else {
            os_log("TCP DNS connection limit reached, refusing", log: log, type: .error)
            sendRST(for: seg, protocolFamily: protocolFamily)
            return
        }

        let relay = Relay(
            clientISN: seg.seq,
            clientIP: seg.srcIP,
            serverIP: seg.dstIP,
            clientPort: seg.srcPort,
            protocolFamily: protocolFamily
        )
        relays[key] = relay
        touch(relay, key: key)
        connectUpstream(relay, key: key)
        sendSYNACK(relay)
    }

    // MARK: - Upstream (runs on `queue`)

    private func connectUpstream(_ relay: Relay, key: ConnectionKey) {
        let host = relay.serverIP.map { String($0) }.joined(separator: ".")
        let conn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: NWEndpoint.Port.IntegerLiteralType(upstreamPort)),
            using: .tcp
        )
        relay.upstream = conn

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                guard let relay = self.relays[key], relay.upstream === conn else { return }
                relay.upstreamReady = true
                if !relay.pendingOut.isEmpty {
                    let queued = relay.pendingOut
                    relay.pendingOut = Data()
                    conn.send(content: queued, completion: .contentProcessed { _ in })
                }
                self.receiveUpstream(on: conn, key: key)
            case .failed(let error):
                os_log("TCP DNS upstream failed: %{public}@", log: self.log, type: .error,
                       error.localizedDescription)
                self.abort(key)
            case .cancelled:
                break
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func receiveUpstream(on conn: NWConnection, key: ConnectionKey) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self = self,
                  let relay = self.relays[key], relay.upstream === conn else { return }

            if let data = data, !data.isEmpty {
                self.sendDataToClient(data, relay: relay)
            }

            if error != nil {
                self.abort(key)
                return
            }

            if isComplete {
                // Resolver finished — pass the EOF on as our FIN.
                self.sendFIN(relay)
                relay.state = .finSent
                if relay.clientClosed {
                    // Client already closed its side; nothing more can arrive
                    // on the TUN reliably, so don't wait for the last ACK.
                    self.teardown(key)
                }
                return
            }

            self.receiveUpstream(on: conn, key: key)
        }
    }

    private func forwardToUpstream(_ data: Data, relay: Relay, key: ConnectionKey) {
        guard let conn = relay.upstream else { return }
        if relay.upstreamReady {
            conn.send(content: data, completion: .contentProcessed { _ in })
        } else {
            relay.pendingOut.append(data)
        }
    }

    // MARK: - Segments to the client (run on `queue`)

    private func sendSYNACK(_ relay: Relay) {
        let pkt = Self.makeSegment(
            srcIP: relay.serverIP, dstIP: relay.clientIP,
            srcPort: 53, dstPort: relay.clientPort,
            seq: relay.iss, ack: relay.rcvNxt,
            flags: TCPFlags.syn | TCPFlags.ack,
            window: Self.advertisedWindow, mssOption: Self.mss, payload: Data()
        )
        writeBack([pkt], [relay.protocolFamily])
    }

    private func sendACK(_ relay: Relay) {
        let pkt = Self.makeSegment(
            srcIP: relay.serverIP, dstIP: relay.clientIP,
            srcPort: 53, dstPort: relay.clientPort,
            seq: relay.sndNxt, ack: relay.rcvNxt,
            flags: TCPFlags.ack,
            window: Self.advertisedWindow, mssOption: nil, payload: Data()
        )
        writeBack([pkt], [relay.protocolFamily])
    }

    private func sendDataToClient(_ data: Data, relay: Relay) {
        var packets: [Data] = []
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = min(offset + Self.chunkSize, data.endIndex)
            let chunk = data.subdata(in: offset..<end)
            let pkt = Self.makeSegment(
                srcIP: relay.serverIP, dstIP: relay.clientIP,
                srcPort: 53, dstPort: relay.clientPort,
                seq: relay.sndNxt, ack: relay.rcvNxt,
                flags: TCPFlags.ack | TCPFlags.psh,
                window: Self.advertisedWindow, mssOption: nil, payload: chunk
            )
            relay.sndNxt = relay.sndNxt &+ UInt32(chunk.count)
            packets.append(pkt)
            offset = end
        }
        writeBack(packets, Array(repeating: relay.protocolFamily, count: packets.count))
    }

    private func sendFIN(_ relay: Relay) {
        let pkt = Self.makeSegment(
            srcIP: relay.serverIP, dstIP: relay.clientIP,
            srcPort: 53, dstPort: relay.clientPort,
            seq: relay.sndNxt, ack: relay.rcvNxt,
            flags: TCPFlags.fin | TCPFlags.ack,
            window: Self.advertisedWindow, mssOption: nil, payload: Data()
        )
        relay.sndNxt = relay.sndNxt &+ 1
        writeBack([pkt], [relay.protocolFamily])
    }

    /// RST for a segment that has no relay (or was refused): swap the
    /// addresses from the offending segment.
    private func sendRST(for seg: Segment, protocolFamily: NSNumber) {
        // RFC 793: if the incoming segment has ACK, the RST takes its ack as
        // seq; otherwise seq 0 with ack covering the segment.
        let seq = seg.flags & TCPFlags.ack != 0 ? seg.ack : 0
        let ackVal = seg.seq &+ UInt32(seg.payload.count)
                   &+ (seg.flags & TCPFlags.syn != 0 ? 1 : 0)
                   &+ (seg.flags & TCPFlags.fin != 0 ? 1 : 0)
        let pkt = Self.makeSegment(
            srcIP: seg.dstIP, dstIP: seg.srcIP,
            srcPort: seg.dstPort, dstPort: seg.srcPort,
            seq: seq, ack: ackVal,
            flags: TCPFlags.rst | TCPFlags.ack,
            window: 0, mssOption: nil, payload: Data()
        )
        writeBack([pkt], [protocolFamily])
    }

    // MARK: - Lifecycle helpers (run on `queue`)

    /// Restarts the idle timer for a relay.
    private func touch(_ relay: Relay, key: ConnectionKey) {
        relay.idleTimer?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.abort(key)
        }
        relay.idleTimer = work
        queue.asyncAfter(deadline: .now() + Self.idleTimeoutSeconds, execute: work)
    }

    /// Removes a relay without notifying the client.
    private func teardown(_ key: ConnectionKey) {
        guard let relay = relays.removeValue(forKey: key) else { return }
        relay.idleTimer?.cancel()
        relay.upstream?.cancel()
    }

    /// Removes a relay and resets the client so it doesn't hang.
    private func abort(_ key: ConnectionKey) {
        guard let relay = relays.removeValue(forKey: key) else { return }
        relay.idleTimer?.cancel()
        relay.upstream?.cancel()
        let pkt = Self.makeSegment(
            srcIP: relay.serverIP, dstIP: relay.clientIP,
            srcPort: 53, dstPort: relay.clientPort,
            seq: relay.sndNxt, ack: relay.rcvNxt,
            flags: TCPFlags.rst | TCPFlags.ack,
            window: 0, mssOption: nil, payload: Data()
        )
        writeBack([pkt], [relay.protocolFamily])
    }

    // MARK: - Packet construction (pure, static for testability)

    /// Builds a complete IPv4+TCP packet with valid IP and TCP checksums.
    static func makeSegment(
        srcIP: Data, dstIP: Data,
        srcPort: UInt16, dstPort: UInt16,
        seq: UInt32, ack: UInt32,
        flags: UInt8, window: UInt16,
        mssOption: UInt16?, payload: Data
    ) -> Data {
        let optionsLen = mssOption != nil ? 4 : 0
        let tcpHeaderLen = 20 + optionsLen
        let totalLen = 20 + tcpHeaderLen + payload.count

        var pkt = [UInt8](repeating: 0, count: totalLen)

        // IPv4 header (20 bytes, no options).
        pkt[0] = 0x45
        pkt[2] = UInt8(totalLen >> 8)
        pkt[3] = UInt8(totalLen & 0xFF)
        pkt[8] = 64 // TTL
        pkt[9] = 6  // TCP
        pkt[12] = srcIP[srcIP.startIndex]
        pkt[13] = srcIP[srcIP.startIndex + 1]
        pkt[14] = srcIP[srcIP.startIndex + 2]
        pkt[15] = srcIP[srcIP.startIndex + 3]
        pkt[16] = dstIP[dstIP.startIndex]
        pkt[17] = dstIP[dstIP.startIndex + 1]
        pkt[18] = dstIP[dstIP.startIndex + 2]
        pkt[19] = dstIP[dstIP.startIndex + 3]

        let ipCksum = checksum(pkt[0..<20])
        pkt[10] = UInt8(ipCksum >> 8)
        pkt[11] = UInt8(ipCksum & 0xFF)

        // TCP header.
        let t = 20
        pkt[t] = UInt8(srcPort >> 8)
        pkt[t + 1] = UInt8(srcPort & 0xFF)
        pkt[t + 2] = UInt8(dstPort >> 8)
        pkt[t + 3] = UInt8(dstPort & 0xFF)
        pkt[t + 4] = UInt8(seq >> 24)
        pkt[t + 5] = UInt8((seq >> 16) & 0xFF)
        pkt[t + 6] = UInt8((seq >> 8) & 0xFF)
        pkt[t + 7] = UInt8(seq & 0xFF)
        pkt[t + 8] = UInt8(ack >> 24)
        pkt[t + 9] = UInt8((ack >> 16) & 0xFF)
        pkt[t + 10] = UInt8((ack >> 8) & 0xFF)
        pkt[t + 11] = UInt8(ack & 0xFF)
        pkt[t + 12] = UInt8(tcpHeaderLen / 4) << 4
        pkt[t + 13] = flags
        pkt[t + 14] = UInt8(window >> 8)
        pkt[t + 15] = UInt8(window & 0xFF)
        // checksum (t+16, t+17) filled below; urgent pointer stays 0.

        if let mss = mssOption {
            pkt[t + 20] = 2 // kind: MSS
            pkt[t + 21] = 4 // length
            pkt[t + 22] = UInt8(mss >> 8)
            pkt[t + 23] = UInt8(mss & 0xFF)
        }

        for (i, byte) in payload.enumerated() {
            pkt[t + tcpHeaderLen + i] = byte
        }

        // TCP checksum over pseudo-header + TCP header + payload.
        let tcpLen = tcpHeaderLen + payload.count
        var pseudo = [UInt8]()
        pseudo.reserveCapacity(12 + tcpLen)
        pseudo.append(contentsOf: pkt[12..<20]) // src + dst IPs
        pseudo.append(0)
        pseudo.append(6)
        pseudo.append(UInt8(tcpLen >> 8))
        pseudo.append(UInt8(tcpLen & 0xFF))
        pseudo.append(contentsOf: pkt[t...])

        let tcpCksum = checksum(pseudo[...])
        pkt[t + 16] = UInt8(tcpCksum >> 8)
        pkt[t + 17] = UInt8(tcpCksum & 0xFF)

        return Data(pkt)
    }

    /// Standard Internet checksum (RFC 1071): 16-bit one's-complement sum.
    static func checksum(_ bytes: ArraySlice<UInt8>) -> UInt16 {
        var sum: UInt32 = 0
        var iter = bytes.makeIterator()
        while let hi = iter.next() {
            let lo = iter.next() ?? 0
            sum &+= UInt32(hi) << 8 | UInt32(lo)
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) &+ (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }
}
