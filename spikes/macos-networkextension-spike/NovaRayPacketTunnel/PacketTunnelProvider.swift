import Foundation
@preconcurrency import ObjectiveC
@preconcurrency import NetworkExtension
import os.log

// MARK: - Typed IPC Contracts & Bounded Schema
private enum SpikeIPCCommand: String, Decodable, Sendable {
    case getStatus
    case ping
}

private struct SpikeIPCRequest: Decodable, Sendable {
    let command: SpikeIPCCommand
}

private struct SpikeIPCResponse: Encodable, Sendable {
    let status: String
    let activeRoutes: [String]
    let mtu: Int
    let errorMessage: String?
}

// Thread-safe state container for provider state
private final class TunnelState: @unchecked Sendable {
    private let lock = NSLock()
    private var _isRunning: Bool = false

    var isRunning: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _isRunning
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _isRunning = newValue
        }
    }
}

public final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let logger = Logger(subsystem: "org.novaray.spike", category: "PacketTunnel")
    private let state = TunnelState()

    public override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting NovaRay PacketTunnelProvider spike...")

        // SAFETY: In this spike, we deliberately route ONLY an isolated test subnet (10.8.0.0/24)
        // and a local test domain. We DO NOT route default 0.0.0.0/0 or wildcard DNS,
        // preventing network blackholes until the protocol engine (Xray/Sing-box) is attached in Gate B.
        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // 1. IPv4 Configuration (Isolated test subnet only)
        let ipv4Settings = NEIPv4Settings(
            addresses: ["10.8.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        ipv4Settings.includedRoutes = [
            NEIPv4Route(destinationAddress: "10.8.0.0", subnetMask: "255.255.255.0")
        ]
        ipv4Settings.excludedRoutes = []
        tunnelNetworkSettings.ipv4Settings = ipv4Settings

        // 2. DNS Configuration (Scoped test domain only)
        let dnsSettings = NEDNSSettings(servers: ["127.0.0.1"])
        dnsSettings.matchDomains = ["spike.novaray.local"]
        tunnelNetworkSettings.dnsSettings = dnsSettings

        // 3. MTU & Overhead
        tunnelNetworkSettings.tunnelOverheadBytes = 80
        tunnelNetworkSettings.mtu = 1420

        // Apply settings to macOS network stack
        nonisolated(unsafe) let completion = completionHandler
        setTunnelNetworkSettings(tunnelNetworkSettings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logger.error("Failed to apply tunnel network settings: \(error.localizedDescription)")
                completion(error)
                return
            }

            self.state.isRunning = true
            self.logger.info("Isolated spike network settings established. Starting packet reader loop.")
            self.startPacketReadingLoop()
            completion(nil)
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping NovaRay PacketTunnelProvider. Reason code: \(reason.rawValue)")
        state.isRunning = false
        completionHandler()
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler = completionHandler else { return }

        // 1. Bound check: enforce strict 4 KB limit on control IPC payload
        guard messageData.count <= 4096 else {
            logger.warning("Rejected oversized IPC message: \(messageData.count) bytes exceeds 4096-byte limit.")
            let errorResponse = SpikeIPCResponse(
                status: "REJECTED",
                activeRoutes: [],
                mtu: 0,
                errorMessage: "Payload size exceeds 4096 bytes"
            )
            let responseData = try? JSONEncoder().encode(errorResponse)
            completionHandler(responseData)
            return
        }

        // 2. Bounded typed IPC parser: decode enum-constrained command schema
        let decoder = JSONDecoder()
        guard let request = try? decoder.decode(SpikeIPCRequest.self, from: messageData) else {
            let errorResponse = SpikeIPCResponse(
                status: "ERROR",
                activeRoutes: [],
                mtu: 0,
                errorMessage: "Invalid JSON or command not in typed allowlist"
            )
            let responseData = try? JSONEncoder().encode(errorResponse)
            completionHandler(responseData)
            return
        }

        switch request.command {
        case .getStatus:
            let response = SpikeIPCResponse(
                status: state.isRunning ? "RUNNING" : "STOPPED",
                activeRoutes: ["10.8.0.0/24"],
                mtu: 1420,
                errorMessage: nil
            )
            let responseData = try? JSONEncoder().encode(response)
            completionHandler(responseData)

        case .ping:
            let response = SpikeIPCResponse(
                status: "PONG",
                activeRoutes: [],
                mtu: 1420,
                errorMessage: nil
            )
            let responseData = try? JSONEncoder().encode(response)
            completionHandler(responseData)
        }
    }

    private func startPacketReadingLoop() {
        guard state.isRunning else { return }

        packetFlow.readPackets { [weak self] (packets: [Data], protocols: [NSNumber]) in
            guard let self = self, self.state.isRunning else { return }

            for (index, packet) in packets.enumerated() {
                let proto = protocols[index]
                self.logger.debug("Received packet (\(packet.count) bytes, protocol: \(proto))")
            }

            self.startPacketReadingLoop()
        }
    }
}
