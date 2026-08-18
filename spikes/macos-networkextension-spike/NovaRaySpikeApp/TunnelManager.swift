import Foundation
@preconcurrency import ObjectiveC
@preconcurrency import NetworkExtension
import SystemExtensions
import Combine

public enum SpikeConnectionStatus: String, Sendable {
    case disconnected = "Disconnected"
    case activatingExtension = "Activating System Extension"
    case awaitingApproval = "Awaiting User Approval in System Settings"
    case connecting = "Connecting"
    case connected = "Connected"
    case disconnecting = "Disconnecting"
    case failed = "Failed"
}

@MainActor
public final class TunnelManager: NSObject, ObservableObject {
    @Published public private(set) var status: SpikeConnectionStatus = .disconnected
    @Published public private(set) var statusMessage: String = "Ready"
    @Published public private(set) var logs: [String] = []

    private var providerManager: NETunnelProviderManager?
    private var statusCancellable: AnyCancellable?
    private let extensionBundleIdentifier = "org.novaray.spike.packettunnel"

    public var isConnected: Bool {
        status == .connected
    }

    public var statusIconName: String {
        switch status {
        case .connected:
            return "bolt.shield.fill"
        case .connecting, .activatingExtension, .awaitingApproval:
            return "bolt.shield"
        case .disconnected, .disconnecting:
            return "shield.slash"
        case .failed:
            return "exclamationmark.shield"
        }
    }

    public override init() {
        super.init()
        appendLog("TunnelManager initialized on macOS 14+ Apple Silicon host.")
        loadProviderManager()
    }

    public func appendLog(_ message: String) {
        let formatter = ISO8601DateFormatter()
        let timestamp = formatter.string(from: Date())
        logs.append("[\(timestamp)] \(message)")
    }

    public func loadProviderManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            nonisolated(unsafe) let mgrs = managers
            let err = error
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if let error = err {
                    self.appendLog("Failed to load tunnel preferences: \(error.localizedDescription)")
                    self.statusMessage = "Load error: \(error.localizedDescription)"
                    return
                }

                // Filter strictly by our bundle identifier to avoid selecting third-party VPN managers
                let matching = mgrs?.first { manager in
                    guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                    return proto.providerBundleIdentifier == self.extensionBundleIdentifier
                }

                if let existing = matching {
                    self.providerManager = existing
                    self.setupStatusObserver(for: existing)
                    self.appendLog("Found existing NovaRay NETunnelProviderManager configuration.")
                } else {
                    self.appendLog("No NovaRay configuration found. Initializing a new NETunnelProviderManager.")
                    let newManager = NETunnelProviderManager()
                    let proto = NETunnelProviderProtocol()
                    proto.providerBundleIdentifier = self.extensionBundleIdentifier
                    proto.serverAddress = "127.0.0.1" // Local loopback for isolated spike
                    proto.providerConfiguration = [
                        "routing_mode": "IsolatedSubnetSpike"
                    ]
                    newManager.protocolConfiguration = proto
                    newManager.localizedDescription = "NovaRay Spike Tunnel"
                    newManager.isEnabled = true
                    self.providerManager = newManager
                    self.setupStatusObserver(for: newManager)
                }
            }
        }
    }

    private func setupStatusObserver(for manager: NETunnelProviderManager) {
        updateStatus(from: manager.connection.status)

        statusCancellable = NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange, object: manager.connection)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self, let mgr = self.providerManager else { return }
                self.updateStatus(from: mgr.connection.status)
            }
    }

    private func updateStatus(from vpnStatus: NEVPNStatus) {
        switch vpnStatus {
        case .invalid:
            status = .failed
            statusMessage = "Configuration invalid"
        case .disconnected:
            status = .disconnected
            statusMessage = "Disconnected"
        case .connecting:
            status = .connecting
            statusMessage = "Connecting..."
        case .connected:
            status = .connected
            statusMessage = "Connected"
        case .reasserting:
            status = .connecting
            statusMessage = "Reasserting..."
        case .disconnecting:
            status = .disconnecting
            statusMessage = "Disconnecting..."
        @unknown default:
            status = .disconnected
            statusMessage = "Unknown state"
        }
        appendLog("Observed NEVPNStatus change: \(status.rawValue)")
    }

    public func activateSystemExtension() {
        appendLog("Requesting system extension activation for \(extensionBundleIdentifier)...")
        status = .activatingExtension

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func toggleConnection() {
        if isConnected {
            disconnect()
        } else {
            connect()
        }
    }

    public func connect() {
        appendLog("Initiating connection sequence...")
        guard let manager = providerManager else {
            status = .failed
            statusMessage = "Tunnel manager not loaded"
            appendLog("Error: providerManager is nil")
            return
        }

        manager.saveToPreferences { [weak self] error in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if let error = error {
                    self.status = .failed
                    self.statusMessage = "Save preferences failed: \(error.localizedDescription)"
                    self.appendLog("Save error (expected without Developer ID / Gate B): \(error.localizedDescription)")
                    return
                }

                guard let currentManager = self.providerManager else { return }
                // Reload configuration after saving to ensure preferences are committed to connection
                currentManager.loadFromPreferences { [weak self] loadError in
                    Task { @MainActor [weak self] in
                        guard let self = self else { return }
                        if let loadError = loadError {
                            self.status = .failed
                            self.statusMessage = "Reload preferences failed: \(loadError.localizedDescription)"
                            self.appendLog("Reload error: \(loadError.localizedDescription)")
                            return
                        }

                        guard let reloadedManager = self.providerManager else { return }
                        do {
                            // startVPNTunnel is an asynchronous start request. Status is updated
                            // strictly via NEVPNStatusDidChange observation.
                            try reloadedManager.connection.startVPNTunnel(options: nil)
                            self.appendLog("VPN tunnel start requested asynchronously.")
                        } catch {
                            self.status = .failed
                            self.statusMessage = "Start tunnel failed: \(error.localizedDescription)"
                            self.appendLog("Start tunnel error (Gate A restriction): \(error.localizedDescription)")
                        }
                    }
                }
            }
        }
    }

    public func disconnect() {
        appendLog("Stopping VPN tunnel...")
        providerManager?.connection.stopVPNTunnel()
        appendLog("VPN tunnel stop requested asynchronously.")
    }
}

// MARK: - OSSystemExtensionRequestDelegate
extension TunnelManager: @preconcurrency OSSystemExtensionRequestDelegate {
    public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        appendLog("System extension replacement requested.")
        return .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        status = .awaitingApproval
        statusMessage = "Approve extension in System Settings -> Privacy & Security"
        appendLog("User approval required in macOS System Settings.")
    }

    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        appendLog("System extension request finished with result: \(result.rawValue)")
        if result == .completed {
            status = .disconnected
            statusMessage = "Extension active. Ready to connect."
        }
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        status = .failed
        statusMessage = "Extension request failed: \(error.localizedDescription)"
        appendLog("System extension error (Requires Gate B Developer ID): \(error.localizedDescription)")
    }
}
