import SwiftUI

public struct ContentView: View {
    @ObservedObject var tunnelManager: TunnelManager

    public init(tunnelManager: TunnelManager) {
        self.tunnelManager = tunnelManager
    }

    public var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Image(systemName: tunnelManager.statusIconName)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 32, height: 32)
                    .foregroundColor(statusColor)

                VStack(alignment: .leading, spacing: 2) {
                    Text("NovaRay macOS Spike")
                        .font(.headline)
                    Text("Phase 0.3 NetworkExtension & SwiftUI Preview")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal)
            .padding(.top, 16)

            Divider()

            // Status Card
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Tunnel Status:")
                        .fontWeight(.semibold)
                    Spacer()
                    Text(tunnelManager.status.rawValue)
                        .foregroundColor(statusColor)
                        .fontWeight(.bold)
                }

                HStack {
                    Text("Message:")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(tunnelManager.statusMessage)
                        .font(.subheadline)
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
            .padding(.horizontal)

            // Actions
            HStack(spacing: 12) {
                Button(action: {
                    tunnelManager.activateSystemExtension()
                }) {
                    Label("1. Activate SysEx", systemImage: "puzzlepiece.extension")
                }
                .disabled(tunnelManager.isConnected)

                Button(action: {
                    tunnelManager.toggleConnection()
                }) {
                    Label(tunnelManager.isConnected ? "Disconnect" : "2. Connect", systemImage: tunnelManager.isConnected ? "stop.fill" : "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(tunnelManager.isConnected ? .red : .blue)
            }

            // Architecture Note
            VStack(alignment: .leading, spacing: 4) {
                Text("Gate A Architectural Notice:")
                    .font(.caption)
                    .fontWeight(.bold)
                Text("Under Gate A (free Apple ID), activation fails because OSSystemExtension & NetworkExtension entitlements require a paid Apple Developer Program (Gate B).")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)

            Divider()

            // Logs
            VStack(alignment: .leading, spacing: 4) {
                Text("Diagnostic Console:")
                    .font(.caption)
                    .fontWeight(.semibold)

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(tunnelManager.logs.enumerated()), id: \.offset) { _, log in
                            Text(log)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.primary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
                .frame(maxHeight: 120)
                .background(Color(NSColor.textBackgroundColor))
                .cornerRadius(6)
            }
            .padding(.horizontal)
            .padding(.bottom, 16)
        }
    }

    private var statusColor: Color {
        switch tunnelManager.status {
        case .connected:
            return .green
        case .connecting, .activatingExtension, .awaitingApproval:
            return .orange
        case .disconnected, .disconnecting:
            return .secondary
        case .failed:
            return .red
        }
    }
}
