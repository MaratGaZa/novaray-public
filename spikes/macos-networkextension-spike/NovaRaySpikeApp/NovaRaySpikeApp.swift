import SwiftUI

@main
struct NovaRaySpikeApp: App {
    @StateObject private var tunnelManager = TunnelManager()

    var body: some Scene {
        WindowGroup("NovaRay Spike — macOS Architecture Preview") {
            ContentView(tunnelManager: tunnelManager)
                .frame(minWidth: 480, minHeight: 360)
        }
        .windowResizability(.contentSize)

        MenuBarExtra("NovaRay Spike", systemImage: tunnelManager.statusIconName) {
            Button(tunnelManager.isConnected ? "Disconnect" : "Connect") {
                tunnelManager.toggleConnection()
            }
            .keyboardShortcut("c", modifiers: [.command])

            Divider()

            Button("Open Control Window") {
                NSApp.activate(ignoringOtherApps: true)
            }

            Divider()

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: [.command])
        }
    }
}
