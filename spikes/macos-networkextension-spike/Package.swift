// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NovaRaySpike",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "NovaRaySpikeAppLib", targets: ["NovaRaySpikeAppLib"]),
        .library(name: "NovaRayPacketTunnelLib", targets: ["NovaRayPacketTunnelLib"])
    ],
    targets: [
        .target(
            name: "NovaRaySpikeAppLib",
            path: "NovaRaySpikeApp",
            exclude: ["Info.plist", "NovaRaySpikeApp.entitlements"]
        ),
        .target(
            name: "NovaRayPacketTunnelLib",
            path: "NovaRayPacketTunnel",
            exclude: ["main.swift", "Info.plist", "NovaRayPacketTunnel.entitlements"]
        )
    ]
)
