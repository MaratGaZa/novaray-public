# NovaRay: Project Specification

Document status: working specification, pre-alpha

Release order: macOS 14+ on Apple Silicon (`aarch64-apple-darwin`) first; Windows 11 x64 (`x86_64-pc-windows-msvc`) second; Android third

Core language: Rust 2021

Product status: library-logic prototype, not a working VPN client

## 1. Product goal

NovaRay is intended to become a native application family for macOS, Windows, and Android backed by
one shared Rust core. The first production release is a macOS Apple Silicon application distributed
as source to be built locally; the second mandatory release is Windows 11 x64; the third is Android.
The product:

1. establishes and supervises a system VPN tunnel;
2. initially supports VLESS + Reality + XTLS Vision;
3. routes IPv4 and IPv6 safely;
4. supports domain and IP/CIDR split tunneling;
5. supports per-app routing as one of the two headline features alongside the VPN itself, within what each platform can enforce reliably;
6. restores routes, DNS, firewall, and system state after disconnects and failures;
7. provides an accessible native UI on each supported desktop platform.

Windows 11 is outside the first macOS production milestone but is the mandatory second release;
Android is the third. Linux and additional protocols are outside the first two production
releases.

## 2. Product boundaries

### 2.1. Meaning of “written in Rust”

Rust owns the shared domain model, configuration, policy engine, state machine, observability,
engine-neutral contracts, and as much of the network core as practical. Platform layers must not
duplicate policy logic. A narrow Swift/Objective-C layer is allowed for macOS SwiftUI/AppKit and
a narrow privileged helper; Windows may use a narrow native shell and a separate Windows
Service/network boundary after an architecture spike.

[ADR-001](./ADR-001-MACOS-UI.md) selects a SwiftUI/AppKit shell with a Rust core for macOS; a second UI stack for macOS is not supported. The Windows and Android UI stack is an open decision with Tauri v2 as the candidate (HTML/CSS/TypeScript in the system WebView), taken by a separate ADR after the first macOS release.
[ADR-006](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md) defines the proposed shared-core/platform boundary.

### 2.2. Meaning of “native desktop application”

The macOS release must provide a `.app`, menu-bar behavior, accessibility, lifecycle integration,
code signing, notarization, and an approved macOS network boundary. The Windows release must provide
a native desktop shell, tray/lifecycle integration, accessibility, a signed installer/update path,
and a separately privileged network service boundary. Exact Windows UI, WFP/Wintun/TUN, and
packaging choices remain `Proposed` until their ADR/spikes.

### 2.3. Platform order

1. Complete the macOS milestones and first production release.
2. Then complete the mandatory Windows 11 milestones while reusing versioned Rust crates, schemas, and fixtures.
3. Then complete the Android milestones on the same core, configuration format, and engine; the privileged boundary is `VpnService`. Android code placement and UI stack are decided by a separate ADR ([ADR-006](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md), item 7).

### 2.4. macOS distribution decision

The product owner has fixed that paid Apple Developer Program membership will not be purchased.
The first release therefore uses **source-first distribution**: users build the application locally
or through a package-manager formula that builds from source. Shipping an unsigned binary with
Gatekeeper-bypass instructions is not considered.

Consequences: the `com.apple.developer.networking.networkextension` entitlement is unavailable, so
the system tunnel is implemented through a privileged helper plus `utun`
([ADR-003](./ADR-003-NETWORK-TOPOLOGY.md)), and the audience is limited to users willing to build
from source.

[ADR-002](./ADR-002-MACOS-DISTRIBUTION.md) stays `Proposed` until Gate S passes (reproducible build,
helper install/uninstall, engine license legal review). Direct Developer ID distribution remains the
target model if a paid account is obtained.

## 3. Current implementation status

Legend: `[x]` implemented, `[~]` partial prototype, `[ ]` absent.

- [x] Rust library and CLI targets.
- [x] Configuration models with typed enums, validation, Serde JSON round trips, and JSON Schemas under `schema/`.
- [x] VLESS URI parsing with basic Reality parameters, TCP/RAW, WebSocket, and gRPC plus fail-closed rejection of other transports.
- [~] Engine JSON generation: the Xray generator and the swappable sing-box strategy generate local SOCKS/HTTP inbounds and VLESS outbounds with standard TLS, Reality, and TCP/WebSocket/gRPC metadata; Xray has controlled loopback traffic evidence, sing-box Reality/TCP passes `sing-box check -c` on pinned `v1.13.18`, but routing/DNS policy is not implemented yet.
- [~] Domain, IP, and app matcher with typed `SplitTunnelMode`; traffic data-plane enforcement requires network extension.
- [~] Process spawn/kill without readiness, log draining, restart, or graceful shutdown.
- [~] No-op RouteManager API.
- [ ] TUN data plane through a privileged helper (`utun`).
- [ ] DNS protection and kill switch.
- [ ] GUI and macOS application bundle.
- [ ] Signing, notarization, updater, and release pipeline.
- [ ] Windows 11 UI, service/network adapter, and signed package.
- [ ] Windows 11 system-test environment.

## 4. Functional requirements

### FR-001 — Configuration and profiles

- [x] Provide versioned JSON schemas under `schema/` (`config.schema.json`, `settings.schema.json`) validated in tests and CI.
- [x] Store server profiles in `config.json` and routing/client preferences in `settings.json`.
- [x] Replace protocol, security, flow, transport, and mode strings with typed enums/value objects.
- [~] Validate UUID, host, port, TLS/Reality requirements (SNI, Base64 public_key, hex short_id, uTLS fingerprint), proxy ports, domain/IP rules (CIDR and GeoIP datasets deferred to M2).
- [ ] Write configuration atomically and preserve the last valid backup.
- [ ] Keep secrets out of logs and use the platform credential store where appropriate.
- [x] URI import rejects incomplete Reality settings (validates mandatory `public_key`, fail-closed for unsupported `security`, `flow`, and transport `type`).

### FR-002 — Protocol support

The first required vertical slice is VLESS + Reality + XTLS Vision over TCP. The selected engine
must validate generated configuration before start. The current MVP must not architecturally block
additional protocols supported by the selected engine. UI, helper/IPC contracts, and the policy
model must not assume that VLESS is the only possible outbound protocol: protocol selection is a
typed profile field translated by engine-specific generators. After stable desktop releases, later
vertical slices may add Trojan + TLS, Shadowsocks AEAD/2022, Hysteria 2, TUIC, WireGuard, VMess, and
debug/enterprise outbounds (`socks`, `http`, `ssh`) where supported by the chosen engine and where
they do not weaken the safety model. Each new protocol requires its own schema, URI/config importer,
semantic validation, capability matrix, generated-config preflight, real-network integration tests,
redaction review, and limitation documentation. WireGuard is treated as a separate VPN-profile model
with keys, addresses, and allowed IPs, not as a simple variant of a VLESS proxy profile.

A VLESS URI without `type`, with `type=tcp`, or with the compatible `type=raw` alias selects the
supported TCP/RAW transport. For TCP, an absent `headerType` and `headerType=none` are accepted;
`headerType=http` and unknown values are rejected until a dedicated TCP header-obfuscation model is
implemented. WebSocket (`type=ws`/`websocket`) and gRPC (`type=grpc`) are retained in the
engine-neutral `transport`, `host`, and `path` profile fields. Empty or whitespace-only `host`,
`path`, `authority`, `serviceName`, and `mode` values are normalized as absent; non-empty transport
values are trimmed. WebSocket requires an absolute `path`; gRPC accepts a non-empty standard
`serviceName` without `/` (or the compatible `path` query) and optional `authority` (or `host`).
Xray's leading-slash gRPC custom-path syntax is outside the current capability and fails closed.
The effective transport host is selected in this order: explicit `host`/`authority`, TLS `server_name`, then the
`server` address. `mode` is interpreted only for `type=grpc`: `mode=gun` is supported and other
non-empty gRPC modes fail closed; a TCP `mode` value is not treated as part of the gRPC contract.
The Xray generator emits normalized `wsSettings` (`path`, `headers.Host`) or `grpcSettings`
(`serviceName`, `authority`) respectively. XTLS Vision with WebSocket/gRPC and Reality with
WebSocket are rejected as incompatible combinations; Reality with TCP/RAW and gRPC is accepted.
`httpupgrade`, `xhttp`, `h2`, `quic`, `kcp`, and unknown values remain fail-closed.
Known critical query-parameter names are case-sensitive; variants such as `Type`, `Security`, and
`HeaderType`, `Host`, `Path`, `ServiceName`, `Authority`, and `Mode` are rejected explicitly instead
of being ignored.

### FR-003 — Engine lifecycle

- Pin and verify the engine version and checksum.
- Automatic pinned binary checksum support covers Xray-core and sing-box on macOS arm64, macOS
  x86_64, Linux arm64, Linux x86_64, and Windows x86_64. Other OS/arch combinations are outside
  the current support matrix, are explicitly marked unsupported by help/`pinned-releases`, and
  cannot start without an explicit trusted `--expected-sha256`.
- Runtime selects an engine version from the versioned pinned catalog: by default the one
  `recommended` version, or an explicit user-provided `--engine-version <VERSION>` for the selected
  `--engine-config`. The
  catalog records `recommended`/`supported`/`deprecated`/`yanked` lifecycle status, full declared
  OS/arch coverage, and both lowercase SHA-256 values; changing the default requires a separate,
  reviewable changelog change. The CLI/API does not treat `engine version` output as a
  trusted security oracle. On a pinned binary checksum mismatch, diagnostics name the engine,
  pinned version, and target OS/arch, and distinguish “different/unsupported version or modified
  artifact” from a missing platform pin. Startup remains fail-closed; `--expected-sha256` is an
  explicit trusted override for expected binary bytes, but it does not select an engine version,
  does not prove the binary version, and does not disable the compatibility check.
- `--engine-version` accepts only catalogued versions for the selected engine. `recommended` and
  `supported` releases are allowed, `deprecated` releases are allowed only with a warning before
  process start, and `yanked`, unknown, uncatalogued, or dialect-incompatible versions are rejected
  before checksum verification or process spawn.
- A typed configuration dialect is stored in the catalog as an exact `engine/version` property and
  validated against the selected release before choosing the checksum source or starting
  a process: the current proven pairs are Xray `v26.3.27`/`XrayV26` and sing-box
  `v1.13.18`/`SingBoxV1_13`. Catalog validation rejects unknown dialect strings and target rows for
  the same version that disagree on dialect.
- The `start` CLI command accepts `--engine-config xray|sing-box` to select the generated
  configuration format and pre-flight command. It defaults to `xray`; `--engine-bin` supplies
  the executable path for the selected engine and does not itself change the configuration format.
  `--engine-version <VERSION>` selects a catalogued version for the selected engine and does not
  itself change the configuration format.
  An unknown strategy value is rejected as a usage error before configuration is read or a process
  is started.
- Treat a readiness probe, not process spawn, as successful start.
- Drain and redact stdout/stderr asynchronously.
- Implement graceful stop, timeout, forced termination, and restart policy.
- On engine failure, enter a safe network state and run rollback.
- Validate whether subprocess execution is compatible with each distribution model before freezing its architecture.

### FR-004 — VPN data plane

- Support IPv4 and IPv6, or explicitly block IPv6 safely until implemented.
- Keep the VPN server endpoint outside the tunnel to prevent routing loops.
- Configure routes, MTU, and DNS through the selected supported API for the current platform.
- Put direct system operations behind a narrow validated privileged boundary.
- Make repeated connect/disconnect operations idempotent.

### FR-005 — Split tunneling

Use typed modes: `proxy_all`, `bypass_selected`, optional `proxy_selected`, and optional
`block_selected`. Rules cover exact/suffix domains, IPv4/IPv6 CIDRs, versioned GeoIP/GeoSite data,
local networks, and app rules only when reliable platform-specific attribution and enforcement are
proven. A `Direct`/`Proxy` return value not applied to live traffic does not count as split tunneling.

### FR-006 — Per-app routing

Per-app routing is one of the two headline product features and is provided by the engine rather
than by a custom process-matching implementation: sing-box exposes `process_name` and `process_path`
rules on macOS/Windows and `package_name` on Android ([ADR-004](./ADR-004-ENGINE-INTEGRATION.md),
fact 2). The core translates the user-facing application list into those rules and normalizes it,
because the engine matches executable name and path rather than a bundle identifier.

Complete a platform-specific spike before production implementation. The spike covers TCP/UDP
attribution, races, QUIC, helpers, sandboxed apps, reconnect behavior, privacy, and distribution
compatibility. Results cannot be transferred between platforms without evidence. If reliability is
not proven, domain/IP split tunneling is the honest release boundary.

### FR-007 — DNS

DNS follows the same routing policy as user traffic. Prevent leaks through connect, reconnect, and
disconnect; support split DNS and IPv6; and restore the original resolver state from a transaction
snapshot.

### FR-008 — Kill switch and recovery

- Prevent silent direct fallback after an unexpected tunnel failure when enabled.
- Snapshot platform network state before mutations.
- Roll back after normal stop, signals, failed partial connection, and recovery on next launch.
- Provide a user-visible safe recovery action.

### FR-009 — UI

Provide a truthful connection state machine, profile management, URI import preview, policy editor,
tray/menu-bar control, redacted diagnostics, settings, keyboard navigation, localization,
accessibility, and light/dark mode. The UI never executes privileged networking operations directly.
macOS follows ADR-001. WinUI 3 is recommended for Windows, but remains `Proposed` under ADR-006
until a spike; a web UI or custom renderer is not the default.

### FR-010 — Updates and diagnostics

Display app, engine, and rules-database versions separately. Verify signed updates. Diagnostic export
requires preview and redaction. Telemetry remains disabled until a separate privacy specification exists.

### FR-011 — Shared core and platform contracts

- The Rust core is the source of truth for policy, profiles, state machine, and engine-neutral diagnostics.
- Platform adapters report capabilities and never advertise unsupported features.
- FFI/IPC commands and events are typed, versioned, and handshake before any network mutation.
- Unknown versions or commands fail safely; the UI displays observed rather than assumed state.
- Platform handles, raw shell commands, and privilege decisions stay outside the shared public contract.
- The platform helper contract skeleton contains only typed handshake, capability reporting,
  allowlisted commands/events, strict schema validation, redacted debug output, and bounded
  validation. It does not install a helper, open an IPC transport, run as `root`, or mutate `utun`,
  routes, DNS, firewall, or system proxy state.

## 5. Target architecture

```text
SwiftUI/AppKit macOS shell ─┐
                           ├─ versioned commands/events ─ Rust Application Core
Windows native shell ──────┘                              │
                                                         ├─ config/policy/state/diagnostics
macOS Network Boundary ◄─────────────────────────────────┤
Windows Service/Network Boundary ◄───────────────────────┘
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for current and target component boundaries.

## 6. Non-functional requirements

- **Security:** deny-by-default privileged APIs, minimal entitlements/service rights, no shell interpolation, artifact verification, no secret logging, and a pre-beta threat model.
- **Reliability:** compensating actions for every network mutation, serialized lifecycle transitions, and automated residue checks after failure.
- **Performance:** responsive native UI, no continuous high-frequency idle rendering, measured throughput/latency, and budgets after the first end-to-end prototype.
- **Compatibility:** macOS 14+ and `aarch64-apple-darwin` first; Windows 11 x64 and `x86_64-pc-windows-msvc` second. Intel universal and Windows ARM64 are separate decisions; Android is not a target of this repository.
- **Observability:** structured state transitions, correlation IDs, redacted diagnostics, and actionable platform errors.

## 7. Configuration contract

The canonical `settings.json` uses the current `client` section. The older `system` section is
retired. Canonical schemas `schema/config.schema.json` and `schema/settings.schema.json` are the authoritative source, and configuration examples are validated against them in tests and CI. Historical free-form modes such as `bypass_ru` and `direct_all` are not a supported public contract; `mode` is strictly typed via `SplitTunnelMode`.

## 8. First working macOS release acceptance criteria

1. A signed arm64 `.app` installs on a clean Mac.
2. A valid VLESS Reality profile connects to a controlled test server.
3. IPv4, IPv6, and DNS match the declared policy.
4. Domain/IP split tunneling passes packet-level tests.
5. Disconnect, engine crash, and forced termination leave no route or DNS residue.
6. Kill-switch negative scenarios pass.
7. The UI displays observed state rather than merely requested state.
8. The release is signed and notarized with documented rollback.

Per-app routing may remain post-release if its spike does not prove safe consumer-grade behavior.

### 8.1. Second Windows 11 release acceptance criteria

1. A signed installer works on a clean Windows 11 x64 machine.
2. A native UI controls a separately privileged service through versioned authenticated IPC.
3. A valid VLESS Reality profile creates a real IPv4/IPv6 and DNS full tunnel, or unsupported IPv6 is blocked safely.
4. Domain/IP split tunneling is confirmed by observed direct/proxy egress.
5. Service/engine/UI crash, reboot, upgrade, and forced stop leave no route, DNS, firewall/WFP-filter, or process residue.
6. Kill-switch and endpoint-loop-prevention negative tests pass.
7. The UI reports observed service/tunnel state and exposes a safe recovery action.
8. Signed package/update plus rollback/uninstall pass clean-machine verification.

## 9. First macOS release non-goals

- a simultaneous Windows release: Windows 11 is the mandatory second release;
- Linux and Windows ARM64;
- an Android app in this repository;
- every advertised protocol;
- a custom Metal-rendered UI;
- cloud accounts and sync;
- telemetry;
- simultaneous App Store and direct-distribution launches when that delays a verifiable release.

## 10. Traceability

- Work inventory: [roadmap](../learning/05_roadmap_zero_to_hero.md).
- Execution order: [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md).
- macOS UI decision: [ADR-001-MACOS-UI.md](./ADR-001-MACOS-UI.md).
- Distribution channel: [ADR-002-MACOS-DISTRIBUTION.md](./ADR-002-MACOS-DISTRIBUTION.md).
- Network topology: [ADR-003-NETWORK-TOPOLOGY.md](./ADR-003-NETWORK-TOPOLOGY.md).
- Engine integration: [ADR-004-ENGINE-INTEGRATION.md](./ADR-004-ENGINE-INTEGRATION.md).
- Cross-platform boundaries: [ADR-006-CROSS-PLATFORM-BOUNDARIES.md](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md).
- Quality gates: [TESTING.md](./TESTING.md).
