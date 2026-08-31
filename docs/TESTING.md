# NovaRay: стратегия тестирования

## 1. Текущий статус

Текущие тесты проверяют Rust-модели и чистую логику. Они не доказывают, что приложение подключается к VPN, создаёт tunnel, применяет split tunneling или восстанавливает macOS/Windows network state.

В проекте есть:

- unit tests в `src/config.rs`, `src/parser.rs`, `src/matcher.rs`, `src/xray_generator.rs`;
- integration-style tests в `tests/`, связывающие несколько Rust-модулей и fixtures;
- проверки повреждённого JSON и некорректных VLESS URI.
- изолированный L3 spike `spikes/macos-rust-ffi-spike/`: Rust unit/layout tests и arm64 Swift
  harness проверяют синхронный ABI v1 callback; это ещё не production lifecycle contract.
- evidence-only manifest `spikes/macos-engine-topology-spike/` фиксирует pinned upstream metadata и
  открытые engine topology gates; offline validator проверяет честность claims, но не запускает engine.

Файл `test_end_to_end_vless_to_xray_pipeline` является end-to-end только для in-memory цепочки `URI → models → matcher → JSON`. Это не системный VPN E2E.

`test_route_manager_and_process_supervisor_initialization` вызывает no-op `RouteManager` и пустой `stop`; он не проверяет маршруты или процесс engine.

## 2. Текущие команды

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

На момент актуализации:

- `cargo test --all-targets` проходит;
- строгий Clippy `-D warnings` проходит после добавления `Default` для `ProcessSupervisor` и
  `RouteManager`;
- duplicate module compilation устранён: binary использует library target и больше не объявляет
  повторные `mod`.

Эти L0/L1 проверки не являются evidence работающего VPN, macOS NetworkExtension или Windows Service/network adapter.

## 3. Уровни тестирования

### L0 — Static gates

- format;
- Clippy warnings as errors;
- dependency/license/security audit;
- JSON Schema validation;
- Swift/Xcode warnings as errors для release targets;
- secret scanning fixtures и logs.

### L1 — Unit tests

Проверяют одну функцию или state transition без OS/network side effects:

- config validators и migrations;
- URI parser;
- domain/IP/CIDR matching;
- rule precedence/conflicts;
- policy compiler;
- engine config generation;
- connection state machine;
- redaction.

### L2 — Property и fuzz tests

- произвольные URI/JSON не приводят к panic или unbounded allocation;
- serialize/deserialize/migrate сохраняют инварианты;
- domain suffix не создаёт partial false positive;
- CIDR precedence детерминирован;
- lifecycle command sequences сохраняют допустимое состояние.

### L3 — Contract tests

- JSON Schema ↔ Rust models;
- Rust FFI ↔ Swift ABI/version handshake;
- Rust core ↔ Windows IPC schema/version/capability handshake;
- generated config ↔ реальный engine validator;
- pinned engine evidence manifest ↔ required candidates/topologies/open gates;
- application commands ↔ state-machine events;
- CLI engine-strategy selection: default Xray, explicit sing-box, invalid value with usage exit code,
  and mapping to `ProxyServiceOptions` before any engine process starts;
- CLI engine-version selection: default recommended version, explicit catalogued version, missing
  value usage errors, unknown/yanked/incompatible version engine errors, deprecated warning, and
  mapping to `ProxyServiceOptions` before any engine process starts;
- platform helper contract skeleton: compatible handshake, protocol-version rejection, unknown
  command/capability/field rejection, missing required capability, bounded serialized command
  validation, bounded correlation IDs/capability lists, redacted debug output, and allowlisted
  command modeling with no network side effects;
- macOS platform helper skeleton binary: stdin/stdout JSON harness over the platform helper
  contract, deterministic help/usage/success/rejected exit codes, macOS idle status reporting, and
  fail-closed unknown-field rejection without `launchd`, root, IPC sockets, `utun` or OS mutation;
- macOS launchd daemon boundary descriptor: deterministic disabled-by-default LaunchDaemon plist for
  `novaray-platform-helper`, fail-closed label/path/argument validation, shell dispatcher rejection,
  and no install/load/root/IPC/utun/network side effects;
- macOS helper install/uninstall plan contract: typed allowlisted install/uninstall operations,
  mandatory admin authorization metadata, fixed root:wheel ownership/modes, traversal-path
  rejection, expected helper SHA-256 metadata validation, and no `sudo`/Authorization Services/
  `launchctl`/root/filesystem/network side effects;
- macOS helper install integrity preflight executor contract: the copy step requests SHA-256 for
  exactly `CopyHelper.source_path`, compares it with `expected_sha256`, records typed preflight
  evidence, and stops before plist/load records on mismatch without filesystem/network side effects;
- macOS helper descriptor-bound source preflight contract: the install preflight opens the source
  once, hashes through the opened source handle, retains a verified source for a future copy executor,
  and rejects mismatch/reordered plans without retaining a verified source;
- macOS helper safe source opener contract: file-backed preflight opens a regular helper source file
  with parent/final symlink rejection on Unix/macOS, non-blocking final-component open, regular-file
  confirmation through opened-handle metadata, handle-bound hashing, handle rewind for future copy
  work, and rejection of symlink/FIFO/non-regular sources without retaining verified source state;
- macOS helper source symlink diagnostics: final and parent symlink rejections expose the offending
  path component in a typed source error, including a macOS `/tmp` prefix rejection case;
- ADR-003 helper install gate split: docs distinguish reversible helper install/deinstall Gate I
  from helper runtime/data-plane Gate H and avoid claiming `utun`, route/DNS/firewall, packet-flow,
  DNS-leak, split tunneling or kill-switch evidence from install-only work;
- macOS helper install/deinstall executor: validated Gate I plans execute through a typed platform
  adapter after preflight, install copies only from the verified opened source handle, partial
  install failures run reverse-order rollback, uninstall failures return completed/remaining
  stop-state diagnostics, concrete file-system destination opens reject parent/final symlink
  components, owner/mode changes use the opened descriptor, installed plist keeps `KeepAlive`
  disabled before helper runtime IPC, and recording adapters prove no source reopen or shell
  interpolation;
- macOS root-helper runtime threat model: ADR-003 documents the pre-Gate-H assets, trust boundaries,
  local attacker capabilities, typed allowlist, runtime authentication/peer validation,
  session-bound replay protection, serialized recovery gate, rollback/fail-closed controls,
  redaction requirements and revisit conditions without implementing persistent IPC, `utun` or
  network mutation;
- macOS helper runtime replay guard contract: pure unit tests validate current-session command
  acceptance, fail-closed no-session and wrong-session rejection before sequence consumption,
  zero/repeated/stale sequence and forward-jump rejection, exact next-sequence acceptance, sequence
  reset only through a new handshake session, bounded session/correlation validation, correlation ID
  not acting as freshness proof, `u64::MAX` jump rejection without session pinning, fail-closed
  behavior after sequence exhaustion, and session/correlation redaction in `Debug`;
- macOS helper runtime session-scope contract: pure unit tests validate a per-session object owns
  replay state, two sessions can accept the same sequence independently, stale envelopes from prior
  sessions remain rejected after a new handshake, allowlisted command validation errors do not
  consume sequence, and session/correlation data remains redacted in session diagnostics;
- engine checksum diagnostics: explicit SHA-256 override, pinned-version mismatch with engine/version/
  OS/arch context, and missing platform pin before a binary is accepted;
- declared engine support matrix: every catalog OS/arch entry has a binary SHA-256 and its recorded
  archive/binary evidence is reproducible from the pinned upstream release asset;
- versioned engine catalog: unique engine/version/target keys, lowercase hash format, complete target
  coverage per version, one lifecycle status per version, one configuration dialect per version,
  exact strategy/release compatibility, and exactly one recommended version per engine;
- network-boundary request ↔ allowlisted operation.

### L4 — Component integration

- supervisor запускает реальный test engine, читает logs и обнаруживает readiness;
- graceful stop не оставляет child process;
- network transaction применяет и отменяет test state;
- config storage восстанавливается после interrupted write;
- recovery journal обрабатывается при следующем запуске.

### L5 — System VPN tests

Выполняются отдельно на изолированном Apple Silicon Mac и controlled Windows 11 x64 host/VM:

- full-tunnel TCP;
- UDP/QUIC capability;
- DNS через контролируемый resolver;
- IPv4 и IPv6;
- endpoint route без loop;
- sleep/wake;
- Wi-Fi/network interface change;
- repeated connect/disconnect.

### L6 — Split-tunneling evidence

Тест использует контролируемые direct и proxy egress endpoints и подтверждает наблюдаемый путь:

- exact domain direct;
- subdomain direct;
- foreign domain proxy;
- direct/proxy IP и CIDR;
- local network exclusion;
- CNAME и DNS cache;
- GeoIP/GeoSite version;
- app-specific egress только если per-app feature прошла architecture gate.

Возврат enum `RoutingDecision` без packet/egress evidence не закрывает L6.

### L7 — Leak и failure tests

- DNS leak;
- IPv6 leak;
- engine crash;
- platform extension/helper/service crash;
- UI crash;
- ошибка на каждом шаге connect transaction;
- forced quit;
- reboot/relaunch с recovery journal;
- kill switch under failure;
- отсутствие route/DNS/firewall residue.

### L8 — UI, package и release

- Swift/macOS и Windows native unit/UI tests;
- keyboard navigation и VoiceOver checklist;
- ADR-002 Gate S source-first proof: reproducible clean-clone build with documented prerequisites;
- clean-machine `.app` launch, helper install/uninstall and no Gatekeeper-bypass instructions;
- Windows installer/binaries signing and package trust verification;
- upgrade/downgrade/rollback;
- uninstall cleanup;
- redacted diagnostic export.

## 4. Реестр текущих тестов

| Область | Реально проверяется сейчас | Не проверяется |
|---|---|---|
| Config | basic required fields, ports, duplicate IDs, typed enums, semantic TLS/Reality validation (32-byte Base64 key, RFC 6066 SNI, even hex short_id), JSON schemas validation & negative corpus, deny_unknown_fields, serde roundtrip | migrations, atomic write, Keychain |
| VLESS parser | scheme, host/port, IPv4/IPv6 handling, standard TLS without SNI on IP hosts, Reality params validation and transport compatibility (WS rejected, TCP/gRPC accepted), TCP aliases (`type` absent, `tcp`, `raw`), WebSocket `host`/`path`, standard gRPC `serviceName` without `/`, `authority` plus compatibility aliases, normalized empty/whitespace query values, Host fallback (`host` → SNI → server), gRPC-scoped `mode=gun`, `headerType=none`, fail-closed on unknown security/flow, unsupported transport/header/gRPC mode/custom-path syntax, misplaced gRPC parameters, incompatible XTLS Vision transport and mis-cased critical query keys | fuzz corpus, full IDN punycode parsing, TCP HTTP-header generation, Xray gRPC custom-path capability |
| Matcher | exact/suffix domain, exact app string, exact IP, `geoip:private` loopback/RFC1918, typed SplitTunnelMode (4 modes), rules validation | CIDR subnets, real GeoIP/GeoSite datasets, live network data-plane enforcement |
| Generator | basic Xray and sing-box local proxy inbounds/outbounds, standard TLS (`allowInsecure: false` for Xray / `insecure: false` for sing-box), Reality key normalization, Xray WebSocket/gRPC settings, sing-box WebSocket/gRPC transport metadata, strategy selection tests, opt-in real Xray `v26.3.27` pre-flight for TLS WS/gRPC and Reality gRPC, opt-in real sing-box `v1.13.18` `check -c` for generated Reality/TCP config, and controlled Xray loopback HTTP-over-SOCKS5 traffic for WS/gRPC | remote TLS/CDN/Reality interoperability, sing-box live traffic, routing, DNS |
| Future protocols | no non-VLESS protocol is implemented; future slices must prove schema/importer/generator/preflight/real traffic per protocol and keep UI/helper boundaries protocol-agnostic | Trojan, Shadowsocks AEAD/2022, Hysteria 2, TUIC, WireGuard, VMess, debug/enterprise `socks`/`http`/`ssh` outbounds |
| macOS platform helper skeleton | `novaray-platform-helper` binary reads one allowlisted `PlatformHelperCommand` JSON document from stdin, writes one `PlatformHelperEvent` JSON document to stdout, validates contract/version/capability/size/unknown fields fail-closed, returns deterministic exit codes, and reports macOS capabilities/status without side effects | `launchd` installation, privilege escalation, persistent IPC, `utun`, route/DNS/firewall/system proxy mutation, packet flow, real helper lifecycle |
| macOS launchd daemon descriptor | deterministic disabled-by-default LaunchDaemon plist generation for `novaray-platform-helper`, including label/path/argument validation and rejection of shell dispatchers, relative paths, mismatched argv0 and control characters | helper installation/loading, root execution, `launchctl`, persistent IPC, `utun`, route/DNS/firewall/system proxy mutation, packet flow, real helper lifecycle |
| macOS helper install/uninstall plan contract | typed allowlisted install/uninstall operation plans with mandatory admin authorization metadata, fixed `root:wheel` ownership and file modes, deterministic LaunchDaemon plist payload, traversal-path rejection, expected helper artifact SHA-256 validation, side-effect-free copy-step preflight records, descriptor-bound helper source opening/hash evidence, file-backed safe source opener with parent/final symlink rejection, symlink component diagnostics, non-blocking FIFO-safe open, opened-handle regular-file confirmation and handle rewind, and validation of missing/mixed/tampered/reordered steps | real filesystem writes/copy, signature/Team ID verification, Authorization Services prompt, `sudo`, writes to `/Library`, `launchctl`, root execution, persistent IPC, `utun`, route/DNS/firewall/system proxy mutation, packet flow, real helper lifecycle |
| ADR-003 helper install gate split | docs define reversible helper install/deinstall as pre-runtime Gate I, keep ADR-003 `Proposed`, and state that Gate I may precede helper runtime without proving `utun`/data-plane behavior | real helper installation, filesystem writes/copy, Authorization Services prompt, `sudo`, `launchctl`, root execution, persistent IPC, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| macOS helper install/deinstall executor | typed executor runs plan validation and source preflight before authorization/system calls, copies from `VerifiedHelperInstallSource`, calls only typed platform adapter methods for copy/plist/load/unload/remove, rolls back partial install in reverse order, reports uninstall completed/remaining stop-state on failure, rejects destination parent/final symlinks, applies owner/mode through the opened descriptor, and keeps installed `KeepAlive` disabled before helper runtime IPC; tests use a recording adapter to prove operation order, mismatch-before-side-effects and no source reopen | live privileged installation, real `sudo`/Authorization Services prompt, actual writes to `/Library`, real `launchctl` execution in CI, persistent IPC, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| macOS root-helper runtime threat model | ADR-003 records root-helper runtime assets, trust boundaries, local attacker capabilities, typed allowlist, runtime authentication/peer validation, session-bound replay protection, serialized recovery gate, snapshot/rollback/fail-closed controls, redacted diagnostics and revisit conditions as a docs-only Gate H prerequisite | persistent IPC implementation, helper runtime startup, live authentication, replay enforcement, actual writes to `/Library`, real `launchctl` execution in CI, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| macOS helper runtime replay guard contract | pure `HelperRuntimeReplayGuard` unit tests cover current-session command acceptance, no-session and wrong-session rejection before sequence consumption, exact next-sequence acceptance, zero/repeated/stale sequence and forward-jump rejection, `u64::MAX` jump rejection without session pinning, fail-closed behavior after sequence exhaustion, sequence reset only through a new handshake session, bounded session/correlation validation, correlation ID not acting as freshness proof, handshake not being accepted as a runtime command, and redacted `Debug` output | persistent IPC implementation, helper runtime startup, live authentication/peer validation, root execution, real `launchctl`, actual writes to `/Library`, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| macOS helper runtime session-scope contract | pure `HelperRuntimeConnectionSession` unit tests cover per-session replay ownership, independent sequence state across two sessions, old-session envelope rejection after a new handshake, allowlisted command validation before sequence consumption, and redacted session diagnostics | persistent IPC implementation, socket/XPC transport, live authentication/peer validation, helper runtime startup, root execution, real `launchctl`, actual writes to `/Library`, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| Connection lifecycle | pure `ConnectionState` executor covers connect/status/disconnect/recover intents, invalid duplicate/concurrent transitions, abort from disconnecting/recovering states, observed helper state mapping, missing/stale correlation rejection, scoped failure observations, and platform-contract error propagation before command emission | real IPC transport, helper runtime, engine readiness binding, system tunnel lifecycle |
| Network transaction contract | pure `NetworkSnapshot` / `AppliedNetworkState` validation covers route/DNS/firewall snapshots, typed operation descriptors, transaction phases, duplicate operation/route rejection, bounded identifiers, missing rollback metadata rejection, explicit `apply_order`, reverse-order rollback step generation, failed/rolled-back/applying semantics, unknown-field rejection, redacted `Debug` output, typed recovery journal persistence with private directory/temp-write/fsync/rename/fail-closed per-file quarantine/orphan temp cleanup/file-safe transaction IDs/explicit clear/redacted journal diagnostics, single-active durable applied-state records after successful dry-run transactions that are separate from pending journals, explicitly clearable, non-blocking for the start gate and loadable after restart for reverse-order rollback work, full-tunnel connect transaction planning with stable operation keys and rollback metadata, deterministic journal recovery after crash immediately after `004_route_full_tunnel`, dry-run typed operation execution with journal writes, status transitions, first-error stop and applied/applying-prefix rollback, pure-core idempotency classification for route/DNS/tunnel address/MTU/firewall/rollback inverse retries, adapter-path enforcement that skips exact retries and rejects same-scope conflicts before inner execution, and a recovery-journal start gate that rejects new transactions while pending recovery work exists before journal/operation side effects | real `utun`, `route`, `scutil`, `pfctl`, DNS/firewall/system proxy mutation, helper runtime, actual OS rollback execution, real platform command idempotence, packet flow |
| Supervisor | actor/worker model, state machine (`Stopped/Starting/Ready/Stopping/Failed`), multi_thread lifecycle, async log drain & redaction (UUID, IPv4, IPv6), self-hosted Rust child helpers for cross-platform deterministic log/readiness checks, 5000-line pipe buffer stress test, spontaneous crash detection, TCP & log pattern readiness probes, timeout & early exit fail-closed, graceful SIGTERM stop & forced SIGKILL / TerminateProcess, Drop safety, runtime config cleanup | bounded restart policy / circuit breaker, real Xray/sing-box binary execution (server domains and public keys remain unmasked by design for diagnostics) |
| Route manager | no-op success | any actual route/DNS behavior |
| Integration-style | in-memory module composition, JSON schema compilation & validation against examples, supervisor process tests, secure runtime config (0600) lifecycle, engine artifact verification & SHA-256 validation, full mock engine lifecycle and TCP proxy request/response | real engine/server/network/OS/UI |

## 5. Test environments

### Fast CI

- Linux, macOS arm64 и Windows hosted where applicable;
- no privileges;
- L0—L3;
- deterministic fixtures;
- runs on every change.

Hosted `windows-latest` проверяет только portable Rust compilation/Clippy/tests. Это x64 hosted runner,
но его green result не закрывает Windows 11 service, WFP/TUN, routes, DNS, signing или VPN system E2E.

### macOS integration runner

- controlled Apple Silicon host;
- development-signed app/extension;
- isolated test network and server;
- L4—L7;
- serialized jobs to avoid shared routing state.

### Windows 11 integration runner

- controlled Windows 11 x64 host/VM или appropriately isolated self-hosted runner;
- test-signed service/driver/adapter только в dedicated environment;
- isolated test network и controlled server;
- L4—L7, включая SCM/service/IPC и выбранный WFP/Wintun/TUN topology;
- serialized jobs, pre-test snapshot и guaranteed recovery path;
- runner не используется как обычная developer workstation.

### Clean release machines

- no developer tool assumptions;
- отдельные чистые macOS Apple Silicon и Windows 11 x64 машины/VM;
- L8 install, signing/trust, connect/disconnect, update/rollback and uninstall smoke;
- captures pre/post network snapshots.

## 6. Network snapshot contract

Перед системным тестом сохраняются как минимум:

- interfaces и addresses;
- IPv4/IPv6 routes;
- DNS resolver state;
- relevant firewall state;
- running NovaRay/engine/helper processes;
- active NetworkExtension configuration/status.
- на Windows: network adapters, route tables, DNS client state, relevant firewall/WFP filters,
  NovaRay services/start mode и service/engine/UI processes.

После teardown выполняется semantic diff. Различие должно быть либо нулевым, либо явно allowlisted и объяснённым. Тест не должен автоматически удалять неизвестное пользовательское состояние.

## 7. Controlled test infrastructure

Нужны:

- VLESS Reality test server с фиксированной test configuration;
- direct и proxy egress echo endpoints;
- authoritative DNS zone/resolver для leak и split DNS tests;
- TCP/UDP endpoints;
- endpoint для induced latency/drop/reset;
- versioned fixtures без production secrets.

External public services не являются единственным oracle: они нестабильны и усложняют диагностику.

## 8. Fault injection matrix

Каждый connect step должен иметь тест ошибки до и после side effect:

1. invalid/migration-failed config;
2. endpoint resolution failure;
3. engine config rejected;
4. engine start timeout;
5. engine exits after readiness;
6. tunnel settings rejected;
7. DNS application failed;
8. route application partially failed;
9. verification probe failed;
10. rollback step failed;
11. process killed during each transition.

Ожидаемый результат всегда включает финальное состояние и доказательство cleanup/block behavior.

## 9. Quality gates по milestones

| Milestone | Обязательные gates |
|---|---|
| Core baseline | L0—L3 |
| Local engine vertical slice | L0—L4 + real proxy request |
| Full system tunnel | L0—L5 + network residue check |
| Split tunneling | L0—L6 |
| Failure safety | L0—L7 |
| Release candidate | L0—L8 |
| Windows decision package | L0—L4 + controlled Win11 service/IPC/snapshot PoC |
| Windows full tunnel | L0—L5 + Windows network/service residue check |
| Windows split and safety | L0—L7 + observed direct/proxy egress |
| Windows release candidate | L0—L8 on clean Windows 11 x64 |

## 10. Правила именования

- Не использовать `e2e` для in-memory/module-only тестов.
- `system_*` означает реальное взаимодействие с OS network stack.
- `packet_*` требует наблюдаемого packet/egress evidence.
- `recovery_*` обязан проверять post-state, а не только отсутствие panic.
- `smoke_*` проверяет минимальную работоспособность, но не заменяет negative scenarios.

## 11. Evidence для завершённой задачи

Сохранять:

- точную команду;
- platform/OS version/architecture;
- app и engine revision;
- sanitized config hash;
- test result;
- pre/post snapshot diff;
- известные gaps;
- ссылку на связанное требование и roadmap item.

Зелёные тесты чистой логики нельзя использовать как утверждение, что VPN, TUN, DNS protection, split tunneling или crash recovery уже работают.

## 12. CI baseline

Workflow [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) запускается для pull request, push
в `main` и вручную:

- Linux: formatting, strict Clippy и Rust tests с `--locked`;
- macOS 14 arm64: проверка архитектуры runner, strict Clippy и Rust tests с `--locked`;
- Windows hosted x64: strict Clippy и Rust tests с `--locked`; portability gate, не Windows 11 VPN evidence;
- macOS arm64: отдельный Rust C ABI ↔ Swift roundtrip spike с warnings-as-errors;
- Linux documentation job: локальные Markdown-ссылки через
  [`scripts/check_markdown_links.py`](../scripts/check_markdown_links.py) и offline validation
  macOS engine topology evidence manifest.

Workflow использует read-only `GITHUB_TOKEN`, pinned official checkout action, отмену устаревших
runs и timeouts. Первый Linux/macOS arm64/documentation запуск успешно завершён:
recorded CI run 31949037576.
Windows hosted x64 portability job и остальные baseline jobs успешно завершены в
recorded CI run 31951959769.

Проверка FFI roundtrip добавлена в workflow в issue #9; до успешного PR run это только настроенный,
а не подтверждённый CI gate.

CI не проверяет Xcode, signing, NetworkExtension, Windows Service/WFP/TUN, privileged networking или
реальный VPN-трафик. Эти claims требуют platform integration/clean-machine environments выше.

Baseline CI не содержит signing certificates, driver keys или privileged runner credentials.
