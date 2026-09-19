# NovaRay: стратегия тестирования

## 1. Текущий статус

Инвентарь тестов включает pure Rust contracts, реальные child processes/filesystem и ограниченные
macOS kernel/Security read-only проверки. Отдельно доступны opt-in real-engine preflight и loopback
traffic tests. Это не доказательство system VPN, tunnel, split tunneling или восстановления
macOS/Windows network state. Ниже описан scope имеющихся тестов, не результат нового полного прогона.

В проекте есть:

- unit tests моделей, parser/matcher, Xray/sing-box generators, catalog/version compatibility,
  network-state/recovery и helper protocol/admission/right-lifecycle contracts;
- integration-style tests в `tests/`, связывающие несколько Rust-модулей и fixtures;
- проверки повреждённого JSON, некорректных VLESS URI и positive/negative JSON Schema corpus;
- CLI/ProxyService/supervisor tests с настоящими child processes, сигналами, таймаутами и cleanup;
- helper source/destination filesystem tests: symlinks, regular-file checks, opened-handle hashing;
- [`tests/helper_peer_credentials_macos.rs`](../tests/helper_peer_credentials_macos.rs): настоящий
  отдельный same-UID процесс и kernel credentials; authorization/session issuance остаются recording;
- [`src/macos_runtime_right.rs`](../src/macos_runtime_right.rs): CF fixtures и реальные read-only
  AuthorizationRightGet tests; exact-owned CF fixture не доказывает native write/read normalization;
- opt-in ignored [`tests/xray_transport_runtime_tests.rs`](../tests/xray_transport_runtime_tests.rs)
  и [`tests/sing_box_runtime_tests.rs`](../tests/sing_box_runtime_tests.rs): требуют отдельно
  предоставленных engine binaries. Xray WS/gRPC loopback traffic не закрывает remote Reality/UDP M2;
- изолированный L3 spike `spikes/macos-rust-ffi-spike/`: Rust unit/layout tests и arm64 Swift
  harness проверяют синхронный ABI v1 callback; это ещё не production lifecycle contract.
- evidence-only manifest `spikes/macos-engine-topology-spike/` фиксирует pinned upstream metadata и
  открытые engine topology gates; offline validator проверяет честность claims, но не запускает engine.

Тест `test_end_to_end_vless_to_xray_pipeline` является end-to-end только для in-memory цепочки `URI → models → matcher → JSON`. Это не системный VPN E2E.

`test_route_manager_and_process_supervisor_initialization` вызывает no-op `RouteManager` и пустой `stop`; он не проверяет маршруты или процесс engine.

## 2. Текущие команды

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
python3 scripts/check_markdown_links.py .
python3 scripts/check_requirements_traceability.py
git diff --check
```

Фактические результаты фиксируются для конкретного commit, OS/arch и команды в CI/session evidence.
`cargo test --all-targets` не запускает ignored engine tests; для них нужен отдельный явный прогон
по условиям соответствующего теста. macOS-only tests на Linux/Windows не выполняются.
Зелёная переносимая Rust-джоба не доказывает macOS NetworkExtension, Gate I/H или Windows Service.

Per-app packet evidence обязательно перед включением функции. Domain/IP-only release требует
документированной отсрочки M7 по FR-006 и отсутствия заявления per-app capability/UI; это не
освобождает от domain/IP traffic, DNS-leak, kill-switch/recovery и остальных release tests.

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
| macOS helper runtime authentication boundary | pure `helper_runtime_admission` unit tests use a recording adapter to cover exact-size/redacted authorization forms, unprivileged expected UID policy, peer → right → handshake → helper-generated session ordering, fail-closed stops at each stage, connection-local form/session ownership, rights recheck before mutating-command sequence consumption, retry after denial and stable redacted error categories; ADR-009 remains `Proposed` | live Unix socket, kernel credential adapter, dedicated authorization right lifecycle, same-UID negative system tests, helper-side Security framework calls, root runtime and any network mutation |
| macOS helper runtime peer credentials | macOS-only tests call `getpeereid` on both endpoints of a real connected `UnixStream::pair` and on a filesystem-socket connection accepted from a separately spawned unprivileged client; they compare returned effective UID/GID with process/child kernel credentials, cover stable invalid-descriptor failure, private directory/socket modes, bounded child failure, RAII cleanup and prove configured UID mismatch stops admission before right/session callbacks | production/persistent helper listener, different-UID process, same-UID attacker authentication, Security framework authorization, root runtime and network mutation |
| macOS runtime Authorization right ownership | pure `helper_runtime_right` tests cover fixed right/rule identity, absent install create, exact install retry, conflicting/unrecognized install rejection, exact uninstall removal, absent uninstall no-op, changed-policy preservation, bounded observation shape and redacted diagnostics | Security framework/Authorization Services calls, authorization database mutation, prompts, expired/invalidated external forms, root runtime and live admission |
| macOS read-only runtime right inspector | `macos_runtime_right` tests use real CF objects for exact single-rule classification, extra-field/type/key/array rejection, bounded ASCII conversion, NUL/control/non-ASCII/unpaired-surrogate rejection, status/null handling and redacted results; native read-only calls cover a missing test right, existing `system.preferences` preservation and the fixed runtime-right lookup | database create/read roundtrip, normalization acceptance, create/remove/update, authorization prompts/acquisition, expired/invalidated forms, mutation races, root runtime and live admission |
| Runtime-right lifecycle executor | `helper_runtime_right_execution` recording tests cover fresh entry inspection, install/uninstall readback, idempotent retry, uncertain create failure without deletion, fresh ownership check before bounded compensation, conflict preservation, primary/cleanup error separation and failed cleanup verification | native database writes/normalization, authorization, cross-process race exclusion, atomic ownership/provenance, crash recovery, root runtime and live admission |
| Opt-in base-case right experiment (#96/#102) | `right_experiment` feature tests cover generated-name approval, every callback failure, absence/exact read ordering, write intent/result journaling, preservation after uncertain create, primary/journal errors, bounded CF structure, private exclusive local journal, watchdog cancellation/deadline, and non-mutating preflight classification for platform, terminal, CI, private directory and manifest state; native adapter is compile-checked only | no native authorization/write/read/remove execution, disposable-environment/restore verification, full native fault/race/reboot matrix, production right adapter or Gate I/H evidence |
| Native authorization-right experiment protocol (#92/#104) | [Runbook](./AUTHORIZATION_RIGHT_NATIVE_VALIDATION.md) defines per-run approval, disposable environment/restore, test-only namespace, checked API facts, normalization/race/fault matrix, redacted evidence and unknown-effect/crash stop states; [public readiness template](./native-right-readiness.template.json) and `check_native_right_readiness_template.py` prove only that the committed template remains non-authorizing | real private readiness evidence, owner-approved disposable environment, restore drill, native database mutation/normalization, authorization, atomic ownership/provenance, production race exclusion, crash recovery and ADR acceptance |
| macOS helper runtime replay guard contract | pure `HelperRuntimeReplayGuard` unit tests cover current-session command acceptance, no-session and wrong-session rejection before sequence consumption, exact next-sequence acceptance, zero/repeated/stale sequence and forward-jump rejection, `u64::MAX` jump rejection without session pinning, fail-closed behavior after sequence exhaustion, sequence reset only through a new handshake session, bounded session/correlation validation, correlation ID not acting as freshness proof, handshake not being accepted as a runtime command, and redacted `Debug` output | persistent IPC implementation, helper runtime startup, live authentication/peer validation, root execution, real `launchctl`, actual writes to `/Library`, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| macOS helper runtime session-scope contract | pure `HelperRuntimeConnectionSession` unit tests cover per-session replay ownership, independent sequence state across two sessions, old-session envelope rejection after a new handshake, allowlisted command validation before sequence consumption, and redacted session diagnostics | persistent IPC implementation, socket/XPC transport, live authentication/peer validation, helper runtime startup, root execution, real `launchctl`, actual writes to `/Library`, `utun`, route/DNS/firewall/system proxy mutation, packet flow, DNS-leak, split tunneling, kill switch |
| Connection lifecycle | pure `ConnectionState` executor covers connect/status/disconnect/recover intents, invalid duplicate/concurrent transitions, abort from disconnecting/recovering states, observed helper state mapping, missing/stale correlation rejection, scoped failure observations, and platform-contract error propagation before command emission | real IPC transport, helper runtime, engine readiness binding, system tunnel lifecycle |
| Network transaction contract | pure `NetworkSnapshot` / `AppliedNetworkState` validation covers route/DNS/firewall snapshots, typed operation descriptors, transaction phases, duplicate operation/route rejection, bounded identifiers, missing rollback metadata rejection, explicit `apply_order`, reverse-order rollback step generation, failed/rolled-back/applying semantics, unknown-field rejection, redacted `Debug` output, typed recovery journal persistence with private directory/temp-write/fsync/rename/fail-closed per-file quarantine/orphan temp cleanup/file-safe transaction IDs/explicit clear/redacted journal diagnostics, single-active durable applied-state records after successful dry-run transactions that are separate from pending journals, explicitly clearable, non-blocking for the start gate and loadable after restart for reverse-order rollback work, full-tunnel connect transaction planning with stable operation keys and rollback metadata, deterministic journal recovery after crash immediately after `004_route_full_tunnel`, dry-run typed operation execution with journal writes, status transitions, first-error stop and applied/applying-prefix rollback, pure-core idempotency classification for route/DNS/tunnel address/MTU/firewall/rollback inverse retries, adapter-path enforcement that skips exact retries and rejects same-scope conflicts before inner execution, and a recovery-journal start gate that rejects new transactions while pending recovery work exists before journal/operation side effects | real `utun`, `route`, `scutil`, `pfctl`, DNS/firewall/system proxy mutation, helper runtime, actual OS rollback execution, real platform command idempotence, packet flow |
| Supervisor | actor/worker model, state machine (`Stopped/Starting/Ready/Stopping/Failed`), multi_thread lifecycle, async log drain & redaction (UUID, IPv4, IPv6), self-hosted Rust child helpers for cross-platform deterministic log/readiness checks, 5000-line pipe buffer stress test, spontaneous crash detection, TCP & log pattern readiness probes, timeout & early exit fail-closed, graceful SIGTERM stop & forced SIGKILL / TerminateProcess, Drop safety, runtime config cleanup | bounded restart policy / circuit breaker, real Xray/sing-box binary execution (server domains and public keys remain unmasked by design for diagnostics) |
| Route manager | no-op success | any actual route/DNS behavior |
| Integration-style | in-memory module composition, JSON schema compilation & validation against examples, supervisor process tests, secure runtime config (0600) lifecycle, engine artifact verification & SHA-256 validation, full mock engine lifecycle and TCP proxy request/response | real engine/server/network/OS/UI |

Дополнение задачи 68 (L1/L3): `kill_switch_order_rejected_before_any_side_effects` проверяет
перестановку apply_order у firewall/route и firewall/DNS после JSON roundtrip, нулевые вызовы
адаптера, журнала и start gate. `kill_switch_order_uses_apply_order_not_vector_position` проверяет
обратный вектор; `kill_switch_rejects_additional_forward_firewall_changes` запрещает второй
firewall-шаг; `firewall_failure_stops_route_dns_and_retains_compensation` проверяет ранний отказ.
Planner tests подтверждают IPv6, выключенный kill switch и DNS/route-before-firewall compensation.
`legacy_firewall_last_journal_keeps_original_recovery_order` записывает и читает прежний порядок
без миграции. Это не L5/L7 evidence: ОС, системный deny state, allowlist и утечки не проверяются.

Дополнение задачи 69 (L1): [kill_switch.rs](../src/kill_switch.rs) проверяет exact endpoint по
IP/port/TCP-or-UDP/uplink, tunnel interface и отдельную IPv4/IPv6 семью, отказ invalid/wildcard
входов, отсутствие неявных direct DNS/DHCP/NDP/LAN/update разрешений и redaction. Тесты в
[network_transaction.rs](../src/network_transaction.rs) проверяют построение из intent, отказ
disabled/missing uplink и независимость уже построенной policy от последующих изменений intent.
Нет kernel/firewall/packet-flow evidence; policy пока не связана с `ApplyFirewallPolicy`.
Для Gate H требуются реальные endpoint/tunnel reachability, блокировка постороннего egress и
неподдерживаемого IPv6, отдельные DHCP/NDP/bootstrap/reconnect проверки и локальный rollback при
потере сети. Успех unit matcher не закрывает ни один из этих системных пунктов.

### Endpoint bootstrap и reconnect (задача 70)

[Протокол](./ENDPOINT_BOOTSTRAP_PROTOCOL.md) задаёт ожидаемое поведение, а не результаты тестов.
Ни один сценарий ниже **не выполнен целиком**; частичные L1-проверки задачи 71 перечислены отдельно
и не заменяют L3-интеграцию или L5/L7 Gate H. Владельцы: core — снимок/переходы; resolver adapter — ограниченный ответ/deadline;
network adapter — kernel context, правила и отзыв established state; engine adapter — числовой
endpoint без подмены TLS/SNI/Reality identity и без скрытого direct DNS.

| ID | Сценарий | Требуемое evidence и отказ |
|---|---|---|
| E01 | Первое подключение с hostname; timeout/пустой/слишком большой ответ | L1/L3: bootstrap только без защиты/recovery, ограниченные ответы и отказ до engine; L5: объявленный начальный DNS вне VPN не выдан за leak protection |
| E02 | Active/inherited/unknown deny при старте | L1/L3: resolver не вызван; L5/L7: нет DNS-пакетов по uplink и автоматического снятия deny |
| E03 | Несколько A/AAAA, повторы, неподдерживаемые адреса | L1: предел 16, порядок и валидация, ровно один tuple; L5: пакетные попытки к невыбранным IP/портам/протоколам блокируются |
| E04 | Переход к следующему кандидату, отказ на каждом шаге | L3: журналирование и запрет нового разрешения до подтверждённого отзыва старого; L5/L7: старый transport/established state больше не пропускает пакеты, deny остаётся непрерывным |
| E05 | Повтор в прежней сети, expiry и исчерпание кандидатов | L1: deadline/budget не продлеваются retry, существующий канал не переключается только из-за expiry, новая попытка запрещена; L5: нет DNS fallback и прямого egress при отказе |
| E06 | Сервер сменил адрес после получения снимка | L1/L5: неизменный снимок не получает новый IP автоматически; после исчерпания — Blocked, новый bootstrap только после подтверждённого прекращения защиты |
| E07 | Wi-Fi/uplink/resolver/profile change, sleep/wake, повторное имя интерфейса | L1/L3: старое поколение инвалидировано; L5/L7: stale tuple не переносится в новую сеть, DNS запрещён. Одного уведомления ОС или строки en0 недостаточно |
| E08 | DNS-ответ старого запроса пришёл после изменения контекста | L1/L3: ответ отвергнут до выдачи разрешения, сериализация и повторная проверка generation/deadline; L5: нет нового отверстия в policy |
| E09 | IP literal и hostname-профиль, IPv4/IPv6 endpoint | L1/L3: literal без DNS, профильная identity сохранена; L5: engine использует выбранный IP, проверяет identity и не выполняет собственный direct resolve |
| E10 | Crash/reboot во время bootstrap/замены, неопределённый journal | L3/L7: recovery раньше connect, cache не разрешает повтор, нет слепой очистки/нового DNS, недоказанное состояние не названо защищённым |
| E11 | Пользователь прекращает защиту; rollback ломается или сеть недоступна | L3/L7: локальная команда доступна без DNS/сети, новый bootstrap запрещён до подтверждённого rollback; при ошибке — диагностируемый stop-state |

Частичное L1-evidence задачи 71, [endpoint_bootstrap.rs](../src/endpoint_bootstrap.rs):

| Аспекты | Существующие unit tests | Что не доказано |
|---|---|---|
| E01/E02 | `admission_is_checked_at_start_response_and_handoff`, `lifetime_is_positive_bounded_and_expires_at_exact_deadline`, `resolver_failure_bad_deadline_and_clock_regression_are_terminal` | Реальный resolver не вызывается вообще; нет orchestration, timeout driver, UI disclosure или доказательства DNS silence |
| E03 | `raw_and_unique_bounds_are_checked_without_truncation`, `address_family_and_freshness_filter_before_selection`, `deterministic_single_handoff_owns_profile_tuple_and_binding` | Нет engine handoff, policy installation или пакетного deny |
| Часть E05 | `duplicates_use_minimum_deadline_and_expiry_does_not_rotate` | Только initial selection/expiry; нет retry и активного проверенного канала |
| Часть E07/E08 | `current_context_change_invalidates_before_response_or_handoff`, `stale_responses_do_not_replace_current_request_or_consume_it` | Поколения вводит тест; нет kernel observation, сети, sleep/wake или cancellation реального resolver |
| Redaction | `diagnostics_redact_addresses_ports_and_binding_generations` | Нет диагностического UI/export runtime |

Задача 71 не реализует E04/E06/E09–E11. В частности, отсутствие метода rotation не
доказывает отзыв established flows. У модели нет IP-literal режима; адреса в тестах — фикстуры
результатов разрешения. Валидация наблюдений не удостоверяет их источник или отсутствие race
между выдачей данных и будущим системным действием.

Частичное L1-evidence задачи 72, [endpoint_revocation.rs](../src/endpoint_revocation.rs):

| Аспект E04 | Recording unit tests | Не доказано |
|---|---|---|
| Scope, порядок, однократность | `revocation_orders_scoped_callbacks_and_is_single_use` | Системный lifecycle lock, native executor |
| Ошибка каждого callback и первичная причина | `every_callback_failure_stops_without_compensation_or_retry`, `adapter_panic_cannot_make_object_reusable_or_trigger_cleanup` | Durable journal, process crash, timeout/cancellation |
| Контекст и deny на каждом чтении | `every_inspection_rechecks_all_binding_generations`, `inactive_or_unknown_deny_stops_at_every_inspection` | Kernel context, непрерывный deny между чтениями |
| Неизвестность, неполный отзыв и регресс | `unknown_transport_exception_or_flows_never_passes`, `incomplete_or_regressed_revocation_prevents_completion`, `absent_rule_does_not_substitute_for_established_state_revocation` | Реальная очистка established flows и старого маршрута |
| Диагностика | `revocation_diagnostics_redact_scope_and_expose_only_categories` | Полный diagnostic export runtime |

Ни один E01–E11 не закрыт полностью. Обязательная будущая проверка Gate H рядом с E04/E07:
после `SelectedEndpoint`/`Consumed`, но до установки нового правила, изменить binding или
довести время до `valid_until`; исполнитель под lifecycle lock обязан отказать в новом grant.
На L3 проверять отсутствие вызова установки, на L5/L7 — отсутствие нового разрешённого egress.
Сам факт выдачи endpoint или результат `Observed` задачи 72 не заменяет эту проверку.
Текущий срез не выдаёт новых разрешений и эту гонку не исполняет.

Дополнительное обязательное evidence E04/Gate H для будущего вызывающего executor'а:
вызвать ошибку на каждом этапе после попытки мутации, в том числе `StopTransport` и
`RemoveException`, оставив старое исключение и живой транспорт/flows. На L3 доказать обязательный
вызов полного teardown соединения, отсутствие нового grant/reconnect/direct DNS, сохранение intent
до подтверждения cleanup, сохранение deny и первичной ошибки при отдельном сбое teardown.
Проверить timeout/частичный отказ teardown: recovery/unknown, а не ложный успех или возврат
старого разрешения. На L5/L7 проверить непрерывность deny и отсутствие старого разрешённого
egress после подтверждённого teardown; отдельно измерить остаточный трафик между исходной ошибкой
и завершением containment. Один `Err`, Active deny или возвращённый callback не доказывает
отсутствие пакетов. Эти проверки **не выполнены**, caller/teardown в задаче 72 не реализованы.

В L5/L7 использовать контролируемые authoritative DNS и два endpoint, непрерывные попытки direct
DNS/обычного egress во время переходов, захват пакетов на старом и новом uplink и проверку
endpoint/tunnel reachability. Включить IPv4 и IPv6, TCP и UDP, старые established flows и потери
наблюдения. Публичное evidence редактируется; hostname, IP, session/context IDs не публикуются.
До native реализации нужны принятые границы resolver и конечные retry/time budgets, подтверждённые
интерфейсы и отдельные DHCP/NDP/bootstrap-link правила. Эта таблица не разрешает запуск эксперимента.

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

Каноническая связь `FR/NFR → задача → тест/проверка → evidence/gap` ведётся в
[`TRACEABILITY.md`](./TRACEABILITY.md). Строка матрицы является индексом, а не доказательством:
текущий status и gap должны обновляться вместе с нормативным требованием или новым evidence.

Зелёные тесты чистой логики нельзя использовать как утверждение, что VPN, TUN, DNS protection, split tunneling или crash recovery уже работают.

## 12. CI baseline

Workflow [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) запускается для pull request, push
в `main` и вручную:

- Linux: formatting, strict Clippy и Rust tests с `--locked`;
- macOS 14 arm64: проверка архитектуры runner, strict Clippy и Rust tests с `--locked`;
- Windows hosted x64: strict Clippy и Rust tests с `--locked`; portability gate, не Windows 11 VPN evidence;
- macOS arm64: отдельный Rust C ABI ↔ Swift roundtrip spike с warnings-as-errors;
- Linux documentation job: локальные Markdown-ссылки через
  [`scripts/check_markdown_links.py`](../scripts/check_markdown_links.py), полнота FR/NFR mapping через
  [`scripts/check_requirements_traceability.py`](../scripts/check_requirements_traceability.py) и
  offline validation macOS engine topology evidence manifest.

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
