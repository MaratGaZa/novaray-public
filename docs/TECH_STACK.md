# NovaRay: фактический и планируемый технологический стек

Этот документ различает уже подключённые зависимости и кандидатов. Наличие технологии в разделе «планируется» не означает её присутствие в коде.

## 1. Фактический стек текущего прототипа

| Область | Используется сейчас | Назначение |
|---|---|---|
| Язык | Rust 2021 | library и CLI core |
| Async runtime | Tokio | process API и async entrypoint |
| JSON | Serde, serde_json | модели и fixtures |
| Ошибки | anyhow, thiserror | текущая обработка ошибок |
| Логи | tracing, tracing-subscriber | консольные сообщения |
| URI | url, percent-encoding | импорт VLESS URI |
| Системные API | libc, macOS-only nix и core-foundation | native peer credentials и read-only AuthorizationRightGet; не live helper runtime |
| Artifact integrity | sha2, hex | pinned SHA-256 проверки engine/helper; не runtime authentication |

`bytes` подключён, но текущий data plane его практически не использует.

В проекте сейчас нет production Tauri/SwiftUI/NetworkExtension target, WinUI target, Windows
Service/WFP/Wintun adapter, `tun`, `tun2proxy`, `smoltcp`, `libproc` bindings или bundled
Xray/Sing-box artifact. Изолированные macOS spikes содержат SwiftUI/System Extension skeleton и
минимальный Rust staticlib C ABI, но не входят в production path и не являются VPN evidence.

## 2. Рекомендуемый UI stack

### macOS — первый release

- SwiftUI для окон, форм, состояния и accessibility;
- AppKit bridge для menu bar и специфичных macOS возможностей, где SwiftUI недостаточно;
- Rust static library для core;
- versioned C ABI по ADR-001; синхронный Rust/Swift roundtrip есть в изолированном spike,
  async production bridge и инструменты генерации bindings ещё требуют проверки;
- Xcode app target и отдельный helper/network boundary по ADR-003; NetworkExtension target относится
  только к отложенному Gate B, а не к обязательному source-first release stack.

Преимущество — максимально нативное поведение macOS и прямой доступ к системным VPN API. Цена — небольшой слой Swift и более сложная сборка Rust + Xcode.

### Другие UI-кандидаты

Tauri v2 не является поддерживаемым резервным UI для macOS: ADR-001 исключает второй параллельный
стек. Для других платформ выбор остаётся отдельным ADR; смена macOS stack потребует пересмотра
ADR-001, а не добавления второй оболочки. WebView shell также не заменяет privileged boundary.

### Не рекомендуемый вариант для NovaRay

Metal — API низкоуровневой GPU-графики и вычислений, а не набор нативных controls. Для VPN-клиента с кнопкой подключения, формами, списками, меню-баром и небольшими графиками собственный Metal renderer избыточен. Он потребует самостоятельно решать текст, layout, input, accessibility, localization и системный внешний вид.

Rust-native `egui`/`wgpu` и Slint допустимы для эксперимента, но не являются первым выбором при требовании максимально нативного macOS UX. Подробное сравнение: [ADR-001](./ADR-001-MACOS-UI.md).

### Windows 11 — второй release

- рекомендуемый кандидат: WinUI 3 / Windows App SDK shell на C# или C++;
- Rust core подключается через узкий versioned FFI/IPC boundary;
- privileged networking принадлежит отдельной Windows Service/network boundary, а не UI;
- WPF/Win32 сравниваются, только если WinUI 3 spike не проходит deployment, accessibility или
  resource gates.

Это proposal, не реализованный stack. Выбор фиксируется Windows ADR после macOS release. Общие
границы описаны в [ADR-006 Cross-platform boundaries](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md).

## 3. macOS network stack: [ADR-003](./ADR-003-NETWORK-TOPOLOGY.md)

### Предлагается (Proposed): privileged helper + `utun`

- Rust LaunchDaemon helper с изолированным типизированным API и отдельным runtime IPC boundary.
- Helper install/deinstall Gate I реализован как типизированный executor с recording-adapter
  evidence; реальная привилегированная установка, root execution и mutation `/Library` не доказаны.
- Live Gate H (persistent helper runtime IPC и authenticated commands) не реализован. Подготовка
  включает replay/admission contracts, kernel peer credential tests, read-only right inspector и
  recording right-lifecycle executor. Ни один из них не доказывает Gate H или native right writes.

### Отложено: Network System Extension (`NEPacketTunnelProvider`)

NetworkExtension остаётся предпочтительной более узкой trust boundary, если появится платный Apple
Developer Program, подходящие entitlements/provisioning и отдельное distribution decision. Gate B
для этого пути остаётся отложенным.

## 4. Windows network stack: отдельный architecture spike

Кандидаты:

- WFP user-mode filters и, только при доказанной необходимости, callout driver;
- Wintun/TUN adapter с engine/tun2proxy integration;
- engine-specific Windows integration;
- Windows Service под SCM с минимальными rights и authenticated typed IPC.

Spike обязан сравнить full/split tunnel, IPv4/IPv6, DNS, endpoint exclusion, kill switch, driver
signing, install/update/reboot и recovery. Hosted `windows-latest` годится для Rust portability, но
не заменяет controlled Windows 11 system tests.

## 5. Protocol engine: [ADR-004](./ADR-004-ENGINE-INTEGRATION.md)

- **Current local-proxy/generator evidence path:** Xray-core (`v26.3.27`), MPL 2.0. Базовый генератор конфигураций в Core (`xray_generator.rs`), валидация через `xray run -test -c`.
- **Proposed production engine direction:** sing-box (`v1.13.18`) по ADR-004; catalog/version-selector contracts приняты отдельно, но production packet-level integration не доказана.
- **Управление:** `ProcessSupervisor` в Rust Core (PID, bounded redacted logging, graceful stop `SIGTERM`/`SIGKILL`, zero residue).
- **Production acceptance gates** задаёт ADR-004: engine lifecycle, packet flow и legal review;
  per-app evidence либо явная domain/IP-only отсрочка M7 по FR-006. Исторический
  `engine-evidence.json` описывает исходный spike, а не текущую сводку пройденных gates.
- **Отложенные альтернативы:** service-owned process или Rust-native protocol implementation после
  отдельного review.

Исторический evidence-only spike issue development task #12 зафиксировал snapshot
Xray-core `v26.3.27` и sing-box `v1.13.18`: оба upstream публикуют macOS arm64 CLI artifacts и
config-validation команды. Для embedding найдены XTLS/libXray Apple wrapper и first-party
sing-box `experimental/libbox`/Apple client path. Это только source/contract evidence: binary не
скачивались и не запускались, API stability, license/distribution, readiness, graceful stop,
NetworkExtension runtime и process residue не проверены. Сравнение и digests находятся в
[`spikes/macos-engine-topology-spike`](../spikes/macos-engine-topology-spike/README.md); engine не выбран.

## 6. Rust-компоненты: реализованная основа и оставшийся scope

| Область | Уже есть | Оставшийся scope |
|---|---|---|
| Конфигурация | Serde, JSON Schema corpus, typed enums и validators | atomic profile storage и migrations |
| State machine | supervisor enum/lifecycle и serialized start; helper contracts | production tunnel lifecycle с OS evidence |
| IP/CIDR и policy | matcher и engine-specific config generation | полноценный policy compiler и packet-level enforcement |
| DNS | typed snapshot/mutation contracts | реальный OS controller, leak tests и rollback |
| Process lifecycle | Tokio child, bounded log readers, readiness, restart, graceful stop | связка с production helper/data plane |
| Secrets | redaction primitives | Keychain и отдельный Windows credential mechanism |
| Diagnostics | tracing и bounded redacted process logs | bounded rotating files и production support bundle |
| Platform contracts | versioned commands/events, handshake, capabilities, replay/admission | authenticated persistent transport и реальные platform adapters |
| FFI/IPC | изолированный синхронный macOS ABI spike | async production bridge; Windows IPC после отдельного решения |

Конкретные crate версии фиксируются отдельным dependency review в момент реализации, а не заранее в документации.

## 7. Сборка и поставка

- Rust target: `aarch64-apple-darwin`;
- Xcode project/workspace для SwiftUI и helper/network boundary;
- reproducible source-build profile для ADR-002 Gate S;
- package-manager formula только как кандидат source-build wrapper, не выбранный канал;
- Developer ID signing, Hardened Runtime, минимальные entitlements и notarization только как
  отложенный path при появлении платного Apple Developer Program;
- signed updater только после threat model и отдельного distribution decision;
- SBOM, dependency audit и artifact checksums;
- CI на macOS ARM runner или контролируемом Apple Silicon build host.

После первого macOS release для Windows планируются:

- Rust target `x86_64-pc-windows-msvc`;
- native Windows project и отдельно устанавливаемая service/network boundary;
- MSIX/Store или signed MSI/EXE — выбор после distribution spike;
- подпись binaries/service/installer и controlled Windows 11 release host;
- clean install/update/rollback/uninstall evidence.

Intel `x86_64-apple-darwin`, Windows ARM64 и Android не входят в первые соответствующие desktop
release targets. Android создаётся отдельным проектом.

## 8. Quality tooling

Минимальный CI gate:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

JSON Schema corpus уже входит в Rust tests; CI также выполняет isolated Swift ABI harness,
Swift/Xcode spike builds и проверки Markdown links/requirements traceability (см.
[workflow](../.github/workflows/ci.yml)). Это не production UI или system-network tests.
Остаются отдельные dependency/license evidence gates, property/fuzz coverage, live helper,
NetworkExtension (отложенный path), Windows service/system, leak/recovery и source-first release
smoke; signed-package smoke относится только к отложенному signing path.

## 9. Запрещённые архитектурные сокращения

- выполнять `route`, `scutil`, `networksetup` или `pfctl` из UI через произвольную shell string;
- считать process spawn доказательством рабочего VPN;
- считать matcher unit test доказательством split tunneling;
- хранить реальные UUID/private keys в публичных fixtures;
- показывать `Connected` до engine readiness и network verification;
- использовать Metal только ради «нативности» обычного desktop UI.
- считать hosted Windows Rust tests доказательством Windows 11 VPN/service/network behavior;
- переносить macOS per-app assumptions на Windows или размещать Android app tree в этом репозитории.
