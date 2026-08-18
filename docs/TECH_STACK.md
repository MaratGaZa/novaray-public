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
| Системные API | libc, macOS-only nix | подключены, но полноценная platform integration отсутствует |

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
- `cbindgen`, UniFFI или вручную определённый C ABI после отдельного FFI spike;
- Xcode targets для app и NetworkExtension.

Преимущество — максимально нативное поведение macOS и прямой доступ к системным VPN API. Цена — небольшой слой Swift и более сложная сборка Rust + Xcode.

### Резервный вариант

Tauri v2 подходит, если приоритетом станет быстрая кроссплатформенная оболочка. Он использует Rust backend и HTML в системном WebView. Это компактнее Electron, но не является полностью Rust UI и не заменяет NetworkExtension/helper.

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
границы описаны в [ADR-006](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md).

## 3. macOS network stack: [ADR-003](./ADR-003-NETWORK-TOPOLOGY.md)

### Предлагается (Proposed): Network System Extension (`NEPacketTunnelProvider`)
Целевая топология для прямой дистрибуции Developer ID по Apple TN3134:
- `NEPacketTunnelProvider` в формате `.systemextension` через `OSSystemExtensionManager`;
- `NEPacketTunnelNetworkSettings` (IPv4/IPv6, DNS, MTU, scoped test routes);
- типизированный bounded IPC (до 4 KB) с allowlist команд;
- наблюдение за статусом через `NEVPNStatusDidChange`.

### Резервный / Dev-only: Privileged helper
- Rust daemon/helper с изолированным типизированным API для локальных тестов до Gate B.

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

- **Базовый кандидат для M1/M2:** Xray-core (`v26.3.27`), MPL 2.0. Базовый генератор конфигураций в Core (`xray_generator.rs`), валидация через `xray run -test -c`.
- **Перспективный кандидат для Gate B embedding:** sing-box (`v1.13.18`), `experimental/libbox`.
- **Управление:** `ProcessSupervisor` в Rust Core (PID, bounded redacted logging, graceful stop `SIGTERM`/`SIGKILL`, zero residue).
- **8 гейтов Gate B** зафиксированы в `engine-evidence.json` и `ADR-004`.
service-owned process или Rust-native protocol implementation после отдельного review.

Evidence-only spike issue development task #12 зафиксировал snapshot
Xray-core `v26.3.27` и sing-box `v1.13.18`: оба upstream публикуют macOS arm64 CLI artifacts и
config-validation команды. Для embedding найдены XTLS/libXray Apple wrapper и first-party
sing-box `experimental/libbox`/Apple client path. Это только source/contract evidence: binary не
скачивались и не запускались, API stability, license/distribution, readiness, graceful stop,
NetworkExtension runtime и process residue не проверены. Сравнение и digests находятся в
[`spikes/macos-engine-topology-spike`](../spikes/macos-engine-topology-spike/README.md); engine не выбран.

## 6. Планируемые Rust-компоненты

| Область | Предпочтительный подход |
|---|---|
| Конфигурация | Serde + JSON Schema + typed enums + migrations |
| State machine | явная enum-модель и сериализация lifecycle-команд |
| IP/CIDR | проверенный crate с IPv4/IPv6 типами |
| DNS | системная конфигурация через network boundary; parser/resolver abstractions в core |
| Policy | отдельный compiler user rules → engine/OS rules |
| Process lifecycle | Tokio process, bounded log readers, readiness, restart, graceful stop |
| Secrets | macOS Keychain и отдельно выбранный Windows credential mechanism |
| Diagnostics | tracing spans, redaction, bounded rotating files |
| Platform contracts | versioned typed commands/events, handshake и capabilities |
| FFI/IPC | минимальный macOS ABI и authenticated Windows IPC после spikes |

Конкретные crate версии фиксируются отдельным dependency review в момент реализации, а не заранее в документации.

## 7. Сборка и поставка

- Rust target: `aarch64-apple-darwin`;
- Xcode project/workspace для SwiftUI и NetworkExtension;
- reproducible release profile;
- Developer ID signing и notarization для direct distribution;
- Hardened Runtime и минимальные entitlements;
- signed updater только после threat model;
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

Дополнительно планируются schema validation, dependency/license audit, Swift/Xcode tests,
NetworkExtension tests, Windows contract/service/system tests, leak tests и platform signed-package smoke.

## 9. Запрещённые архитектурные сокращения

- выполнять `route`, `scutil`, `networksetup` или `pfctl` из UI через произвольную shell string;
- считать process spawn доказательством рабочего VPN;
- считать matcher unit test доказательством split tunneling;
- хранить реальные UUID/private keys в публичных fixtures;
- показывать `Connected` до engine readiness и network verification;
- использовать Metal только ради «нативности» обычного desktop UI.
- считать hosted Windows Rust tests доказательством Windows 11 VPN/service/network behavior;
- переносить macOS per-app assumptions на Windows или размещать Android app tree в этом репозитории.
