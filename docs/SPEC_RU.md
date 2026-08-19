# NovaRay: спецификация проекта

Статус документа: рабочая спецификация, pre-alpha

Порядок релизов: macOS 14+ / Apple Silicon (`aarch64-apple-darwin`) первым; Windows 11 x64 (`x86_64-pc-windows-msvc`) вторым; Android третьим

Основной язык core: Rust 2021

Статус продукта: прототип библиотечной логики, не рабочий VPN-клиент

## 1. Цель продукта

NovaRay должен стать семейством нативных приложений с общим Rust core для macOS, Windows и Android. Первый production-релиз — приложение macOS Apple Silicon, распространяемое сборкой из исходников; второй обязательный релиз — Windows 11 x64; третий — Android. Продукт:

1. устанавливает и контролирует VPN-туннель;
2. начинает с VLESS + Reality + XTLS Vision;
3. безопасно маршрутизирует IPv4 и IPv6;
4. поддерживает split tunneling по доменам и IP/CIDR;
5. поддерживает per-app routing как одну из двух главных функций наравне с самим VPN, в пределах доказанных возможностей каждой платформы;
6. восстанавливает маршруты, DNS и системное состояние после отключения, сбоя или принудительного завершения;
7. предоставляет нативный и доступный UI для подключения, выбора профиля и диагностики на каждой поддерживаемой desktop-платформе.

Windows 11 не входит в первый macOS production milestone, но является обязательным вторым релизом; Android — третьим. Linux и дополнительные протоколы не входят в первые два production-релиза.

## 2. Принятые границы

### 2.1. Что означает «на Rust»

На Rust реализуются общие доменная модель, конфигурация, policy engine, state machine, наблюдаемость, engine-neutral contracts и максимально возможная часть network core. Платформенные слои не дублируют policy logic. Для macOS допускается узкий Swift/Objective-C слой SwiftUI/AppKit и отдельный привилегированный helper; для Windows — узкий native shell и отдельная Windows Service/network boundary после architecture spike; для Android — узкий слой `VpnService`.

Для macOS выбран SwiftUI/AppKit shell + Rust core ([ADR-001](./ADR-001-MACOS-UI.md)); второй UI-стек для macOS не поддерживается. UI для Windows и Android — открытое решение, кандидат Tauri v2 (HTML/CSS/TypeScript в системном WebView); оно принимается отдельным ADR после первого macOS-релиза.

### 2.2. Что означает «нативное desktop-приложение»

macOS release должен содержать `.app`, menu bar behavior, корректный lifecycle, accessibility, code signing, notarization и одобренную macOS network boundary. Windows release должен содержать нативный desktop shell, tray/lifecycle integration, accessibility, подписанный installer/update path и отдельно привилегированную network service boundary. Точные Windows UI, WFP/Wintun/TUN и packaging choices остаются `Proposed` до ADR/spikes.

### 2.3. Порядок платформ

1. Сначала завершаются macOS milestones и первый production-релиз.
2. Затем выполняются обязательные Windows 11 milestones с повторным использованием versioned Rust crates, schemas и fixtures.
3. Затем выполняются Android milestones поверх того же core, того же формата конфигурации и того же движка; привилегированная граница — `VpnService`. Размещение Android-кода и UI-стек определяются отдельным ADR ([ADR-006](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md), пункт 7).

### 2.4. Модель распространения macOS

Владелец продукта зафиксировал, что платное членство Apple Developer Program не приобретается.
Поэтому для первого релиза выбрано **распространение исходным кодом**: пользователь собирает
приложение локально либо через формулу пакетного менеджера, выполняющую сборку из исходников.
Раздача готового неподписанного бинарника с обходом Gatekeeper не рассматривается.

Следствия: entitlement `com.apple.developer.networking.networkextension` недоступен, поэтому
системный туннель реализуется через privileged helper + `utun` ([ADR-003](./ADR-003-NETWORK-TOPOLOGY.md)),
а аудитория ограничена пользователями, готовыми собрать проект из исходников.

[ADR-002](./ADR-002-MACOS-DISTRIBUTION.md) остаётся `Proposed` до прохождения Gate S
(воспроизводимая сборка, установка/деинсталляция helper, legal review лицензии движка).
Direct Developer ID distribution сохраняется как целевая модель при появлении платного аккаунта.

## 3. Текущее состояние

Легенда: `[x]` реализовано, `[~]` частичный прототип, `[ ]` отсутствует.

- [x] Rust crate, library и CLI target.
- [x] Модели конфигурации с типизированными перечислениями, валидацией, Serde JSON round trips и JSON Schemas в `schema/`.
- [x] Парсер VLESS URI с базовыми Reality-параметрами, TCP/RAW, WebSocket и gRPC и fail-closed отказом для остальных транспортов.
- [~] Генерация engine JSON: Xray-генератор и сменяемая стратегия sing-box генерируют локальные SOCKS/HTTP inbounds и VLESS outbounds со стандартным TLS, Reality и TCP/WebSocket/gRPC metadata; Xray имеет controlled loopback traffic evidence, sing-box Reality/TCP проходит `sing-box check -c` на pinned `v1.13.18`, но routing/DNS/policy ещё не реализованы.
- [~] Matcher доменов, IP и приложений с типизированным `SplitTunnelMode`; применение к трафику на уровне data-plane требует Network Extension.
- [~] Process supervisor: spawn/kill без лог-стримов, health-check, restart и graceful shutdown.
- [~] Route manager: публичный API является no-op заглушкой.
- [ ] TUN data plane через privileged helper (`utun`).
- [ ] Реальный DNS controller и leak prevention.
- [ ] Kill switch.
- [ ] GUI и macOS application bundle.
- [ ] Signing, notarization, updater и release pipeline.
- [ ] Windows 11 UI, service/network adapter и signed package.
- [ ] Windows 11 system-test environment.

## 4. Функциональные требования

### FR-001. Конфигурация и профили

- [x] Версионированные JSON-схемы созданы в `schema/` (`config.schema.json`, `settings.schema.json`) и проверяются в тестах и CI.
- [x] `config.json` хранит серверные профили; `settings.json` — параметры клиента и routing policy.
- [x] Заменить строковые protocol, security, flow, transport и mode на типизированные перечисления (`ProtocolType`, `SecurityType`, `FlowType`, `TransportType`, `SplitTunnelMode`).
- [~] Валидировать UUID, host, port, обязательные Reality/TLS-параметры (SNI, Base64 public_key, hex short_id, uTLS fingerprint), порты прокси и правила доменов/IP (CIDR и GeoIP датасеты отложены до M2).
- [ ] Запись выполняется атомарно: temp file, `fsync`, rename, резервная копия последней валидной версии.
- [ ] Секреты не логируются и при необходимости хранятся через Keychain.
- [x] Импорт URI не должен принимать неполные Reality-настройки (валидирует обязательный `public_key`, fail-closed для неподдерживаемых `security`, `flow` и transport `type`).

### FR-002. Протоколы

Первый обязательный вертикальный срез:

- VLESS;
- Reality;
- XTLS Vision;
- TCP transport;
- проверка конфигурации реальным выбранным engine до запуска.

VLESS URI без параметра `type`, с `type=tcp` и с совместимым alias `type=raw` обозначают
поддерживаемый TCP/RAW transport. Для TCP разрешены отсутствие `headerType` и
`headerType=none`; `headerType=http` и неизвестные значения отклоняются до появления отдельной
модели TCP header obfuscation. WebSocket (`type=ws`/`websocket`) и gRPC (`type=grpc`) сохраняются в
engine-neutral полях профиля `transport`, `host`, `path`. Пустые или состоящие из пробелов значения
`host`, `path`, `authority`, `serviceName` и `mode` нормализуются как отсутствующие, а непустые
transport-значения обрезаются по краям. WebSocket `path` обязателен и начинается с `/`; gRPC принимает
непустой стандартный `serviceName` без `/` (либо совместимый query `path`) и опциональный `authority`
(либо `host`). Xray custom-path синтаксис gRPC с ведущим `/` пока не входит в capability и отклоняется
fail-closed. Эффективный transport host выбирается в порядке: явный `host`/`authority`, TLS `server_name`,
адрес `server`. `mode` интерпретируется только для `type=grpc`: поддерживается `mode=gun`, прочие
непустые gRPC-режимы отклоняются fail-closed; для TCP значение `mode` не считается gRPC-контрактом.
Xray-генератор формирует соответственно `wsSettings` (`path`, `headers.Host`) и `grpcSettings`
(`serviceName`, `authority`) из нормализованных значений. XTLS Vision с WebSocket/gRPC и Reality с
WebSocket отклоняются как несовместимые комбинации; Reality с TCP/RAW и gRPC разрешён. `httpupgrade`,
`xhttp`, `h2`, `quic`, `kcp` и неизвестные значения остаются fail-closed.
Имена известных критичных query-параметров регистрозависимы; варианты вроде `Type`, `Security` и
`HeaderType`, `Host`, `Path`, `ServiceName`, `Authority` и `Mode` отклоняются явно, а не игнорируются.

После стабильного первого релиза могут добавляться WireGuard, Shadowsocks 2022, Trojan и Hysteria 2. Каждый протокол требует отдельной схемы, capability matrix и integration tests.

### FR-003. Network engine lifecycle

- Engine поставляется проверяемым способом и имеет зафиксированную версию и checksum.
- Start подтверждается readiness probe, а не только успешным `spawn`.
- stdout/stderr читаются асинхронно с redaction и ротацией.
- Поддерживаются graceful stop, timeout, forced termination и restart policy.
- Crash engine переводит приложение в безопасное состояние и запускает rollback сети.
- Возможность запуска subprocess внутри выбранной модели распространения должна быть подтверждена отдельным spike до фиксации архитектуры.

### FR-004. VPN data plane

- Поддерживаются IPv4 и IPv6 или IPv6 явно блокируется безопасным способом до реализации.
- VPN endpoint всегда имеет маршрут вне туннеля, исключающий routing loop.
- Приложение управляет MTU, DNS и маршрутизацией через выбранный поддерживаемый API текущей платформы.
- Прямые системные команды допускаются только через ограниченный и проверяемый privileged boundary.
- Повторный connect/disconnect должен быть идемпотентным.

### FR-005. Split tunneling

Policy model должен поддерживать типизированные режимы:

- `proxy_all`;
- `bypass_selected`;
- `proxy_selected` — после отдельной threat-model проверки;
- `block_selected` — опционально.

Минимальные типы правил:

- exact domain и subdomain suffix;
- IP и CIDR для IPv4/IPv6;
- GeoIP/GeoSite с версионированным источником данных;
- local/private networks;
- app rule, если architecture текущей платформы позволяет надёжно определить и применить владельца потока.

Domain/IP rules должны превращаться в реальные engine или OS routes. Простое вычисление `Direct`/`Proxy` без применения к трафику не считается реализацией split tunneling.

### FR-006. Per-app routing

Per-app routing является одной из двух главных функций продукта и обеспечивается движком, а не
собственной реализацией сопоставления процессов: sing-box предоставляет правила `process_name` и
`process_path` на macOS/Windows и `package_name` на Android ([ADR-004](./ADR-004-ENGINE-INTEGRATION.md),
факт 2). Core транслирует пользовательский список приложений в эти правила и нормализует его:
движок сопоставляет имя и путь исполняемого файла, а не bundle identifier.

До production-реализации на каждой платформе требуется spike. Он проверяет:

1. process/socket attribution для TCP и UDP;
2. race conditions между открытием сокета и обнаружением процесса;
3. QUIC, shared helpers, browser subprocesses и sandboxed apps;
4. поведение после обновления/перезапуска приложения;
5. совместимость с выбранным способом распространения.

Если надёжность не доказана, релиз должен честно ограничиться domain/IP split tunneling.

Результат macOS spike нельзя автоматически переносить на Windows и Android и наоборот.

### FR-007. DNS

- DNS-запросы следуют той же policy, что и целевой трафик.
- Должны быть предотвращены DNS leaks при connect, reconnect и disconnect.
- Требуются обработка split DNS, кеша, системного resolver state и IPv6.
- Исходные настройки восстанавливаются по транзакционному snapshot.

### FR-008. Kill switch и recovery

- При неожиданном падении туннеля трафик не должен тихо уходить напрямую, если включён kill switch.
- До изменения сети сохраняется snapshot применяемого состояния.
- Rollback выполняется при штатном stop, signal, crash-recovery следующего запуска и ошибке посередине connect transaction.
- Есть отдельная команда/экран безопасного восстановления.
- Нельзя оставлять постоянное широкое правило `pf` или сломанный DNS после удаления приложения.

### FR-009. UI

Обязательные экраны и состояния:

- connect/disconnect и state machine `Disconnected → Connecting → Connected → Reconnecting/Disconnecting/Error`;
- список и редактор профилей;
- импорт VLESS URI с preview и validation errors;
- редактор domain/IP/app rules с объяснением фактических ограничений;
- menu bar control;
- диагностический экран без секретов;
- настройки launch-at-login, notifications, DNS и kill switch;
- системные accessibility, keyboard navigation, localization и dark/light mode.

UI не должен напрямую выполнять privileged network operations. Он вызывает ограниченный application service API.

macOS UI следует ADR-001. Для Windows рекомендуется WinUI 3 shell, но окончательный выбор остаётся `Proposed` до spike по ADR-006; web UI или собственный renderer не являются default.

### FR-010. Обновления и диагностика

- Версии приложения, engine и rules database отображаются отдельно.
- Обновления подписываются и проверяются.
- Экспорт diagnostic bundle требует preview и redaction secrets/IP/UUID по политике.
- Telemetry по умолчанию выключена до появления отдельной privacy specification.

### FR-011. Общий core и platform contracts

- Rust core является источником истины для policy, profiles, state machine и engine-neutral diagnostics.
- Platform adapters сообщают capabilities и не объявляют неподдерживаемые функции.
- FFI/IPC commands и events типизированы, версионированы и выполняют handshake до любой network mutation.
- Неизвестная версия/команда отклоняется безопасно; UI показывает наблюдаемое, а не предполагаемое состояние.
- Platform-specific handles, raw shell commands и privilege decisions не входят в общий публичный contract.

## 5. Целевая архитектура

```text
SwiftUI/AppKit macOS shell ─┐
                           ├─ versioned commands/events ─ Rust Application Core
Windows native shell ──────┘                              │
                                                         ├─ config/policy/state/diagnostics
macOS Network Boundary ◄─────────────────────────────────┤
Windows Service/Network Boundary ◄───────────────────────┘
```

Компоненты и границы подробнее описаны в [ARCHITECTURE.md](./ARCHITECTURE.md).

## 6. Нефункциональные требования

### NFR-001. Безопасность

- deny-by-default privileged API;
- отсутствие shell interpolation для системных команд;
- минимальные entitlements;
- проверка подписей/checksum bundled artifacts;
- zero secret logging;
- threat model до первого beta.

### NFR-002. Надёжность

- connect/disconnect transaction имеет компенсационные действия;
- повторный запуск исправляет незавершённое предыдущее состояние;
- отсутствие routing/DNS residue подтверждается автоматизированным тестом;
- network changes сериализованы и защищены от concurrent connect/disconnect.

### NFR-003. Производительность

- UI остаётся отзывчивым при connect/reconnect и streaming logs;
- idle UI не выполняет постоянный high-frequency rendering;
- throughput и latency измеряются относительно прямого соединения;
- memory/CPU budgets фиксируются после первого end-to-end prototype.

### NFR-004. Совместимость

- production baseline фиксируется до beta; предварительно macOS 14+;
- обязательная цель `aarch64-apple-darwin`;
- Intel universal binary — отдельный post-MVP decision, не неявное требование.
- второй desktop baseline: Windows 11 x64 и `x86_64-pc-windows-msvc`; Windows ARM64 — отдельное решение;
- Android не является target этого репозитория.

### NFR-005. Наблюдаемость

- структурированные логи и state transitions;
- correlation ID на connect attempt;
- redacted diagnostics;
- понятные пользователю ошибки permissions, engine, DNS и routing.

## 7. Конфигурационный контракт

Канонический `settings.json` использует секцию `client`, как текущий `settings.example.json`. Старое описание секции `system` отменено.

Канонические схемы `schema/config.schema.json` и `schema/settings.schema.json` являются авторитетным источником, а примеры конфигурации валидируются против них в тестах и CI.

Поле `mode` типизировано через `SplitTunnelMode` (`proxy_all`, `bypass_selected`, `proxy_selected`, `block_selected`). Несогласованные исторические значения `bypass_ru` и `direct_all` не являются поддерживаемым публичным контрактом.

## 8. Критерии первого рабочего macOS-релиза

Первый macOS release считается готовым только когда одновременно выполнено следующее:

1. Подписанное arm64 `.app` устанавливается на чистый Mac.
2. Валидный VLESS Reality профиль подключается к тестовому серверу.
3. IPv4/IPv6 и DNS поведение соответствует заявленной policy.
4. Domain/IP split tunneling подтверждён packet-level тестом.
5. Disconnect, engine crash и принудительное завершение не оставляют маршруты/DNS.
6. Kill switch проходит негативные сценарии.
7. UI корректно отображает фактическое состояние, а не только отправленную команду.
8. Release подписан и notarized; rollback процедуры документированы.

Per-app routing может быть вынесен из MVP, если spike не докажет безопасную consumer-grade реализацию.

### 8.1. Критерии второго Windows 11-релиза

Windows release готов только когда:

1. Подписанный installer устанавливается на чистую Windows 11 x64 машину.
2. Нативный UI управляет отдельно привилегированной службой через versioned authenticated IPC.
3. Валидный VLESS Reality профиль создаёт реальный full tunnel для IPv4/IPv6 и DNS либо неподдерживаемый IPv6 безопасно блокируется.
4. Domain/IP split tunneling подтверждён наблюдаемым direct/proxy egress.
5. Service/engine/UI crash, reboot, upgrade и forced stop не оставляют routes, DNS, firewall/WFP filters или процессы.
6. Kill switch и endpoint-loop prevention проходят негативные тесты.
7. UI показывает фактическое состояние службы/tunnel и предоставляет безопасный recovery action.
8. Подписанные package/update и rollback/uninstall проходят clean-machine verification.

## 9. Не-цели первого macOS-релиза

- одновременный Windows release: Windows 11 является обязательным вторым релизом;
- Linux и Windows ARM64;
- Android app в этом репозитории;
- полный набор протоколов;
- собственный Metal-rendered UI;
- облачный аккаунт и синхронизация;
- telemetry/analytics;
- App Store одновременно с direct distribution, если это задерживает проверяемый релиз.

## 10. Трассировка реализации

- Полный список задач: [roadmap](../learning/05_roadmap_zero_to_hero.md).
- Порядок исполнения: [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md).
- UI decision: [ADR-001-MACOS-UI.md](./ADR-001-MACOS-UI.md).
- Distribution channel: [ADR-002-MACOS-DISTRIBUTION.md](./ADR-002-MACOS-DISTRIBUTION.md).
- Network topology: [ADR-003-NETWORK-TOPOLOGY.md](./ADR-003-NETWORK-TOPOLOGY.md).
- Engine integration: [ADR-004-ENGINE-INTEGRATION.md](./ADR-004-ENGINE-INTEGRATION.md).
- Cross-platform boundaries: [ADR-006-CROSS-PLATFORM-BOUNDARIES.md](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md).
- Тестовые уровни и quality gates: [TESTING.md](./TESTING.md).
