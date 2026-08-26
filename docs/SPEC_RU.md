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
- [x] Connection lifecycle skeleton: `ConnectionState` и serialized helper command executor валидируют
  connect/status/disconnect/recover transitions без IPC transport, helper runtime или network mutation.
- [x] Network transaction contract skeleton: `NetworkSnapshot` и `AppliedNetworkState` описывают
  route/DNS/firewall snapshot, typed операции, phase validation и rollback metadata без `utun`,
  `route`, `scutil`, `pfctl`, DNS/firewall mutation или helper runtime.
- [x] Rollback ordering contract: applied network operations несут explicit `apply_order`, а core
  возвращает rollback steps в строгом обратном порядке применения без OS mutation.
- [x] Recovery journal persistence contract: core записывает и читает typed JSON journal для
  `NetworkSnapshot` + `AppliedNetworkState` через private каталог, temp-write/fsync/rename,
  карантинит corrupt/unknown fields/invalid state fail-closed, удаляет осиротевшие temp-кандидаты и
  очищает valid journal только по явной успешной recovery-команде; deterministic test покрывает
  восстановление rollback work после crash сразу после full-tunnel route step; это ещё не выполняет
  rollback против ОС.
- [x] Connect transaction planner: core строит ordered `AppliedNetworkState` в фазе `Planned` для
  full-tunnel connect intent с endpoint route, tunnel address/MTU, default-route/full-tunnel route,
  DNS и firewall policy operations, включая rollback metadata и redacted diagnostics, без helper
  runtime или OS mutation.
- [x] Dry-run network operation executor contract: core применяет typed `NetworkOperationKind` plan
  в `apply_order`, пишет recovery journal до/после dry-run операции, обновляет статусы
  `Planned` → `Applying` → `Applied`/`Failed`, останавливается на первой ошибке и строит rollback
  work по applied/applying prefix; `Applying` трактуется как «возможно применено» и требует
  идемпотентного rollback в будущих platform adapters; это ещё не выполняет OS operations.
- [x] Network operation idempotency contract: каждая typed route, tunnel address/MTU, DNS, firewall
  и rollback inverse команда имеет pure-core retry scope; идентичный retry классифицируется как
  идемпотентный, same-scope другой payload — как конфликтующая мутация, unrelated scope — как
  независимая работа. Это ещё не выполняет OS operations.
- [x] Adapter-level idempotency enforcement path: typed transaction executor теперь оборачивает
  platform operation execution retry-контрактом, принимает точные повторы без второго inner
  execution, отклоняет same-scope conflicts до конфликтующей мутации и сохраняет unrelated scopes
  независимыми. Пока это только dry-run adapters без OS operations.
- [x] Network transaction start-gate path: core предоставляет serialized transaction executor,
  который проверяет shared recovery-journal store перед стартом и отклоняет новую transaction при
  наличии pending recovery work до любых новых journal или operation side effects. Helper runtime и
  IPC transport всё ещё отсутствуют.
- [x] Applied network state persistence contract: после перехода dry-run transaction в `Applied`
  core очищает pending recovery work и записывает отдельный durable applied-state record, который
  startup может загрузить для построения rollback work после crash во время долгого connected-state.
  Store хранит не больше одного active applied-state record и предоставляет explicit clear для
  будущего successful disconnect/recovery flow. Applied-state records не блокируют новые
  transactions; helper runtime, OS mutation и реальное выполнение rollback всё ещё отсутствуют.
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

Текущий MVP не должен архитектурно закрывать добавление других поддерживаемых движком протоколов.
UI, helper/IPC contract и policy model не должны предполагать, что единственный возможный outbound
protocol — VLESS: протокол выбирается типизированным profile field и транслируется в engine-specific
generator. После стабильных desktop-релизов могут добавляться отдельными vertical slices: Trojan +
TLS, Shadowsocks AEAD/2022, Hysteria 2, TUIC, WireGuard, VMess и debug/enterprise outbounds
(`socks`, `http`, `ssh`) там, где они поддержаны выбранным движком и не ломают safety model.
Каждый новый протокол требует отдельной схемы, URI/config importer, semantic validation,
capability matrix, generated-config preflight, real network integration tests, redaction review и
документации ограничений. WireGuard считается отдельной моделью VPN-профиля с ключами, addresses и
allowed IPs, а не простой разновидностью VLESS-proxy profile.

### FR-003. Network engine lifecycle

- Engine поставляется проверяемым способом и имеет зафиксированную версию и checksum.
- Автоматически pinned binary checksum поддерживается для Xray-core и sing-box на macOS arm64,
  macOS x86_64, Linux arm64, Linux x86_64 и Windows x86_64. Иные OS/arch не входят в текущий
  support matrix, явно помечаются в help/`pinned-releases` как неподдерживаемые и не запускаются
  без явного trusted `--expected-sha256`.
- Runtime выбирает версию движка из versioned pinned catalog: по умолчанию единственную
  `recommended`, либо явно заданную пользователем через `--engine-version <VERSION>` для выбранного
  `--engine-config`.
  Catalog хранит `recommended`/`supported`/`deprecated`/`yanked` lifecycle status, полное покрытие
  declared OS/arch и оба lowercase SHA-256; смена default требует отдельного reviewable changelog
  change. CLI/API не считает вывод `engine version` trusted
  security oracle. При несовпадении pinned binary checksum диагностика называет движок, pinned
  версию и целевые OS/arch и различает «другая/неподдерживаемая версия либо изменённый артефакт»
  от отсутствия pin для платформы. Запуск остаётся fail-closed; `--expected-sha256` — явный
  trusted override для ожидаемых байтов бинарника, но не выбирает версию движка, не доказывает
  версию бинарника и не отключает compatibility check.
- `--engine-version` принимает только catalogued версии выбранного движка. `recommended` и
  `supported` разрешены, `deprecated` разрешена только с предупреждением до старта, а `yanked`,
  неизвестная, uncatalogued или несовместимая с dialect версия отклоняется до проверки checksum и
  запуска процесса.
- Typed configuration dialect хранится в catalog как свойство exact пары `engine/version` и
  проверяется против выбранного release до выбора checksum source и старта процесса:
  текущие доказанные пары — Xray `v26.3.27`/`XrayV26` и sing-box `v1.13.18`/`SingBoxV1_13`.
  Catalog validation отклоняет неизвестную строку dialect и рассинхрон dialect между target-записями
  одной версии.
- CLI-команда `start` принимает `--engine-config xray|sing-box` для выбора формата генерируемой
  конфигурации и pre-flight команды. По умолчанию выбирается `xray`; `--engine-bin` указывает
  путь к исполняемому файлу выбранного движка и сам по себе не меняет формат конфигурации.
  `--engine-version <VERSION>` выбирает catalogued версию для выбранного движка и сам по себе не
  меняет формат конфигурации.
  Неизвестное значение стратегии отклоняется как usage error до чтения конфигурации или запуска
  процесса.
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
- До любой системной мутации core/helper contract фиксирует `NetworkSnapshot` исходного состояния и
  `AppliedNetworkState` с типизированными операциями, фазой транзакции и rollback metadata; этот
  contract не является доказательством работающего tunnel до реальных L5/L7 проверок.
- Компенсация network transaction должна выполняться в обратном порядке применения операций; порядок
  фиксируется явным `apply_order`, а не позицией в массиве или результатом диагностической группировки.
- Незавершённая network transaction должна иметь recovery journal с `NetworkSnapshot` и
  `AppliedNetworkState`; journal читается fail-closed при следующем запуске, corrupt/partial данные
  не считаются валидной recovery work, а clear допускается только после явной успешной recovery.
- Успешно применённое network state должно сохраняться отдельно от pending recovery journals, чтобы
  startup мог обнаружить и восстановить ранее подключённую сессию после crash/relaunch. Это applied
  state не блокирует новые transactions, но остаётся typed, versioned, private, redacted в
  diagnostics, clearable после successful disconnect/recovery, ограниченным одним active record и
  должно строить rollback steps в обратном `apply_order`. Если crash происходит после записи
  applied state, но до очистки pending journal, recovery может безопасно предпочесть pending journal
  и выполнить идемпотентный rollback.
- Connect должен сначала моделироваться как ordered transaction plan: stable operation keys,
  explicit `apply_order`, typed network operations и rollback metadata формируются до передачи в
  privileged boundary; сам planner не доказывает реальную мутацию сети.

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
- Частично применённая network transaction не считается успешной без явного `AppliedNetworkState`;
  missing rollback metadata и inconsistent transaction phases должны отклоняться fail-closed.
- Missing или duplicate rollback order для применённых операций отклоняется fail-closed до любой
  попытки выполнить компенсацию.
- Recovery journal хранится как typed JSON с версией схемы; unknown fields, corrupt JSON,
  несовпадение snapshot/transaction metadata или invalid rollback state карантинятся fail-closed без
  блокировки других валидных journals.

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
- Platform helper contract skeleton содержит только типизированные handshake, capability report,
  allowlisted commands/events, strict schema validation, redacted debug output и bounded validation.
  Он не устанавливает helper, не открывает IPC transport, не запускается под `root` и не мутирует
  `utun`, routes, DNS, firewall или system proxy.
- Connection lifecycle skeleton сериализует только allowlisted helper commands, проверяет допустимые
  state transitions и correlation IDs и не запускает helper, engine или системный tunnel.
- Network transaction contract skeleton содержит только типизированные snapshots, applied-state,
  route/DNS/firewall operation descriptors и rollback metadata. Он не выполняет shell-команды, не
  открывает privileged transport и не меняет состояние операционной системы.

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
