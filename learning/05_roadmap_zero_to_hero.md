# NovaRay: полный roadmap от прототипа до macOS и Windows desktop-релизов

Актуально на 2026-08-16.

## Обозначения

- `[x]` — реализовано и проверено в текущем репозитории;
- `[~]` — существует частичный прототип, но задача не завершена;
- `[ ]` — не реализовано;
- `Gate` — решение или проверка, без которой нельзя безопасно начинать зависимые задачи.

Roadmap фиксирует последовательность: первый production-релиз для macOS 14+ Apple Silicon, затем
обязательный второй релиз для Windows 11 x64. Android — отдельный будущий проект/репозиторий. Linux,
universal/Windows ARM64 binaries и дополнительные протоколы не входят в первые два релиза.

## Текущее положение

```text
Rust models/parser/matcher/tests
              ↓
      [мы находимся здесь]
              ↓
CLI поверх core → engine vertical slice → privileged helper + utun data plane
              ↓
domain/IP split tunneling → per-app split tunneling (движок) → security/recovery
              ↓
native macOS UI → source-first release
              ↓
Windows topology/service spike → Windows full/split tunnel → UI → release
              ↓
Android VpnService → Android UI → release
```

---

## Фаза 0. Зафиксировать продукт и архитектурные решения

Цель: прекратить смешивать желаемую архитектуру с реализованным состоянием.

### 0.1. Документация и scope

- [x] Разделить current state и target state в README/spec/architecture.
- [x] Зафиксировать Apple Silicon как обязательную первую цель.
- [x] Вынести Windows/Linux и дополнительные протоколы из первого MVP.
- [x] Зафиксировать порядок: macOS первым, Windows 11 вторым, Android в отдельном проекте (issue #5).
- [x] Описать proposed shared-core/platform boundaries в ADR-006.
- [x] Определить минимальный MVP: VLESS Reality, domain/IP split, recovery, native UI, signed `.app`.
- [x] Добавить отдельный implementation plan и UI ADR.
- [ ] Добавить владельца и дату следующего review для каждого архитектурного решения.
- [ ] Ввести requirements traceability: `FR/NFR → задача → тест → evidence`.

### 0.2. Gate: модель распространения

- [x] Сравнить direct Developer ID distribution и Mac App Store в ADR-002 (issue #1).
- [x] Зафиксировать отказ от платного Apple Developer Program как входное ограничение продукта.
- [~] Зафиксировать source-first distribution как первичную модель в [ADR-002](../docs/ADR-002-MACOS-DISTRIBUTION.md) со статусом `Proposed`.
- [ ] Пройти Gate S: воспроизводимая сборка из чистого клона на Apple Silicon.
- [ ] Пройти Gate S: документированные установка и полная деинсталляция privileged helper.
- [ ] Пройти Gate S: legal review GPL-3.0-or-later и naming restriction sing-box для выбранной модели раздачи.
- [ ] Отложено до платного аккаунта: NetworkExtension entitlements, Developer ID, notarization.

### 0.3. Gate: network topology

- [~] Создать spike `NEPacketTunnelProvider` на Apple Silicon в `spikes/macos-networkextension-spike/` (issue #7; остаётся валидным evidence для отложенного пути).
- [x] Зафиксировать факт: `utun` требует `root`, но не требует Apple entitlement.
- [~] Зафиксировать privileged helper + `utun` как основную топологию в [ADR-003](../docs/ADR-003-NETWORK-TOPOLOGY.md) со статусом `Proposed`.
- [ ] Пройти Gate H: демон создаёт `utun`, поднимает и снимает туннель.
- [ ] Пройти Gate H: доказанный откат маршрутов, DNS и firewall при остановке, `SIGKILL` и перезагрузке.
- [ ] Пройти Gate H: отсутствие DNS-утечек и остаточных процессов/правил.
- [ ] Описать threat model root-демона, typed allowlist и авторизацию установки.
- [ ] Отложено до платного аккаунта: NetworkExtension как предпочтительная топология (Gate B).

### 0.4. Gate: engine integration

- [~] Pinned license/source/release metadata, официальные arm64 artifacts и embedding paths Xray-core
  и Sing-box собраны в evidence-only spike issue #12; локальная arm64-сборка и запуск не выполнялись.
- [~] Host subprocess, extension embedding/subprocess и helper-owned варианты сравнены по первичным
  источникам; runtime внутри development-entitled topology не доказан.
- [~] Команды config validation и требуемые readiness/logging/graceful-stop contracts описаны;
  реальное L4 lifecycle evidence отсутствует.
- [x] Проверить по исходникам, поддерживают ли движки маршрутизацию по приложениям: Xray-core `v26.3.27` — нет, sing-box `v1.13.18` — `process_name`/`process_path` (macOS/Windows) и `package_name` (Android).
- [~] Зафиксировать sing-box как production-движок в [ADR-004](../docs/ADR-004-ENGINE-INTEGRATION.md) со статусом `Proposed`.
- [x] Зафиксировать версию, source revision и checksum sing-box в runtime catalog/evidence: `v1.13.18`,
  revision `45ca32dcb966f07f97fc888fe8586e359dbe8405`, archive SHA-256 и binary SHA-256 для
  `darwin-arm64`, `linux-arm64`, `windows-amd64`.
- [ ] Пройти гейты ADR-004, включая per-app routing на реальном трафике и legal review.

Критерий завершения фазы: оформлен базовый архитектурный пакет ADR по UI, distribution, network topology и engine; дальнейшие задачи больше не зависят от скрытых предположений.

---

## Фаза 1. Привести Rust Core prototype к надёжной библиотечной основе

Цель: создать типизированный, тестируемый core, не зависящий от конкретного UI.

### 1.1. Структура workspace

- [x] Создан Rust 2021 crate с library и binary targets.
- [x] Модули config/parser/matcher/generator/supervisor/routing выделены по файлам.
- [ ] Превратить проект в Cargo workspace с явными crates, если это подтвердит architecture design:
  - `novaray-domain`;
  - `novaray-config`;
  - `novaray-policy`;
  - `novaray-engine`;
  - `novaray-contracts`;
  - `novaray-platform-macos`;
  - `novaray-platform-windows`;
  - `novaray-ffi` или отдельные узкие platform bindings.
- [x] Устранить дублирование модулей между `lib.rs` и `main.rs`.
- [ ] Добавить rust-toolchain, minimum supported Rust version и build profiles.

### 1.2. Конфигурационный контракт

- [x] Базовые `AppConfig`, `ServerProfile`, `UserSettings` и Serde roundtrip.
- [x] Проверка пустого профиля, отсутствующего active profile и коллизии портов.
- [x] Пример `config.example.json` и `settings.example.json` ссылается на валидные schemas в `schema/`.
- [x] Создать `schema/config.schema.json` и `schema/settings.schema.json`.
- [x] Заменить строковые `protocol`, `security`, `flow`, `mode` на enum/value objects (`ProtocolType`, `SecurityType`, `FlowType`, `SplitTunnelMode`).
- [x] Унифицировать `mode`: `proxy_all`, `bypass_selected`, `proxy_selected`, `block_selected`.
- [ ] Добавить schema version и migration framework.
- [ ] Проверять UUID, hostname/IP, port, DNS, CIDR, Reality public key, short ID, SNI и fingerprint.
- [ ] Реализовать atomic write, backup и recovery последней валидной конфигурации.
- [ ] Перенести реальные secrets в Keychain; fixtures заменить очевидными test values.
- [x] Добавить duplicate-ID policy.
- [ ] Добавить conflicting-rule и unknown-field policy.

### 1.3. VLESS importer

- [x] Парсинг базового `vless://uuid@host:port`.
- [x] Percent-decoding имени профиля.
- [x] Извлечение `security`, `sni`, `pbk`, `sid`, `fp`, `flow`.
- [ ] Валидировать обязательные параметры для Reality и XTLS Vision.
- [ ] Обрабатывать IPv6 literals, IDN/punycode и duplicate query parameters.
- [ ] Добавить ограничения длины и безопасные ошибки без отражения secrets.
- [ ] Ввести canonical normalization и deterministic profile ID без коллизий.
- [ ] Добавить property/fuzz tests URI parser.

### 1.4. Error model и observability

- [ ] Заменить `Result<(), String>` на типизированные ошибки.
- [ ] Ввести стабильные error codes для FFI/UI.
- [ ] Добавить connection-attempt correlation ID.
- [ ] Реализовать redaction UUID, keys, tokens, endpoint по policy.
- [ ] Добавить bounded rotating logs и user-visible diagnostic events.
- [ ] Запретить secret-bearing types реализовывать небезопасный `Debug`.

### 1.5. Quality baseline

- [x] Текущие unit/integration-style тесты проходят.
- [x] Исправить строгий Clippy (`Default` для `ProcessSupervisor` и `RouteManager`).
- [x] Добавить `cargo fmt --check`, Clippy `-D warnings` и test в CI: Linux, macOS 14 arm64 и
  documentation jobs прошли в recorded CI run 31949037576.
- [x] Добавить Windows hosted x64 Clippy/tests как portability gate: job прошёл в
  recorded CI run 31951959769. Это не Windows 11
  system VPN evidence.
- [ ] Добавить dependency, license и supply-chain audit.
- [ ] Определить coverage не как процент ради процента, а как список критических boundary scenarios.

Критерий завершения фазы: core имеет стабильный публичный API, schemas и migrations; `fmt`, Clippy и tests зелёные; fuzzing не находит crash на bounded corpus.

---

## Фаза 2. Получить первый реальный protocol-engine vertical slice

Цель: доказать, что Rust core может подготовить, запустить и проверить реальное VLESS Reality соединение без системного VPN.

### 2.1. Генерация engine config

- [x] Генерируются SOCKS и HTTP inbounds.
- [x] Генерируются VLESS, direct и block outbounds.
- [x] Генерируются основные Reality settings (с полем `password`, дефолтом `fingerprint` и поддержкой пустого `shortId: ""`).
- [x] Обязательная валидация непустого Reality `public_key` и нормализация в канонический Raw URL-safe Base64.
- [x] Исправить обычный `security=tls`, который генерирует корректный `tlsSettings` с `allowInsecure: false`.
- [x] Проверять JSON реальной командой движка: для Xray-core подтверждено (`xray run -test -c` → `Configuration OK`, запуск и bind 10808/10809 на pinned `v26.3.27`); для sing-box Reality/TCP generated config подтверждён `sing-box check -c` на pinned `v1.13.18`.
- [x] Реализовать генератор конфигурации sing-box как сменяемую стратегию рядом с Xray-генератором.
- [x] Fail-closed импорт VLESS URI: отсутствие `type`, `type=tcp` и alias `type=raw` разрешены; non-TCP transport, `headerType` кроме `none` и некорректный регистр критичных query keys отклоняются до создания профиля — issue development task #33, шаг 1.
- [x] Добавить engine-neutral поля `transport`, `host`, `path` и поддержку WebSocket/gRPC; parser,
  schema, semantic validation и Xray `wsSettings`/`grpcSettings` реализованы, а оба конфига прошли
  `xray run -test` на pinned `v26.3.27`; controlled loopback test провёл реальные HTTP-запросы
  через Xray server/client и SOCKS5 для обоих transport. Остальные transport capabilities
  остаются fail-closed. Correction-pass также запрещает Reality+WebSocket до генерации, разрешает
  Reality+gRPC, нормализует пустые transport query values, использует server как последний Host
  fallback, запрещает `host`/`path` для TCP в JSON Schema и ограничивает gRPC стандартным
  `serviceName` без `/` (custom-path syntax отложен) — issue
  development task #33, шаг 2.
- [ ] Генерировать DNS и routing sections из policy compiler.
- [ ] Добавить IPv6, UDP, transport и mux options только после capability review.
- [ ] Добавить golden fixtures по поддерживаемым capabilities.

### 2.2. Engine artifact

- [ ] Автоматизировать получение/сборку arm64 engine (sing-box) для macOS, Windows и Android.
- [x] Зафиксировать version, source revision и checksum: для Xray-core `v26.3.27` зафиксированы archive sha256 с разделением archive/binary; для sing-box `v1.13.18` зафиксированы revision, archive SHA-256 и binary SHA-256 для `darwin-arm64`, `linux-arm64`, `windows-amd64`.
- [~] Проверять checksum до запуска.
- [x] Уточнить fail-closed диагностику: автоматически принимать только recommended pinned версию
  strategy; различать mismatch pinned артефакта (включая возможную неподдерживаемую версию) и
  отсутствие pin для OS/arch, не доверяя `engine version` выводу как security oracle (issue #5).
- [x] Завершить declared matrix pinned binary checksums для Xray-core и sing-box: macOS arm64/x86_64,
  Linux arm64/x86_64 и Windows x86_64; доказать archive/binary SHA-256 официальных release assets,
  показывать отсутствие иных targets через `pinned-releases` и покрыть matrix contract test (issue #3).
- [x] Ввести versioned engine catalog и maintainer-only offline updater (issue #9): отделить
  configuration dialect от release identity, проверять lifecycle и checksum/matrix invariants без
  сети и не открывать user-selectable version до compatibility contract.
- [x] Выразить compatibility contract release/dialect (issue #11): Xray `v26.3.27`/`XrayV26` и
  sing-box `v1.13.18`/`SingBoxV1_13` проходят typed fail-closed gate до start.
- [x] Определить безопасный путь временной/runtime конфигурации и permissions.
- [x] Удалять runtime secrets после остановки.

### 2.3. Process/engine supervisor

- [x] Есть базовый `spawn` и принудительный `kill`.
- [x] Ввести state machine `Stopped/Starting/Ready/Stopping/Failed`.
- [x] Асинхронно читать stdout/stderr, не допуская заполнения pipe.
- [x] Реализовать readiness probe с timeout.
- [x] Добавить graceful stop и forced-kill fallback.
- [ ] Добавить bounded restart policy и circuit breaker.
- [x] Обрабатывать самопроизвольное завершение child.
- [x] Гарантировать cleanup runtime config.

### 2.4. Local proxy integration test

- [x] Проверять доступность локальных портов до старта движка (защита от ложного readiness при занятом порте).
- [x] Выполнять pre-flight валидацию конфигурации через CLI движка (`xray run -test -c`).
- [~] Поднять контролируемый VLESS Reality test server/fixture.
- [~] Запустить engine через supervisor.
- [~] Проверить HTTP и SOCKS TCP запрос через tunnel.
- [ ] Проверить UDP/QUIC отдельно, если входит в MVP capability.
- [ ] Проверить неверный key, недоступный endpoint и timeout.
- [ ] Измерить latency/throughput baseline.

### 2.5. CLI поверх core

- [x] Реализовать foreground-команды `start`/`connect`, `validate`/`check`, `status`, `pinned-releases`, `--help`, `--version` поверх `ProxyService` с проверяемыми exit codes.
- [x] Загружать `config.json`/`settings.json` с диска и вызывать `validate()` на пути загрузки.
- [x] Показывать состояние сервиса, PID, активный профиль и локальные порты при запуске.
- [x] Добавить `--engine-config xray|sing-box`: по умолчанию Xray, явный выбор формата
  конфигурации и pre-flight команды, usage error для неизвестного значения и тесты mapping
  CLI → `ProxyServiceOptions` (issue #4).
- [x] Добавить `--engine-version <VERSION>` для выбора catalogued версии выбранного движка:
  recommended/supported разрешены, deprecated предупреждает до старта, yanked/unknown/
  incompatible версии отклоняются до binary/checksum/preflight (issue #13).
- [x] Добавить platform helper IPC contract skeleton: typed handshake, capability report,
  allowlisted commands/events и bounded validation без launchd/root/IPC transport/network mutation
  (issue #15).
- [ ] Реализовать удалённое управление `disconnect`/`stop` через persistent daemon/helper IPC (Milestone 3 / ADR-003).
- [ ] Опционально включать системный прокси (`networksetup`) как временный режим до появления TUN.

Критерий завершения фазы: автоматизированный тест проходит через реальный локальный SOCKS/HTTP proxy к контролируемой цели и корректно останавливает engine без зависших процессов, а CLI позволяет проверить core на реальной пользовательской подписке без GUI.

---

## Фаза 3. Реализовать macOS network data plane

Цель: превратить локальный proxy vertical slice в системный VPN.

### 3.1. Privileged helper skeleton

- [ ] Создать отдельный привилегированный компонент (`launchd`-демон) согласно ADR-003.
- [ ] Реализовать установку и полную деинсталляцию с административной авторизацией, без ослабления SIP/Gatekeeper.
- [x] Реализовать typed IPC/FFI contract skeleton с Rust core без transport/runtime side effects.
- [x] Добавить protocol/version handshake между компонентами.
- [x] Ограничить команды allowlist и валидировать все аргументы.
- [x] Реализовать `ConnectionState` и serialized helper command executor в Rust core без
  transport/runtime side effects: connect/status/disconnect/recover intents, observed-state mapping,
  transition validation и запрет concurrent connect/disconnect на уровне core skeleton.

### 3.2. Tunnel lifecycle

- [ ] Создать виртуальный interface штатным выбранным API.
- [ ] Настроить IPv4 address, routes и MTU.
- [ ] Настроить IPv6 или безопасно закрыть IPv6 leak до поддержки.
- [ ] Настроить DNS servers/search domains/match domains.
- [ ] Сохранить route к VPN endpoint вне туннеля.
- [ ] Связать packet flow со встроенным TUN движка sing-box.
- [ ] Проверить TCP, UDP, large packets и fragmentation/MTU.

### 3.3. Транзакционное применение сети

- [~] `RouteManager` API существует, но методы no-op.
- [x] Описать `NetworkSnapshot` и `AppliedNetworkState` как pure Rust core contract без OS mutation:
  route/DNS/firewall snapshots, typed operation descriptors, transaction phases, rollback metadata,
  duplicate-key и bounded identifier validation.
- [ ] Сделать connect последовательностью применимых/отменяемых операций.
- [~] Добавить compensation для каждого шага: pure core contract теперь требует rollback metadata и
  explicit `apply_order`, а `rollback_steps_reverse_order()` возвращает compensation plan в обратном
  порядке применения; реальное выполнение rollback ждёт helper/runtime slice.
- [~] Создать recovery journal для восстановления после crash: pure core persistence contract
  записывает и читает typed JSON journal для `NetworkSnapshot` + `AppliedNetworkState` через
  temp-write/fsync/rename, отвергает corrupt/invalid state fail-closed и очищает journal только после
  явной успешной recovery; реальное выполнение rollback ждёт helper/runtime slice.
- [~] Сериализовать concurrent connect/disconnect: core `ConnectionState` executor запрещает
  недопустимые state transitions; runtime/helper-level serialization ждёт IPC transport и real
  network transaction.
- [ ] Сделать повторные команды идемпотентными.

### 3.4. Проверки data plane

- [ ] Проверить внешний IP через tunnel.
- [ ] Проверить route к endpoint без loop.
- [ ] Проверить DNS resolver и отсутствие fallback leak.
- [ ] Проверить IPv4/IPv6 matrix.
- [ ] Проверить Wi-Fi reconnect, sleep/wake и смену сети.
- [ ] Проверить captive portal сценарий.

Критерий завершения фазы: весь системный трафик тестового Mac проходит через tunnel; disconnect и failure возвращают исходные routes/DNS.

---

## Фаза 4. Реальное domain/IP split tunneling

Цель: связать policy model с engine и системной маршрутизацией.

### 4.1. Policy model

- [~] Есть типизированный `mode` (`SplitTunnelMode`) и правила `direct_domains`, `direct_ips`, `direct_apps`.
- [x] Exact/suffix domain matcher защищён от частичных false positives.
- [~] `geosite:category-ru` имитируется правилом `.ru`; `geoip:private` поддерживает loopback и RFC 1918.
- [ ] Интегрировать полноценную базу GeoIP (страны, `geoip:ru`, префиксы) и версионированные GeoIP/GeoSite датасеты.
- [ ] Реализовать типы DomainRule, IpNetRule, GeoRule, AppRule и RuleAction.
- [ ] Реализовать precedence и conflict diagnostics.
- [ ] Добавить effective-policy preview.
- [ ] Версионировать GeoIP/GeoSite dataset и обновления.

### 4.2. Policy compiler

- [ ] Компилировать domain/geosite rules в engine routing.
- [ ] Компилировать IP/CIDR/geoip в engine и OS route rules.
- [ ] Явно исключать local/private networks по настройке.
- [ ] Не допускать endpoint, DNS или control channel routing loop.
- [ ] Проверять output schema и semantic conflicts.
- [ ] Реализовать hot reload либо документированный reconnect, но не скрытый частичный reload.

### 4.3. Packet-level verification

- [ ] Проверить direct domain по наблюдаемому egress IP.
- [ ] Проверить proxied domain по наблюдаемому egress IP.
- [ ] Проверить IP/CIDR без DNS.
- [ ] Проверить CNAME, cached DNS, DoH/DoT ограничения и QUIC.
- [ ] Проверить local LAN exceptions.
- [ ] Проверить policy после reconnect и hot reload.

Критерий завершения фазы: domain/IP правила подтверждены реальным сетевым поведением, а не результатом matcher unit test.

---

## Фаза 5. Per-app split tunneling research и реализация

Цель: не обещать per-app routing, пока он не доказан на macOS consumer use case.

### 5.1. Исследовательский spike

- [ ] Проверить правила движка `process_name`/`process_path` на реальном трафике macOS.
- [ ] Проверить `package_name` на Android и эквивалент на Windows.
- [ ] Проверить attribution для TCP и UDP средствами движка.
- [ ] Измерить attribution race и поведение короткоживущих flows.
- [ ] Проверить browser helpers, XPC services, QUIC и shared sockets.
- [ ] Проверить permissions и App Store/direct distribution совместимость.
- [ ] Сформировать failure modes и privacy impact.

### 5.2. Gate: решение о scope

- [ ] Если механизм надёжен — принять ADR-005 и перейти к реализации.
- [ ] Если механизм ограничен MDM или ненадёжен — перенести per-app routing после MVP.
- [ ] Обновить UI так, чтобы он не показывал неподдерживаемую возможность.

### 5.3. Реализация при положительном решении

- [~] Строковый `match_app` существует как чистая policy функция.
- [ ] Транслировать `direct_apps` в правила движка и нормализовать: движок сопоставляет имя и путь исполняемого файла, а не bundle identifier.
- [ ] Создать AppIdentity: bundle ID, signing identity, executable path и process metadata.
- [ ] Сканировать установленные `.app` безопасным системным способом.
- [ ] Связать flow attribution с policy decision.
- [ ] Кешировать только с корректной invalidation strategy.
- [ ] Обрабатывать app update, helper processes и удаление приложения.
- [ ] Добавить live flow evidence и redacted diagnostics.
- [ ] Провести packet-level per-app тесты минимум для Safari/Chrome/Telegram/helper process.

Критерий завершения фазы: разные приложения одновременно дают доказуемо разные egress paths без случайных direct leaks.

---

## Фаза 6. Kill switch, DNS safety и crash recovery

Цель: сделать failure безопаснее обычного отключения VPN.

### 6.1. Kill switch

- [ ] Определить allowlist control-plane traffic.
- [ ] Реализовать deny state до изменения default route.
- [ ] Сохранять защиту при engine crash/reconnect.
- [ ] Не блокировать recovery/update без явного плана.
- [ ] Проверить disable/uninstall cleanup.

### 6.2. DNS safety

- [ ] Проверить системный resolver до/во время/после tunnel.
- [ ] Реализовать split DNS policy.
- [ ] Обработать IPv6 resolver и fallback.
- [ ] Очистить/обновить cache только поддерживаемым способом.
- [ ] Добавить DNS leak test с контролируемыми authoritative servers.

### 6.3. Recovery matrix

- [ ] Normal disconnect.
- [ ] Engine process crash.
- [ ] NetworkExtension/helper crash.
- [ ] UI crash.
- [ ] SIGTERM/forced quit.
- [ ] Mac sleep/wake.
- [ ] Wi-Fi interface change.
- [ ] Reboot во время active tunnel.
- [ ] Ошибка на каждом шаге connect transaction.
- [ ] Следующий запуск с незавершённым recovery journal.

Критерий завершения фазы: автоматизированные негативные тесты не оставляют route/DNS/firewall residue и не допускают незаявленный direct fallback.

---

## Фаза 7. Нативный macOS UI

Цель: дать пользователю минимальный, честный и системно интегрированный интерфейс.

### 7.1. UI architecture spike

- [x] Доказать минимальный arm64 Swift → Rust → typed event roundtrip через C ABI в изолированном
  `spikes/macos-rust-ffi-spike/` (issue #9).
- [~] Зафиксировать предложение по UI в [ADR-001](../docs/ADR-001-MACOS-UI.md) со статусом `Proposed`
  (runtime требует Gate B).
- [ ] Измерить cold launch, idle memory и idle CPU.
- [ ] Проверить menu bar, notifications, accessibility и dark/light mode.
- [ ] Зафиксировать FFI ownership, threading и error mapping.

### 7.2. App shell

- [ ] Создать SwiftUI app target для arm64.
- [ ] Реализовать menu bar item и основное окно.
- [ ] Реализовать application lifecycle и single-instance behavior.
- [ ] Реализовать launch-at-login через поддерживаемый API.
- [ ] Добавить localization RU/EN.

### 7.3. Connection screen

- [ ] Connect/disconnect action.
- [ ] Observed state machine и progress steps.
- [ ] Active profile summary.
- [ ] Последняя безопасная ошибка и recovery action.
- [ ] Traffic counters и небольшой low-frequency chart без собственного Metal renderer.

### 7.4. Profile management

- [ ] List/add/edit/delete/activate profile.
- [ ] До production profile editor зафиксировать protocol profile extensibility contract:
  `ProtocolType` как typed discriminator, protocol-specific fields через schema/metadata, UI/helper/IPC
  без assumptions «профиль всегда VLESS».
- [ ] VLESS URI paste/QR import с preview.
- [ ] Рендерить VLESS editor как первый protocol-specific view поверх общего profile model, чтобы
  Trojan/Shadowsocks/Hysteria2/TUIC/WireGuard/VMess добавлялись без переписывания VLESS path.
- [ ] Inline validation без отображения secrets.
- [ ] Keychain integration.
- [ ] Import/export с redaction controls.

### 7.5. Split-tunneling editor

- [ ] Domain/IP/CIDR rules и effective-policy preview.
- [ ] Conflict/error explanation.
- [ ] Geo dataset version/update status.
- [ ] App selector только если Phase 5 прошла gate.

### 7.6. Diagnostics and settings

- [ ] DNS, kill switch, notifications и reconnect settings.
- [ ] Engine/app/rules versions.
- [ ] Redacted logs и diagnostic export preview.
- [ ] Repair network state action.
- [ ] Permissions and entitlement guidance.

Критерий завершения фазы: пользователь выполняет весь MVP flow без CLI; VoiceOver и keyboard navigation проходят ручной checklist.

---

## Фаза 8. Полная стратегия тестирования

Цель: перейти от тестов чистой логики к доказательству реального VPN поведения.

### 8.1. Unit/property/fuzz

- [x] Unit tests конфигурации, VLESS parser, matcher и generator.
- [ ] Property tests для domain/CIDR precedence и config migrations.
- [ ] Fuzz targets для URI, JSON и policy compiler.
- [ ] Deterministic state-machine tests.

### 8.2. Contract tests

- [ ] JSON Schema ↔ Rust model compatibility.
- [~] Rust FFI ↔ Swift ABI/version compatibility: синхронный ABI v1 roundtrip доказан issue #9;
  version-range handshake, incompatible-version tests и production ownership/threading отсутствуют.
- [ ] Rust core ↔ Windows IPC schema/version/capability compatibility.
- [ ] Generated config ↔ real engine validation.
- [ ] UI command ↔ application-state transition.

### 8.3. Integration/system tests

- [ ] Controlled VLESS Reality server fixture.
- [ ] Full-tunnel TCP/UDP/DNS tests.
- [ ] Domain/IP split egress tests.
- [ ] Per-app egress tests, если feature принята.
- [ ] Leak tests: DNS, IPv6, route bypass.
- [ ] Recovery fault-injection matrix.
- [ ] Sleep/wake and network-change tests.
- [ ] Повторить применимые system tests на controlled Windows 11 после Windows phases 11—15.

### 8.4. UI/release tests

- [ ] Swift unit/UI tests.
- [ ] Accessibility audit.
- [ ] Clean-machine install/uninstall.
- [ ] Signed `.app`/`.dmg` smoke test.
- [ ] Notarization and Gatekeeper verification.
- [ ] Upgrade and rollback test.

Критерий завершения фазы: все quality gates из [TESTING.md](../docs/TESTING.md) зелёные на release candidate.

---

## Фаза 9. Security, privacy и supply chain

### 9.1. Threat model

- [ ] Активы: credentials, network traffic, privileged state, update channel.
- [ ] Trust boundaries: platform UI, Rust core, macOS extension/helper, Windows Service/network
  boundary, engine, config files, installer/update server.
- [ ] Атаки: command injection, malicious config/URI, binary replacement, DNS leak, downgrade, log leakage.
- [ ] Mitigations и residual risks.

### 9.2. Privilege and secrets

- [ ] Минимальные entitlements.
- [ ] Allowlisted typed privileged operations.
- [ ] Keychain and memory-lifetime policy.
- [ ] Zero-secret logging tests.
- [ ] Secure diagnostics export.

### 9.3. Supply chain

- [ ] Pin dependencies and engine revision.
- [ ] SBOM.
- [ ] License inventory.
- [ ] Vulnerability audit.
- [ ] Reproducible/checksummed artifacts.
- [ ] Signed update metadata и anti-rollback policy.

Критерий завершения фазы: threat model reviewed; high-risk findings закрыты; release artifacts traceable до source revisions.

---

## Фаза 10. Packaging и первый production release

### 10.1. Build pipeline

- [ ] Согласовать Cargo + Xcode build orchestration.
- [ ] Создать arm64 Release configuration.
- [ ] Встроить engine/rules artifacts выбранным безопасным способом.
- [ ] Добавить deterministic versioning.
- [ ] Архивировать symbols для crash diagnosis.

### 10.2. Signing и notarization

- [ ] Hardened Runtime.
- [ ] Developer ID certificates в защищённом CI.
- [ ] Подписать nested code в правильном порядке.
- [ ] Notarize и staple ticket.
- [ ] Проверить `codesign`, `spctl` и установку на чистом Mac.

### 10.3. Release readiness

- [ ] Privacy policy и список сетевых данных.
- [ ] User guide: install/connect/split/recovery/uninstall.
- [ ] Known limitations, включая per-app status.
- [ ] Support bundle и issue template.
- [ ] Rollback release.
- [ ] Staged rollout и stop conditions.

Критерий завершения фазы: подписанное и notarized приложение проходит MVP acceptance criteria из `SPEC_RU.md` на чистом Apple Silicon Mac.

---

## Фаза 11. Windows decision package

Цель: после первого стабильного macOS-релиза выбрать проверяемую Windows architecture до product code.

### 11.1. Product и compatibility baseline

- [ ] Зафиксировать минимальную поддерживаемую Windows 11 build/edition и `x86_64-pc-windows-msvc`.
- [ ] Отдельно записать Windows ARM64 как future decision, не скрытое требование.
- [ ] Определить supported protocols/features первого Windows release, равные macOS там, где это
  доказуемо, и platform-specific capability gaps.
- [ ] Создать Windows threat model: user UI, SCM service, IPC, engine, network stack, installer/update.

### 11.2. Network topology spike

- [ ] Сравнить WFP user-mode filters/callouts, Wintun/TUN и engine-specific integration.
- [ ] Для каждого варианта проверить full tunnel, DNS, IPv4/IPv6, endpoint exclusion и split policy.
- [ ] Измерить необходимость driver/kernel code, signing, admin consent, reboot и update impact.
- [ ] Определить ownership firewall/WFP filters и collision behavior с Windows Firewall/другими VPN.
- [ ] Выполнить snapshot → test mutation → compensation → semantic diff на controlled Windows 11.
- [ ] Зафиксировать topology в отдельном ADR; без него остановить Windows network implementation.

### 11.3. Service и IPC spike

- [ ] Создать минимальную test Windows Service, управляемую SCM.
- [ ] Выбрать минимальный service account/privileges и service ACL.
- [ ] Спроектировать authenticated local IPC и caller authorization.
- [ ] Добавить version/capability handshake, command allowlist, bounds и replay/idempotency rules.
- [ ] Проверить service crash, forced stop, UI crash и несовместимую версию contract.
- [ ] Запретить raw command line, arbitrary filesystem paths и shell interpolation.

### 11.4. Native UI и distribution spike

- [ ] Проверить WinUI 3 shell + Rust roundtrip; сравнить WPF/Win32 только если spike не проходит gates.
- [ ] Проверить tray, single-instance, accessibility, high contrast, DPI и localization.
- [ ] Измерить cold launch, idle memory/CPU и wakeups.
- [ ] Сравнить MSIX/Store signing и signed MSI/EXE direct distribution.
- [ ] Определить install/update/rollback/uninstall ownership для app, service, engine и rules.
- [ ] Не добавлять production signing credentials в pull-request CI.

Критерий завершения фазы: приняты Windows topology/distribution/service ADR; controlled Windows 11
PoC доказывает typed IPC, минимальные privilege и восстановление test network mutation.

---

## Фаза 12. Windows full-tunnel vertical slice

### 12.1. Platform adapter и service

- [ ] Создать `novaray-platform-windows` без дублирования core policy.
- [ ] Реализовать install/start/stop/upgrade service lifecycle.
- [ ] Реализовать versioned IPC commands/events и observed state.
- [ ] Интегрировать engine artifact validation, readiness, log drain и graceful stop.

### 12.2. Transactional network state

- [ ] Снимать adapters, IPv4/IPv6 routes, DNS, firewall/WFP filters и service/process snapshot.
- [ ] Создать durable recovery journal до первой mutation.
- [ ] Применять tunnel/interface, MTU, routes и DNS выбранными API.
- [ ] Сохранять endpoint/control-channel path вне tunnel.
- [ ] Добавить compensation для каждого side effect и идемпотентный recovery следующего запуска.

### 12.3. Real system evidence

- [ ] Проверить full-tunnel TCP/UDP и DNS на controlled endpoints.
- [ ] Проверить IPv4/IPv6 или safe IPv6 block.
- [ ] Проверить repeated connect/disconnect, network change, sleep, reboot и service restart.
- [ ] Проверить отсутствие route/DNS/firewall/WFP/process residue.

Критерий завершения фазы: controlled Windows 11 выполняет реальный full tunnel и возвращается к
ожидаемому baseline после disconnect/failure.

---

## Фаза 13. Windows split tunneling, kill switch и recovery

### 13.1. Общая policy на Windows

- [ ] Использовать общие typed domain/IP/CIDR rules, precedence и golden fixtures.
- [ ] Компилировать policy в выбранные engine/Windows primitives.
- [ ] Проверить direct/proxy egress для domains, IPv4/IPv6 CIDR, CNAME/cache и local networks.
- [ ] Реализовать effective-policy/capability diagnostics.

### 13.2. Failure safety

- [ ] Реализовать Windows kill-switch state machine и control-plane allowlist.
- [ ] Проверить DNS и IPv6 leaks при connect/reconnect/crash.
- [ ] Inject failures в engine, service, IPC и каждый connect/rollback step.
- [ ] Проверить reboot/upgrade/uninstall с активным tunnel.
- [ ] Не удалять неизвестные user firewall/WFP rules при recovery.

### 13.3. Per-app decision

- [ ] Провести отдельный Windows attribution/enforcement spike.
- [ ] Проверить process identity, services/helpers, browsers, UDP/QUIC и races.
- [ ] Принять отдельное решение: реализовать доказуемо или исключить из Windows release UI.

Критерий завершения фазы: packet-level split evidence и failure matrix подтверждают safe block или
чистый rollback; matcher-only tests не принимаются.

---

## Фаза 14. Нативный Windows UI

- [ ] Создать native shell по принятому ADR; текущая рекомендация — WinUI 3.
- [ ] Реализовать tray, main window, single-instance и launch-at-login lifecycle.
- [ ] Показывать observed service/tunnel state и compatibility/capability errors.
- [ ] Реализовать profiles, VLESS import preview и credential storage.
- [ ] Реализовать domain/IP editor, effective-policy preview и conflict diagnostics.
- [ ] Добавить settings, redacted logs, diagnostic export и safe network recovery action.
- [ ] Добавить RU/EN, keyboard/screen-reader, high contrast, DPI и dark/light mode.
- [ ] Проверить launch/idle resource budgets; custom Metal/DirectX renderer для такого UI не нужен.

Критерий завершения фазы: весь Windows user flow выполняется без terminal и постоянного elevation; UI
не объявляет `Connected` до observed service/network evidence.

---

## Фаза 15. Windows packaging и production release

- [ ] Собрать versioned app/service/engine/rules artifacts и symbols.
- [ ] Выполнить SBOM, license/vulnerability audit и закрыть high threat-model findings.
- [ ] Подписать binaries/service/installer выбранным production path.
- [ ] Проверить install/service registration на clean Windows 11 x64.
- [ ] Проверить update, downgrade protection, rollback и uninstall без network/service residue.
- [ ] Выполнить L0—L8, leak/fault/performance и compatibility regression suite.
- [ ] Подготовить user/recovery/privacy docs, support bundle и staged rollout stop conditions.

Критерий завершения фазы: все Windows acceptance criteria из `SPEC_RU.md` подтверждены evidence bundle
на clean Windows 11 x64 machine.

---

## Фаза 16. После двух desktop-релизов и отдельные продукты

- [ ] Создать отдельный Android product/repository с Kotlin/Jetpack UI и Android `VpnService`.
- [ ] Публиковать для Android только versioned shared Rust crates/schemas/fixtures с compatibility tests.
- [ ] Intel/universal macOS и Windows ARM64 builds при подтверждённом спросе.
- [ ] Linux network backend и packaging.
- [ ] Проверить, что pre-UI protocol-extensible core/UI/helper boundary сохранён: новые протоколы добавляются через
  typed profile/schema/importer/generator/capability slices, без переписывания VLESS path.
- [ ] Trojan + TLS отдельным vertical slice: schema/importer/validation/generator/preflight/real traffic.
- [ ] Shadowsocks AEAD/2022 отдельным vertical slice.
- [ ] Hysteria 2 отдельным UDP/QUIC-heavy vertical slice с leak/MTU/DNS evidence.
- [ ] TUIC отдельным UDP/QUIC-heavy vertical slice.
- [ ] WireGuard отдельной VPN-profile family: keys, addresses, peers, allowed IPs, DNS/routing и recovery.
- [ ] VMess только как legacy compatibility slice с documented warning.
- [ ] Debug/enterprise outbounds (`socks`, `http`, `ssh`) только с explicit user intent и redaction review.
- [ ] Optional telemetry только с privacy spec и explicit opt-in.
- [ ] Advanced rules, subscriptions и managed configuration.

Каждый новый protocol/OS проходит: schema → capability → real network tests → recovery → signed package.

---

## Критический путь двух desktop-релизов

```text
ADR distribution/network/engine
→ harden config and errors
→ real local VLESS connection
→ system tunnel and DNS
→ domain/IP split tunneling
→ kill switch and recovery
→ SwiftUI + Rust integration
→ packet/leak/fault tests
→ signing and notarization
→ macOS release
→ Windows topology/service/distribution ADR
→ Windows full tunnel
→ Windows domain/IP split + failure safety
→ Windows native UI
→ Windows signed package + clean-machine verification
→ Windows release
```

Per-app routing идёт отдельной веткой после research gate и не должен маскировать отсутствие базового надёжного VPN.
