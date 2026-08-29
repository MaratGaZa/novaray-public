# ADR-003: Топология сетевого уровня macOS

- Статус: Proposed
- Дата: 2026-08-16
- Ревизия: 2026-08-17 — основной путь пересмотрен в пользу privileged helper + utun после фиксации ограничения по Apple Developer Program
- Ревизия: 2026-08-29 — установка/деинсталляция helper выделена в pre-runtime Gate I; это разрешает следующий reversible install-slice без утверждения `utun`/data-plane топологии
- Ревизия: 2026-08-29 — threat model root-helper runtime зафиксирован как docs-only prerequisite перед Gate H
- Ревизия: 2026-08-29 — runtime replay guard scope зафиксирован per authenticated session/connection
- Ревизия: 2026-08-29 — runtime sequence contract ужесточён до exact next sequence
- Решение требуется до: реализации системного туннеля и раздельного туннелирования по приложениям (M3)

## Контекст

NovaRay реализует системный VPN/туннель на macOS с поддержкой полного и раздельного (split-tunneling) туннелирования трафика.

Владелец продукта зафиксировал 2026-08-17 ограничение: **платное членство Apple Developer Program не приобретается**, поскольку продукт некоммерческий. Это ограничение является входным для данного ADR, а не предметом обсуждения в нём.

Архитектура сетевого слоя macOS должна удовлетворять следующим требованиям:
1. Возможность перехвата и маршрутизации IP-пакетов (IPv4/IPv6) на уровне системы.
2. Минимальный практически достижимый уровень привилегий при данном ограничении.
3. Надежность и автоматическая очистка: падение или завершение процесса не должно приводить к «зависанию» маршрутов и блокировке сети (Network Blackhole).
4. Соответствие официальным стандартам и политикам безопасности Apple (SIP, Notarization, Hardened Runtime, TN3134) без ослабления системной безопасности.

## Проверенные факты

1. Entitlement `com.apple.developer.networking.networkextension` выдаётся только в рамках Apple Developer Program и связан с App ID и provisioning profile (см. [ADR-002](./ADR-002-MACOS-DISTRIBUTION.md), проверенные факты 1–3). Бесплатный Apple Account его не предоставляет ни на каких условиях.
2. Создание виртуального интерфейса `utun` выполняется через `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` с control name `com.apple.net.utun_control` и **требует прав `root`, но не требует Apple entitlement**. Этим механизмом пользуются распространяемые вне App Store клиенты (sing-box, wireguard-go, tun2socks).
3. Штатная установка привилегированного helper через `SMJobBless` требует подписи Developer ID, то есть платного членства. Ручная установка `launchd`-демона в `/Library/LaunchDaemons` через `sudo` не требует подписи и не блокируется SIP.
4. sing-box предоставляет встроенный TUN-слой и правила `process_name`/`process_path` (см. [ADR-004](./ADR-004-ENGINE-INTEGRATION.md), факты 2–3), поэтому собственная реализация packet-обработки и per-app сопоставления не требуется.

## Рассмотренные варианты

| Вариант | Доступен без Apple Developer Program | Уровень привилегий | Сложность и риски | Вывод |
|---|:---:|:---:|:---:|---|
| **Privileged Helper Daemon (`launchd` + `utun` + `pfctl`/`route`)** | **Да** (факты 2–3) | Отдельный `root`-демон, UI без привилегий | Высокая: ручное управление маршрутами, DNS-leak risks, собственный rollback | **Рекомендуется (Proposed)** |
| **Network System Extension (`NEPacketTunnelProvider`)** | Нет (факт 1) | Изолированный системный демон (без root shell) | Средняя | Целевая топология при появлении платного аккаунта; отложено |
| **App Extension (`NEPacketTunnelProvider` в `.appex`)** | Нет | Песочница приложения | Низкая | Запрещено Apple TN3134 для direct distribution |
| **User-space SOCKS5/HTTP Proxy (без TUN)** | **Да** | Обычный пользователь | Низкая | Принят как промежуточный этап M2; не покрывает трафик мимо системного прокси и per-app правила |

## Предлагаемое решение

1. **Основная топология: privileged helper + `utun`.**
   - Системный туннель создаётся движком sing-box, работающим под отдельным `launchd`-демоном с правами `root`.
   - Демон владеет виртуальным интерфейсом `utun`, таблицей маршрутов, DNS-настройками и правилами `pfctl`.
   - UI и Rust Core работают с правами обычного пользователя и никогда не получают `root`.
   - Собственная packet-обработка не реализуется: перехват, маршрутизация и per-app сопоставление выполняются движком (факт 4).

2. **Модель привилегий и безопасность:**
   - Привилегированный компонент принимает **только типизированные allowlisted-операции** от Core: применить снимок конфигурации, поднять/опустить туннель, откатить состояние. Произвольные shell-строки, `route`, `scutil` и `pfctl` как команды через границу не передаются.
   - Каждая мутация маршрутов, DNS и firewall сопровождается снимком предыдущего состояния и транзакционной компенсацией с проверяемым откатом при ошибке, сигнале, падении и следующем запуске.
   - Приложение целиком через `sudo` не запускается.

3. **Связь между приложением и демоном (IPC):**
   - Unix domain socket с проверкой прав доступа; сообщения строго типизированы и ограничены по размеру.
   - Контракт версионируется, handshake выполняется до любой сетевой мутации; несовместимость версий приводит к безопасному отказу до начала connect-транзакции.

4. **Защита от сетевых сбоев (Failure Safety):**
   - Падение демона обязано приводить к восстановлению исходной сетевой конфигурации, а не к «зависшим» маршрутам.
   - Kill switch реализуется правилами `pfctl` и снимается тем же транзакционным механизмом.
   - На этапах разработки захват дефолтного маршрута `0.0.0.0/0` включается только после прохождения тестов отката.

5. **Установка привилегированного компонента:**
   - Без платного аккаунта `SMJobBless` недоступен (факт 3), поэтому демон устанавливается явным административным шагом с запросом пароля и с обратимой деинсталляцией.
   - Ослабление SIP или Gatekeeper как штатный путь установки не допускается.
   - Установка/деинсталляция helper является отдельным pre-runtime gate: её можно реализовать и проверить до запуска `utun`, IPC runtime и сетевых мутаций, но такой evidence не утверждает full-tunnel topology.

## Threat Model Root Helper Runtime

Этот раздел является docs-only prerequisite для Gate H. Он не переводит ADR-003 в `Accepted` и не
доказывает, что persistent IPC, `utun`, маршруты, DNS, firewall, packet flow, DNS-leak protection,
split tunneling или kill switch реализованы.

### Активы

- root-процесс `novaray-platform-helper`;
- LaunchDaemon plist и helper binary в `/Library`;
- IPC endpoint будущего runtime;
- engine configuration, recovery journal и applied-state records;
- route table, DNS settings, firewall/PF rules, system proxy state и `utun` interface;
- пользовательские profile secrets, endpoint addresses, UUID/correlation IDs и diagnostic bundle.

### Trust Boundaries

- UI и обычный Rust core остаются unprivileged и не получают shell/root capability.
- Helper runtime является единственным компонентом, которому разрешены typed privileged operations.
- IPC boundary обязан выполнять handshake по protocol version/capabilities до любой мутации.
- Установочный Gate I boundary отделён от runtime boundary: успешная установка helper не разрешает
  сетевые команды без отдельного Gate H runtime contract.
- External engine process получает только already-validated runtime config и не становится
  источником policy decisions.

### Предполагаемые атакующие возможности

- локальный unprivileged пользователь может посылать malformed/oversized IPC payloads, повторять
  старые сообщения, пытаться угадать correlation IDs и менять файлы в доступных ему каталогах;
- profile/config input может быть злонамеренным, но уже проходит core validation до privileged call;
- helper source/destination paths могут содержать symlink или race attempts до открытия descriptor;
- engine может завершиться, зависнуть или вернуть ошибку после частичного применения network state;
- attacker не считается уже root: при root-компрометации этот boundary не является защитой.

### Обязательные Controls

- IPC принимает только typed allowlisted commands; raw shell strings, arbitrary executable paths и
  произвольные `route`/`scutil`/`pfctl` commands через boundary запрещены.
- Каждая команда несёт bounded payload, protocol version, capability expectations и correlation ID;
  unknown version/command/field/capability отклоняются до side effects.
- Freshness/replay protection не полагается только на correlation ID: runtime commands должны быть
  привязаны к текущей handshake session и иметь exact next sequence/nonce; сообщения вне текущей
  session, с повторной/устаревшей sequence или с forward jump отвергаются до side effects.
- Replay guard state должен быть scoped per authenticated IPC session/connection. Один process-wide
  sequence counter для нескольких клиентов запрещён: независимые session не должны конкурировать за
  sequence, а envelope прошлой session не должен становиться валидным после нового handshake.
- Authorization decision для установки не переносится на runtime commands: runtime обязан иметь
  отдельную authentication/peer-validation модель для локального клиента.
- Любая network mutation начинается только после serialized lifecycle/start gate и pending recovery
  check; параллельные conflicting commands отклоняются.
- Route/DNS/firewall/system proxy changes требуют snapshot, explicit rollback metadata,
  idempotency scope и recovery journal write до применения операции.
- Failure handling обязан быть fail-closed: first error останавливает последующие операции,
  запускает reverse-order rollback или сохраняет диагностируемый recovery work.
- Diagnostics must redact secrets, user IPs, endpoint identifiers and UUID-like correlation values
  unless an explicit debug artifact policy permits disclosure.

### Revisit Conditions

- Gate H failure по rollback, DNS-leak, residual route/firewall state или IPC authentication
  переводит helper runtime implementation обратно в redesign.
- Появление Apple Developer Program заново открывает NetworkExtension path и требует пересмотра
  root-helper threat boundary до acceptance ADR-003.
- Любое расширение allowlist privileged commands требует отдельного SPEC/ADR update и evidence tests
  до реализации.

## Разделение по гейтам готовности (Gates)

- **Gate A (Architecture & Prototype Baseline — Выполнено):**
  - Подтверждена сборка `.app` и встроенного `.systemextension` без ошибок подписи (`CODE_SIGNING_ALLOWED=NO`) на Apple Silicon; спайк остаётся валидным evidence для отложенного пути NetworkExtension.
  - Реализованы Swift 6 strict concurrency, ограниченный IPC, наблюдение за системным статусом `NEVPNStatusDidChange`.
- **Gate I (Helper Install/Deinstall — pre-runtime prerequisite):**
  - Должна быть реализована явная административная установка helper как `launchd`-демона без ослабления SIP/Gatekeeper и без использования `SMJobBless` до появления Developer ID signing.
  - Перед копированием должна проверяться целостность именно открытого helper source handle; установка не должна повторно открывать путь как доказательство тех же байтов.
  - Должна быть доказана обратимая деинсталляция: сначала выгрузить job, затем удалить plist и helper binary; частичные install/uninstall failures должны иметь диагностируемый rollback или stop-state.
  - Scope gate намеренно исключает `utun`, route/DNS/firewall mutation, persistent IPC runtime, packet flow, DNS-leak, split tunneling и kill-switch evidence.
  - Успешный Gate I разрешает переход к helper runtime work, но не переводит ADR-003 из `Proposed` в `Accepted`.
- **Gate H (Helper Runtime — требуется для утверждения этого ADR):**
  - Gate H начинается только после Gate I или эквивалентного documented install/deinstall evidence.
  - Демон создаёт `utun`, поднимает туннель и корректно его снимает.
  - Доказан откат маршрутов, DNS и firewall при штатной остановке, `SIGKILL` демона и перезагрузке.
  - Подтверждено отсутствие DNS-утечек и отсутствие остаточных процессов и правил.
  - Правило per-app направляет трафик выбранного приложения в отдельный outbound на реальном трафике.
- **Gate B (Developer Program & NetworkExtension — отложен):**
  - Активируется только при появлении платного Apple Developer Program.
  - Оформление Provisioning Profile с правом `com.apple.developer.networking.networkextension` и `com.apple.developer.system-extension.install`, runtime-активация туннеля.

## Последствия решения

### Положительные:
- Системный туннель и раздельное туннелирование становятся достижимы без платного Apple Developer Program.
- Топология симметрична целевым платформам: macOS — `launchd`-демон, Windows — служба, Android — `VpnService`; Core и контракт остаются общими.
- Отсутствие зависимости от Apple-специфичного жизненного цикла расширения упрощает переносимость.
- Gate I снижает риск следующей реализации: install/deinstall можно доказать отдельно от `utun` и packet-flow, не выдавая подготовительный privileged lifecycle за готовую сетевую топологию.

### Отрицательные / Риски:
- **`root`-демон — более широкая доверительная граница, чем изолированное системное расширение.** Требования раздела 2 (allowlist, снимки, откат) становятся обязательными, а не желательными.
- Управление маршрутами, DNS и firewall выполняется самостоятельно, поэтому DNS-leak и recovery-тесты обязательны и не заменяются unit-тестами.
- Установка требует административного пароля и явного шага пользователя.
- Раздача готового бинарника вне сборки из исходников остаётся недоступной (см. [ADR-002](./ADR-002-MACOS-DISTRIBUTION.md)).

## Условия пересмотра

- Появление платного Apple Developer Program переводит NetworkExtension из отложенного пути в предпочтительный: доверительная граница уже, а Gate A по нему пройден.
- Отрицательный результат Gate H по откату или DNS-утечкам обязывает вернуться к промежуточному proxy-режиму без системного туннеля.

## Ссылки на источники

- Apple TN3134: Network Extension Provider Deployment: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- Apple NetworkExtension Framework: https://developer.apple.com/documentation/networkextension
- Apple SystemExtensions Framework: https://developer.apple.com/documentation/systemextensions
- Apple Entitlements for Network Extensions: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension
- Apple SMJobBless: https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:)
- Apple TN3165: Packet Filter is not API: https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
- Исходный код спайка: [spikes/macos-networkextension-spike/](../spikes/macos-networkextension-spike/)
