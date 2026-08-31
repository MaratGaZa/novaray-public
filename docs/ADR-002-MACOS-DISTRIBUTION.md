# ADR-002: канал распространения macOS-приложения

- Статус: Proposed
- Дата: 2026-08-16
- Владелец решения: MaratGaZa
- GitHub issue: development task #1
- Следующий review: после entitlement/signing spike на development Mac, но до начала production data plane

## Контекст

NovaRay должен поставляться как нативное приложение macOS 14+ для Apple Silicon. Канал
распространения определяет доступные certificates, provisioning profiles, sandbox, упаковку
`NEPacketTunnelProvider` и допустимый способ интеграции protocol engine.

Сейчас у владельца нет активного членства Apple Developer Program. Это не мешает разработке Rust
core, SwiftUI shell и обычного FFI, но не является evidence для NetworkExtension entitlement,
Developer ID signing или notarization.

## Проверенные факты

Факты ниже проверены 2026-08-16 по первичной документации Apple.

Ревизия 2026-08-31: текущие primary Apple pages по membership, Developer ID certificates и
notarization подтверждают, что Apple Developer Program остаётся границей для distribution,
advanced capabilities и Developer ID path; Developer ID signing + notarization остаются механизмом
trust для Mac software outside Mac App Store. TN3134 не передатируется этой ревизией.

1. Бесплатный Apple Account даёт Xcode, документацию и локальное тестирование. Distribution,
   advanced capabilities, Developer ID и notarization входят в Apple Developer Program.
2. `NETunnelProvider`, `NETunnelProviderManager` и `NEPacketTunnelProvider` требуют entitlement
   `com.apple.developer.networking.networkextension`, связанный с App ID и provisioning.
3. Для приложения вне Mac App Store Apple требует включить Network Extension capability для
   Developer ID App ID, создать provisioning profile и подписать приложение соответствующим
   certificate/profile.
4. Согласно TN3134, packet tunnel provider на macOS как app extension имеет ограничение
   `App Store only`; direct distribution поддерживается при упаковке provider как system extension.
5. Mac App Store требует App Sandbox. Встроенный command-line helper возможен, но должен соблюдать
   sandbox inheritance и signing constraints; это не доказывает совместимость Xray/Sing-box.
6. Direct distribution использует Developer ID. Для распространяемого Developer ID build Apple
   требует notarization, корректную code signature, Hardened Runtime и secure timestamp.
7. `sudo` меняет Unix privileges процесса, но не создаёт Apple entitlement, App ID или provisioning
   profile. Поэтому запуск CLI через `sudo` не подтверждает работоспособность NetworkExtension.

## Выводы из фактов

- Полностью работоспособный системный VPN через выбранный NetworkExtension boundary нельзя честно
  подтвердить только с бесплатным Apple Account.
- Бесплатная стадия всё же полезна: на ней можно реализовать и проверить SwiftUI/AppKit shell,
  menu bar, Rust static library, C ABI roundtrip, state events, mock network boundary и engine
  experiments без заявления о системном VPN.
- Direct distribution оставляет больше свободы для consumer VPN и bundled engine, но для packet
  tunnel на macOS требует system-extension topology и всё равно требует платного membership.
- App Store снимает отдельную notarization submission, но добавляет обязательный sandbox и App
  Review; совместимость выбранного engine должна доказываться отдельно.
- Без Developer ID у локально собранного helper/app нет проверяемого Team ID. Поэтому install-time
  подлинность helper для source-first пути не может опираться на signature/Team ID check и должна
  держаться на `expected_sha256` из install-плана, opened-handle hashing/copy и documented
  source-build provenance. Signature/Team ID verification остаётся отложенной до Developer ID path.

## Предлагаемое решение

Ревизия 2026-08-17. Владелец продукта зафиксировал, что платное членство Apple Developer Program
не приобретается: продукт некоммерческий, и рекуррентная плата за один клиент не оправдана.
Это входное ограничение, а не предмет обсуждения в данном ADR.

Выбрать для первого релиза **распространение исходным кодом (source-first)**: пользователь собирает
приложение локально либо устанавливает его через формулу пакетного менеджера, выполняющую сборку из
исходников.

Source-first путь разрешает личное локальное использование собранного GUI/helper без платного Apple
Developer Program. Он не является раздачей готового подписанного binary artifact другим
пользователям. Документация не должна требовать обход Gatekeeper как штатный install path.

Основание: локально скомпилированный бинарник не помечается атрибутом карантина, поэтому Gatekeeper
не требует нотаризации. Раздача готового `.app`/`.dmg` без Developer ID и нотаризации потребовала бы
от пользователя обходить Gatekeeper вручную, что запрещено разделом «Безопасность и надёжность»
инструкции проекта и поэтому не рассматривается как вариант.

Упаковка network boundary следует [ADR-003](./ADR-003-NETWORK-TOPOLOGY.md): privileged helper
(`launchd` + `utun`) вместо system extension, так как второе требует entitlement из платной
программы.

Direct distribution через Developer ID + notarization сохраняется как **целевая модель при появлении
платного аккаунта** и остаётся описанной в Gate C ниже.

Разделить разработку на gates:

### Gate A — бесплатная локальная разработка

Разрешено:

- собирать Rust core для `aarch64-apple-darwin`;
- создать SwiftUI/AppKit shell, menu bar и developer UI;
- выполнить Swift ↔ Rust C ABI roundtrip и typed state event;
- использовать mock network boundary;
- запускать отдельно помеченный developer-only CLI/engine experiment, включая `sudo`, только с
  snapshot/rollback и без утверждения о NetworkExtension.

Не считается подтверждённым:

- запуск `NEPacketTunnelProvider`;
- установка/активация network system extension;
- Developer ID archive, notarization или распространение готового бинарника;
- реальный system VPN, DNS protection или split tunneling.

### Gate S — source-first release proof (основной путь)

До первого публичного релиза:

1. воспроизводимая сборка из чистого клона на Apple Silicon по документированной инструкции;
2. проверка, что локально собранный бинарник запускается без обхода Gatekeeper пользователем;
3. документированная установка и полная деинсталляция privileged helper по ADR-003;
4. фиксация версий и контрольных сумм загружаемых артефактов движка;
5. legal review совместимости GPL-3.0-or-later и naming restriction sing-box с выбранной моделью
   распространения (см. [ADR-004](./ADR-004-ENGINE-INTEGRATION.md), гейт 9).

Пока Gate S не пройден, ADR-002 остаётся `Proposed`.

### Gate B — development entitlement spike (отложен)

Активируется только при появлении платного Apple Developer Program:

1. создать отдельные explicit App IDs для app и system extension;
2. включить Network Extensions capability и получить подходящие development profiles;
3. подтвердить entitlement в embedded profiles и подписях через `codesign`/`security`;
4. установить и активировать system extension на development Mac;
5. запустить и остановить минимальный packet tunnel;
6. проверить IPv4/IPv6/DNS settings и rollback без production engine;
7. сохранить команды, macOS/Xcode versions и sanitized evidence.

Gate B больше не блокирует production data plane: системный туннель реализуется по ADR-003 через
privileged helper, которому entitlement не нужен.

### Gate C — direct release proof (отложен вместе с Gate B)

Применяется только если появится Developer ID; до release candidate:

1. собрать arm64 archive с минимальными entitlements;
2. подписать все вложенные компоненты в корректном порядке через Developer ID;
3. включить Hardened Runtime и secure timestamp;
4. отправить build через актуальный notarization workflow;
5. staple ticket и проверить `codesign` и `spctl` на чистом Mac;
6. проверить install, update, rollback и uninstall cleanup.

## Альтернативы

### Mac App Store как первый канал

Плюсы: знакомая установка, обновления и App Store trust/discovery; отдельная notarization submission
не нужна. Минусы: обязательный App Sandbox, App Review и app-extension topology; engine embedding и
исполнение необходимо доказать до выбора. Отложено до результата engine spike или изменения
release-целей.

### Одновременный App Store и direct release

Отклонено для первого MVP: два профиля distribution удваивают signing, packaging и verification
matrix до появления первого работающего vertical slice.

### Раздача неподписанного `.dmg` с инструкцией обойти Gatekeeper

Отклонено. Ослабление Gatekeeper как штатный путь установки запрещено разделом «Безопасность и
надёжность» инструкции проекта, а для VPN-клиента, требующего привилегированный компонент, такая
модель распространения недопустима отдельно.

### Privileged helper как production-топология

Ранее было отклонено как production default в пользу system extension. Ревизией 2026-08-17 решение
изменено: при отсутствии платного членства system extension недоступен, и helper становится
единственным путём к системному туннелю. Требования threat model, typed allowlist, installation
authorization и transactional rollback перенесены в [ADR-003](./ADR-003-NETWORK-TOPOLOGY.md) и
остаются обязательными.

## Последствия

Положительные:

- первый релиз не зависит от платного членства и рекуррентных расходов;
- отсутствие обязательного App Store sandbox для основной оболочки;
- отсутствие signing/notarization matrix в CI до появления Developer ID;
- честное разделение бесплатной разработки и entitlement-dependent evidence.

Отрицательные:

- **аудитория ограничена пользователями, готовыми собрать проект из исходников**; готовый бинарник
  не распространяется;
- обновления не автоматизированы средствами Apple и выполняются пересборкой;
- отсутствие подписи усложняет проверку подлинности сборки конечным пользователем;
- privileged helper требует административного пароля при установке;
- GPL-3.0-or-later движка накладывает дополнительные требования на любую будущую бинарную раздачу.

## Stop conditions

Остановить зависимую production-реализацию и вернуть решение на review, если:

- Network Extension capability/profile нельзя получить для App ID;
- packet tunnel system extension не активируется на development Mac;
- выбранный engine нельзя безопасно встроить или связать с system extension;
- connect/disconnect spike оставляет network residue;
- Developer ID archive не проходит signing/notarization verification.

## Rollback и условия пересмотра

ADR можно отклонить без миграции пользовательских данных, пока production targets не созданы.
Пересмотреть решение необходимо после ADR-003/ADR-004 spikes, при обязательном App Store требовании
или если direct system-extension topology несовместима с engine. Замена оформляется новым ADR либо
статусом `Superseded` со ссылкой, а не переписыванием исторического решения.

## Ссылки

- [Apple: Choosing a Membership](https://developer.apple.com/support/compare-memberships/)
- [Apple: Supported capabilities for macOS](https://developer.apple.com/help/account/reference/supported-capabilities-macos)
- [Apple: Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [Apple: Configuring network extensions](https://developer.apple.com/documentation/xcode/configuring-network-extensions)
- [Apple TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Apple: App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [Apple: Embedding a command-line tool in a sandboxed app](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app)
- [Apple: Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)
- [Apple: Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
