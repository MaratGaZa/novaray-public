# ADR-009: macOS helper runtime authentication

- Статус: Proposed
- Дата: 2026-09-04
- Владелец решения: MaratGaZa
- GitHub issue: #78
- Следующий review: перед реализацией live Gate H IPC, при переходе к App Sandbox или при появлении
  Developer ID/стабильного Team ID

## Контекст

ADR-003 выбирает root-owned `launchd` helper и Unix domain socket как целевой macOS runtime
boundary. Уже существующий handshake проверяет protocol version/capabilities, а per-connection
session guard защищает exact sequence от replay. Ни handshake, ни `session_id`, ни sequence, ни
correlation ID не доказывают, кто открыл соединение.

Source-first build из ADR-002 не имеет стабильного Developer ID/Team ID. Проверка владельца socket и
effective UID peer отделяет другие локальные аккаунты, но любой процесс того же UID может открыть
разрешённый socket. Перед live IPC нужен отдельный admission contract, который не принимает identity
из payload и не переносит install authorization на runtime автоматически.

## Проверенные факты

Факты ниже сверены 2026-09-04 с macOS 15.7 `getpeereid(3)`, установленным MacOSX 26.2 SDK и
первичной документацией Apple.

1. `getpeereid` возвращает effective UID/GID peer уже соединённого Unix `SOCK_STREAM`; credentials
   фиксируются kernel в момент `connect`/`listen` и не задаются полями сообщения.
2. Authorization Services позволяет приложению запросить named right, экспортировать
   `AuthorizationRef` через `AuthorizationExternalForm`, а helper — восстановить reference и
   проверить right перед privileged operation.
3. External authorization form является bearer capability: Apple прямо предупреждает, что любой
   процесс, получивший её bytes, может использовать связанную authorization reference. Её нельзя
   логировать, сохранять как конфигурацию или передавать по незащищённой границе.
4. `AuthorizationRightSet` создаёт или обновляет explicit named right в policy database; wildcard
   right names не допускаются. Поэтому отсутствие или неожиданная policy definition не должно
   молча заменяться более широким встроенным правом.
5. Authorization Services не поддерживается в App Sandbox. Текущий source-first путь уже использует
   non-sandboxed app/helper topology; переход к sandbox требует пересмотра этого ADR.
6. Security framework умеет получать running-code object по audit token и проверять code
   requirement. Без Developer ID текущий проект не имеет стабильного Team ID, поэтому такую проверку
   нельзя выдавать за доступную source-first identity guarantee.

## Выводы из фактов

- Socket permissions и kernel UID/GID являются обязательным первым фильтром, но не аутентификацией
  конкретного NovaRay-процесса внутри одного пользовательского аккаунта.
- Authorization right может разрешить privileged capability без доверия к присланному PID/UID, но
  external form должна обрабатываться как secret и повторно проверяться непосредственно перед
  мутацией, потому что права имеют session/time limits.
- Code-signature binding по audit token полезен как будущий дополнительный слой после появления
  Developer ID, но не заменяет source-first модель сейчас.

## Предлагаемое решение

Для source-first Gate H использовать layered admission для каждого нового IPC connection:

1. Helper получает effective UID/GID только из connected Unix socket. Ожидаемый numeric client UID
   выбирается явным административным install/bootstrap шагом и хранится в root-owned configuration;
   UID/GID/PID из payload игнорируются. Mismatch или ошибка credential inspection закрывает
   соединение до parsing privileged commands.
2. Первый bounded authentication frame несёт opaque `AuthorizationExternalForm` для fixed right
   `org.novaray.platform-helper.runtime`. UI получает этот right через Authorization Services с
   разрешённым пользовательским interaction; helper никогда не показывает authentication UI.
   Install/runtime-bootstrap создаёт exact right definition только если right отсутствует, принимает
   exact idempotent match и fail closed при уже существующей другой policy вместо её перезаписи.
   Uninstall удаляет right только если definition всё ещё совпадает с owned policy; чужое изменение
   сохраняется и возвращается как diagnostic stop-state. Policy, rollback и cleanup проверяются
   отдельным privileged spike до live IPC.
3. Helper восстанавливает authorization reference и проверяет exact named right через
   `AuthorizationCopyRights` с default flags: без interaction, extend или partial-right acceptance.
   Ошибка, отсутствие, неверный размер, истёкшее/отозванное право или peer mismatch отклоняют
   connection до создания runtime session и до любых side effects.
4. После peer/authentication checks выполняется version/capability handshake. Только helper создаёт
   cryptographically unpredictable `session_id`; client-supplied session identity не принимается как
   источник доверия. Затем действуют существующие exact-sequence и allowlist contracts.
5. Для каждой mutating command порядок остаётся fail-closed: bounded parse → rights recheck без
   interaction → envelope/sequence validation → side effect. Отказ authorization не потребляет
   sequence как успешно принятую команду, не выполняет side effects и закрывает connection либо
   переводит её в диагностируемое denied state.
6. External form/reference живёт не дольше connection, не пишется на диск, не попадает в обычный или
   debug log и не включается в diagnostics. Ошибки раскрывают только стабильную категорию и стадию.
7. При появлении Developer ID admission дополнительно проверяет running peer по kernel-derived audit
   token и pinned code requirement/Team ID. Это отдельный hardening gate, не выполненный данным ADR.

Correlation ID, session ID, sequence, socket path secrecy и file permissions не считаются
authentication factors. Они остаются diagnostics, freshness и defense-in-depth controls.

## Альтернативы

### Только socket mode + `getpeereid`

Отклонено как полная authentication model: другой UID блокируется, но произвольный процесс
разрешённого UID неотличим от NovaRay UI/core.

### Shared secret в пользовательском файле

Отклонено: процесс того же UID обычно может прочитать тот же файл. Перенос секрета в Keychain без
стабильного code requirement не даёт требуемой process identity и добавляет собственную ACL/prompt
модель.

### Только code signature / Team ID

Отложено до Developer ID. Ad-hoc/source-first подпись не является стабильной publisher identity для
всех локально пересобранных binaries.

### Authorization один раз при установке

Отклонено: install authorization разрешает изменение `/Library`, но не является бессрочным
разрешением любых будущих network mutations. Runtime проверяет отдельный named right.

## Последствия

Положительные:

- другой пользователь и same-UID процесс без authorization capability отклоняются до session;
- helper принимает решение по kernel credentials и Security Server, а не по identity из JSON;
- существующий replay guard становится частью уже authenticated connection, как требует ADR-003;
- модель работает без Developer ID в текущем non-sandboxed source-first path.

Отрицательные:

- initial runtime admission может вызвать системный authorization prompt в UI-процессе;
- external form становится чувствительным bearer secret и требует отдельного bounded transport frame;
- Authorization Services исключает App Sandbox и требует пересмотра при смене distribution model;
- same-UID attacker всё ещё может вызывать connection/authorization-prompt denial of service, хотя
  privileged command без действующего right выполнить не должен.

## Validation spike до принятия

1. На реальном Apple Silicon Mac доказать, что helper adapter получает UID/GID connected client через
   kernel API и отклоняет другой expected UID независимо от полей payload.
2. Создать dedicated test right с exact inspected policy, получить external form в unprivileged test
   client, восстановить её в helper-side adapter и проверить success/denied/expired or invalidated
   paths без helper-side UI. Отдельно проверить absent → create, exact retry, conflicting existing
   policy rejection и uninstall preservation of a changed policy; rollback должен удалить только
   собственный test right.
3. Доказать, что same-UID client без form, с random/truncated/oversized или invalidated form не может
   создать `HelperRuntimeConnectionSession`. Отдельно подтвердить bearer-риск: скопированная ещё
   действующая form не привязана к процессу и потому должна оставаться secret.
4. Доказать ordering: peer check → authorization check → version/capability handshake →
   helper-generated session → command validation; все failures происходят до side effects.
5. Проверить redaction, connection-local lifetime, cleanup socket/reference после disconnect/crash и
   отсутствие authorization bytes в logs/diagnostics.

До прохождения spike ADR остаётся `Proposed`; документация не является evidence live authentication.

## Rollback и условия пересмотра

Документ можно отклонить без миграции runtime state, пока live IPC не реализован. Пересмотр обязателен
при App Sandbox, Developer ID, отказе Authorization Services на поддерживаемой macOS, невозможности
надёжно связать external form с connection или обнаружении same-UID bypass. Замена оформляется новым
ADR либо статусом `Superseded`, а не переписыванием исторического решения.

## Ссылки

- [Apple: Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [Apple: AuthorizationExternalForm](https://developer.apple.com/documentation/security/authorizationexternalform)
- [Apple: AuthorizationMakeExternalForm](https://developer.apple.com/documentation/security/authorizationmakeexternalform%28_%3A_%3A%29)
- [Apple: AuthorizationRightSet](https://developer.apple.com/documentation/security/authorizationrightset%28_%3A_%3A_%3A_%3A_%3A_%3A%29)
- [Apple: Authorization Services Programming Guide — factored applications](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/03authtasks/authtasks.html)
- [Apple: Code Signing Services](https://developer.apple.com/documentation/security/code-signing-services)
- [Apple: SecCodeCopyGuestWithAttributes](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes%28_%3A_%3A_%3A_%3A%29)
