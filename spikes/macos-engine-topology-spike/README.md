# Spike: Xray-core и sing-box в macOS topology

Статус: evidence-only, issue development task #12.

Дата snapshot: 2026-08-16. Ни один engine в этой фазе не скачивался, не запускался и не выбирался.
Этот spike не доказывает VPN, Network/System Extension runtime или совместимость распространения.

## Цель и границы

Spike сравнивает официальный subprocess и embedded/library surface двух кандидатов для будущего
ADR-004. Проверяются только upstream/Apple contracts, pinned release metadata и topology gaps.
Следующие действия намеренно исключены:

- реальное VLESS/Reality соединение;
- включение engine binary в NovaRay;
- signing, entitlement или запуск Network System Extension;
- network mutation;
- юридическое заключение по распространению.

Machine-readable snapshot находится в [`engine-evidence.json`](./engine-evidence.json) и проверяется
офлайн:

```bash
python3 spikes/macos-engine-topology-spike/scripts/validate_manifest.py
```

Validator запрещает случайно превратить этот evidence в утверждение о выбранном engine или закрытом
production gate.

## Проверенные версии

| Кандидат | Pinned source | macOS arm64 release artifact | License declaration | Выполнено локально |
|---|---|---|---|---|
| Xray-core | `v26.3.27`, `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0` | `Xray-macos-arm64-v8a.zip`, SHA-256 `2e93a67e...f8409eaf` | MPL-2.0 | нет |
| sing-box | `v1.13.18`, `45ca32dcb966f07f97fc888fe8586e359dbe8405` | `sing-box-1.13.18-darwin-arm64.tar.gz`, SHA-256 `9fbc0594...91149107` | GPL-3.0-or-later и дополнительное upstream naming/association условие | нет |

Полные digests и URLs сохранены в manifest. Значения получены из GitHub release API; наличие
артефакта подтверждает upstream packaging, но не build reproducibility, подпись NovaRay или запуск
в extension. Перед распространением обоих вариантов нужен отдельный license review; особенно нельзя
автоматически свести текст лицензии sing-box к одному SPDX identifier.

## Subprocess surface

### Xray-core

- официальный repository описывает pure-Go build для macOS через `CGO_ENABLED=0 go build ... ./main`;
- CLI валидирует конфигурацию без запуска через `xray run -test -c CONFIG.json`;
- process boundary даёт NovaRay возможность контролировать PID, stdout/stderr, timeout и forced kill;
- стабильный machine-readable readiness endpoint, формат логов и проверенный graceful-stop contract
  в этой фазе не установлены. Их должен доказать отдельный L4 runtime spike.

Источники: [pinned repository](https://github.com/XTLS/Xray-core/tree/v26.3.27),
[build instructions](https://github.com/XTLS/Xray-core/blob/v26.3.27/README.md),
[CLI reference](https://xtls.github.io/en/document/command.html) и
[license](https://github.com/XTLS/Xray-core/blob/v26.3.27/LICENSE).

### sing-box

- официальный repository собирает CLI из `./cmd/sing-box`; downstream packager должен использовать
  pinned `release/DEFAULT_BUILD_TAGS` и `release/LDFLAGS`, а не произвольный набор flags;
- CLI предоставляет `sing-box check -c CONFIG.json`;
- официальный release содержит Darwin arm64 artifact;
- конкретные readiness, bounded logging и graceful-stop semantics для NovaRay не исполнялись и
  остаются L4 gate.

Источники: [pinned repository](https://github.com/SagerNet/sing-box/tree/v1.13.18),
[build documentation](https://sing-box.sagernet.org/installation/build-from-source/),
[configuration check](https://sing-box.sagernet.org/configuration/) и
[license](https://github.com/SagerNet/sing-box/blob/v1.13.18/LICENSE).

## Embedded/library surface

### Xray-core через libXray

Сам Xray-core предоставляет импортируемый Go package, но это не является Swift ABI. Официальный
XTLS wrapper [libXray `v26.3.27`](https://github.com/XTLS/libXray/tree/v26.3.27) добавляет Apple
gomobile/cgo outputs и Swift-compatible native boundary. Pinned wrapper revision:
`38ae3cd8914d5bc2a7f81122fc6206efe3c07ad6`.

Критические ограничения upstream wrapper:

- API stability не гарантируется и wrapper совместим только с соответствующим актуальным Xray-core;
- в один процесс нельзя загружать несколько независимо собранных Go runtimes;
- lifecycle включает JSON entrypoint и `runXray`/`stopXray`, но NovaRay ещё должен проверить
  ownership, concurrency, panic containment, memory pressure и cancellation внутри extension;
- process-wide Xray state ограничивает concurrent instances.

Следовательно, наличие `LibXray.xcframework` path делает embedding правдоподобным, но не закрывает
Gate B и не разрешает production integration.

### sing-box через libbox

Pinned sing-box source содержит [`experimental/libbox`](https://github.com/SagerNet/sing-box/tree/v1.13.18/experimental/libbox)
и [Apple build definition](https://github.com/SagerNet/sing-box/blob/v1.13.18/experimental/libbox/ffi.json).
Apple client подключён как submodule
[sing-box-for-apple revision `9e17f432...`](https://github.com/SagerNet/sing-box-for-apple/commit/9e17f432dce4e38ab27db087e0aef6008f217277).
Platform interface libbox явно знает о NetworkExtension и принимает platform-owned TUN handle.

Это более прямое upstream evidence Apple embedding, чем generic subprocess, но оно не доказывает:

- что NovaRay может переиспользовать чужой Xcode packaging и entitlements;
- стабильность experimental API;
- допустимость planned NovaRay distribution с учётом полного license text;
- memory, crash, cancellation, logging и rollback на development Mac.

## Topology matrix

| Placement | Технический статус | Что доказано | Что блокирует выбор |
|---|---|---|---|
| Обычный host app запускает bundled subprocess | правдоподобно для macOS app | Apple `Process` запускает и наблюдает child; bundled external tool допускается при корректной упаковке | child наследует sandbox; engine не получает автоматически `NEPacketTunnelFlow`; нужны signing, IPC/data bridge и lifecycle tests |
| Engine embedded в Network System Extension | правдоподобно для обоих | libXray имеет Apple native output; libbox имеет Apple/NetworkExtension-aware path | entitlement runtime, memory budget, Go runtime, ABI/API, panic/cancel и packet-flow tests отсутствуют |
| Extension запускает engine subprocess | непроверено | runtime evidence отсутствует | нельзя предполагать поддержку по факту работы `Process` в обычном app; требуется signed Gate B proof и Apple-supported lifecycle |
| Отдельный helper владеет subprocess | архитектурно правдоподобно | direct distribution допускает отдельный process layout | ADR-003, installer authorization, authenticated typed IPC, least privilege, snapshot/rollback и clean uninstall |

Apple указывает, что child sandboxed app наследует sandbox родителя, а для отличающихся entitlements
предпочтителен XPC service. Одновременно TN3134 требует system-extension packaging для direct
distribution packet tunnel provider. Из этих документов нельзя вывести, что произвольный engine
subprocess внутри Network System Extension поддержан: это остаётся явным runtime gate.

Источники Apple: [`Process`](https://developer.apple.com/documentation/foundation/process),
[embedding a command-line tool](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app),
[TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

## Результат и следующий gate

Оба кандидата остаются допустимыми для следующего controlled runtime spike:

- Xray-core ближе к уже существующему NovaRay config generator и имеет XTLS Apple wrapper, но wrapper
  прямо не обещает стабильный API;
- sing-box имеет более прямой first-party Apple/libbox topology, но experimental API и license text
  требуют отдельного review.

ADR-004 нельзя принимать только по этой таблице. Следующая архитектурная фаза должна выбрать один
pinned candidate для минимального Gate B/L4 эксперимента и измерить на Apple Silicon:

1. build/link/sign/install для одного process layout;
2. config rejection и one-instance lifecycle;
3. readiness probe с timeout;
4. bounded redacted stdout/stderr или typed logs;
5. graceful stop → timeout → forced termination;
6. crash/panic behavior, process residue и memory/idle cost;
7. packet-flow ownership без route/DNS mutation;
8. license/distribution review до включения binary/framework в NovaRay.

До прохождения этих проверок ADR-004 остаётся `Proposed`, engine не выбран, а NovaRay не является
работающим VPN-приложением.
