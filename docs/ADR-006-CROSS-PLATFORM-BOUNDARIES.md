# ADR-006: границы общего Rust core и целевых платформ

- Статус: `Proposed`
- Дата: 2026-08-16
- Ревизия: 2026-08-17 — Android переведён из отдельного продукта в целевой scope
- Владелец решения: MaratGaZa
- Связанная задача: development task #5
- Следующий review: после стабилизации versioned core contract и Windows topology spike, до начала Windows platform implementation

## Контекст

Владелец продукта зафиксировал порядок выпусков: сначала production-релиз для macOS Apple Silicon,
затем обязательный desktop-релиз для Windows 11, затем Android. Ревизией 2026-08-17 Android переведён
из отдельного продукта в целевую платформу NovaRay. Текущий код — переносимый Rust-прототип логики; macOS и Windows network/UI adapters
ещё не существуют.

Платформы имеют разные доверительные границы. На macOS исследуются Network/System Extension и
SwiftUI/AppKit. На Windows системные сетевые изменения требуют отдельного привилегированного
boundary. Windows Filtering Platform (WFP) предоставляет user/kernel-mode filtering layers и Base
Filtering Engine, но сама по себе не выбирает VPN topology. Windows Service Control Manager (SCM)
управляет службами и их security requirements. Поэтому выбор WFP, Wintun/TUN, engine integration,
службы и IPC нельзя сделать одним названием технологии.

GitHub-hosted `windows-latest` даёт x64 Windows runner для portable build/test, но не заменяет
контролируемую пользовательскую Windows 11 среду с проверкой routes, DNS, firewall, service crash и
rollback.

## Предлагаемое решение

1. Сохранить один versioned Rust application core как источник истины для конфигурации, profiles,
   policy, state machine, diagnostics и engine-neutral contracts.
2. Запретить platform UI и privileged adapters дублировать policy logic. Они сообщают capabilities,
   принимают только типизированные allowlisted commands и возвращают наблюдаемые typed events.
3. Версионировать command/event contract и требовать handshake до сетевой мутации. Несовместимость
   должна приводить к безопасному отказу до connect transaction.
4. Выпустить macOS первым по ADR-001—ADR-005 и macOS milestones M0—M8.
5. После первого macOS production release выполнить Windows milestones M9—M13:
   - topology/distribution/signing spike и отдельный ADR;
   - proposed native WinUI 3 shell;
   - отдельная минимально-привилегированная Windows Service/network boundary;
   - full tunnel, split tunnel, safety/recovery и signed installer.
6. Не выбирать WFP, Wintun/TUN или engine-specific topology до измеримого spike. WinUI 3 также
   остаётся рекомендацией, а не реализованным или принятым компонентом.
7. Android входит в целевой scope продукта (ревизия 2026-08-17). Порядок выпуска — третий, после
   macOS и Windows. Android использует тот же versioned Rust core, тот же формат конфигурации и тот
   же движок (sing-box по [ADR-004](./ADR-004-ENGINE-INTEGRATION.md)), а привилегированная граница
   реализуется через `VpnService`. Решение о размещении Android-кода (этот репозиторий или отдельный)
   и о UI-стеке принимается отдельным ADR после первого macOS-релиза и не предопределяется здесь.

## Целевая зависимость компонентов

```text
macOS SwiftUI/AppKit shell ─┐
                           ├─ typed versioned contract ─ Rust application core
Windows native shell ──────┘                              │
                                                         ├─ engine-neutral config/policy
macOS Network Boundary ◄─────────────────────────────────┤
Windows Service/Network Boundary ◄───────────────────────┘

Android shell ─────────── тот же versioned contract; привилегированная граница = VpnService
```

## Последовательность и gates

- Windows portability CI начинается сейчас и проверяет только portable Rust code.
- Production Windows code не начинается до стабилизации shared contracts и реального macOS local
  engine vertical slice.
- По принятому release order Windows product milestones начинаются после первого macOS production
  release. Ранний research допустим только отдельной явно запланированной задачей.
- Windows network implementation блокируется, пока отдельный ADR не зафиксирует topology, service
  privilege model, authenticated IPC, installer/update channel и recovery ownership.
- Заявление о Windows VPN допускается только после system tests на контролируемой Windows 11 x64
  машине/VM со snapshot и проверяемым rollback.
- Никакие signing credentials не добавляются в baseline CI.

## Альтернативы

### Один cross-platform web UI

Снижает число UI codebases, но ухудшает platform lifecycle integration и не устраняет разные
привилегированные network boundaries. Не выбран как default.

### Полностью независимые продукты без общего core

Упрощает platform ownership, но дублирует protocol/policy/state logic и повышает риск разного
поведения правил. Отклонено.

### Одновременный первый релиз macOS и Windows

Увеличивает критический путь до появления первого проверяемого продукта и требует одновременно
закрыть две системные архитектуры. Отклонено решением владельца продукта.

## Последствия

Положительные:

- platform-specific privilege и lifecycle остаются явными;
- общая policy semantics проверяется одними fixtures;
- Windows не блокирует первый macOS релиз;
- Android включён в scope с явным третьим порядком выпуска и не начинается до Windows.

Издержки и риски:

- потребуются два native UI shells и два system-test стенда;
- versioned FFI/IPC contract становится release-critical;
- Windows installer, signing и service security требуют отдельного бюджета и review;
- одинаковое название feature не гарантирует одинаковые OS capabilities, поэтому UI должен показывать
  effective capability platform-specific.

## Проверка решения

ADR может перейти в `Accepted` только после evidence:

1. shared contract имеет version handshake, negative compatibility tests и не содержит OS handles;
2. macOS vertical slice подтверждает, что core boundary не протекает platform policy;
3. Windows spike сравнивает WFP/Wintun/TUN/engine alternatives и документирует privilege/rollback;
4. proposed WinUI 3 shell вызывает Rust core через выбранный typed boundary;
5. Windows Service PoC отклоняет неизвестные/неавторизованные commands;
6. controlled Windows 11 test выполняет snapshot → connect mutation → rollback → semantic diff;
7. packaging/signing/update path подтверждён на clean machine.

## Откат и пересмотр

Если общий ABI/IPC начинает переносить OS-specific policy или мешает recovery, контракт разделяется на
общую domain-модель и platform capability extensions. Если WinUI 3 spike не проходит resource,
accessibility или deployment budgets, сравниваются WPF/Win32 alternatives. Если consumer-grade Windows
split tunneling невозможно реализовать выбранной topology, Windows scope возвращается на ADR review;
это не разрешает имитировать feature matcher-тестом.

## Официальные источники

- [Windows Filtering Platform architecture](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview)
- [Windows services and Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/about-services)
- [Windows App SDK and WinUI](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/)
- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub self-hosted runners reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
- [Windows app code-signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Android `VpnService`](https://developer.android.com/reference/android/net/VpnService)
