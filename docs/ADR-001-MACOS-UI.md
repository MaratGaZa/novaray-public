# ADR-001: UI и системная оболочка macOS

- Статус: Proposed
- Дата: 2026-08-16
- Ревизия: 2026-08-17 — зафиксирован scope из трёх платформ; убран Tauri как резервный UI для macOS
- Владелец решения: MaratGaZa
- Решение требуется до: реализации production GUI
- Следующий review: перед созданием production SwiftUI/AppKit target или при выборе второго UI stack

## Контекст

NovaRay ориентирован прежде всего на macOS Apple Silicon (macOS 14+). Пользовательский интерфейс представляет собой системную утилиту (dashboard, menu bar, connect/disconnect, выбор профилей, редактор маршрутизации, диагностика и мониторинг). Основная сложность продукта сосредоточена в управлении жизненным циклом туннеля, привилегированной границе, многопоточности и восстановлении после сбоев.

Владелец продукта зафиксировал 2026-08-17 целевые платформы: **macOS, Windows и Android**. Это делает выбор UI-стека вопросом не одной платформы, а трёх, и требует явного решения о том, где стек общий, а где нативный.

Требования к архитектуре UI:
- максимальная нативность и интеграция с системным дизайном macOS (AppKit/SwiftUI);
- сохранение бизнес-логики, парсера, стейт-машины, политик и маршрутизации в независимом Rust Core;
- минимальное потребление ресурсов CPU/RAM в фоновом режиме (idle);
- возможность добавить Windows и Android UI без переписывания Core и без дублирования policy.

## Рассмотренные варианты

| Вариант | Нативность macOS | Rust purity | Ресурсы | Системная интеграция | Вывод |
|---|---:|---:|---:|---:|---|
| **SwiftUI/AppKit + Rust core** | максимальная | core на Rust, shell на Swift | низкие | максимальная | **Рекомендуется для macOS (Proposed)** |
| **Tauri v2 + Rust core** | средняя/высокая для WebView app | backend на Rust, UI web | умеренные | привилегированный компонент нужен отдельно на любой платформе | **кандидат для Windows и Android**; для macOS не используется |
| **Slint + Rust** | custom native-rendered UI | высокая | низкие | native bridge всё равно нужен | отклонено для первого релиза |
| **egui/eframe + wgpu** | custom GPU UI, не AppKit look | максимальная | зависит от redraw policy | native bridge нужен | только для внутренних CLI/tools |
| **Собственный Metal UI** | custom renderer, не native controls | много Rust + shaders/FFI | неоправданно высокая цена | всё системное пишется с нуля | отклонено |

Замечание к строке Tauri: ранее её минусом указывалось «требует отдельного native extension/helper». По [ADR-003](./ADR-003-NETWORK-TOPOLOGY.md) привилегированный компонент теперь необходим на каждой платформе при любом UI-стеке, поэтому этот минус перестал различать варианты.

## Предлагаемое решение

1. **Интерфейс приложения macOS:**
   - Основное окно настроек и профилей реализуется на **SwiftUI**.
   - Меню-бар (menu bar item / status bar item) реализуется через декларативный **SwiftUI `MenuBarExtra`** с возможностью точечного моста к **AppKit** (`NSStatusItem`, `NSStatusBar`) там, где стандартных возможностей SwiftUI недостаточно.
2. **Второй UI-стек для macOS не поддерживается.** Держать одновременно SwiftUI и Tauri на одной платформе означает реализовывать каждую функцию дважды и сопровождать нетестируемый резерв, поэтому вариант отклонён явно. Замена стека, если она когда-либо потребуется, выполняется как переход, а не как параллельное существование.
3. **UI для Windows и Android — открытое решение.** Кандидат — **Tauri v2** (подтверждена поддержка macOS, Windows, Linux, Android 8+ и iOS 9+). Выбор принимается отдельным ADR после первого работающего macOS-релиза, как того требует последовательность в [ADR-006 Cross-platform boundaries](./ADR-006-CROSS-PLATFORM-BOUNDARIES.md). Решение сознательно откладывается: сейчас нет данных о фактической трудоёмкости SwiftUI-части и о финальном виде редактора правил маршрутизации.
4. **Архитектурная граница (FFI / ABI):**
   - NovaRay Core компилируется как Rust `staticlib` (`libnovaray_core.a`).
   - Граница между Swift и Rust оформляется через строгий, типизированный и версионированный C ABI (стандарт C99/C11, `stdint.h`, `#[repr(C)]`).
   - Swift 6 взаимодействует с C ABI без использования bridging header через Clang Module Map (`module.modulemap`).
   - Доказан сквозной синхронный roundtrip вызова Rust из Swift с доставкой типизированного события `NovaRayStateEvent` (Issue #9).
   - Контракт остаётся UI-нейтральным: любой второй стек обязан использовать тот же набор команд и событий без собственной policy-логики (ADR-006 Cross-platform boundaries, пункт 2). Именно это делает пункт 3 отложенным без риска.
5. **Сетевая граница:**
   - Системный туннель выносится в отдельный привилегированный компонент по [ADR-003](./ADR-003-NETWORK-TOPOLOGY.md); UI не получает `root` и не выполняет сетевые мутации напрямую.

## Доказательства готовности (Evidence)

Текущий статус остаётся `Proposed` до закрытия Gate B и production-интеграции.
В рамках спайков Gate A подтверждено:
- [x] **SwiftUI + System Extension target:** проект `NovaRaySpike.xcodeproj` успешно собирает `.app` и встроенный `org.novaray.spike.packettunnel.systemextension` для `arm64` (Issue #7).
- [x] **Rust C ABI ↔ Swift 6 roundtrip:** Swift вызывает Rust `staticlib` и получает типизированные события `NovaRayStateEvent` в режиме Swift 6 strict concurrency (Issue #9).
- [x] **Menu bar & Async State:** в спайке реализован статус-бар и наблюдение за системными нотификациями `NEVPNStatusDidChange`.
- [x] **CI автоматизация:** в GitHub Actions включены сборка Swift 6 и unsigned Xcode build.

## Оставшиеся шаги до утверждения

1. Разработка асинхронного Tokio ↔ Swift AsyncStream моста для стриминга событий Core.
2. Внедрение механизма защиты от паник (`std::panic::catch_unwind`) на FFI границе.
3. Измерение cold launch time, idle memory и idle CPU на реальном Apple Silicon Mac.
4. Отдельный ADR по UI-стеку Windows и Android после первого macOS-релиза.

## Последствия решения

### Положительные:
- Идеальная интеграция с Human Interface Guidelines macOS, поддержка темной/светлой темы, VoiceOver и Keyboard Navigation из коробки.
- Полная независимость Rust Core от Cocoa/UI библиотек — ядро может тестироваться в `cargo test` и переиспользоваться на Windows и Android.
- Отсутствие overhead от WebView или постоянного GPU-рендеринга в idle.
- Отказ от параллельного второго стека на macOS исключает двойную реализацию функций и нетестируемый резерв.

### Отрицательные / Риски:
- Необходимость поддержки двух языковых экосистем (Xcode/Swift + Cargo/Rust).
- Необходимость тестирования бинарной совместимости ABI и версионирования структур данных.
- **При выборе Tauri для Windows и Android интерфейс придётся реализовать дважды** — на SwiftUI и на web-стеке. Это осознанная цена нативности macOS; она станет предметом пересмотра, если трудоёмкость SwiftUI-части окажется существенно выше ожидаемой.
- Tauri не покрывает привилегированный слой: `VpnService` на Android и служба на Windows требуют нативного кода в любом случае.

## Условия пересмотра

- Если объём SwiftUI-части существенно превысит оценку либо расхождение функций между платформами станет заметным, вариант «единый Tauri v2 для всех трёх платформ» пересматривается как основной, а SwiftUI-оболочка выводится из эксплуатации целиком, а не дублируется.

## Ссылки на источники

- Apple SwiftUI: https://developer.apple.com/documentation/swiftui/
- Apple MenuBarExtra: https://developer.apple.com/documentation/swiftui/menubarextra
- Apple AppKit NSStatusItem: https://developer.apple.com/documentation/appkit/nsstatusitem
- Tauri v2 поддерживаемые платформы: https://github.com/tauri-apps/tauri
- Исходный код спайка UI: [spikes/macos-networkextension-spike/](../spikes/macos-networkextension-spike/)
- Исходный код спайка FFI: [spikes/macos-rust-ffi-spike/](../spikes/macos-rust-ffi-spike/)
