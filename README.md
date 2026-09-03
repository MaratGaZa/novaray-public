# NovaRay Core

Rust-прототип общего ядра будущего desktop VPN-клиента NovaRay: macOS Apple Silicon — первый
production-релиз, Windows 11 x64 — второй обязательный релиз.

> Статус: **pre-alpha / core prototype**. Репозиторий пока не содержит работающий VPN data plane,
> platform GUI или готовое приложение для macOS/Windows. Android запланирован как отдельный проект.

## Реализовано

- модели серверных профилей и пользовательских настроек;
- базовая валидация конфигурации;
- импорт VLESS URI, включая параметры Reality;
- генерация базовых `inbounds`/`outbounds` Xray JSON;
- чистая логика сопоставления доменов и app identifier с `Direct`/`Proxy`;
- минимальные `ProcessSupervisor` и `RouteManager` API;
- unit- и integration-style тесты логики.

`RouteManager` сейчас является заглушкой, `ProcessSupervisor` не реализует health-check/restart/graceful shutdown, а результат split-tunneling matcher не применяется к реальному трафику.

## Не реализовано

- загрузка конфигурации в `main` и долгоживущий daemon lifecycle;
- запуск проверенного встроенного сетевого движка;
- TUN или NetworkExtension;
- маршруты IPv4/IPv6, DNS и rollback;
- доменные/IP-правила в генерируемой конфигурации Xray;
- process/socket attribution для per-app routing;
- GUI, menu bar, `.app`, `.dmg`, code signing и notarization;
- Windows native UI, Service/network adapter, installer и Windows 11 system tests;
- реальные сетевые, leak-, crash-recovery- и end-to-end-тесты.

## Сборка текущего прототипа

Требуется Rust toolchain с поддержкой edition 2021.

```bash
cargo check
cargo test --all-targets
cargo run
```

`cargo run` без подкоманды выводит справку и завершается. Даже `start` пока является local-proxy
vertical slice: он не подключает системный VPN и не изменяет маршруты или DNS.

## Выбор формата конфигурации движка

`novaray-core start` по умолчанию генерирует конфигурацию Xray. Для sing-box нужно выбрать
формат явно и передать путь к соответствующему бинарнику:

```bash
cargo run -- start \
  --config config.example.json \
  --settings settings.example.json \
  --engine-config sing-box \
  --engine-version v1.13.18 \
  --engine-bin /path/to/sing-box
```

`--engine-config` выбирает формат JSON и pre-flight команду, а `--engine-bin` только задаёт путь
к исполняемому файлу. Допустимы `xray` и `sing-box`; неизвестное значение завершается с usage error.
`--engine-version` выбирает только версию из pinned catalog: `recommended`/`supported` разрешены,
`deprecated` печатает предупреждение до старта, `yanked` и неизвестные версии отклоняются fail-closed.
Этот local-proxy CLI не создаёт системный VPN-туннель и не изменяет маршруты или DNS.

Для строгой статической проверки:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

На момент актуализации документации formatting, строгий Clippy и Rust tests проходят локально.
Baseline GitHub Actions для Linux/macOS/documentation подтверждён в
development task #3. Windows hosted x64 portability job впервые
прошёл в recorded CI run 31951959769; это не
доказательство Windows 11 VPN.

## Документация

- [Спецификация RU](./docs/SPEC_RU.md)
- [Specification EN](./docs/SPEC_EN.md)
- [Текущая и целевая архитектура](./docs/ARCHITECTURE.md)
- [Фактический и планируемый стек](./docs/TECH_STACK.md)
- [Стратегия тестирования](./docs/TESTING.md)
- [Трассировка требований](./docs/TRACEABILITY.md)
- [План реализации](./docs/IMPLEMENTATION_PLAN.md)
- [ADR-001: выбор macOS UI](./docs/ADR-001-MACOS-UI.md)
- [ADR-002: распространение macOS](./docs/ADR-002-MACOS-DISTRIBUTION.md)
- [ADR-007: выбор версии движка](./docs/ADR-007-ENGINE-VERSION-SELECTOR.md)
- [ADR-006: границы общего core и desktop-платформ](./docs/ADR-006-CROSS-PLATFORM-BOUNDARIES.md)
- [Полный roadmap](./learning/05_roadmap_zero_to_hero.md)
- [Политика безопасности](./SECURITY.md)
- [Лицензия GPL-3.0-or-later](./LICENSE)

## Принцип статусов

Документы используют три состояния:

- `[x]` — реализовано и подтверждено тестом или ручной проверкой;
- `[~]` — частичный прототип, непригодный для production;
- `[ ]` — не реализовано.

Заявление в целевой архитектуре не означает, что компонент уже существует.
