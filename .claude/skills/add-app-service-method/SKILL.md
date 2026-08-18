---
name: add-app-service-method
description: Добавить UI-независимый use case в Rust application core NovaRay с типизированными входами, ошибками, state transitions и тестами. Использовать для доменной, policy и orchestration логики.
---

# Skill: add-app-service-method

## Шаги

1. Найти действующего владельца use case в `src/core.rs`, `src/config.rs`, `src/matcher.rs` или другом
   модуле. Не создавать новый слой только ради названия `service`.
2. Сверить контракт с обеими SPEC и plan. Для нового поведения сначала применить `add-spec`.
3. Определить типизированные input/output/error и допустимые state transitions. Библиотечный код не
   импортирует SwiftUI/AppKit, CLI presentation и произвольные shell-команды.
4. Оставить pure policy синхронной; использовать Tokio только для реального I/O/concurrency. На
   библиотечной границе предпочитать предметные ошибки `thiserror`; `anyhow` допустим в executable
   composition layer.
5. Внедрять network/engine/clock зависимости через узкую trait-границу, если это требуется для
   детерминированного теста. Не маскировать no-op как успешную операцию.
6. Добавить unit tests для happy/error/state paths и integration test, если меняется взаимодействие
   модулей. Выполнить проверки из `AGENTS.md`.

## Checklist

- [ ] Use case не зависит от UI и presentation.
- [ ] Ошибки и состояния типизированы.
- [ ] Privileged operation не принимает shell string.
- [ ] Частичная ошибка имеет compensation/rollback там, где меняется система.
- [ ] Тест доказывает поведение, а не только создание типа.
