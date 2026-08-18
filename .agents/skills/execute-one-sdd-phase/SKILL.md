---
name: execute-one-sdd-phase
description: Выполнить ровно одну явно одобренную фазу NovaRay SDD, доказать acceptance criteria, обновить честный статус и остановиться. Использовать после take next step или эквивалентной команды.
---

# Skill: execute-one-sdd-phase

## Шаги

1. Прочитать `AGENTS.md`, обе SPEC, применимые ADR, roadmap, implementation plan и testing strategy.
   Зафиксировать pre-existing `git status`; назвать одну фазу, её границы и acceptance criteria.
2. Если документы расходятся с кодом, сначала применить `reconcile-current-state`. Не начинать фазу,
   пока обязательное архитектурное решение остаётся неразрешённым.
3. Реализовать только эту фазу, сохраняя Rust core независимым от UI/privileged boundary. Добавить
   focused tests и rollback/recovery для системных мутаций.
4. Запустить targeted tests, затем применимые команды из `AGENTS.md`. Не заявлять real VPN,
   NetworkExtension, signing или packet routing по mock/unit evidence.
5. Менять status roadmap/plan только после прохождения acceptance criteria. Применить
   `create-session-artifacts`.
6. Остановиться. Не начинать следующую фазу, commit/push, dependency install, notarization или
   system-extension activation без новой явной команды.

## Checklist

- [ ] Выполнена ровно одна фаза.
- [ ] Acceptance criteria имеют воспроизводимое evidence.
- [ ] Невыполненные проверки и blockers перечислены.
- [ ] Документационный статус соответствует факту.
- [ ] Следующая фаза не начата.
