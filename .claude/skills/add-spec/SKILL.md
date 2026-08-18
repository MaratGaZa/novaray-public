---
name: add-spec
description: Синхронно добавить или изменить требование NovaRay в SPEC_RU.md и SPEC_EN.md, затем отразить его в roadmap, implementation plan и testing strategy. Использовать до реализации новой функции или изменения контракта.
---

# Skill: add-spec

## Входы

Функция или изменение, границы MVP, acceptance criteria, зависимости, риски и известный текущий статус.

## Шаги

1. Прочитать `docs/SPEC_RU.md`, `docs/SPEC_EN.md`, `docs/IMPLEMENTATION_PLAN.md`,
   `../learning/05_roadmap_zero_to_hero.md` и применимые ADR/тестовую стратегию.
2. Проверить код и тесты перед изменением статуса. Использовать только `[x]` — evidence подтверждено,
   `[~]` — частичный прототип, `[ ]` — отсутствует.
3. В одной задаче внести семантически одинаковые изменения в RU и EN SPEC: цель, non-goals,
   functional/non-functional requirements, failure behaviour и acceptance criteria.
4. Добавить или уточнить roadmap-задачи с зависимостями и подзадачами. Обновить milestone и порядок в
   `docs/IMPLEMENTATION_PLAN.md`; при необходимости — `docs/TESTING.md` и `docs/ARCHITECTURE.md`.
5. Если изменение выбирает труднообратимую архитектуру, применить `add-adr` до утверждения решения.
6. Проверить локальные Markdown-ссылки, смысловую синхронность RU/EN и `git diff --check`.

## Checklist

- [ ] RU и EN описывают одинаковый контракт и статус.
- [ ] Planned не выдано за implemented.
- [ ] Roadmap и implementation plan содержат зависимости и acceptance evidence.
- [ ] Security, rollback и тестовые уровни указаны для network/system изменений.
- [ ] Реализация не начата без отдельного разрешения.
