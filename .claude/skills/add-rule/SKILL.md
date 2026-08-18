---
name: add-rule
description: Добавить узкое проверяемое RULE-NNN для повторяющейся NovaRay-конвенции и зарегистрировать его в AGENTS.md. Использовать по явному запросу или на основании повторённого evidence.
---

# Skill: add-rule

## Шаги

1. Подтвердить, что правило повторяемо, проектно-специфично и проверяемо. Одноразовое решение обычно
   относится к SPEC/ADR, а подробный workflow — к skill.
2. Проверить `docs/rules/`; создать каталог при первом принятом правиле. Выбрать следующий
   `RULE-NNN-<slug>.md`.
3. Описать Purpose, MUST/MUST NOT, Scope, Valid/Invalid examples, Exceptions, Validation и Changelog.
   Для network safety указать failure consequence и применимый тест.
4. Добавить короткую строку в раздел обязательных правил `AGENTS.md` и ссылки из затронутых skills.
5. Запустить указанную validation-команду и `git diff --check`.

## Checklist

- [ ] Правило нельзя заменить существующим пунктом AGENTS/SPEC/ADR.
- [ ] Scope и исключения однозначны.
- [ ] Есть автоматическая проверка или чёткая review-процедура.
- [ ] Короткий trigger находится в AGENTS, детали — в RULE.
