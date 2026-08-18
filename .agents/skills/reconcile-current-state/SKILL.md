---
name: reconcile-current-state
description: Сверить целевые SPEC/ADR/планы NovaRay с фактическим кодом, тестами и runtime evidence, классифицируя claims как implemented, partial, missing, contradicted или unverified.
---

# Skill: reconcile-current-state

## Шаги

1. Прочитать `AGENTS.md` и собрать конкретные claims из SPEC, ADR, architecture, roadmap, plan,
   README и предыдущих review/memory. Зафиксировать текущий worktree.
2. Для целевого контракта использовать SPEC/принятые ADR. Для утверждения «реализовано сейчас»
   проверять source → tests → воспроизводимый runtime/system evidence; planned docs не являются
   доказательством runtime.
3. Классифицировать каждый claim: `implemented`, `partial`, `missing`, `contradicted`, `unverified`.
   Указать файл/строку, evidence level и минимальную коррекцию.
4. Изменяемые внешние факты (Apple entitlements/distribution, API/протоколы) перепроверить по текущей
   первичной документации и отделить прямой факт от inference.
5. Findings упорядочить: security/behaviour, contract drift, sequencing, test gaps. Активные документы
   исправлять только если пользователь просил; историю не переписывать.
6. Если scope включает запись результатов, применить `create-session-artifacts`.

## Checklist

- [ ] Каждый существенный claim имеет evidence.
- [ ] Target и current implementation не смешаны.
- [ ] Mock/unit/no-op не повышены до system-level evidence.
- [ ] External facts обновлены по primary sources.
- [ ] Pre-existing изменения сохранены.
