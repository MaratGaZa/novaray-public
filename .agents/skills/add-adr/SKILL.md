---
name: add-adr
description: Создать или обновить NovaRay ADR для значимого решения по UI, FFI/IPC, distribution, NetworkExtension/helper, protocol engine или security boundary. Использовать до необратимой реализации.
---

# Skill: add-adr

## Входы

Решение, контекст, варианты, ограничения, evidence и статус `Proposed`, `Accepted`, `Rejected` или
`Superseded`.

## Шаги

1. Проверить существующие `docs/ADR-*.md`, обе SPEC, architecture, roadmap и текущий код.
2. Для изменяемых Apple API, signing, entitlements и distribution проверить актуальную первичную
   документацию Apple.
3. Создать `docs/ADR-NNN-<slug>.md` со следующим трёхзначным номером либо обновить существующий ADR.
4. Зафиксировать: Status, Context, Decision, Alternatives, Consequences, validation spike,
   rollback/revisit conditions и References.
5. Не ставить `Accepted`, пока decision gate не подтверждён владельцем и указанным spike/evidence.
6. Синхронно связать ADR из `SPEC_RU.md`, `SPEC_EN.md`, `ARCHITECTURE.md`, roadmap и plan там, где он
   меняет требования или порядок работ.

## Checklist

- [ ] Решение сформулировано однозначно.
- [ ] Рассмотрена минимум одна реальная альтернатива.
- [ ] Отделены проверенные факты, inference и proposal.
- [ ] Указаны последствия для signing, entitlements, privileges и distribution.
- [ ] Superseded ADR не переписан без ссылки на замену.
