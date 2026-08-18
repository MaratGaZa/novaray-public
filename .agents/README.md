# Локальные skills NovaRay

Этот каталог содержит проектные workflows для AI-агентов, работающих в Rust/macOS-проекте
NovaRay. Короткие обязательные триггеры находятся в `../AGENTS.md`; подробная процедура каждого
workflow — в соответствующем `SKILL.md`.

| Skill | Назначение |
|---|---|
| `reconcile-current-state` | Сверить SPEC/ADR/планы с кодом, тестами и runtime evidence |
| `review-plan-before-approval` | Проверить полноту, порядок и безопасность roadmap/плана |
| `add-spec` | Синхронно изменить `SPEC_RU.md`, `SPEC_EN.md`, roadmap и plan |
| `add-adr` | Зафиксировать значимое архитектурное решение NovaRay |
| `add-rule` | Добавить узкое проверяемое правило для людей и агентов |
| `add-app-service-method` | Добавить UI-независимый use case в Rust application core |
| `add-cli-command` | Добавить тонкую команду NovaRay CLI |
| `add-rest-endpoint` | Спроектировать явно одобренный локальный HTTP control API |
| `execute-one-sdd-phase` | Выполнить ровно одну одобренную SDD-фазу |
| `create-session-artifacts` | Записать review, learning и memory артефакты задачи |
| `migrate-workspace-capsule` | Безопасно мигрировать один workspace capsule |

## Правила использования

1. Агент сначала сопоставляет запрос с таблицей триггеров в `AGENTS.md`.
2. Каждый выбранный `SKILL.md` читается полностью до изменений.
3. Несколько skills применяются в порядке, указанном в `AGENTS.md`.
4. Manifest содержит имя, версию и canonical entrypoint; при существенном изменении workflow
   увеличивается major version.
5. Новый skill добавляется только для повторяемого workflow с явными входами, шагами, stop-condition
   и проверяемым checklist; после этого обновляются этот README и dispatch-таблица `AGENTS.md`.

Skills не дают разрешение на commit/push, публикацию, системную установку, отключение защит macOS или
другие внешние/destructive действия.

`evolve-ai-instructions` является внешним maintainer workflow и намеренно не копируется в публичный
проект. Обычная работа с clone не зависит от локальных путей maintainer.

## Claude Code

`../CLAUDE.md` и каталог `../.claude/` являются regular-file mirrors canonical-файлов
`../AGENTS.md` и `.agents/`. Изменять нужно canonical-файлы, затем синхронно обновлять mirrors и
запускать `python3 scripts/check_agent_mirrors.py`; symlink не используются для совместимости с
Windows checkout.
