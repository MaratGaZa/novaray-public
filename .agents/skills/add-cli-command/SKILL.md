---
name: add-cli-command
description: Добавить или изменить тонкую команду NovaRay Rust CLI, делегирующую работу application core и имеющую проверяемые exit codes. Использовать для novaray-core или отдельного developer CLI.
---

# Skill: add-cli-command

## Шаги

1. Уточнить, является команда пользовательской или `developer-only`; privileged dev-команды должны
   быть явно помечены и не входить автоматически в release UI.
2. Сначала определить/использовать метод application core через `add-app-service-method`. В
   `src/main.rs` оставить parsing, вызов core, безопасный вывод и отображение ошибки в exit code.
3. Не добавлять CLI framework автоматически: при одной-двух командах допустим текущий минимальный
   parser; новая зависимость требует обоснования в `TECH_STACK.md` и plan.
4. Не принимать secrets через аргументы, видимые в process list; использовать защищённый stdin,
   Keychain boundary или файл с проверенными permissions по утверждённому контракту.
5. Для `sudo`/network spike не запускать UI как root и не принимать произвольные route/scutil/pfctl
   строки. Команда должна иметь allowlisted typed operations, dry-run/status и rollback.
6. Добавить integration tests успешного вызова, invalid input и ненулевого exit code; обновить README,
   `--help` и примеры. Выполнить проверки `AGENTS.md`.

## Checklist

- [ ] CLI является тонким adapter над core.
- [ ] Dev-only и release behavior не смешаны.
- [ ] Secrets не раскрываются в argv/logs.
- [ ] Ошибки дают стабильный ненулевой exit code.
- [ ] Документация и integration tests обновлены.
