---
name: migrate-workspace-capsule
description: Безопасно мигрировать или повторно подключить один workspace capsule NovaRay с сохранением Git, private files, snapshot и rollback evidence. Использовать только по явному запросу миграции.
---

# Skill: migrate-workspace-capsule

Обычный рефакторинг, перемещение одного файла или изменение структуры Rust crate не запускает этот
skill.

## Шаги

1. Определить точные source/target roots, внешнюю и вложенную `.git`-границу, branch/head/remotes,
   ignored/private files, размер и существующее состояние target. Не печатать secrets.
2. Не перезаписывать занятый target. Создать восстанавливаемый snapshot; сначала выполнить dry-run
   сравнение/копирование и записать manifest.
3. Сохранить source Git и private/ignored material; не добавлять `.env`, credentials, signing keys,
   provisioning profiles или Developer ID certificates в repository.
4. После переноса проверить `git fsck`, source-target comparison, status, symlinks, permissions и
   применимые NovaRay tests.
5. Применить `create-session-artifacts` с точной rollback-командой и остановиться после одного capsule.

## Checklist

- [ ] Target и Git boundaries разрешены однозначно.
- [ ] Snapshot проверен и восстановим.
- [ ] Private/signing material не попал под Git.
- [ ] Сравнение и проверки записаны.
- [ ] Следующая миграция не начата.
