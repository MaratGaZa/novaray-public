---
name: create-session-artifacts
description: Создать согласованные датированные review, learning и memory записи NovaRay после завершённой фазы, аудита или документационной задачи. Использовать явно или как завершающий шаг другого skill.
---

# Skill: create-session-artifacts

Версия контракта: `3.0.0`.

## Входы

Topic slug, timestamp `YYYYMMDD-HHMM`, scope/changed files, findings, verification, gaps, risks и одна
безопасная инструкция следующему агенту.

## Определение output root

1. Запустить из корня project Git repository:

   ```bash
   python3 .agents/skills/create-session-artifacts/scripts/resolve_artifact_root.py \
     --project-root "$(git rev-parse --show-toplevel)"
   ```

2. Resolver ищет `.novaray-capsule.json` только среди canonical ancestors project root и принимает
   ровно один marker. Поля `project_path` и `artifact_root` должны быть относительными путями.
3. `project_path` обязан разрешаться ровно в текущий project root. `artifact_root` обязан находиться
   внутри capsule root и снаружи project root.
4. Если marker отсутствует, неоднозначен, невалиден, указывает наружу либо внутрь project root,
   ничего не создавать и запросить у пользователя явный output root. Никогда не использовать
   `project/docs/{learning,memory,reviews}` как fallback.

## Шаги

1. В подтверждённом artifact root создать `reviews/<topic>-<timestamp>.md`: findings по severity,
   evidence, assumptions, recommendation и verification gaps.
2. Создать `learning/<topic>-<timestamp>.md`: что изменено/решено, почему, применённые patterns и
   устойчивые термины.
3. Создать `memory/chat-summary-<topic>-<timestamp>.md`: Current State, Verification, Open Risks,
   Next Agent Instruction. Чётко разделить implemented, proposed, blocked и deferred.
4. Использовать один timestamp и относительные project paths. Не копировать secrets и не
   переписывать старые артефакты; изменение прошлого оформлять новой датированной коррекцией.
5. В verification включить `git diff --check`, применимые проверки `AGENTS.md` и явно перечислить
   невыполненные проверки.
6. После записи доказать, что ни один новый файл не появился под
   `project/docs/{learning,memory,reviews}`.

## Checklist

- [ ] Resolver подтвердил один безопасный capsule artifact root или пользователь явно выбрал root.
- [ ] Три файла используют один topic/timestamp.
- [ ] Ни один session artifact не создан внутри project Git root.
- [ ] Findings и residual risk явные.
- [ ] Proposed не названо implemented.
- [ ] Next Agent Instruction не разрешает следующую фазу автоматически.
