# Инструкция для AI-агентов NovaRay

Версия instruction contract: `2.1.0`.

## 1. Область действия

Этот файл действует для всего репозитория. Корень Rust crate и рабочий каталог для
`cargo`-команд — корень репозитория. Перед изменениями агент обязан прочитать этот файл, проверить
`git status --short` и сохранить все несвязанные пользовательские изменения.

## 2. Источники истины

1. Целевое поведение продукта синхронно задают `docs/SPEC_RU.md` и `docs/SPEC_EN.md`.
2. Архитектурные решения задают `docs/ADR-*.md`; пока ADR имеет статус `Proposed`, его нельзя
   выдавать за принятое production-решение.
3. Последовательность работ задают `learning/05_roadmap_zero_to_hero.md` и
   `docs/IMPLEMENTATION_PLAN.md`.
4. Фактически реализованное состояние доказывают исходный код, тесты и воспроизводимая runtime-
   проверка. План, README, mock и существование типа не доказывают реализацию.
5. Стратегию evidence и уровни тестирования задаёт `docs/TESTING.md`.

Новая или существенно изменённая функция сначала описывается в обеих SPEC, затем в roadmap и
implementation plan, и только после этого реализуется. Русская и английская SPEC изменяются в одной
задаче и не должны расходиться по смыслу или статусу.

## 3. Обязательное применение локальных skills

Локальные skills находятся в `.agents/skills/<name>/SKILL.md`.

- Если пользователь назвал skill явно или запрос совпал с триггером ниже, агент обязан до действий
  полностью прочитать соответствующий `SKILL.md` и следовать ему.
- Нельзя переносить skill на следующий запрос автоматически: триггеры оцениваются заново.
- Если подходят несколько skills, применять минимальный достаточный набор в порядке:
  `reconcile-current-state` → `review-plan-before-approval` → `add-spec`/`add-adr`/`add-rule` →
  implementation skill → `execute-one-sdd-phase` → `create-session-artifacts`.
- В итоговом сообщении перечислить применённые skills. Если очевидный skill не использован, кратко
  объяснить почему.
- Skill не расширяет полномочия: commit, push, публикация, установка системного расширения,
  destructive-операции и внешние изменения требуют явного разрешения пользователя.

| Skill | Обязательный триггер |
|---|---|
| `reconcile-current-state` | Проверка текущей стадии, аудит соответствия документации коду, возобновление старой работы, спор о том, что уже реализовано |
| `review-plan-before-approval` | Создание или существенный пересмотр roadmap/implementation plan, просьба оценить готовность плана перед реализацией |
| `add-spec` | Новая функция, изменение требований, acceptance criteria, границ MVP или статуса возможности |
| `add-adr` | Решение о UI, FFI/IPC, NetworkExtension/helper, distribution, engine integration, security boundary или иной труднообратимой архитектуре |
| `add-rule` | Пользователь просит добавить обязательное правило либо повторяющаяся ошибка требует проверяемого MUST/MUST NOT |
| `add-app-service-method` | Новый use case или доменная/policy/state-machine логика Rust core, вызываемая UI/CLI/network boundary |
| `add-cli-command` | Добавление или изменение пользовательской команды `novaray-core` либо отдельного developer CLI |
| `add-rest-endpoint` | Только явный запрос на HTTP/REST control API; обычный Swift↔Rust FFI/IPC этот skill не запускает |
| `execute-one-sdd-phase` | Явная команда `take next step`, «выполни фазу/задачу N» или эквивалент с одной одобренной фазой |
| `create-session-artifacts` | Явный запрос на артефакты сессии либо обязательный завершающий шаг другого активированного skill |
| `migrate-workspace-capsule` | Только явная миграция/re-onboarding workspace; обычный рефакторинг или перенос файла не является триггером |
| `evolve-ai-instructions` | Изменение `AGENTS.md`, skills/rules/prompts после повторяющейся ошибки, review или evaluation; требуется evidence, regression cases, versioning и human approval |

`evolve-ai-instructions` является внешним maintainer workflow и намеренно не входит в публичный
репозиторий. Если изменение instruction contract требует этого workflow, агент должен запросить у
maintainer доступ к одобренной версии; отсутствие внешнего workflow не блокирует обычный clone.

## 4. Архитектурные ограничения

1. **Core:** Rust 2021 + Tokio. Доменная модель, policy, state machine, конфигурация и диагностика
   остаются независимыми от SwiftUI, CLI и конкретного privileged boundary.
2. **macOS UI:** следовать `docs/ADR-001-MACOS-UI.md`. Текущая рекомендация — SwiftUI/AppKit shell
   + Rust core; production scaffolding требует принятого ADR.
3. **Network boundary:** UI не выполняет произвольные `route`, `scutil`, `pfctl` или shell-строки и
   не запускается целиком через `sudo`. Допустим только узкий типизированный FFI/IPC к отдельно
   ограниченному network component.
4. **Apple capability gate:** root не заменяет entitlement. Без активной Apple Developer Program и
   подходящего provisioning profile нельзя заявлять успешный запуск `NEPacketTunnelProvider` или
   подписанного Network System Extension. До этого допускаются только mock/proxy и явно помеченный
   developer-only `sudo` CLI spike.
5. **Distribution:** до production network implementation явно выбрать direct distribution,
   Mac App Store или отдельные профили; выбор фиксируется ADR.
6. **Engine:** внешний Xray/sing-box subprocess, embedded library и NetworkExtension-совместимый
   runtime считаются разными вариантами и требуют отдельного evidence.

## 5. Безопасность и надёжность

- Каждая мутация routes, DNS или firewall должна иметь snapshot, транзакционную compensation и
  проверяемый rollback при ошибке, сигнале, crash и следующем запуске.
- Privileged API принимает allowlisted типизированные операции, а не команды shell.
- Secrets, UUID, адреса серверов и пользовательские IP не попадают в обычные логи или fixtures.
- Kill switch и split tunneling являются fail-sensitive функциями: unit matcher не заменяет
  packet-level, DNS-leak и recovery tests.
- Не отключать SIP/Gatekeeper и не ослаблять системную безопасность как штатный путь разработки.

## 6. Проверка изменений

Для Rust-изменений запускать из корня репозитория как минимум:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
git diff --check
```

Сначала допускаются более узкие тесты, но итоговые применимые проверки должны быть перечислены.
Непройденная или недоступная проверка сообщается явно и не подменяется утверждением об успехе.
Для Markdown дополнительно проверить локальные ссылки и синхронность RU/EN требований.
Изменения `.agents/**`, `.claude/**`, `AGENTS.md` и `CLAUDE.md` дополнительно проверяются командой
`python3 scripts/check_agent_mirrors.py`.

## 7. Дополнительные проверяемые rules

Подробные узкие правила, созданные через `add-rule`, живут в `docs/rules/` и регистрируются здесь.
Пока отдельных RULE-документов нет; обязательные ограничения разделов 2–6 уже действуют.

Политика раскрытия уязвимостей и запрет на публикацию реальных credentials описаны в
[`SECURITY.md`](./SECURITY.md).

| Rule | Краткое требование |
|---|---|
| — | Отдельные RULE-документы ещё не приняты |

## 8. Границы выполнения

- Реализовывать ровно запрошенную или одобренную фазу; соседняя задача roadmap не разрешена
  автоматически.
- Не менять статусы `[ ]`/`[~]` на `[x]` до выполнения acceptance criteria и evidence-теста.
- Не создавать commit, push, release, notarization submission и не активировать системное
  расширение без отдельной явной команды.
- Не изменять исторические review/memory файлы задним числом; добавлять датированное уточнение.

## 9. GitHub workflow для задач roadmap

Для выполнения roadmap используется строго одна execution task за итерацию. Execution task —
отдельный нумерованный пункт ближайшей очереди `docs/IMPLEMENTATION_PLAN.md`; вложенные подзадачи
остаются checklist одного issue, если владелец явно не потребовал отдельные issues.

1. До реализации создать или найти GitHub issue с требованиями, зависимостями, acceptance criteria,
   проверками, рисками и stop condition.
2. Создать отдельную branch от актуальной целевой ветки. Не смешивать несколько execution tasks и
   несвязанные пользовательские изменения.
3. Выполнить ровно одну задачу через `execute-one-sdd-phase` и создать три артефакта через
   `create-session-artifacts`.
4. После прохождения Definition of Done создать commit, содержащий код, тесты, документацию и
   session artifacts. Сообщение commit должно описывать одну задачу и при наличии ссылаться на issue.
5. Push и создание PR разрешены только для заранее определённого GitHub repository. PR связывается с
   issue, содержит evidence, выполненные/невыполненные проверки, риски и rollback.
6. Дождаться завершения CI и review. Исправить подтверждённые замечания в той же branch, повторить
   проверки и обновить PR; спорные рекомендации объяснить evidence, а не применять автоматически.
7. Не выполнять merge без отдельного явного разрешения. После чистого review остановиться и ждать
   команды `take next step` для следующей execution task.

Если `origin` отсутствует, GitHub authentication недействительна или repository не определён, не
создавать новый repository по предположению и не начинать следующую execution task: сообщить blocker
владельцу. Один roadmap checkbox не равен автоматически отдельному issue — массовое создание issues
требует согласованной гранулярности.
