---
name: review-plan-before-approval
description: Проверить roadmap и implementation plan NovaRay против SPEC, ADR, кода и тестов до утверждения или выполнения, выдать severity findings, dependency map и readiness decision.
---

# Skill: review-plan-before-approval

## Шаги

1. Прочитать обе SPEC, применимые ADR, `ARCHITECTURE.md`, `TESTING.md`, roadmap, implementation plan,
   затрагиваемый source/tests и последние review. При сомнении применить `reconcile-current-state`.
2. Для каждого acceptance criterion определить owner component, prerequisite phase, test/evidence,
   failure behaviour и rollback. Фаза не может зависеть от работы, запланированной позже.
3. Отдельно проверить gates: Apple Developer/signing/entitlements, direct distribution против App
   Store, NetworkExtension против helper, engine embedding, FFI ownership, DNS/IPv6, kill switch,
   split routing, crash recovery и clean-Mac verification.
4. Findings упорядочить P0/P1/P2/P3. Неизмеренные performance/security утверждения помечать
   unverified, а не принимать как критерий успеха.
5. Дать решение `ready`, `ready with conditions` или `blocked`. P0/P1 остаются blocking до указанной
   проверки.
6. Представить три таблицы: Current-State Claim Check, Phase Dependency Check, Readiness Conditions.
   При запрошенной записи результата применить `create-session-artifacts`; код не изменять.

## Checklist

- [ ] Planned не засчитано как implemented.
- [ ] Все обязательные dependencies принадлежат более ранней или текущей фазе.
- [ ] Каждый P0/P1 имеет owner и required verification.
- [ ] Paid-account/system gates нельзя заменить mock evidence.
- [ ] Readiness decision однозначен.
