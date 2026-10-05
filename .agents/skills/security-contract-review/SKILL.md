---
name: security-contract-review
description: Risk-triggered review NovaRay для security-sensitive parser/generator boundaries, state transitions, partial mutation, cleanup/containment, recovery и redaction. Использовать как дополнительный adversarial pass, а не вместо SPEC, tests или основного review.
---

# Skill: security-contract-review

Статус: ограниченный experiment. Не считать skill окончательно accepted до evaluation после 4–6 недель или минимум пяти applicable PR.

## Когда применять

Применять только если изменение затрагивает хотя бы одну область:

- parser security policy или импорт недоверенного URI/config;
- public generator/serialization boundary;
- network/security state transition;
- bootstrap/revocation;
- privileged mutation;
- cleanup, containment или recovery;
- redaction security-sensitive diagnostics.

Для обычного refactor, docs-only typo или изменения вне этих boundaries skill не запускать.

## Evidence audit

Для каждого high-impact claim зафиксировать:

| Claim | Evidence | Coverage / boundary | Gap |
|---|---|---|---|
| Что утверждается | test/run/code observation | public/internal/runtime/system | что осталось unverified |

Правило: **сила claim не должна превышать силу evidence**.

## Adversarial pass

1. **Fail-closed.** Malformed, ambiguous, timeout и `Unknown` не должны превращаться в разрешённое/безопасное состояние по умолчанию.
2. **Public/internal parity.** Public entrypoint должен сохранять те же invariants, что internal helper; другой путь вызова не должен обходить guard.
3. **Derived representations.** Проверить отдельно представления одной сущности на разных boundaries: parser value, normalized value, engine address, URI authority, HTTP `Host`, gRPC authority, SNI и diagnostics.
4. **State transitions.** Illegal/repeated transition и stale/wrong ownership должны отклоняться до mutation.
5. **Partial mutation.** Для каждого mutation point спросить, что произойдёт при ошибке, panic, timeout или `Unknown` на следующем шаге.
6. **Cleanup / containment.** Проверять observable postcondition, а не только факт вызова cleanup-функции или log line. Containment failure не должен скрывать primary error.
7. **Residual state.** После failure/recovery явно классифицировать owned process/transport/routes/DNS/firewall/exceptions/established state как absent/present/unknown там, где это применимо.
8. **Redaction.** Проверить `Display`, `Debug` и public errors после normalization/validation: credentials, UUID, raw URI/query, server/user addresses и owner identifiers не должны отражаться.
9. **Negative / mutation evidence.** Для каждого нового guard нужен хотя бы один test, который упадёт при удалении, перестановке или ослаблении guard.

## Verdict discipline

Не заявлять `safe`, `verified`, `[x]` или `ready` только по code inspection, если acceptance criterion описывает observable runtime/security postcondition. Недоступное packet/system evidence фиксировать как gap.

## Experiment telemetry

Для applicable PR записать:
- какие пункты skill реально сработали;
- finding до merge;
- later review correction;
- false positive / unnecessary check;
- verification gap;
- outcome: `helped`, `neutral`, `harmful` или `insufficient evidence`.

После 4–6 недель или минимум пяти applicable PR провести evaluation. Skill не становится accepted автоматически.
