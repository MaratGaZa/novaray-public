# RULE-001 — Execution task metadata

## Purpose

Execution task numbers must be stable, reviewable identifiers, not inferred only from Markdown list
rendering. Each new roadmap execution task needs enough metadata for reviewers and future agents to
trace what was approved, implemented and merged.

## Scope

This rule applies to new or materially edited execution tasks in `docs/IMPLEMENTATION_PLAN.md`,
especially the nearest queue and the append-only task log. Historical entries created before this
rule may remain in their original prose format until they are touched for another approved reason.

## MUST

- Record a stable `Task ID` for every new execution task.
- Record the task title.
- Record a short description of the approved scope.
- Record the GitHub issue, or `TBD` only before the issue exists.
- Record the pull request, or `TBD` while no PR exists yet.
- Keep task status separate from PR status: `[x]` means task acceptance criteria passed, not merely
  that a PR exists.
- Preserve historical task IDs; never renumber old tasks to make a table prettier.

## MUST NOT

- Refer to a task only by Markdown list position when creating, reviewing or reporting work.
- Use a bare issue number as a substitute for the task title or description.
- Mark live/system evidence as complete because a harness, plan, protocol or PR exists.
- Rewrite historical review or memory artifacts just to retrofit metadata.

## Valid Examples

```md
| Task ID | Status | Title | Description | Issue | PR |
|---|---|---|---|---|---|
| 64 | `[x]` | Refresh native-right next queue | Record that task 63 merged and live native mutation remains blocked without a disposable environment. | #98 | #99 |
```

```md
64. [x] Refresh native-right next queue — issue #98, PR #99:
    Record that task 63 merged and that `native-right-roundtrip --run` remains blocked without a
    disposable environment and separate per-run approval.
```

## Invalid Examples

```md
Next task: #98.
```

The issue number is not a task ID, title or scope.

```md
64. [x] Done.
```

The entry has no title, description, issue or PR.

## Exceptions

- Archived pre-rule entries may keep their original format unless they are materially edited.
- A future task may list `PR: TBD` before a PR exists, but the PR field must be updated by the
  delivery PR that completes the task.
- A documentation-only task may omit Rust test commands from its validation, but not the task
  metadata.

## Validation

Review `docs/IMPLEMENTATION_PLAN.md` in every execution-task PR. New or materially edited task
entries must expose `Task ID`, title, description, issue and PR either in the nearest-queue table or
in the task entry itself. `git diff --check` must pass.

## Changelog

- 2026-09-14: Initial rule after task 64 showed that inferring task identity from Markdown list
  numbering was too ambiguous.
