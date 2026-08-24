# Review: connect transaction planner

Date: 2026-08-24 19:33 Europe/Samara

## Scope

Implemented issue #26 as one pure Rust core slice: model full-tunnel connect as an ordered recoverable network transaction plan.

Changed project files:

- `src/network_transaction.rs`
- `src/network_state.rs`
- `src/lib.rs`
- `docs/SPEC_RU.md`
- `docs/SPEC_EN.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `learning/05_roadmap_zero_to_hero.md`
- `docs/TESTING.md`

## Findings

No blocking findings after local verification.

Implemented:

- `ConnectNetworkIntent` and `ConnectNetworkTransactionPlanner`.
- Ordered `AppliedNetworkState` generation in `Planned` phase.
- Stable operation keys and explicit `apply_order`.
- Planned descriptors for endpoint route preservation, tunnel address, MTU, DNS, and firewall policy.
- Rollback metadata for every planned mutating operation.
- Additional typed inverse descriptors needed by future helper execution.
- Redacted debug output for endpoint, DNS, and user network identity.

Deferred:

- helper runtime;
- IPC transport;
- launchd/root;
- `utun`;
- route/DNS/firewall/system proxy execution;
- idempotent repeated command execution;
- packet-flow evidence.

## Evidence

Commands run from `project/`:

```bash
cargo test network_transaction --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
git diff --check
python3 scripts/check_markdown_links.py
```

Observed result:

- `cargo test network_transaction --all-targets`: 5 planner tests passed.
- `cargo clippy --all-targets -- -D warnings`: passed.
- `cargo test --all-targets`: 141 lib tests plus integration suites passed; 5 opt-in runtime tests remained ignored.
- Markdown links: `checked_markdown_files=48 broken_links=0`.

## Verification gaps

- No real helper consumes the plan.
- No OS route, DNS, firewall, system proxy, or `utun` mutation happens.
- No repeated connect/disconnect idempotency is implemented yet.

## Recommendation

Merge only after CI confirms the same Rust/docs gates. The next execution task should address repeated-command idempotency or helper/runtime consumption as a separate issue, not extend this planner slice.
