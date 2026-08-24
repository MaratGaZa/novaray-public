# Learning: connect transaction planner

Date: 2026-08-24 19:33 Europe/Samara

## What changed

Added a pure core planner that turns a full-tunnel connect intent into an ordered `AppliedNetworkState` in `Planned` phase.

The generated plan contains deterministic operations for:

- preserving the VPN endpoint route outside the tunnel;
- setting tunnel interface address;
- setting tunnel MTU;
- setting DNS;
- applying firewall / kill-switch policy placeholder.

Every operation has a stable key, explicit `apply_order`, and rollback metadata before any future privileged boundary receives it.

## Patterns used

- Model before mutation: build and validate a complete transaction plan before execution.
- Keep `Debug` redacted even when serialized state must contain real network details.
- Add typed inverse operation descriptors instead of using shell strings or opaque rollback text.
- Keep idempotent execution separate from deterministic planning.

## Durable terms

- `ConnectNetworkIntent`
- `ConnectNetworkTransactionPlanner`
- planned `AppliedNetworkState`
- stable operation key
- explicit `apply_order`
- typed inverse descriptor

## Deferred work

The planner does not execute operations. Helper/runtime execution, idempotent repeated commands, and real OS rollback remain separate future slices.
