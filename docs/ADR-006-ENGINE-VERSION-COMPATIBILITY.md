# ADR-006: Engine release and configuration-dialect compatibility

- Status: Accepted
- Date: 2026-08-21

## Decision

`EngineConfigStrategy` owns a typed configuration dialect, while the catalog owns artifact versions.
Startup validates their compatibility before checksum resolution or process spawn. The current proven
pairs are Xray `v26.*` with `XrayV26`, and sing-box `v1.13.*` with `SingBoxV1_13`.

## Consequences

An incompatible release fails closed with a typed error. Future selection may expose only proven
`recommended`/`supported` pairs, warn for `deprecated`, and reject `yanked`. Runtime update remains
out of scope. Real preflight evidence is required when adding a pair.

## Evidence and revisit

On 2026-08-21 the pinned macOS arm64 Xray `v26.3.27` and sing-box `v1.13.18` passed generated-config
preflight. Revisit this ADR before adding a new dialect or `--engine-version`.
