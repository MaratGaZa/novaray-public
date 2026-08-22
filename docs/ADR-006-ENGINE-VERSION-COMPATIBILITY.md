# ADR-006: Engine release and configuration-dialect compatibility

- Status: Accepted
- Date: 2026-08-21

## Decision

`EngineConfigStrategy` owns a typed configuration dialect, while the catalog owns artifact versions.
Each catalog release records the exact configuration dialect proven for that engine/version pair.
Startup resolves the engine's single `recommended` catalog version, validates the strategy dialect
against that catalog release, and only then chooses the checksum source or spawns a process.

`--expected-sha256` overrides the expected binary bytes only. It does not select an engine version
and does not bypass the configuration-dialect compatibility check. This keeps unsupported OS/arch
targets usable with a trusted checksum while still binding them to the current recommended catalog
version.

## Consequences

An incompatible release fails closed with a typed error. Catalog validation rejects unknown dialect
strings and rejects engine/version rows that disagree on dialect across targets. ADR-007 exposes
only proven `recommended`/`supported` pairs, warns for `deprecated`, and rejects `yanked`. Runtime
update remains out of scope. Real preflight evidence is required when adding a pair.

## Evidence and revisit

On 2026-08-21 the pinned macOS arm64 Xray `v26.3.27`/`XrayV26` and sing-box
`v1.13.18`/`SingBoxV1_13` pairs passed generated-config preflight. Revisit this ADR before adding a
new dialect or truly uncatalogued/unsafe binary overrides.
