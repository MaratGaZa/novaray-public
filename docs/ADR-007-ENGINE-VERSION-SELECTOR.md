# ADR-007: Engine version selector

- Status: Accepted
- Date: 2026-08-22
- Decision owner: MaratGaZa
- Next review: before adding uncatalogued/unsafe binary selection, runtime download/update, or user-facing deprecated-version override UX

## Context

ADR-005 introduced the versioned engine catalog. ADR-006 Engine version compatibility bound configuration dialects to exact
catalogued engine releases and kept `--expected-sha256` as a byte override, not a version selector.
NovaRay now needs a CLI selector for catalogued versions without allowing uncatalogued binaries to
opt out of compatibility checks.

## Decision

`novaray-core start` and `connect` may accept `--engine-version <VERSION>`. The value selects a
catalogued version for the engine chosen by `--engine-config`; when omitted, NovaRay keeps using the
engine's single `recommended` catalog version.

Selection is resolved before binary path validation, checksum lookup, checksum verification,
pre-flight, or process spawn. `recommended` and `supported` releases are selectable. `deprecated`
releases are selectable only with a visible warning before process start. `yanked`, unknown,
uncatalogued, or configuration-incompatible versions fail closed.

`--expected-sha256` remains a checksum-byte override. It may supply expected bytes for an unsupported
OS/arch target, but only for the selected catalogued version after lifecycle and dialect checks pass.
It does not prove the binary's version and does not enable truly uncatalogued versions.

## Alternatives

- Trust the engine's own `version` output: rejected because the binary is not trusted until after
  checksum verification.
- Let `--expected-sha256` imply an uncatalogued version: rejected because it would bypass ADR-006 Engine version compatibility's
  compatibility contract.
- Add an unsafe uncatalogued override now: deferred; it needs a separate explicit security contract.

## Consequences

Maintainers can add multiple catalogued versions without changing CLI shape, but every selectable
version still needs catalog metadata, lifecycle status, compatibility dialect, and real-engine
preflight evidence. Future update/download work remains outside this ADR.

## Evidence and revisit

The first selector implementation exposes only the already catalogued Xray `v26.3.27`/`XrayV26` and
sing-box `v1.13.18`/`SingBoxV1_13` pairs. Both had real macOS arm64 generated-config preflight
evidence in ADR-006 Engine version compatibility. Revisit this ADR before adding uncatalogued/unsafe binary selection or runtime
download/update.
