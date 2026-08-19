# ADR-005: Versioned engine catalog and offline update workflow

- Status: Accepted
- Date: 2026-08-20
- Decision owner confirmation: explicit implementation approval after review of the sing-box 1.13 compatibility regressions

## Context

Engine configuration dialect and engine artifact version are separate axes. The sing-box generator
already required changes for removed legacy `sniff` fields and deprecated `block` outbound syntax.
Selecting an arbitrary binary version while generating the current dialect would move this failure
from CI to the user. The checksum matrix also needs a repeatable maintainer workflow as releases
change across five declared targets.

## Decision

`engine_catalog.json` is the checked-in runtime source of truth. Each artifact entry contains engine,
version, upstream revision, target, archive/binary SHA-256 and lifecycle status. Catalog validation
requires unique `(engine, version, os, arch)` keys, full declared-target coverage per version,
lowercase SHA-256 values and exactly one `recommended` version per engine.

Lifecycle values are `recommended`, `supported`, `deprecated`, and `yanked`. Runtime uses only the
single recommended version. A future selector may offer only versions whose generator compatibility
has separately been proven; it must reject `yanked` versions. Changing the recommended version is a
separate reviewed change with a changelog entry.

`scripts/update_engine_catalog.py` is a maintainer-operated network tool. It downloads explicit
assets, verifies the supplied archive SHA-256, hashes the extracted binary, and emits a candidate
catalog plus evidence. It never runs at application runtime or in ordinary CI.

## Alternatives

- Keep one Rust literal per engine: rejected because release update evidence remains manual and
  artifact identity stays coupled to configuration strategy.
- Runtime latest-release lookup: rejected because remote metadata cannot replace reviewed binary
  extraction, reproducibility, or fail-closed trust.
- Add `--engine-version` now: deferred until version-to-generator compatibility is modeled and tested.

## Consequences and validation

The catalog can retain rollback releases, but lifecycle policy prevents a yanked release becoming a
default. Offline unit tests validate catalog invariants; maintainer review independently verifies
upstream assets and the generated evidence. Rollback is a reviewed change of `recommended`, not a
silent updater side effect. This ADR changes no privileges, signing, entitlement, or distribution
boundary.

## Revisit conditions

Revisit before exposing version selection, adding runtime download/update behavior, or changing the
declared target matrix.
