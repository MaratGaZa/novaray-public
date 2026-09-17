# Native Authorization Right Validation Protocol

Status: proposed experiment protocol, not execution authorization or native evidence.
Implementation update: 2026-09-16, issue #102, task 66 (non-mutating preflight only).
Prior implementation update: 2026-09-14, issue #96, task 63 (base-case harness only).
Owner: MaratGaZa. Date: 2026-09-13. Issue: #92. Execution task: 61.
Parent decision: [ADR-009](./ADR-009-MACOS-HELPER-RUNTIME-AUTHENTICATION.md), still `Proposed`.

## 1. Purpose and current boundary

Specify the isolated experiment needed before a native mutation adapter can be reviewed. This
document does not implement a runner, authorize a host change, prove a database roundtrip, accept
normalization, or close Gate H / Gate I / ADR-009. Its adoption approves only the written protocol.

Current evidence has three distinct levels:

| Component | Proven | Not proven |
|---|---|---|
| [Ownership classifier](../src/helper_runtime_right.rs), #86 | bounded exact single-rule matching | provenance or system normalization |
| [Read-only inspector](../src/macos_runtime_right.rs), #88 | native reads, CF ownership/type checks | write/read equivalence |
| [Lifecycle executor](../src/helper_runtime_right_execution.rs), #90 | recording call order, readback checks, bounded cleanup | authorization, atomic ownership, external-writer exclusion, crash recovery |

The next implementation may build an explicitly opt-in experimental harness only after review of
this protocol. A real run additionally requires the per-run owner approval below. Neither an
ordinary test command nor CI may mutate the authorization database.

## 2. Checked facts and inference

Checked on 2026-09-13 against installed macOS SDK 26.2 `Security.framework/Headers/AuthorizationDB.h`
and the Apple pages below (their Markdown representations were read when HTML required JavaScript).
This revision does not redate older ADR facts or claim that native writes were tested.

- `AuthorizationRightGet` reads a definition without an authorization reference and returns a
  dictionary the caller must release. SDK `errAuthorizationDenied` means no definition for this
  particular API. [Apple RightGet](https://developer.apple.com/documentation/security/authorizationrightget%28_%3A_%3A%29)
- `AuthorizationRightSet` can create **or update**, uses authorization for modification, and rejects
  wildcard names. The SDK lists denied, canceled and interaction-not-allowed outcomes; none is a
  missing-definition observation for a write. [Apple RightSet](https://developer.apple.com/documentation/security/authorizationrightset%28_%3A_%3A_%3A_%3A_%3A_%3A%29)
- `AuthorizationRightRemove` takes an authorization reference and explicit name, not an expected
  previous definition or version. [Apple RightRemove](https://developer.apple.com/documentation/security/authorizationrightremove%28_%3A_%3A%29)

Inference limited to these APIs: their signatures do not supply a conditional create-if-absent or
compare-and-delete primitive. A get/set/get sequence is not a transaction. This is not a claim that
every possible macOS coordination mechanism has been ruled out.

Protocol policy (proposal, not an Apple guarantee): a per-run random name and process-local lock
reduce accidental collision/concurrent harness execution, but cannot constrain another authorized
writer. An exact definition or matching digest identifies content, not who wrote it. A disposable
environment limits experiment damage; it does not solve production ownership races.

## 3. Admission checklist for a future run

All items require recorded evidence and explicit owner approval before the first mutation:

- [ ] Dedicated disposable macOS installation on Apple Silicon, with no user workloads, production
  credentials or managed authorization policy. A VM is acceptable only after its required Security
  Services behavior and snapshot/restore procedure are separately verified; VM support is not assumed.
- [ ] Owner-approved environment identifier, macOS build, SDK/toolchain, reviewed runner commit and
  binary digest recorded privately. No run on the developer workstation by default.
- [ ] Whole disposable-environment snapshot/reimage baseline and a tested out-of-band restore path.
  Restore must remain possible after the runner dies; an authorization-database file backup alone
  is not an approved restore mechanism. Snapshot creation/restoration itself requires owner approval.
- [ ] Controlled writer set recorded: one test controller; no parallel runners, policy management or
  other administrative writers. If that condition cannot be established, stop before mutation.
  Deliberate interference tests below are separate runs and never authorize production use.
- [ ] One fresh test name in `org.novaray.validation.runtime-right.<32-lowercase-hex>` selected by
  the harness and approved for this run. No wildcard, caller-selected arbitrary name, production
  `org.novaray.platform-helper.runtime`, or built-in right may be a mutation target.
- [ ] Native preflight reports that exact test name absent; lookup failure is not absence. Any
  existing definition, including an exact match, aborts a fresh run. Never adopt a prior run's right.
- [ ] Owner approves the exact create/read/remove operations, any planned fixture updates and
  interruption points, time budget and permitted authorization interaction on that environment.
  Approval is not implicit in `take next step`, commit/push/PR, or the existence of this document.
- [ ] Authorization reference acquisition/release and denial/cancel paths are reviewed separately
  in the runner. Any interaction is confined to the operator-side experiment controller. No helper
  prompt, credentials in command lines, broad fallback right, or unattended escalation is allowed.

The harness must keep its test namespace separate from the public fixed-runtime-right API. Do not
make `inspect_macos_runtime_right` accept arbitrary names or implement the fixed-name lifecycle
adapter using a test name. Reuse only reviewed internal decoding/observation logic where appropriate.

## 4. Bounded procedure and evidence matrix

Each row below is a separate controlled case starting from the approved clean baseline unless the
row explicitly tests an in-run retry. No automatic retry of a failed mutation. After each mutation,
readback records observed state, never atomic provenance. Existing classifier rules remain unchanged.
Cases requiring a compatible created definition are blocked if normalization is incompatible; they
must not be reported as passed or enabled by weakening the classifier within the experiment.

| Case | Required observation | Stop / recovery |
|---|---|---|
| Clean baseline | fresh test name absent; production runtime name only observed read-only if needed | existing/unknown test state: no writes |
| Create candidate | one Set with exact `rule = authenticate-admin` dictionary; record status, then complete bounded CF shape inspection after success | any error: effects unknown; no cleanup delete |
| Native normalization | record returned key count, CF types, string-vs-array rule, and whether existing strict classifier accepts | extra metadata or another shape: incompatible, not silently stripped |
| Exact in-run retry | only after successful compatible readback; re-inspection produces no second Set | mismatch/error: preserve and stop |
| Conflict / superset | reviewed non-granting or additional-metadata synthetic test policy, installed only by the approved controller in this isolated run, is rejected by reconciliation | no overwrite or delete by subject under test |
| Normal uninstall | successful compatible create, uninterrupted controlled run and fresh exact observation; one Remove followed by absence readback | error or non-absence: stop; no second Remove or policy recreation |
| Remove retry | after verified removal in the same run, absent inspection causes no second Remove | changed state: stop |
| Failed create | denied/canceled/interaction failure or injected uncertain-return boundary retains primary failure and `CreateEffectsUnknown` semantics | no blind deletion, even if later read looks exact |
| Failed readback / cleanup | after successful create, independently fault readback and each cleanup stage; preserve primary error plus cleanup outcome | fresh conflict/unknown state is never deleted; no retry loop |
| Controlled writer interference | insert a controller write between inspection and Set/Remove and between mutation and readback | record overwrite/removal exposure or other outcome; this tests a limitation, not race safety |
| Process termination / reboot | terminate at the approved before-call, after-call-before-result and after-result-before-verification boundaries; inspect from a new process | interrupted ownership is uncertain; no automatic resume/delete |

Post-write dictionary evidence must include **all** fields in bounded structural inspection, not
just the fields the classifier understands. Do not log arbitrary values: record known key identifiers,
unknown-key counts, CF type categories, lengths and accepted/rejected classification. A digest may
be recorded privately only for deterministically encoded, reviewed synthetic fixture content; it
must not be used to claim ownership. Size/type/encoding overflow stops the case without truncating
the input into an apparently valid definition.

If macOS returns system metadata, a rule array or another shape, the result is valuable evidence of
incompatibility with #86/#88, **not** permission to normalize it away. Preserve the strict rejection;
propose a separately reviewed decoder/ownership change with new tests before retrying that path.

## 5. Cleanup and crash recovery boundary

Automatic per-right cleanup is eligible only after a known successful create in the same
uninterrupted, controlled run and a fresh compatible exact observation. These are experiment
preconditions, not a general compare-and-delete guarantee. A local lock never upgrades them to one.

On lost writer control, unexpected definition, failed create, interrupted process, reboot,
unreadable state, cleanup failure or normalization mismatch: stop writes, release in-process
resources, retain a redacted result, and quarantine the disposable environment. Do not delete a
right merely because its name/digest matches. Fresh inspection is diagnostic, not recovery authority.

The operator then restores/reimages the **whole dedicated environment** from the approved baseline
through the out-of-band procedure. This intentionally discards that experiment, including deliberate
conflict fixtures; it is not an in-place uninstall and must not run on a shared workstation. Verify
baseline health and test-name absence before reuse. If restoration cannot be verified, leave the
environment quarantined and mark the experiment blocked. Do not copy the authorization database
file back manually, weaken SIP/Gatekeeper, or broaden privileges to force cleanup.

A private durable run manifest must record stage intent before each mutation and its result after
return, without authorization bytes or raw policy. Missing/corrupt/unflushed manifest or a crash
between these writes means unknown effects, not permission to resume. The manifest helps diagnosis;
it is neither a database transaction nor proof of provenance.

## 6. Evidence and completion gates

Evidence includes environment/build, reviewed commit/digest, approved case identifier, stage order,
API status category, bounded shape classification, primary/cleanup outcomes and baseline restore
verification. Keep authorization references/external forms, session IDs, credentials and raw policy
out of logs, manifests, fixtures and PRs. Public reports use sanitized case labels, not host identity
or the run's random right name. Bound waits in the future runner; timeouts enter unknown-effect
recovery, not retry. The operator approves a per-case deadline before execution.

These are unfulfilled native gates; this documentation task changes none of them to `[x]`:

- [ ] Reviewed opt-in harness enforces environment/name/operation gates, resource lifetimes,
  bounded inspection and fault injection; default local/CI tests cannot write the database.
- [ ] Owner-approved disposable environment and restore drill satisfy section 3.
- [ ] Native create/read shape is measured; either strict compatibility is demonstrated or a
  separately reviewed incompatibility decision is recorded. Recording tests are not this evidence.
- [ ] Success, retry, conflict, uncertain effects, cleanup failures and interruption cases have
  native evidence plus verified restoration. A destructive race demonstration is not a passing
  production-safety result.
- [ ] A separate production mutation design resolves or explicitly rejects the remaining
  external-writer/provenance risk. This protocol does not enable the fixed runtime-right adapter.

External-form authorization success/denial/invalidation, same-UID attacker behavior, authenticated
IPC and helper runtime remain the separate [ADR-009 validation spike](./ADR-009-MACOS-HELPER-RUNTIME-AUTHENTICATION.md).
Even a completed experiment here does not accept ADR-009 or prove Gate H/I.

## 7. Alternatives and rollback

Rejected for this experiment: mutate the real runtime right on the workstation; add only a process
lock and call it race-safe; drop system fields until classification passes; remove any matching name
on startup. All hide an unproven ownership or recovery assumption.

Chosen proposal: isolate a test-only harness and recover uncertain state by discarding the approved
disposable environment. Cost: environment setup and manual approval; no reusable production writer
yet. Revisit if controlled isolation, authorization, restore or bounded evidence cannot be achieved.

Documentation rollback is a code-review revert with no host cleanup. Implementing or running this
protocol, accepting normalization changes and promoting ADR-009 each require their own review and
owner authorization; none follows automatically from merging the documentation PR.

## 8. Opt-in base-case harness (2026-09-14, #96)

The `native-right-roundtrip` Cargo example requires `native-right-experiment`; neither the normal
CLI nor helper calls it. `--help`, `--preflight`, compile checks, recording tests and CF fixtures
never mutate the database. `--preflight` performs only automatable local launch checks: macOS Apple
Silicon target, stdin/stdout/stderr as terminals, absence of `CI`, current directory owned by the
current non-root user with mode `0700`, and absence of `native-right-roundtrip.jsonl`. It does not
call Security.framework, acquire authorization, prompt, inspect or mutate the authorization database,
create the manifest, generate a test right name or approve a run. A successful preflight only allows
manual owner review to continue; it does not prove disposable environment, restoration, controlled
writers, reviewed binary, native evidence or Gate I/H. `--run` is macOS Apple Silicon only, refuses
root/setuid execution, non-terminal
stdin/stdout/stderr and any `CI` environment variable. These are accident-prevention guards, not
authentication or proof that a machine is disposable. Run authorization remains the owner's
separate decision under section 3, including independently checked restoration and writer control.

This implementation covers only the clean baseline/create/normalization/remove/absence base case.
Fault injection is recording-adapter evidence. Exact retries, deliberate conflict/interference,
native injected failures, process termination and reboot cases in section 4 are not implemented as
native cases. None of section 6's native gates is completed by compiling this harness.

The controller starts a 120-second whole-process watchdog, including operator input and native
calls. Expiry exits with code 3 without cleanup, leaving effects unknown. Ordinary return releases
the Authorization reference using RAII; abrupt termination does not promise resource cleanup in
Security Services. A private current directory must already exist, be owned by the unprivileged
operator with mode 0700, and contain no prior `native-right-roundtrip.jsonl`. The directory is held
open and locked; the manifest is created relative to that descriptor with exclusive/no-follow
flags and mode 0600. A symlink or existing manifest is refused. The lock coordinates only this
directory, not other database writers. There is no resume/cleanup command and no manifest reader.

Before any authorization request the terminal displays a fresh 128-bit system-RNG test name, the
binary file's SHA-256 and actual OS build. The operator must independently compare the reviewed
binary and enter one JSON line (maximum 4096 bytes, including newline) with exactly these fields:

```json
{"environment":"PRIVATE-ENVIRONMENT-REFERENCE","os_build":"DISPLAYED-BUILD","sdk":"REVIEWED-SDK-TOOLCHAIN","reviewed_commit":"40-lowercase-hex","reviewed_sha256":"64-lowercase-hex","restore_evidence":"PRIVATE-RESTORE-DRILL-REFERENCE","disposable":true,"restore_tested":true,"exclusive_writers":true,"allow_authorization_interaction":true,"confirmation":"CREATE READ REMOVE GENERATED-TEST-NAME 120"}
```

Placeholders are intentionally invalid. Do not paste credentials, external forms, policy values
or unrelated host data. The generated name is approved only for this uninterrupted run; it is not
an input to a public right-name API. The booleans and references are operator attestations, not
automated verification. Hashing the executable file does not attest the loaded process image;
the environment must prohibit replacing the reviewed binary during the run. The commit/SDK and
restore references are validated for shape, not independently established by this program.

The private manifest records approval, stage order, write intent and returned write status,
complete bounded CF structure, and final result. Each entry is followed by `sync_all`; creation also
syncs the directory. Limits: 16 KiB per record, 64 KiB total, 16 members per container, 64 visited CF
nodes, depth 3, 128 UTF-16 units per string and 1024 bytes per data value. Evidence includes known
key identifiers, unknown key categories, types and lengths, never raw values/unknown names. Overflow
stops the run, not truncates a policy into a compatible shape. Power loss or missing writes remain
unknown effects, not recovery authority. Public reports must exclude the private manifest/challenge.

Order: absent baseline -> authorization -> fresh absent check -> synced create intent -> one Set ->
synced result -> full structural inspection and unchanged strict classifier -> fresh exact check ->
synced remove intent -> one Remove -> synced result -> absence readback. No automatic retry. Any
uncertain write, incompatible/read failure after create, changed definition, manifest failure or
deadline means quarantine and separately approved whole-environment restoration. The harness is
more conservative than the recording production lifecycle executor: it performs no compensating
delete on a failed readback. Exact equality plus a local lock still does not prove provenance.

Exit codes: 0 means the base case observed final absence, not successful restoration or production
safety; 2 means refusal before database mutation; 3 requires quarantine/unknown-effect handling.
Even code 0 does not waive the protocol's restoration verification before environment reuse.

FFI signatures/ownership were checked on 2026-09-14 against installed SDK 26.2 `Authorization.h`
and `AuthorizationDB.h`, and Apple documentation for
[AuthorizationCreate](https://developer.apple.com/documentation/security/authorizationcreate(_:_:_:_:))
and [AuthorizationRightSet](https://developer.apple.com/documentation/security/authorizationrightset(_:_:_:_:_:_:)).
Create uses null rights/environment and defaults to obtain a reference; Set/Remove can require
operator interaction. No external authorization forms, shell commands or fallback rights are used.
Denied/canceled/interaction-not-allowed writes are failures, never absence. This is implementation
review evidence, not a live authorization/create/read/remove result.

## 9. Readiness evidence package (2026-09-16, #104)

The public [readiness template](./native-right-readiness.template.json) defines the shape of the
private evidence that must be reviewed before a future `native-right-roundtrip --run` task can be
approved. The committed template is intentionally non-authorizing: it contains placeholders, keeps
all run-enabling booleans `false`, permits only `--preflight-only`, contains no generated test right
name and requires `confirmation` to remain `NOT A RUN APPROVAL`.

`scripts/check_native_right_readiness_template.py` validates that the committed template stays
structurally aligned with this protocol and cannot be mistaken for a runnable approval. It fails if
the template claims disposable readiness, restore success, exclusive writer control, authorization
interaction, a real-looking reviewed commit/SHA-256, a generated test right name or a run approval
confirmation. The validator is offline and does not call Security.framework, inspect the
authorization database, create a manifest or run the experiment.

A future native-run task must create a private per-run evidence package outside the public
repository and compare it with the live runner output for the concrete disposable environment,
restore drill, reviewed binary and generated test name. That private package is not reusable across
runs and must not be committed. Passing the public template validator is only a documentation/CI
guard; it does not prove the environment is disposable, restoration is tested, writers are
controlled, the binary is reviewed, native evidence exists or Gate I/H is complete.
