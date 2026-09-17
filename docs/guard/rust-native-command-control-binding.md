# Native command control binding

The optional `command_extensions` field extends `hol-guard-native-policy.v3`
with `guard.native-command-control-binding.v1`. Its program, catalog, and trust
digests identify the exact packaged native matcher program. Its health, local
revision, managed revision, effective digest, and complete layers reproduce the
existing Python `ExtensionControlRuntimeSnapshot` projection. Native execution
still requires the resident to admit that exact packaged program.

The production publisher requires `native-command-program-v1` together with
the existing snapshot/resident capabilities. A missing capability, missing or
invalid program, catalog mismatch, invalid control binding, or failed verified
authority read closes readiness. It does not emit an unbound legacy snapshot as
a substitute. Direct snapshot builders retain their explicit legacy mode:
omitting `command_extensions` preserves the existing policy digest, signing
bytes, and canonical JSON exactly.

## Authenticated authority and freshness

The publisher worker calls
`GuardStore.read_extension_control_authority_for_registry`. This verifies the
credential-backed local authority and independently authenticated managed
activation/revision, including existing catalog migration behavior. Plain
persisted-authority readers omit managed activation and are insufficient for
this projection. The reader does not compile IR or evaluate matchers.

The immutable control runtime retains independent local and managed revision
floors. A lower protected revision, or different protected effective state at
the same pair of revisions, is rejected. Existing degraded/tampered health is
preserved, and a later unhealthy observation does not erase protected revision
floors.

Local enrollment, mutation, recovery, resumed transitions, and catalog
migration invalidate registered native publishers before mutation under the
authority lock. Managed activation and removal use that same ordering. The
publisher acquires the authority lock to read committed controls; callers do
not wait for resident ACKs while holding store locks. An epoch check rejects an
older in-flight ACK. Readiness reopens only after verified projection,
authenticated snapshot publication, and a matching resident ACK.

DB/WAL metadata remains an invalidation hint. Bounded markers cover the signing
material, local authority snapshot/latest transition, and managed active/revision
state. Receipt, activity, and unrelated sync-state churn leave these markers
unchanged. Periodic reconciliation independently re-verifies authority, and a
verified read after the resident ACK detects controls changed by another
process during publication. A database marker never supplies control authority.

This tranche does not provide a cross-process mutation-completion handshake.
After an independent writer returns, an already acknowledged publisher in
another process discovers the change through DB/WAL observation or periodic
verified reconciliation. The default poll interval is 250 ms and the independent
reconciliation timer is one second; verification and lock waits add time, so
these intervals are not a hard maximum staleness guarantee. Immediate
cross-process revocation requires an authenticated resident invalidation or
authority-epoch protocol.

Existing `GuardStore.recover_extension_control_authority` can call
`_reset_extension_control_authority` and rebootstrap local revision zero. The
publisher's ordinary verified reader and the resident's persisted protected
floor deliberately reject that decrease after observing a higher revision.
`ExtensionControlRuntime.replace_after_recovery` is an explicit in-process
recovery path; it does not authorize resetting the native resident's durable
floor. Native readiness after such a reset requires a separately authenticated
recovery/epoch handoff. Health changes alone never clear an anti-rollback floor.

## Bounds and digest compatibility

| Boundary | Limit and behavior |
| --- | --- |
| Program artifact | At most 4 MiB, regular file, duplicate JSON keys rejected; domain-separated program digest checked before metadata is used |
| Metadata cache | Two exact captured byte strings, at most 8 MiB total; file timestamps alone cannot preserve a cache hit |
| Metadata JSON | At most 64 levels, 16,384 children per collection, and 1,000,000 visited values |
| Control layers | At most two, with distinct `local-admin`/`signed-cloud` kinds |
| Controls | At most 512 per layer; unique `(target_kind, target_id)` within each layer |
| Targets | ASCII `command.*` identifiers, at most 256 characters, with permission kind matching `.permission.` |
| Revisions | Independent unsigned 64-bit local and managed counters; booleans are rejected |
| Snapshot transport | Existing 256 KiB total snapshot/push envelope limit remains; oversized complete projections fail explicitly |
| Synchronous hook read | Existing small in-memory generation/digest/runtime/mode binding; no artifact, database, registry, or compiler reads |

When a binding is present, the policy digest adds
`command_extensions_digest = SHA256(canonical binding JSON)`. The generation
fingerprint and snapshot materialization receive the same captured binding.
The existing HMAC authenticates the whole body, including that binding.

Rust's combined authority record may also contain `command_control_floor` with
the highest protected local/managed revisions and effective digest. The Python
cache reader validates this optional shape and its domain-separated floor MAC.
The legacy floor MAC remains unchanged when the field is absent. The floor is
anti-rollback evidence and is never used as a replacement for verified policy.

## Evidence

`tests/test_native_command_control_binding.py` covers existing effective-digest
parity, complete 512+512 control projections, malformed/unknown fields, mutable
caller isolation, absent-field byte compatibility, control-only generation
changes, exact-content metadata caching, malformed/oversized artifacts,
independent revision floors, and optional authority-floor authentication.

`tests/test_native_command_control_binding_publisher.py` covers capability
incomparability, missing-program failure, pre-commit invalidation and ordered
ACK, control changes during ACK without a local callback, local opt-in together
with managed restrictions, managed removal/rollback, WAL tampering, and the
in-memory hook binding boundary.

This establishes the Python publication portion of RSP-115. Installed native
matcher admission, complete catalog outcome parity, and end-to-end performance
qualification are separate evidence owned by the native interpreter workstream.
