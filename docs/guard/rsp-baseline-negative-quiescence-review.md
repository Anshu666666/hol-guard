# Original-baseline negative-attempt quiescence review

This is a design review, not a new cleanup implementation or a passing
qualification receipt. It inspects immutable baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` and the transition collector at
`9be77cd0a` in the CI audit checkout. The failed `abf319d5` attempts remain
failed. A legacy `resident-stop` return code of 2 is not a retirement proof.

The native executable boundary is narrow enough to consider a separate,
strict negative-attempt certificate. The existing helpers do not yet provide
that certificate. A process-group result, absent generation files or one
empty PID scan cannot establish it.

## Active baseline launch graph

| Role | Immutable source evidence | Image and containment |
| --- | --- | --- |
| Python publisher's native client | `native_policy_snapshot_publisher_transport.py`, `_publish_snapshot_v3`; `native_resident_stream.py`, `_start` | Publication supplies `identity.path`; the child runs `resident-client-stream` and starts a new session. |
| Managed supervisor | `managed_resident.rs`, `client_request_with_lease`; `managed_resident_containment.rs`, `spawn_managed_for_owner` | `current_exe()` launches `supervise-managed` in a new process group. |
| Managed server | `managed_resident.rs`, `supervise_managed_for_owner` | `current_exe()` launches `serve-managed`; this active implementation keeps it in the supervisor's group. |
| Capability and explicit stop probes | `native_runtime.py`, `_run_native_process`; collector `verify_failed_start_retirement` | Short-lived calls use the same verified runtime path and must finish before a final census. |

`main.rs` dispatches the resident commands to `managed_resident.rs`. That
module declares its containment, client-stream, lease and transport modules;
it does **not** declare the adjacent `managed_resident_supervisor.rs` or
`managed_resident_stop.rs` files. Their presence in the Git tree is not proof
that their alternative lifecycle behavior is compiled into this baseline.

Automatic runtime selection uses the installed wheel's
`codex_plugin_scanner/_native/hol-guard-runtime` binary. The native-binary and
mode overrides are removed by the collector. The inspected active spawn
chain does not copy or select a second runtime image. Both native descendants
use `current_exe()`. The old Python `native_runtime_resident.py` implementation
also has no importing production caller in the inspected baseline.

There is one relevant exclusion to make explicit: the Linux runtime can
spawn `/usr/bin/secret-tool` through `approval_enrollment_platform.rs`.
`approval_authority.rs::load_locked` and
`approval_v4_authority.rs::load_locked` return before secure-store access when
their signed public enrollment record is absent. This negative fixture does
not enroll a native approval authority or run enrollment commands. A future
certificate must verify that both records are absent before and after the
attempt; it must not generalize this one-image claim to enrolled homes.

## Required proof boundary

1. Preserve the preceding candidate phase's real authenticated retirement
   certificate before replacing its wheel. An observation about the baseline
   image cannot discharge an older candidate generation's ownership.
2. Pin the installed runtime's exact private path, file identity, digest,
   owning installation and current-user ownership before starting the negative
   worker. Keep that installation unchanged until retirement is proven. A
   digest or inode shared with an unrelated installation is insufficient
   scope for signaling; the private path and invocation provenance also matter.
3. Preserve the original readiness rejection, authority bytes, registration
   and prior receipts. Require the exact expected baseline, the established
   rejection reason, an unready and closed publisher, no active hook request,
   and a normal completed worker. A timeout or forced worker termination must
   not acquire this certificate merely because a later scan is empty.
4. Close all sources of new native launches before accepting a final census.
   This includes the publisher, worker-owned clients, capability probes and
   the explicit stop diagnostic. Do not start a new stop subprocess between
   the final census and wheel replacement.
5. Use bounded, fresh **global** process inventories, not only descendants of
   a Python PID that may already have exited. For every possible matching
   process, bind owner, PID, birth identity and the frozen executable image;
   retain observed identities until their termination is established. An
   unreadable identity, truncated inventory, changing executable or unsupported
   host API is an unverified result, never evidence of absence.
6. Prefer an observer-only first version: wait within a separate bounded
   cleanup budget and reject the attempt if any possible survivor remains.
   The baseline's lease expiry is one second, but elapsed time alone is not
   evidence that the corresponding process was scheduled or exited. A future
   forced retirement path needs its own platform-specific ownership proof.
7. Only after this separate proof may the collector preserve the failed
   baseline phase as an expected negative and attempt a fresh candidate
   restore. The baseline phase still does not become a functional downgrade
   success. Re-read the protected state and artifact identities after the
   proof, retaining both the original failed stop and the new certificate.

## Concrete races and helper limits

The Python outer group does not contain native streams created with
`start_new_session=True`, or their managed supervisor groups. Recursive
`psutil` descendants are also insufficient after reparenting.

A process census is not an atomic snapshot of the spawn graph. A client can
spawn a supervisor after the PID list is obtained and exit before its metadata
is inspected; a supervisor can do the same with its server. The active native
graph has finite depth, but an implementation must explicitly close each
role's producer and take fresh inventories after that closure, or use an
equivalent kernel-backed creation/lifetime boundary. Merely repeating an
empty list after an arbitrary sleep does not establish that invariant.

There is an additional boundary during Python `Popen`: the forked child can
enter its new session before it executes the native image. If the Python
worker is killed during that interval, a native-image-only census can miss
the child while it still has the Python image. This is why a forced or
unverified worker exit must not qualify the proposed observer-only path.

`live_process_identity.py` exposes identity checks, but its generic POSIX
fallback uses `ps lstart` and it does not bind a process to an executable or
provide a global census. `native_slo_resources.py` observes descendants for
resource accounting; it is not a containment certificate. The immutable
Rust identity helper uses Linux start ticks or Darwin seconds/microseconds
plus executable-path/digest checks, but its per-process validator is not a
public complete-census operation.

A PID/birth check followed by `kill(pid)` still has a check-to-signal race.
Forced retirement would need a retained process handle or equivalent atomic
identity binding where the host supports it; otherwise that path must stay
unverified. Existing group-kill helpers should not be repurposed into a
global same-user kill mechanism.

The bounded implementation should exercise detached native clients,
supervisor-to-server creation during inventory, a leader exiting before its
child, the pre-exec Python window, PID reuse, permission denial, inventory
overflow, a different image at the same path, a same-digest image in another
installation, surviving legacy processes, and absent enrollment records.
Those checks have not been implemented or run in this review. No process was
signaled, no runtime was rebuilt and no acceptance result was changed.
