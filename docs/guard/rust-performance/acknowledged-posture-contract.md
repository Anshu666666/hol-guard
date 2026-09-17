# Acknowledged posture on ordinary native hooks

RSP-031 and RSP-032 use one resident-acknowledged policy binding for both native
evaluation and Python response transformation. The signed v3 snapshot already
contains the complete effective policy and its collapsed `mode`; its request
binding carries generation, policy digest, runtime identity and mode. No schema,
native protocol, authority store, or availability policy changes are required.

The earlier optimization removed configuration reads only when the binding was
already `observe`. An enforcing binding still loaded configuration and ORed the
local Watch setting into response transformation. Native evaluation ignores
that caller-supplied observe flag and evaluates its accepted snapshot. Python
could therefore turn the enforcing result into a Watch continuation before the
resident accepted the weaker mode, and omit an enforcing command-control lease.

The ordinary `_review_native_edge` path now derives `recording_only` once from
the same binding it passes to native evaluation. It does not read home or
workspace configuration for that decision. Explicit off/shadow compatibility
surfaces retain their existing separate handling.

## Visibility contract

| Request binding | Local configuration before a new ACK | Ordinary posture |
| --- | --- | --- |
| Accepted `enforce` | Protected | Enforcing |
| Accepted `enforce` | Watch | Enforcing until the replacement is acknowledged |
| Accepted `observe` | Watch | Recording only |
| Accepted `observe` | Protected | Recording only while this remains the accepted binding |
| No accepted binding | Any configuration or missing files | Existing native-unavailable result; no evaluated decision |

The ENFORCE-ACK to unacknowledged Watch case is an intentional correction.
An unacknowledged local setting cannot weaken an enforcing native decision or
disable its command-control fence. It follows the same acknowledgement boundary
already used for the opposite transition.

Successful public configuration mutations invalidate in-process publisher
readiness and request publication before returning. A publishing worker obtains
no request binding while that barrier is closed. Failed or superseded ACKs do
not reopen it. A raw file edit becomes visible through the existing publisher
observer and reconciliation path; this change does not add a synchronous file
watch or promise visibility before that observer detects the edit. Cross-process
and non-publishing workers retain their existing authenticated resident-state
readback and native generation checks.

First use of a workspace registers it and withdraws the home-only binding before
publication. Current configuration rules prohibit workspace files from selecting
mode, posture, security level or action overrides. The transition regression
therefore exercises the accepted stricter `sandbox_analysis = "strict"` overlay,
checks the changed policy digest and effective snapshot, and also checks that a
workspace Watch request cannot weaken protected home posture. The signed policy
continues to merge accepted overlays using the existing stricter-floor rules.

Expiry, generation rollback rejection, resident restart, publication epochs and
the command-control mutation lease retain their existing owners and deadlines.
The worker does not cache a posture across requests. An in-flight request keeps
the binding it acquired; resident evaluation and existing authority fences still
determine whether that binding may execute. No config reread substitutes for
those checks.

## Availability and evidence

Without a binding, the production native edge returns no native decision. The
existing availability renderer is posture-independent, so removing its unused
configuration read preserves the same harness JSON, exit behavior and route
attribution. Such continuations remain unavailable outcomes and do not count as
native evaluated allows. Completed policy results, Watch transformation rules,
integrity/size errors and permission/lifecycle handling use the existing renderers.

The [source operation-count diagnostic](evidence/acknowledged-posture/source-candidate.json)
and [installed baseline component](evidence/acknowledged-posture/installed-baseline-component.json)
each run seven fixtures, with 100 calls per fixture. Every source candidate case
records zero configuration loads, home config opens and workspace config opens.
The installed baseline records one configuration load per call and one open of
each present config file; its missing-file fixture has no config opens. Both
reports bind the measured worker module by SHA-256. The workspace fixture uses
the accepted strict sandbox overlay.

The source diagnostic deliberately stops at the first native transport call.
Its bindings are synthetic and it creates no native result. Its timings are not
eligible for installed or headline performance claims, and comparing its elapsed
times with the installed baseline would not qualify an installed speedup.
`--expected-contract acknowledged-only` asserts both the selected mode and zero
config reads; the default installed diagnostic remains available for the next
candidate wheel.

Source regressions cover all combinations of enforce/observe/missing binding,
Watch/protected local configuration and PreToolUse/PostToolUse; one binding lookup
and identical binding delivery; zero configuration reads; and enforcement-fence
preservation. A real-config, signed-snapshot source fixture drives public
Watch/protected mutations, failed and accepted ACKs, and first-workspace
publication through the production publisher. Its transport and native results
are explicit source doubles. Existing publisher, expiry, restart, authenticated
readback, mutation-fence and availability suites remain required. Actual installed
transition/load qualification remains RSP-034/RSP-035 and the platform gates.

The [source validation record](evidence/acknowledged-posture/source-validation.json)
retains every focused test attempt. The broader batch completed with 124 passes,
one Windows-only skip and two fixture-path failures: placing ordinary workspace
tests under `/dev/shm` conflicts with the unchanged emergency-safe `/dev/`
restriction. Both passed when rerun under an ordinary scratch workspace, with
no product or budget changes. The initial workspace-posture fixture correction
is also recorded. Four scoped Python files type-check with zero errors; Ruff
check, formatting and diff validation pass.
