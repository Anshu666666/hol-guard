# Installed default-auto command fixture provisioning

The round-three Linux installed-wheel run passed all 17 runtime identity
cases, then its normalized daemon-ingress corpus returned a deny for the
synthetic `printf guard` pre-tool request. The old failure record omitted the
public reason code. An independent native command classification returned
`allow` with `native_exact_safe_command`; the intrinsic command classifier
was not the cause of that deny.

The corpus created a fresh GuardStore without enrollment. A fresh authority
is `unenrolled`, and current native command controls deliberately block that
health. The fixture now provisions an empty authenticated authority before
constructing the daemon, following the existing installed Extension Control
Center CI setup: production `EncryptedFileSecretStore`, a newly generated
32-byte key, actual persisted snapshot and anchor, and a verified read of
protected health. Existing or degraded authority is rejected; no test key,
invented health, native ACK, or policy relaxation is supplied.

The receipt labels this setup `isolated_ci_generated_key_empty_authority`
and `enrollment_flow=not_exercised`. Interactive operator enrollment is not
being qualified. The native publisher must still authenticate the real
marker and snapshot and meet the unchanged 400 ms workspace readiness gate.
The expected allow response for `printf guard` is unchanged. Pre-tool
failures now include only fixed public decision, policy and reason codes,
with arbitrary text collapsed to `other`.

Local validation: 31 tests passed, including reopening the persisted fixture
with an independent GuardStore, rejecting an existing authority, rejecting a
bootstrap that did not persist verified state, privacy-safe diagnostics and
the existing receipt, cleanup and mode-invariant suite. Socket-enabled
installed execution is required to establish the final corrected route;
the fixture diagnosis does not retrospectively invent the omitted reason
from the original failed run.

The same provisioner now runs in `AdapterSession` before constructing the
daemon, including normal and fault qualification sessions. Its fixed setup
receipt is retained in `FaultFixture` evidence. J118 Ollama verifies and reuses
that empty protected authority, then configures the real password gate and
uses its existing production mutation approval flow. Default-auto shares the
same provisioner. Existing, degraded, nonempty and nonzero-revision state is
not treated as a fresh fixture.

The exact pinned baseline `2e672d2` has a non-reentrant authority lock. The
shared provisioner uses its concrete locked reader inside a single exclusive
lease; calling the public reader there would reacquire the same lock and
eventually return degraded state. A separate process importing that baseline
source successfully generated and persisted the authority, reopened it with
an independent GuardStore and verified protected empty state. This establishes
source API compatibility, not a new installed performance result.

The release-gate benchmark uses only PostToolUse and now has explicit normal
policy configuration. It does not need command enrollment to scan those
outputs. The general `native_policy_test_support` helper remains generic so
unenrolled, degraded and recovery tests can still exercise their intended
states.

The older large-source SLO helper wrote `.txt` files and accepted a delivered
allow alone. It now writes the same bounded sizes with the eligible `.rs`
extension. Its fixture observes the actual raw Rust result during the real
HTTP request and requires exactly one `allow/allow_original` decision with
the offered content SHA-256 as `reviewed_output_sha256`. Missing output,
wrong digest, absent or duplicate native decisions, and other authority fail
the workload. The wrapper keeps only bounded metadata and is restored before
the next case. Digest verification happens outside the recorded HTTP elapsed
interval; the tiny capture callback executes within it. This does not alter
the native byte, deadline or admission limits. The newer frozen qualification
corpus already checks this native digest independently.

Focused source regression run after this audit: 133 tests passed across the
session fixture, source witness, fault setup, SLO contracts, startup, installed
Ollama controls, wheel probes and default-auto suites. Platform runs must
still establish actual installed admission and large-source success.

## Round-four source witness failure diagnostics

The macOS Intel native-wheel job `105154528161` in run `35206822343` failed
the exact source witness after its installed identity, default-auto and OMP
plugin probes succeeded. The recorded merge source was
`f7293abfe50cfb8f6b05e99f3e1b9c0449ada61c`. That source already canonicalized
the temporary workspace and wrote eligible `.rs` fixtures with exact byte
writes. The original exception omitted the failing harness, content size and
native result, so it cannot establish whether the cause was absent native
review, a source denial, a deadline, or a digest mismatch. No source-policy
relaxation or retrospective diagnosis is justified by that traceback.

The strict witness now reports a bounded failure summary: allowlisted harness
and size, at most two native observations, fixed authority/decision/action/reason
fields, and digest-present/matching booleans. It also retains bounded native-call
elapsed milliseconds and the original deadline's remaining milliseconds at
entry. These values diagnose elapsed-budget failure; they never refresh or
extend that budget. Two monotonic clock reads and the tiny metadata callback
execute inside the measured HTTP interval; failure formatting remains outside.
No source text, paths, digest values or arbitrary reason strings enter the
failure summary. Unknown values become `other`.

Acceptance still requires exactly one actual Rust `allow/allow_original` result
whose reviewed digest equals the offered full-content digest. Missing output,
multiple calls, denials, wrong digest and non-native results continue to fail.
Installed source qualification remains open until a fresh platform run passes
or identifies a concrete underlying defect through these retained diagnostics.
