# Installed posture transition qualification

RSP-034 requires mode toggles, stricter workspace overlays, expiry, restart,
failed publication and races to preserve the adopted behavior matrix. The
existing `native_slo_mixed` scenario already exercises public allow/block action
changes and resident restart under ordinary HTTP load, with matching published
and resident-accepted bindings and durable native receipts. Its policy remains
Enforce. Static Watch corpus cases, expiry corpus cases and pending Codex
approval faults do not independently demonstrate ordinary-hook mode transitions.

The additional `posture_transitions` scenario supplies that missing installed
fixture. Its actual execution belongs to the existing paired hosted workflow.
Local source tests and transport doubles are not installed acceptance evidence.
Local installed execution was not attempted because the previously retained
AF_UNIX `EPERM` restriction prevents a valid resident run in this environment.

| Group | Actual operations | Required witnesses |
| --- | --- | --- |
| Mode round trip | Public `update_guard_settings` selects Watch; contain and restart the resident while Watch is acknowledged; public settings select Protected | Authenticated before/after binding, original 400 ms ACK barrier, overlapping ordinary HTTP attempts, exact request-mode/native-receipt/delivery coherence, committed receipts |
| First workspace | Create a permitted `sandbox_analysis="strict"` workspace file; its first ordinary HTTP use registers it while the real generation lock is held | Previously unregistered workspace, first-use readiness withdrawal, explicit unavailable delivery while publication is blocked, stronger compiled policy/digest after ACK, ignored workspace attempts to select Watch |
| Failed publication | Hold the actual private generation lock; request Watch through the public settings API; observe the publisher's existing lock timeout; release the lock | The actual fixed `native_policy_snapshot_generation_lock_timeout`, unavailable delivery and absent publisher readiness while held, then automatic recovery under the unchanged 400 ms ACK requirement |
| Expired authority | Reuse the real signed short-lived renewal and authenticated readback helper while ordinary requests run | Preserved policy/control binding, actual accepted short-lived authority, explicit resident `snapshot_expired`, unavailable ordinary delivery, stopped renewal, rejected readiness |

The publication failure is a physical generation-lock fault. It does not claim a
fabricated negative native ACK or a resident protocol rejection. Releasing that
lock is the recorded recovery trigger. The fixture does not notify a private
publisher method, reapply settings or silently retry a missed automatic recovery
barrier. A missed ACK remains failed installed evidence.

Four workers send ordinary authenticated Claude/Codex PreToolUse and PostToolUse
HTTP requests. Each request has a unique correlation ID, a 4,000 ms remaining
budget and the existing 5 second transport timeout. The synthetic dangerous
command and output only request review; no tool is executed. Before and after
probes require each of the four routes. During-transition observations may use
either independently authenticated binding, or the frozen explicit unavailable
response. They cannot replace a missing native decision with an inferred allow,
borrow another concurrent request's counter delta, or count an unknown denial
or fallback as successful coverage.

Watch preserves the intrinsic native block. The observer checks the exact
request generation/digest/runtime, the acknowledged mode and actual Python
observe argument, the native semantic result, and the receipt's intrinsic
decision/action/reason. It separately checks the final delivered response
against the frozen corpus oracle for that mode. Every observed receipt is
reconciled through the existing installed-arm reader; the candidate requires
the validated binding-aware store getter. The pinned baseline retains its
explicit audited legacy reader and is never silently upgraded.

The observer wraps real functions only to record arguments and returned
receipts. It never replaces evaluation, ACKs, clocks, authority, policy decisions
or response rendering. Ordinary requests traverse authenticated HTTP even
though this diagnostic load generator runs inside the disposable daemon
process. These runs do not contribute startup, latency, resource or migration
benefit samples. The private control implementation is imported lazily so the
new observation code is not added to unrelated fixture startup.

Collection is finite: at most 64 attempts per worker per transition, three
transitions per shared fixture, 1,024 attempts per fixture, 32 records per page,
one 10 second completion drain, and the existing 5 second writer drain. Native
readiness stays at 400 ms. The product's original platform publication timeout
stays unchanged. The outer private control operation retains its 30 second
deadline. Each physical-fault group has a fresh private daemon/home; failed or
unsupported groups remain failed while independent groups still collect.

The private JSONL retains each attempted request, safe delivered semantics,
request binding, receipt identity, persistence result and failure. The published
aggregate has flat per-transition and per-group proof: attempted/completed
counts, overlap, actual native/fail-safe/other route totals, Watch/Enforce
deliveries, authenticated bindings, receipt commitments and fault witnesses.
Page order and total counts must conserve all offers and observed receipts.
An outer `run_block.additional_scenarios.posture_transitions` sanitize-and-JSON
roundtrip test keeps required proof within the existing privacy depth limit.

The first source batch retained 95 passed / 1 failed in 8.88 seconds. The failed
test reached the actual generation-lock timeout but its source-modeled publisher
did not automatically recover within 400 ms after release. A single diagnostic
run with extra state reporting passed in 3.14 seconds. Neither attempt proves
an installed recovery result or a production cause; neither is discarded. The
source physical-lock regression now checks the real fault, public invalidation
and release with a deliberately incomplete continuation result. A separate
deterministic test verifies that the installed `ack()` implementation uses one
unchanged 400 ms deadline and rejects stale, late and mismatched authenticated
readback. The real installed scenario still requires that original recovery
deadline. The frozen implementation passed all 111 source regressions in 7.06
seconds. Static analysis covered seven new files with zero errors and 478
warnings; formatting, lint and whitespace checks passed. The
[source validation manifest](evidence/installed-posture/source-validation.json)
retains the five attempts, exact log digests, source hashes, coverage and
unchanged limits. Hosted acceptance remains pending until a real run and its
authenticated receipts are retained.
