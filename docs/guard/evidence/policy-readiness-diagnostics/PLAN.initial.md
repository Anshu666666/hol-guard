# Windows policy-readiness diagnostic gap

This is a read-only source review and proposed private-fixture change.
No production readiness, publisher, validator, deadline, corpus, or fixture
source has been modified for this investigation.

## Exact observations and provenance

Paired run `35330471726`, Windows job `105553416357`, artifact `10541486704`
is pinned by archive SHA-256
`4989afbe1b210d6bfdf0fcfa9421ed9359f09c03e88531a1ed13b8ec8b42bbad`.
Its eight JSON members were independently byte/hash verified. They identify
candidate source `590ce01334a7724f3f1349b2ab252110a5a268f5` and frozen
baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b`. The paired wheel hash
reported by the candidate is
`7888659f1a24365ce998ecb61c5c7f9495382c9a45a720710bbd2a6f6b856c89`.
This archive does not retain the wheel itself. The separate native-wheel job
built merge `698155...`; its verified installed source is useful corroboration
of the shared source tree, not byte proof for this different paired wheel.

`pi.PostToolUse.empty-output.empty` failed the unchanged route validator. The
response was `allow` with `native_policy_not_ready`; the wrapped hook-native
call count and completed-call count were both zero. Worker timeout,
containment failure, and resource-limit flags are false. That zero counts the
wrapped hook-native function, not all publisher/native IPC in the process.

The separate installed Ollama probe completed its two initial cases, then
failed enabled-phase readiness at expected revision 1. It retained elapsed
0.0 ms, `budget_exhausted=false`, no returned snapshot, publisher not ready,
publisher not closed, and `publisher_error="unclassified"`. This proves a
nonempty error outside the probe's closed allowlist was observed. It does not
identify that error. Several ordinary exception labels, including
`operationalerror`, are already in the allowlist; the unknown value must not
be called SQLite BUSY merely because the same platform also recorded a
receipt persistence failure.

Neither retained digest encodes the missing publisher error. The candidate
digest hashes the generic route-mismatch assertion; its reason-code digest
hashes `native_policy_not_ready`. The Ollama digest hashes the generic
readiness-failure assertion. The full job log contains no additional publisher
exception detail. The two failures remain unqualified and their common cause
is unproven.

## Source-bound explanation of the missing evidence

`HookWorker.prepare_workspace_policy` skips `wait_until_ready` when a nonempty
publisher error already exists. It then tries the existing acknowledged
snapshot/binding and returns `None` if none is usable. This is an existing
bounded failure path; 0 ms alone is not evidence that the 400 ms budget was
exhausted or needs increasing.

`prepare_native_hook_policy` produces `native_policy_not_ready` before the
wrapped hook-native function is called. Therefore `observe_native_call` never
captures publisher fields in this case. The production helper
`_native_policy_not_ready_reason` does read the current publisher error and
returns it inside its existing reason string, but PostToolUse availability
rendering deliberately drops that reason string and emits the mechanical
continuation response. The private fixture currently retains neither value.

The reason helper's AST is exactly identical between frozen 2e and candidate
590. This gives a narrower observation point than wrapping readiness itself:
observe the existing reason string immediately after the original helper
returns, before the renderer discards it. There is no need to recheck readiness,
wait again, read configuration, touch a native client, or change a deadline.

The existing Ollama collector already has the exact `publisher.last_error`
value in a local variable after timing ends. It discards any unlisted value as
`unclassified`. The list omits many fixed Windows policy storage/ACL, snapshot
generation, and command-binding codes, as well as some Python error classes.

`read-only-witness.json` exercises these original functions with inert doubles.
Two distinct fixed errors (`native_policy_windows_acl_verify_failed` and
`native_policy_snapshot_generation_lock_timeout`) both skip the readiness wait
and collapse into byte-equivalent logical Ollama failure data and the same
PostToolUse response. The original reason helper produced distinct strings,
confirmed by their hashes. No native transport or installed qualification was
executed, and these are demonstrations of information loss, not claims about
the hosted causes.

## Proposed minimal private-fixture change

1. Add a small bounded publisher-error serializer in
   `scripts/native_slo_publisher_diagnostic.py`. It accepts only exact plain
   strings, exports a code only from a reviewed closed set of public source
   codes, and otherwise retains a fixed `unlisted` state with a bounded
   SHA-256 fingerprint and completeness flag. Missing and invalid values are
   distinct from observed zero. Never emit arbitrary text, error objects,
   paths, local identities, or raw ACL data. For the parameterized Windows ACL
   code, export only the fixed base code plus a fingerprint of the bounded
   original; do not export its free-form suffix. The same 128-character bound
   already used by native-call diagnostics remains sufficient for the
   publisher's bounded stored label. The closed set is static and source
   reviewed, never discovered by filesystem reads during a request.
2. In `FaultFixture.__enter__`, wrap only the existing module helper
   `_native_policy_not_ready_reason`. Call the original once with the same
   server object, return the identical result, and let its original exceptions
   propagate unchanged. Capture only when the server object is exactly this
   fixture's owned daemon. Parse the known fixed reason prefix/trailing period
   and record only the bounded error diagnostic. Diagnostic failures must not
   replace the original return or exception. This adds work only on an already
   failed policy-admission path and leaves successful timed paths untouched.
3. Keep one last refusal record and an observation count under the fixture's
   existing capture lock; reset them in `before_case` and restore the original
   helper on context exit. Add `policy_refusal_diagnostic` and
   `policy_refusal_count` to the private result and copy them to the existing
   corpus failure envelope. A missing observer is unavailable, not a claimed
   zero. This does not change native-call counters or validation behavior.
4. In the existing Ollama failure branch, serialize the already-read `error`
   variable into additive flat fields inside `readiness`. Keep the original
   `publisher_error` value, started/finished timestamps, readiness method call,
   deadline, `is_ready`/`closed` reads, flags, exception, and failure result
   exactly as they are. No additional publisher property or clock call is
   needed. This captures an unknown code without changing either acceptance
   or the existing measured duration.
5. Keep the original workload/oracle source, requirements, six-level privacy
   limit, corpus count/order, 400 ms readiness budget, 3-second hook payload
   budget, route predicates, and all production package files unchanged.
   The change is confined to private diagnostic helpers, fault/corpus plumbing,
   the Ollama failure collector, and focused tests. Recheck the actual Desktop
   binding inventory; no generator change is expected from these paths.

This records the exact explanatory code selected by the existing handler or
collector. It does not prove that a cached error caused every refusal: an error
can be absent, or asynchronous state can change. It also cannot reconstruct
exception details already discarded inside the publisher before `last_error`
was set. If a future report retains only a generic class label, that remains
the stated evidentiary limit; it must not be expanded into an invented cause.

## Focused validation after approval

- Run the original production pre-admission/availability functions with a
  controlled unready publisher and verify the output/route rejection stays
  exact while the existing reason survives in the private diagnostic with zero
  wrapped hook-native calls.
- Distinct error codes that previously collapsed to `unclassified` retain
  distinct bounded evidence; unknown/private text and parameterized ACL values
  never appear as raw strings. Test overlong/Unicode values and hostile custom
  objects without invoking their callbacks.
- A publisher change immediately after the reason helper returns cannot alter
  the already captured explanatory code. Unowned server calls are ignored;
  the original helper receives the same object and is invoked only once.
- Verify exact return identity and exception identity, context restoration,
  reset between cases, no extra readiness/native/client calls, and unchanged
  native-call accounting. Inject a diagnostic-only error and retain the
  original behavior.
- Extend existing Ollama tests to require the exact original 400 ms deadline,
  two timestamp reads and legacy fields alongside the new error evidence.
- Round-trip the full failure envelope through the unchanged privacy validator
  and preserve the route validator's rejection. No corpus threshold changes,
  retry of old cohorts, or local native-transport workaround.
- Run focused fault/native-diagnostic/Ollama/privacy tests, changed-file Ruff,
  formatting and type checks under the shared lock; retain an AST/source scope
  proof and the original diagnostic-gap witness.

## Retained source review

`provenance.json` records 14 exact 590 Git blobs, current file-byte matches,
all eight paired archive member hashes, the missing paired-wheel limitation,
and the identical frozen/current reason helper AST. The `source/` captures,
`observed/` JSONs and finite read-only witness make this plan reviewable.
