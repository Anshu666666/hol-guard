# Evaluated hook identity diagnostic

This RSP-025 diagnostic observes the identity work of three actual evaluated
hooks in a separate, normally prepared installed fixture. It supplies source
instrumentation for the next qualification run, not a new measurement result.
The implementation starts from source `3eb1cea3c565821c40a36c95fedac54149185312`.

The first request is **the first hook after normal resident preparation**. The
next two requests are warm hooks in the same fixture. Preparation may already
have validated the binary and populated the capability cache. The observer
records that cache's initial entry count and never clears it, retires a live
proof, restarts the resident, retries a failed lookup, or changes admission.
Neither this first request nor the existing fresh-launcher series establishes
a cold resident, cold executable, cold capability cache, or cold OS cache.
An actual unprepared cold-hook partition remains outside this diagnostic.

## Route and observations

`native_slo_qualification_scenarios.py` creates a new `DaemonFixture` with the
unchanged `normal` setup, separate from headline timings and the existing
Python phase scenario. `native_slo_identity_run.py` sends the existing 1 KiB
benign Claude `PostToolUse` phase case three times. The original attempt helper
checks its exact serialized request identity, current setup witness, one
`native_resident` route increment, native decision and delivered response. A
fixture that has already received any hook is rejected before offering work.

`native_slo_identity_phases.py` wraps the original implementations and calls
each once. It does not synthesize a runtime status, native response or cache
result. Per hook, the finite report retains:

| Observation | Exact meaning |
| --- | --- |
| Status calls and exceptions | Entries into the canonical status implementation on current source; exact public aliases on the frozen baseline. |
| Status wall and thread CPU nanoseconds | Inclusive status spans in the hook's calling thread. They are diagnostic timings, not process-tree CPU or headline latency. |
| Binary validation calls and returned identities | Calls to the original `_validate_binary`, including exceptions. |
| Executable bytes hashed | Bytes accepted by SHA-256 during those validation calls; arguments, bytes, paths and digest values are omitted. |
| Live proof calls and hits | Actual `live_native_identity` lookups when that source implements them. This is separate from capability caching. |
| Capability calls, hits, misses and ambiguity | Original LRU counter deltas checked against actual capability subprocess calls. Concurrent counter changes or an unclassifiable outcome remain ambiguous. |
| Capability subprocess calls | Actual runtime calls with the exact `capabilities --json` arguments during the hook. |

The observer uses the hook handler's context, so unrelated background work is
not charged to the hook. Global LRU counter interference cannot be assigned
as a hit: it makes the diagnostic incomplete. The observer admits at most
three expected serial hooks. Unexpected routes, overlap, missing status work,
an unfinished dispatch, ambiguous cache attribution, or failed cleanup also
prevent completeness. Wrapper restoration waits up to one second for active
hooks to drain; this is an observer cleanup bound, not a production deadline.
The enclosing fixture retains its original process-containment behavior.

## Accounting, retention and limits

The private `*-identity-cases.jsonl` journal uses the existing exclusive owned
file writer and its 8 MiB bound. The fixed diagnostic adds at most three offer
and three terminal attempt records, one observer record, and start/finish
records. The aggregate is retained separately in `*-identity-summary.json`
through the existing additional-scenario path and encrypted evidence archive.
Raw arguments, paths, output, credentials and exception text are not added to
the observer report. Its control reply uses an exact field schema and bounded
three-row list; unknown fields and invalid metric types are rejected.

`offered` counts successfully retained attempt offers, not dispatched hooks.
The summary separately counts request calls confirmed by terminal evidence
(`request_started`), attempts that failed before the request call
(`request_not_started`), and offered attempts whose terminal evidence could
not be retained (`request_start_unknown`). A reservation, changed-wire or
offered-record failure does not become an offer. All unoffered work remains
explicit. The first original failure survives observer cleanup, and partial
observer data remains incomplete. Fixture construction failure is retained by
the existing additional-scenario failure record; no hook result is invented.

This scenario adds three diagnostic requests per arm **only when its stage is
reached**. It does not change original main phase or headline offers, limits,
acceptance gates, production behavior, baseline source, or receipt validation.
The exact candidate source and installed runtime remain bound by the existing
qualification context. An earlier failed stage can leave this scenario
unexecuted, which is not a passing or zero-cost observation.

The source tests exercise the real binary validator's byte count and exact
original-result/exception forwarding, cache state preservation, frozen public
aliases, cache-counter interference, finite projection, accounting failures,
the unchanged native/delivery oracle, and separate scenario wiring. They are
collector correctness tests, not installed performance measurements. RSP-025
cannot be closed from these tests alone: platform observations and the literal
cold-path gap must still be assessed from actual retained evidence.
