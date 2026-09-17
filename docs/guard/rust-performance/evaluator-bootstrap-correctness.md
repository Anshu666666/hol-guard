# Direct compatibility evaluator: first-request preparation

This source investigation follows the separately committed HTTP/storage-burst
correction at `90f3a5073fee9cf7132f725c6938c59b90253bbc`. It addresses the direct
fixed-size evaluator test, not native installed latency or overall release
qualification. Its original 24 offers, four workers, 1.8-second review budget,
one-second fan-in assertion and accepted failure-code set remain unchanged.

## Observed boundaries

Test-owned spawn wrappers recorded only process/stage identifiers, monotonic
timestamps and closed outcome fields, without request values, SQL or keys.
C-level snapshots ran in the evaluator and guardian separately. All four
workers reported ready before offers and received their reviews promptly.
Store construction took 12–23 ms and worker-object construction took 3–7 ms in
the first diagnostic; neither observation establishes a general latency bound.

At 0.8 seconds, two evaluators were building the immutable built-in catalog
target manifest, one was importing compatibility/rendering code, and one was
processing action-context JSON. The guardians were correctly waiting for
evaluator replies. All four reviews timed out at the existing budget; the
remaining 20 offers returned the expected not-ready result.

Moving compatibility code and immutable manifest preparation before readiness
removed those cold operations from the first request, but did not immediately
make the test pass. Subsequent diagnostics identified the existing redacting
JSON emitter importing the rich renderer, and harness canonicalization loading
all 16 adapter implementations. Payload preparation also imported four harness
preparers regardless of which harness sent the request. These intermediate
failures remain evidence; a later passing test does not change their outcomes.

## Bounded correction

The evaluator prepares admitted Python-oracle code, the existing renderer and
the immutable built-in target manifest before announcing readiness. The
existing `python_oracle_surface_enabled` predicate controls this preparation.
Normal `auto`/`force`, an unadmitted oracle and nondiagnostic `shadow` do not
enter it. Preparation failure prevents a ready message.

This preparation receives no guard-home or request input. Store construction,
configuration, authenticated local/managed authority, approval checks and
request evaluation stay on the request path. The existing manifest cache
continues to require the same built-in registry object, extension tuple and
catalog digest, and returns copies. It does not cache an authority decision.

CLI canonicalization now uses the existing static contract map, including all
accepted aliases and unchanged unknown strings. Payload preparation imports
only the selected harness preparer. It still normalizes the selected result
with the caller's original alias, and returns the original payload object for
unrelated harnesses. Rendering and redaction behavior are unchanged.

## Validation scope

The original state-readiness test and direct fan-in test passed together after
the complete correction. The state test checks exact guard-home file digests,
runtime state, receipts and approvals before and after real worker readiness.
Eleven deterministic bootstrap tests separately cover admission gates, ordering,
failures before readiness and immutable-cache isolation. Ten import regressions
cover identity, unrelated payloads and each selected preparer; the existing
25 harness-contract tests also passed.

A broader four-module run retained **91 passes and one failure**. The direct
fan-in, state-readiness and 48-review tests passed in that run, while
`test_deferred_runner_bounds_backfill_deferral_during_active_reviews` failed
its unchanged eight-second capacity wait. A separate instrumented rerun of that
backfill test passed. It recorded 9.81 seconds for the first worker's readiness
under its existing 30-second startup budget, and 3.16 seconds for both deferred
workers under the eight-second wait. Those deferred evaluators spent 0.386 and
0.408 seconds in the added oracle preparation, and 1.73 and 1.67 seconds in the
pre-existing `commands_hook` bootstrap import. The diagnostic does not establish
why the broader run missed the deadline; its failure remains unresolved. Moving
required cold work before readiness also adds startup work, which must continue
to meet the existing readiness budgets.

The final deterministic bootstrap, import and harness-contract batch passed
46 tests. The Python semantic callgraph gate passed all 15 configured roots;
Ruff lint and formatting passed. Scoped type checking reported zero errors and
eight warnings. No source gate, failure-code assertion or timeout was relaxed.

Private diagnostic logs and bounded stage/stack captures are retained with
file hashes and byte counts in the review evidence directory. They contain no
request payload values, SQL or authentication keys. These are source diagnostics:
no original timeout or failed result was reclassified, and no installed/paired
performance qualification is claimed.
