# Foreground evidence cost and original failure observations

This implementation adds measurement coverage for RSP-121 and observations needed
to investigate the twelfth cohort's existing failures. It changes diagnostic
scripts and tests. The Rust decision core, ordinary installed responses, frozen
baseline and original performance gates are unchanged. Its source and validation
are pinned in [RELEASE_REVIEW](RELEASE_REVIEW.md).

## Foreground submission cost

The original RSP-121 criterion is: “Attribute full payload copies/JSON before
response, queue admission, native receipt validation and rejected work; use
maximum envelopes.” The eleventh authenticated phase groups already cover small
and maximum ordinary HTTP envelopes on all four candidate platforms. The maximum
HTTP body is 1,000,000 bytes; the separate native protocol ceiling is not the
ordinary HTTP maximum. Each of the eight groups records four activity and four
receipt submissions, all returning true. They provide no rejected-submission
latency. Earlier bounded component diagnostics cover saturated rejection at
their separate source and inclusive timing scope.

The new `EvidencePhaseObserver` observes the existing receipt validator module,
its writer and journal aliases, receipt identity serialization, receipt JSON and
SHA-256 operations, writer JSON, and compact activity serialization/validation.
It retains original arguments, objects, return values, exceptions and classmethod
binding. Byte counts use already-produced buffers; measurement does not encode
or traverse an additional payload. Only the declared foreground route context
can contribute timings or work counts. Reader and background work is excluded.
Original aliases and module bindings are restored on exit.

Coverage records distinguish unsupported bindings, incomplete setup/teardown,
observed calls and complete windows with zero calls. The original eight normal
hook offers, sizes and deadlines remain unchanged. The report validator requires
the applicable evidence work and permits an observed early activity rejection
to have no subsequent activity serializer calls. It does not manufacture those
calls to make the count check pass.

The real-writer correctness fixtures exercise a unique acceptance, deduplication,
saturation and invalid receipt, including maximum-input behavior and capacity
available before or exhausted after receipt submission. They establish observer
behavior, not an installed performance distribution. Inclusive submission spans
do not isolate evidence-queue admission or the receipt's mapping copy. A true
submission result can mean acceptance or deduplication, and does not prove durable
enqueue. No SQLite VFS, full qualification or optional Rust-spool implementation
is added as a prerequisite to the original criterion. RSP-121 remains OPEN for
the remaining measured attribution and rejected-work evidence at declared scopes.

## Mac baseline resolver observation

Both frozen Mac baselines still stop in `HTTPServer.server_bind` → `getfqdn` on
the bound loopback address. Existing hosts/PTR maintenance has not established a
remedy. One diagnostic sampler now targets the already-started direct-libSystem
probe, only after that probe's fixed call-entry marker and only in the before
phase. It uses the same UID and `/usr/bin/sample`; no elevated command or baseline
source patch is introduced.

Sampler acquisition ends 750 ms before the original five-second phase deadline,
reserving a bounded 500 ms containment wait. The sampler and probe retain their
unreaped process identities until owned process-group cleanup. Probe cleanup
remains separate from its lookup timeout. Incomplete cleanup prevents measured
arms from starting. This does not establish the absence of arbitrary descendants
from earlier failed qualification fixtures.

Each sampler output stream is bounded to 64 KiB. A usable graph must bind the
owned probe PID, have recognized call-graph records and an end marker. Public
output contains fixed frame-presence categories and explicit missingness. A
complete graph followed by collector-induced SIGKILL remains an observed graph;
it is separately marked as not having an observed successful process exit. A
probe killed during exit cannot become a successful lookup. Partial, malformed,
unbound, oversized or late output cannot prove frame absence or an OS cause.
Raw output is retained in one fixed-name private archive member. Local parser
tests are synthetic; actual Mac permissions, format and capture require CI.

## Original launcher and recovery failures

The twelfth Windows Claude failure returned `{}` at optimized-Python PostToolUse
sample 14. The validator rejects that object before the original after-route
read, so the historical empty after map was unobserved. The new failure path
takes one existing fixture metrics snapshot after the measured process interval
has ended, then rethrows the original validator exception. That control read has
its existing 30-second receive bound. There is no polling, hook retry or extra
native request. Only bounded known route counters are retained; captured zero,
captured empty, invalid and unavailable are distinct. A global count does not
prove which route produced the rejected response. The success path keeps its
original route validation.

The twelfth Intel recovery failure returned `native_post_tool_unavailable` after
the resident stop had returned true. Its later cleanup artifact cannot identify
the stop before that failed request. The recovery witness therefore observes
the original stop diagnostic and original recovery call, with bridge stages
collected inside the actual worker thread. It adds no status or transport call,
retry or waiting period. Its bounded snapshot closes at the original observe
return, before journal I/O; late worker completion cannot rewrite the recorded
failure. Unsupported, overlapping, in-flight or failed projections remain
explicit. Original exceptions are preserved. Stage-observer overhead belongs to
an instrumented diagnostic, not a claimed performance improvement.

## Evidence custody

The prior local recovery key could not be found after the workspace reset.
The active public recipient was rotated only after a new offline key was saved
and an authenticated round trip succeeded. Historical receipts and their
recipient IDs are unchanged; a new key cannot recover old archives. See
[private qualification evidence](private-qualification-evidence.md) for the
current fingerprint and recovery limits. This rotation affects diagnostic
archive encryption, not runtime signing or policy authority.
