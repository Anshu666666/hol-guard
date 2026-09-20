# Bounded workspace request and receipt observation

This component fills one missing RSP-128/129 observation boundary: it joins
an explicitly declared request to the native wrapper result, delivered
response and complete validated SQLite receipt. It reuses the current
publication observer and ACK barrier; it does not create a policy cache,
change publisher readiness, replace the native result, or change a deadline.

Enter the actual `ReceiptWitness` before `WorkspaceRequestObserver`. The
latter captures and forwards that exact installed native-review callable.
Its `probe(index, workspace_index)` calls the existing authenticated
`_request` once with the declared workspace and a bounded, unique
`mixed-policy-N` attempt ID. The fixture must own the canonical root,
guard home, daemon, writer and all declared workspace directories.

After the fixture's original bounded writer drain, close the request
observer and reconcile the receipt witness with `verify_all=True`. Then
call `join` with the accepted public mutation's monotonic return time,
the actual authenticated target snapshot, expected action and every
declared request index. The publication chain uses its own original
observer clock origin. Preserve that already matched chain and its
publication ID alongside this result; do not substitute a transport reply
for the production committed barrier.

The result distinguishes two observations:

* The earliest native wrapper completion after acceptance among the
  complete declared request set.
* The earliest such completion whose request offer and native-wrapper
  entry both occurred at or after acceptance.

A request offered before acceptance is not relabeled because it completes
later. Negative acceptance-to-offer offsets are retained. Equal completion
timestamps retain all ties and cannot prove a unique first completion.
Every declared attempt must have one observed native call, validated
receipt, writer admission, matching delivered decision, and a matching
committed receipt. Missing, duplicate, mismatched, late or in-flight
observations keep the result incomplete. Calls outside the declared set
are counted separately; this is not a first-decision claim for all daemon
traffic.

The native completion timestamp comes from the existing receipt witness
after the original Python native-review callable returned. It is not an
internal Rust decision timestamp. All timings include observer overhead;
no headline latency or installed qualification is granted.

Authority readback and the sequential SQL count/getter/count observations
run on the controlling caller, outside the native hook call. When the
separately supplied SQLite VFS observer is present, these operations use
its explicit readback scope. They are not writer I/O, atomic transaction
commit timestamps, kernel fsync counts or physical storage byte counts.
The receipt itself must pass the product's complete privacy/identity
validator before capture and again at comparison. Full receipts are kept
for independent identity verification, with the existing 16 KiB per
receipt bound and at most 32 declared requests. No SQL text, hook payload,
workspace path or key material appears in the result.

The owned wrapper is restored only if it is still installed. A later
owner is preserved and completeness is refused. HTTP and native calls
have separate in-flight counts: an HTTP timeout cannot hide a native call
which continues afterward. Closing the observer does not cancel work or
extend its deadline. The caller retains responsibility for the daemon,
writer and process lifetime.

The three new finite test modules use the actual receipt validator,
SQLite receipt schema/store mixin, public getter and `ReceiptWitness`.
Native and HTTP calls are synthetic controls for argument/result/exception
forwarding and timing/identity falsification. These tests do not execute
a Rust runtime, authenticate a real published policy image, or qualify a
workspace campaign.

Local Linux/Python 3.12 validation collected and passed all 90 controls:
62 pure joins, 16 forwarding controls and 12 lifecycle controls. This includes
two new regressions for a retained native call starting during committed
readback and for a closed receipt witness being mistaken for active
instrumentation. The same test process also passed 54 existing writer,
mixed-witness and persistence-gate regressions plus 24 actual compiled SQLite
VFS controls: 168 passed with no skips. These establish bounded Python and
SQLite compatibility; the native and HTTP calls in the workspace controls
remain synthetic. Installed runtime qualification requires separate evidence.

The next separate lifecycle fixture must retain one owned temporary root
across two service instances, register later workspaces through the
existing API, and probe the declared secondary workspace. Replacement
must require actual service containment and a closed old publisher before
constructing a new provider on the same home, then explicitly re-register
the intended scopes. This is same-process service/provider replacement,
not a Python-process restart. Lost hints, Python restart, key rotation,
expiry, rollout admission and full installed 1/10/100 qualification remain
pending distinct experiments. Existing six-phase workspace scenarios,
publisher coalescing/cache rules and qualification limits are unchanged.
