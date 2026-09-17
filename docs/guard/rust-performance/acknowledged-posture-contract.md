# Acknowledged posture at the ordinary native hook boundary

RSP-031 uses the existing authenticated v3 policy as the source of request
posture. This is an explicit release behavior change: a local Watch setting
becomes effective for delivery only through its correct resident acknowledgement.
The former asymmetric transition is recorded as historical evidence in
[the request-time posture measurement](../rsp-runtime-identity-performance.md#request-time-posture-attribution).
No new latency, resource benefit or installed transition qualification is claimed.

## Request authority and visibility

The full snapshot already binds effective protection posture, security level,
policy actions, workspace scope, mode, rule identity and runtime identity. Its
canonical policy digest includes mode. The publisher exposes a compact binding
only after its ACK matches the candidate generation and digest, the resident
generation remains current, and the publication epoch remains valid. No schema
extension or new local posture cache is needed.

An ordinary `auto`/`force` request samples that binding once. The same binding
selects native evaluation, the Python command-control lease and the final Watch
delivery transform. The raw native edge keeps intrinsic decisions and receipts;
Watch rendering does not rewrite the native evidence. Local configuration cannot
weaken an enforcing result or bypass its lease while a Watch update awaits ACK.
An in-flight request retains its sampled binding rather than mixing a later
policy or configuration read into its response.

| Sampled request binding | Local requested posture | Completed native delivery |
| --- | --- | --- |
| Acknowledged enforce | Protected or Watch awaiting ACK | Enforcing native floor; bound PreToolUse retains its shared command-control lease |
| Acknowledged observe | Watch or protected awaiting ACK | Existing Watch recording and continuation transform |
| Newly acknowledged observe | Watch | Watch becomes effective for newly admitted requests |
| Newly acknowledged enforce | Protected | Enforcing delivery becomes effective for newly admitted requests |
| No admitted binding | Either | No posture authority; unchanged native-unavailable handling |

An in-process mutation or newly registered workspace withdraws publisher
readiness immediately. Expiry and resident replacement also withdraw it. An ACK
for an invalidated epoch, different policy or stale resident cannot reopen that
barrier. External configuration writes still depend on the existing bounded
observer/reconciliation contract; this change does not promise instantaneous
cross-process configuration visibility. The authenticated command-control
mutation fence retains its separate stronger contract.

One resident composes the strongest effective home and registered workspace
policy. A local Watch overlay cannot weaken the acknowledged enforcing snapshot
for that scope. Managed policy and strict workspace composition remain in the
publisher, outside ordinary request delivery.

## Availability and compatibility boundaries

Absent, expired or rejected policy acknowledgement follows the existing
availability path. Ordinary PreToolUse unavailability warns and allows without
another Python semantic classifier; PostToolUse retains its existing continuation
shape. Designated integrity failures, malformed adapter input, permission requests
and lifecycle events retain their own contracts. A continuation caused by
unavailability is not evidence of Watch authority or successful native evaluation.

Production `off`/`shadow` behavior is unchanged. Legacy local posture reads in the
explicit Python test-oracle paths remain separate. The outer server does not
apply its local Watch override to native-authoritative errors. No default mode,
timeout, retry, queue limit or approval rule changes with this correction.

## Source verification

- [Delivery transition matrix](../../../tests/test_native_acknowledged_posture.py)
  covers native Pre block/review, shared-lease selection, Post redaction
  and original-output digests, unchanged unavailable responses, strict workspace
  composition, no ordinary local posture reread, and preservation of the sampled
  binding, native result and receipt across an in-flight transition.
- [Publication transition matrix](../../../tests/test_native_acknowledged_posture_publication.py)
  runs the real signed snapshot builder, ACK decoder and publisher barrier with
  an injected resident transport. Both directions remain closed on missing ACK,
  wrong digest, concurrent epoch invalidation and wrong resident generation,
  then open only on a matching ACK. Expiry withdraws the binding afterward.
- Existing snapshot composition, mode-only reconciliation, mutation-fence,
  native receipt, Watch rendering and availability suites remain applicable.

The transport-injected tests establish source contracts, not an executed installed
Rust result. Actual cross-platform and mixed-load transition qualification remains
separate. Historical measurements are retained with their original behavior and
must not be used as timing evidence for this correction.

The scoped source run passed all 24 new tests and 153 adjacent tests, with one
platform-specific skip. Ruff, formatting, source type checking (zero errors),
the PreTool no-Python gate and the receipt persistence source gate passed.
These results do not convert source gates into installed runtime evidence.
