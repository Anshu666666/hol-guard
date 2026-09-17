# Registered launcher approval fixture

`scripts/native_slo_launcher_approval.py` services the actual local approval
wait used by installed Codex and Claude launchers. The owner starts a private
`AdapterSession`, captures an approval operation before spawning the registered
launcher, runs that launcher with a synthetic request, then observes its real
delivery. The helper neither launches the reviewed tool nor opens a browser or
network connection. Native review and receipt proof still come from the actual
launcher/daemon/resident path, which the owner must qualify independently.

```python
controller = LauncherApprovalControl(session, approval_gate_input=local_gate_input)
started = controller.begin("claude", synthetic_payload, resolution="allow", timeout_seconds=8)
# The owner now runs the actual registered launcher with that same payload.
evidence = controller.result(started["operation_id"])
# Poll result until its state is resolved or failed, within the owner's deadline.
controller.close()
```

`begin` accepts `claude`, `claude-code`, and `codex`; Claude aliases are
canonicalized to the resident's `claude-code` before capturing identity. It
returns only an opaque operation ID, state, and input digest. `result` never
waits on the control pipe. A resolved result contains the exact request ID,
resolution, artifact scope, durable-row status, binding presence/digest, input
digest, and route-counter differences. These counters are observations, not a
claim that the original launcher completed or that every route was native.
The owner's delivery assertions must conserve routes and classify availability
outcomes separately.

The production queue currently does not retain the submitted `tool_use_id`.
The fixture therefore captures the exact command, canonical harness, tool,
workspace, and a SQL row-creation watermark before launch. It selects only one
new pending native-pretool review with those fields, the exact native-pretool
artifact ID, and `tool_call` artifact type. It verifies the action envelope's
event, action type, harness, tool, command, and workspace before resolution and
compares the complete envelope afterward. A pre-existing deduplicated row is
never selected; an ambiguous pair fails explicitly. Raw command/workspace
values remain local and are never included in evidence.

Resolution calls the existing `apply_approval_resolution` service with the
exact request ID, `scope="artifact"`, `persist_policy=False`, and
`resolve_scope_matches=False`. Enabled approval gates use the caller's local
`ApprovalGateInput`; the helper does not bypass or disable them. The narrow
`resolve_launcher_review(store, request_id, action, approval_gate_input=...)`
function is also available to other installed lifecycle probes.

This is the existing ordinary local review/resolved-row flow. An artifact
resolution does not establish one-time consumption, and the helper never calls
the separate native v3/v4 approval claim/consume API. Same-domain repeat reuse
and policy/control-change invalidation must be evaluated using the production
binding correction and real installed retries.

| Bound | Contract |
| --- | --- |
| Active waiters | One per controller; conflicting begin fails |
| Retained operations | At most 32; capacity fails explicitly |
| Captured command | At most 2,048 UTF-8 bytes |
| Tool identifier | At most 64 ASCII identifier characters |
| Pending candidates | SQL query returns at most two; two means ambiguous |
| Wait deadline | Positive finite value, at most 8 seconds, captured before setup |
| Poll interval | At most 10 ms, cancelled by an event |
| SQLite contention wait | Existing thread-local production override, 50 ms per connection |
| Control result | Bounded IDs, digests, counters and classified errors through the privacy sanitizer |
| Cleanup | Cancel waiter and join for at most one second; a live resolver raises an explicit uncontained result |

The deadline does not cancel a production resolution already inside its
transaction. If it completes late or after cancellation, evidence records the
actual durable resolution and marks the operation failed. It never reports
late resolution as timely qualification success. If cleanup cannot join a
resolver, the fixture owner must terminate and reap the private process tree;
it must not claim successful containment.

Focused tests use real GuardStore queue and resolution APIs, including an
enabled password gate, exact identity and older-row exclusion, ambiguity,
canonical Claude aliases, both resolutions, bounded input/capacity/deadlines,
cancellation, late durable resolution, and privacy checks. Actual registered
executable/browser-wait delivery still requires the installed fixture on a
platform that permits resident IPC; these source tests do not substitute for
that qualification.
