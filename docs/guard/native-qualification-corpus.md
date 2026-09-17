# Native qualification corpus

`scripts/native_slo_workloads.py` freezes the response contract at
`2e672d2d950c6ec471005ddba46e49bba16dc23b` in 386 synthetic cases. The manifest
is `tests/fixtures/guard-native-qualification/corpus.v1.json`. It records the
source tests, installed surfaces, event aliases, content limits, and required
setup evidence. The oracle does not import candidate response renderers.

This supplies executable correctness fixtures for RSP-A012 and RSP-B013–024.
It does not complete those tasks or certify installed performance. The focused
tests exercise the frozen projections against current renderers and reject
changed decisions, reasons, output proofs, route claims, HTTP statuses, and
unwitnessed setup. They do not claim that a native binary or installed launcher
ran. A qualification run must first pass this same oracle on the pinned
baseline, then on the candidate.

The helper exposes these operations:

| API | Required use |
| --- | --- |
| `build_cases(workspace)` | Create deterministic synthetic files in a private disposable workspace; return case payloads, classifications, and oracles. Existing files must still match, and matching files are not rewritten. |
| `configuration_text(setup)` | Seed an explicit synthetic policy before daemon construction. This is an allow policy used to isolate intrinsic detector behavior. It is not the product default. |
| `validate_setup(case, evidence)` | Require every manifest prerequisite to be independently observed as a boolean `True`. A setup label or a fabricated failure response is insufficient. |
| `validate_case(case, response, route, http_status=200)` | Check the daemon-adapter response, required and absent semantic fields, review approval identifiers, exact reason codes where exposed, route, and transport status. |
| `validate_native_result(case, result)` | Check the native result before delivery rewriting. Availability and transport failures must have no semantic native result. |
| `installed_response_expectation(case)` / `validate_installed_response(case, stdout_json, exit_code)` | Separately validate Cursor and Cline wrapper stdout and exit conventions. Other wrappers require their own installed launcher oracle. |

The response projection permits dynamic explanation text and approval URLs but
requires nonempty approval identities for review. It rejects absent expected
fields, unexpected semantic fields, and JSON type changes such as `true` to `1`.
Errors identify only case and field names; they do not print response content,
source paths, command text, or secrets. The source fixtures contain only repeated
ASCII text and a deliberately synthetic GitHub-shaped token used by existing
native tests.

The current matrix has 237 native semantic cases and 149 availability, lifecycle,
permission, or transport cases. It covers benign commands, destructive commands,
review, approval persistence failure, Watch, native transport unavailability,
policy expiry/revocation prerequisites, explicit native-off mode, malformed
payload references, byte admission, and source digest mismatch. Cursor file/MCP
aliases carry file/MCP actions; they are not shell commands relabeled as file
events. Copilot uses `preToolUse` and `postToolUse`. Normalizer-only aliases are
marked separately, and preflight-only/unavailable harness routes are excluded
from installed enforcement coverage.

| Content class | Exact UTF-8 content bytes | Admitted representation |
| --- | ---: | --- |
| `empty` | 0 | Present empty inline output; require `output_empty_allow` and empty digest |
| `1k` | 1,024 | Inline output |
| `16k` | 16,384 | Inline output |
| `256k` | 262,144 | Inline output |
| `1m` | 1,048,576 | Local source reference |
| `max` | 5,242,880 | Local source reference at the existing native scan bound |

Each case also records the full JSON wire byte count. The daemon HTTP body cap
is **1,000,000 bytes**, so inline `1m` and `max` are distinct HTTP 413
`body_too_large` fixtures with no native invocation and no semantic latency
denominator. The driver sends the oversized Content-Length and verifies rejection
before transmitting a body the server will refuse to read; it reports this
declared-length boundary explicitly. Admitted large source-reference fixtures
still require actual file reads and complete digest checks. A source reference binds path, tool input target, output character
count, and SHA-256 to the complete synthetic file. Increasing the body limit or
treating a rejected request as a fast completed scan would change this contract.

Watch preserves a separate native and delivered projection. Under the pinned
policy contract, an intrinsic native secret block remains a native deny, then
HookWorker delivers the original output with `policy_action=warn` and a matching
output digest to Pi/OMP. Non-Pi/OMP post-tool renderers omit that public digest
and reason code. Their native result therefore remains necessary evidence;
an empty adapter response cannot stand in for an allowed post-tool response.

Native unavailability usually continues the session, including protected
PreToolUse. Malformed authenticated payload references and retained-byte
admission failures still block PreToolUse. Copilot permission unavailability
keeps `behavior=deny` with `interrupt=false`. Grok lifecycle unavailability
returns exactly `{}`. These are existing contracts, not a universal fail-closed
rule.

Cursor `afterShellExecution` and `afterMCPExecution` are installed observers:
their wrapper emits `{}` and exits zero even when the daemon classified output
as blocked. Cline native PostToolUse emits `cancel=false`, may attach context,
and exits zero; its plugin replacement transport is a different boundary.
Neither observer proves model-output withholding. Cursor read review maps to
`permission=deny` and exit 2; shell/write/MCP review maps to `permission=ask`
and exit zero. These wrapper expectations are checked separately from daemon
JSON.

Fault setup must occur in a separate installed-interpreter session. Concrete
baseline mechanisms and the limits of their evidence are:

| Setup | Mechanism and required witness |
| --- | --- |
| `normal`, `watch` | Write the synthetic config before starting the daemon, register its workspace, await `HookWorker.prepare_workspace_policy`, then inspect the resident-accepted effective policy and mode. A successful TOML write alone is not an ACK. |
| `unavailable`, `watch_unavailable` | After a current ACK, inject a counted `None` return at `native_hook_edge.native_resident_client_request`. The real edge records transport failure and the real worker renders availability. This proves that failure boundary, not process-crash containment. |
| `off` | Set `HOL_GUARD_NATIVE=off` in the isolated child after startup, verify `HookWorker.test_oracle is None`, and observe no worker route increment. |
| `integrity` | Send the corpus's malformed `guard_payload_ref`; the real `hook_payload_reference_size` rejection must occur before scheduler/native admission. Observe no semantic result and no worker route increment. |
| `queue_bytes` | Exhaust the real scheduler byte reservation, or inject its `reserve_bytes` failure with `daemon_hook_queue_bytes` while counting it. Report which mechanism was used; an injected failure is not a memory-pressure stress test. |
| `review_queue_failed` | Inject `sqlite3.OperationalError` only from the private store's `add_approval_request`. Require a completed native review result and delivered `native_review_queue_failed` block. |
| `expired` | Publish and authenticate a genuinely short-lived, correctly signed generation, suspend renewal, observe its real expiry, then require preparation rejection. `native_policy_snapshot_v3` accepts `issued_at_ms`, `expires_at_ms`, and `renew_after_generation`; `_policy_snapshot_push_bytes_v3` and the normal resident client perform the authenticated push. Force a newer generation to avoid reusing a cached long-lived snapshot. Keep signing material inside the private child and never report it. Closing the publisher or mocking preparation alone does not prove expiry. |
| `revoked` | Require a witnessed authenticated generation revocation/invalidation and failed preparation with refresh suspended. The pinned baseline has generation replay rejection, but no standalone public revocation API was identified in this scoped review. Until the driver can prove this setup, report this matrix row as unqualified; do not substitute a missing file or mocked failure and call it revocation. |

The driver must retain exact route counter deltas. Zero increments mean
`engine_bypassed`; they are not an observed `native_fail_safe` increment. Expired
policy at the server preparation barrier should record `native_fail_safe`;
native-off and pre-admission reference/byte rejection should bypass the worker.
Unexpected multiple or mixed increments fail attribution.

Actual installed argv timing, cold launch and concurrent launch counts, native
receipts, timeout/late-result faults, native size/depth/UTF-8/duplicate-key
protocol vectors, platform validation, crash containment, long-duration soak,
and exact commit/build identity remain qualification responsibilities. A daemon
HTTP run must identify its boundary and cannot claim the launcher SLO.
