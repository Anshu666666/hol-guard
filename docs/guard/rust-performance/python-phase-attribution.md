# Python diagnostic phase attribution (RSP-008 / RSP-037)

This extends the existing `phases_start` / `phases_finish` instrumentation in the
isolated installed qualification daemon. It changes **scripts and tests only**.
Production runtime functions, policy decisions, admission limits, transport
protocols and evidence persistence remain owned by their existing modules.

`PhaseProfiler` emits `hol-guard-python-phase-diagnostics.v2`. Every report is
marked `diagnostic_instrumented_run`, `headline_timing_eligible: false` and
`inclusive_do_not_sum`. These wall-clock spans include probe overhead. They are
attribution diagnostics, not replacements for uninstrumented hook SLO samples.

## Observed boundaries

| Phase or work count | Actual production boundary | Meaning and limit |
| --- | --- | --- |
| `daemon_hook_inclusive` | `_GuardDaemonHandler._handle_runtime_hook` | Existing inclusive handler span, with bounded harness/event attribution. |
| `http_post_inclusive`, `http_body_read_inclusive` | `do_POST`, `_read_request_body` | HTTP processing and bounded read loop; the former includes subsequent hook work. |
| `http_body_read` | The request handler's real `rfile.read1` | Counts returned bytes, including a partial body before an error. This is a Python buffered-I/O call, not an OS syscall or physical disk read. |
| `daemon_json_loads`, `edge_json_loads` | Existing module-local `json.loads` calls | Measures actual input parse calls; bytes and string characters have distinct counters. Decode errors remain raised outcomes. |
| `daemon_json_dumps`, `edge_json_dumps`, `evidence_json_dumps` | Existing module-local `json.dumps` calls | Counts actual returned characters, including serialization later rejected by the envelope size limit. No extra serialization/encoding is performed to count work. |
| `envelope_encode`, `receipt_record_serialization` | `_encode_hook_envelope`, `_NativeDecisionReceiptRecord.serialized` | Inclusive serialization plus encoding/validation; counts returned bytes. No claim that this isolates the UTF-8 encoding or allocation itself. |
| `runtime_identity_including_hash` | `native_runtime._validate_binary` | Existing inclusive path/stat/read/hash validation. |
| `runtime_sha256_*`, `runtime_manifest_sha256_*` | SHA-256 constructor, update and finalization in `native_runtime` and `native_runtime_identity` | Actual hash callable time and bytes passed to successful hash calls. Repeated hashing is counted repeatedly. Filesystem read time remains outside the hash-only spans. Other modules' hashing is not observed. |
| `config_lookup` | Canonical `config.load_guard_config` and the existing aliases in `daemon.hook_worker`, `daemon.server`, and `daemon.hook_native_review_continuation` | Outermost observed lookup, with original return/exception behavior. A forwarding alias and its nested canonical call produce one timed lookup; separate fixed binding-entry counts retain both observations. |
| `byte_admission` | `RuntimeHookScheduler.reserve_bytes` | Attempted payload bytes, reservation/rejection counts and inclusive call time; rejected work does not invent a queue span. |
| `admission_and_queue` | `RuntimeHookScheduler.acquire` | Inclusive admission and waiting, attempted payload bytes, queued/never-queued and admitted/rejected counts. Exceptions remain in outcomes. |
| `scheduler_queue_admitted` | Scheduler item's `queued_at` and `admitted_at` | Uses the real scheduler's timestamps even when another thread dispatches the item. Includes scheduling from initial queue insertion to admission. |
| `scheduler_queue_unadmitted_until_return` | Real queued timestamp to `acquire` returning/raising | Retains expiry/cancellation/failure residence. The return boundary can be later than removal from the queue; it is not labelled exact dequeue time. |
| `scheduler_condition_wait`, `client_pool_condition_wait` | `Condition.wait` on the exact active scheduler/pool condition | Wait call time, including mutex reacquisition; one request may wait more than once. Unrelated conditions are not counted. |
| `client_pool_lease_inclusive` | `_PersistentNativeClientPool._lease` | Pool lock, lookup/construction and waiting; does not claim to isolate only queue wait. |
| `client_snapshot_start_or_attestation`, `client_process_spawn` | `_request_snapshot`, stream module's `subprocess.Popen` | Snapshot locks, client reuse/attestation or startup, and process constructor respectively. A process spawn is not a verified resident socket connection or readiness measurement. |
| `client_stream_exchange_inclusive`, `native_client_inclusive` | `_PersistentNativeClient.request`, the edge's native-client request binding | Inclusive transport/client work, with payload byte counts. Overlaps the nested framing, startup and wait spans. |
| `client_frame_header_pack`, `client_frame_header_unpack` | Real stream module's `struct.pack`/`unpack` | Header serialization/parsing calls and header bytes. Body concatenation time and allocation counts are not isolated. |
| `client_frame_write` | Stream module's actual `write_frame` helper | Attempted frame bytes and helper-reported completed frame bytes. A false result may follow a partial write; partial/unknown attempts are explicit and are never counted as zero written bytes. |
| `client_response_wait_inclusive` | `Queue.get` on the queue captured by the active request snapshot | Wait for a response, including native work, transport and reader delivery. Tracks timeout exceptions and stream-failure sentinels. It does not isolate native evaluation or socket I/O. |
| `activity_submission`, `receipt_submission` | Real evidence-writer submission methods | Preserves true/false outcomes. A true receipt result may be deduplication; it is not proof of unique enqueue or durable persistence. |
| `response_encode_write`, `http_response_write` | `_write_json`, handler's real `wfile.write` | Inclusive response creation and actual buffered writes, including HTTP headers. Short returned counts are counted as returned; caught disconnects retain raised write outcomes. An exception may follow partial output. |

The standard-library JSON and hash modules are not patched globally: probes
replace only specific importing modules' local bindings. Server HMAC hashing is
intentionally not wrapped because changing its digest constructor would select a
different HMAC implementation. The existing `Condition.wait` and `Queue.get`
methods are temporarily wrapped in the isolated diagnostic process, but only the
exact request-scoped condition or captured response queue is measured.

### Config binding coverage correction

The original profiler patched only `config.load_guard_config`. Existing imports
in `HookWorker`, the daemon server and native continuation code retain separate
module bindings and could bypass that wrapper. The correction resolves these
four fixed bindings before installing any config wrapper. It observes each
original callable once without an additional config read, retry or production
change. Dynamic imports in the availability helper use the canonical wrapper.

The additive `config_lookup_coverage` object has the closed schema
`hol-guard.config-lookup-observation.v1`. Per-binding `entries` and
`outermost_calls` distinguish alias forwarding from separate lookups; entries
must not be summed as independent lookups. Observation applies only to the
existing foreground HTTP/hook context. Unscoped background work and the explicit
`unattributed.native_stream_reader` context are excluded.

`zero_calls_observed` requires successful installation, a finished scope with
the same wrapper still bound at teardown, completed restoration, a foreground
root admitted and completed while observation was open, and
zero binding entries. Foreground/config calls still active at teardown mark the
window `in_flight_at_teardown`, with no wait or added deadline. Observation
admission closes atomically before restoration; late original calls still run
and return/raise normally but cannot certify the old window. The foreground
coverage snapshot is frozen at teardown, so a late root cannot turn an empty
window into a measured zero. A foreground call already running at installation
also makes the window incomplete. An active scope, no observed foreground request, missing
historical module/callable, setup failure, binding replacement or restoration
failure cannot establish zero. Missing modules/callables use `unsupported` and
null counts; a missing dependency inside an existing module still raises its
original import error. These states describe only the four declared bindings,
not every config read in another process, a previously captured arbitrary local
reference, or the publisher's background work.

Focused regressions call the actual `HookWorker._load_config` method, the
availability helper's dynamic import, and each fixed alias; they preserve exact
argument, result and exception identities, verify restoration and nested-call
accounting, and distinguish zero, missing, changed and failed observation.
Fresh installed execution must supply the new coverage field. Old v2 reports
without it remain historical partial observations and cannot gain a zero-call
claim retroactively. Complete authenticated phase journals remain authoritative;
this change does not repair the separate deeply nested aggregate projection or
increase any evidence/timing bound.

The correction's four-module source suite passes 72 tests, including deterministic
blocked-call teardown and late-wrapper cases. Ruff, formatting and whitespace
checks pass; the changed script has zero type errors and 86 existing/dynamic
typing warnings. Independent source review is clear. These are correctness
checks, not a new installed phase observation or completion of RSP-008.

## Attribution, failures and bounds

Input parsing occurs before a hook event is available. HTTP ingress stays in
`<allowlisted-harness>.transport_unclassified`; the nested hook handler uses its
existing bounded route pair. Malformed/unrecognized events go to `other.other`.
The persistent reader does not inherit request context and can span many
requests. Its header parsing is explicitly reported as
`unattributed.native_stream_reader`, never charged to an arbitrary caller.

Reports retain fixed callable outcomes (`returned_none`, `returned_false`,
`returned_true`, `returned_value`, `raised`) and timestamp observations. These are
not semantic allow/deny results. Aggregate outcomes continue after timing samples
or series are discarded. The installed runner must retain each corresponding
raw delivered response/route/failure separately; these counters do not replace
its semantic oracle or completion denominator.

Storage is capped at **512 route/phase series and 100,000 total timing samples**.
Per-series timing is also bounded. Discarded samples and series updates are
explicit. A series with no retained timing uses `timing: not_retained`, with no
fabricated zero percentile. Missing phases mean not observed. Counts are from
fixed internal probe fields, and arguments, payloads, output text, paths,
correlation identifiers, exception messages and hash digests are never exported.
Byte totals overlap across callable boundaries and must not be summed as unique
I/O bytes or inferred allocation counts.

Only one profiler may be installed per process. Partial setup, caller exceptions
and normal exit restore patches and release the installation guard. Request
context is reset in `finally` blocks. The queue item/response queue references
exist only for their active call; no cross-request payload cache is introduced.

## Verification and remaining qualification

The focused tests exercise actual production encoders at 1 KiB, exactly the
6 MiB native request limit, and one byte beyond that limit. They check non-ASCII
JSON units, incremental hash bytes, cross-thread scheduler admission, expiry,
pre-queue rejection, pool wait expiry, real framed-client request helpers with
controlled streams/queues, malformed/partial HTTP input, exact response wire
parity, caught disconnect, and real receipt submission under deduplication and
queue saturation. They also cover restoration, nested installation rejection
and report-storage bounds. Controlled stream fixtures establish instrumentation
behavior, not native daemon availability or transport performance.

Validation from integration baseline `bc0876a6e142a941731d96ba6078709a007bd6bb`:
65 tests passed across the phase profiler, scheduler, native client pool/cleanup,
native decision receipts and isolated daemon-fixture suites. Ruff, formatting
and `git diff --check` passed. Explicit BasedPyright inspection of the four
diagnostic modules reported 0 errors and 408 warnings (primarily dynamic probe
types and private diagnostic access); this is not a claim of warning-free
typing or of a new production-wide type-check run.

The installed qualification runner must collect separate small/maximum payload
reports alongside their raw outcomes. This change does not complete installed
cross-platform phase qualification. Rust socket connection/authentication,
evaluation, timeout/protocol/shutdown parsing and allocation/copy diagnostics
remain the Rust diagnostic workstream's responsibility. Python UTF-8 and body
copy time cannot be isolated at the current callable boundaries. OS syscall,
physical-byte, SQLite VFS/busy-lock and background durability metrics remain
explicitly **not measured**, not zero. RSP-008 and RSP-037 therefore remain
partial until the combined installed evidence meets their full acceptance.
