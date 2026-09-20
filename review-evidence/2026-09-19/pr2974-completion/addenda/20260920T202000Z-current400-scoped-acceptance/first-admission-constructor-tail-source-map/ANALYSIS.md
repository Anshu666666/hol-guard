# Source map of the measured post-worker constructor region

The complete constructor diagnostic narrows the failed first-admission readiness check to a **49.689146 ms inclusive interval after `HookWorker.__init__` returned and before `_initialize_request_services` returned**. It does not identify the operation that consumed that interval. No product correction is selected from this record.

The original diagnostic result is preserved in tree `ec9c7d9693f3e2485712345a739e7f9ff0f91fd1`; its result blob is `886bd685bdb3b80c1ad5d70c15eea2d16cb18ee8`. Partition independently verified the original ZIP, 41 members, 66 log frames and timing joins in peer tree `d0998d395c96053ab656761c927ad94be99b5683`, receipt `9780e6ef808bde957cd8ac489348ae2bdb40ce84`.

The original first-admission cell failed at `await_ack` line 73 under the unchanged 400 ms deadline. The actual accepted response was withheld, the subsequent real transport call was forwarded, and no successful ACK was fabricated. Publisher wait returned true at acceptance +386.230335 ms, worker construction at +386.237187 ms, request-services at +435.926333 ms, HTTP construction at +436.096622 ms and service construction at +436.117070 ms. These successful exit pairs share the retained observer origin. They include observer and scheduling overhead. The publication observer has a separate origin; its ready observation does not timestamp an internal commit. No recovered hook request was offered and no new native/SQLite receipt was expected or lost.

## Exact source applicability

All 23 retained provider, fixture and existing-test files in `source-identity.json` are byte-identical between E440 (`e44008445630aad28ccc291ec234f55a14892e6d`) and current400 (`4001185e4f39cad51fd5eab314bf02b86b8a1674`). Each entry binds Git blob, SHA-256, size and retained body. This is a selected-path equality proof, not a claim that the two complete products are identical. The executed diagnostic used the separately bound original be612 default wheel; current400 has not executed this diagnostic.

## Actual order after HookWorker

`daemon/server_http.py:206–233` executes the following operations sequentially before socket-server construction. Python evaluates the authority read before calling `ExtensionControlRuntime`.

| Region | Actual source behavior | Evidence limit |
| --- | --- | --- |
| Authority read | Calls `store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)` with default `read_only=False`; validates schema, reads authenticated authority, synchronizes catalog state when protected, composes managed controls, and may migrate/write when required. | No duration, selected inner branch, lock contention or SQL result was observed for this call. |
| Runtime snapshot | Builds an immutable authority snapshot using canonical JSON and SHA-256 and allocates its lock. | Inclusive CPU/allocation cost is unknown. |
| Extension-control API | Stores references, allocates two locks and two ordered dictionaries. | No I/O appears in the constructor body; duration remains unmeasured. |
| Local CLI API | Stores its store reference and initializes its discovery cache to `None`. | No discovery is performed here. |
| Approval attention | Stores callbacks/state and allocates a condition; its thread remains `None`. | Thread startup occurs in a later `start()`, not this constructor. |
| General executor | Allocates queue/event/lock, then eagerly starts **32** daemon threads. | No individual startup duration or CPU cost was measured. |
| Control executor | Performs the same constructor with **8** daemon threads. | No individual startup duration or CPU cost was measured. |

The executor workers immediately wait on their queue; their request callback is invoked only after a later submit. The queue limits remain 128 and the separate general/control capacities are deliberate source behavior. The source therefore establishes **40 eager worker starts**, not 40 measured slow operations.

## Checks that constrain an optimization

The authority read is substantive current-state validation, not a reusable historical assertion. Its exclusive mutation-capable lease admits migration/recovery paths; its return is used to initialize the live extension-control runtime. A prior publisher ACK does not establish that this later read may safely be omitted or replaced with stale state. Repeated schema checks use distinct connections and modes; this audit does not establish an invariant permitting their removal.

Repeated `_catalog_target_manifest` calls are not proof of repeated full catalog compilation. `store_extension_control_manifest.py` already caches only the exact built-in registry, retained extension tuple and catalog digest, and returns a copy of the immutable cached mapping. The record does not observe cache hits or misses, and no cache weakening is proposed.

The original replacement fixture explicitly assigns `EncryptedFileSecretStore(home)` before verifying the empty protected authority and constructing the service. Thus an OS keyring prompt/lookup is not supported as the explanation for this measured authority call. Real encrypted-file reads/decryption remain possible. A 49.689 ms interval is also not evidence of a 50 ms SQLite busy wait: no busy event, SQL leaf or wait was captured in this region.

The current executor lifecycle deliberately exposes thread-start failure during construction, before socket bind. Existing `test_guard_daemon_startup_rollback.py` cases require rollback after the second executor fails and after an actual worker start fails; they also require no live new HTTP threads and preserve the original error. `submit` uses bounded queues under the lifecycle lock, and shutdown drains queued requests through the discard callback and joins workers. Lazy worker creation would change when resource exhaustion is reported and require a new concurrent submit/shutdown design. It is not a semantics-free startup optimization.

Moving work before the fixture's acceptance point would change which work is covered by the existing readiness requirement. This audit does not propose that change or infer that a 400 ms deadline should increase. The daemon package lazy-export change in current400 does not alter these 23 exact bodies; by this measured point the HTTP/server/worker classes are already imported, so no reduction of this tail follows from that change alone.

## Smallest remaining observation, if separately selected

The measured region supports a finite next observation rather than a product repair: retain the five existing boundaries and wrap only **two additional original method definitions**, producing three closed spans: the owned store's registry authority read and the general/control `BoundedRequestExecutor.__init__` calls. Bind the real store and enclosing request-services call; derive executor labels only from the original exact `name`, `workers` and `queue_limit` arguments. Preserve class identity and call each original once with identical arguments, return and exception. Do not add getters, DB/file reads, thread census, retries or worker-level probes. Record no authority content or private paths.

These spans would distinguish authority validation from the two groups of eager starts. The remaining gap would include runtime/API/coordinator construction, wrapper overhead and scheduling; it must remain unattributed. A failed/missing pair must not yield a duration, and inclusive nested spans must not be summed. No additional first-admission attempt is launched or authorized by this report. Concrete code, strict source/ownership binding, forwarding/exception/partial/overflow controls and operational review would be required before any later selected diagnostic.

This review ran only Git/file reads and pure hashing. It did not import product code, run controls, start a native process, rerun the fault workload, alter acceptance or move any source/evidence ref.
