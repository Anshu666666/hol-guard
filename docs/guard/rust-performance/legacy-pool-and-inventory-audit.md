# Legacy pool and inventory performance audit

The remaining Python evaluation pool should keep its current startup behavior until actual first-approval deadlines are qualified. Inventory request planning can avoid repeated encoding now: the implemented byte-accounting change preserves the existing atomic snapshot and wire contracts while reducing local CPU work. Neither finding justifies an additional Rust port yet.

This audit implements the bounded RSP-092 and RSP-130 investigation against integration source `cebf2d1bb9b4bd30d1f50c400d68db655dffaeb3`. The measured inventory candidate is `139fed730e7f142ce739ce65af810d4713941270`. It does not mark RSP-093, the complete RSP-130 acceptance criteria, installed latency gates, or cross-platform qualification complete.

The later [inventory refresh and persistence follow-up](inventory-refresh-audit.md) supplies actual filesystem-change, SQL, scanner-process, and controlled cloud-client attribution. It records the measured repeated collection traversal, its bounded Python correction, and the remaining installed/incremental qualification limits. The remaining-work list below describes this earlier tranche's scope.

**Legacy pool ownership and consumers.** `guard/daemon/hook_process_runner.py::HookProcessRunner` owns a bounded pool of guardian/evaluator pairs. `GuardDaemonServer` constructs it, connects its ready capacity to the process scheduler, starts it during owned-service startup, and calls contained shutdown during service completion. The ordinary adaptive initial target is two slots, with a maximum of sixteen. Deferred daemon startup initially exposes one slot and later enables backfill; that is separate from lazy initialization inside each evaluator.

Each slot starts one guardian with an OS process-group or Windows Job containment boundary, then one evaluator. The evaluator imports its review dependencies before signaling ready. Its `GuardStore` and `HookWorker` are initialized on the first request already. A Python multiprocessing resource tracker may also remain in the parent process tree.

| Production consumer at the frozen baseline | Ownership and deadline |
| --- | --- |
| `guard/daemon/server.py::_revalidate_codex_live_allow` | Calls `HookProcessRunner.review` for fresh reevaluation before completing a Codex live approval. Carries the saved approval hash and request identity. The server supplies a 1.45-second outer deadline. |
| `guard/daemon/server.py::_handle_runtime_hook_compatibility_cli` | Acquires the dedicated process scheduler, then calls `review`. Uses 1.45 seconds for ordinary hooks and 2.75 seconds for PostToolUse. This is the compatibility/oracle route. |
| `guard/daemon/server.py::_execute_runtime_hook` | Selects the fast/native path first. Required-native mode returns a native failure if that path cannot complete; it does not silently use the Python process pool. |
| `guard/native_resident_client.py::_PersistentNativeClientPool` | A separate native transport/client pool. It is not the Python evaluation pool audited here. Removing Python pool startup would not remove ordinary native hook IPC. |

Other multiprocessing users include bounded continuation work and local trust work. They are separate from `HookProcessRunner`; benchmark-oracle processes are measurement infrastructure. This inventory does not propose combining their isolation boundaries.

`scripts/profile_legacy_hook_pool.py` runs the actual spawn, readiness, request, and containment code using the locked editable Python 3.12 environment. It creates a fresh private state directory for each run and measures fixed one-slot and two-slot pools, five times each. Fixing the slot count disables adaptive scaling; these observations do not measure deferred daemon startup. The request is an observation-only Pi SessionStart. It verifies the real isolated request protocol, not actual Codex approval reevaluation, a native decision, HTTP transport, or registered launchers.

| Local component | One slot | Two slots |
| --- | ---: | ---: |
| Guardian + evaluator processes when ready | 2 | 4 |
| Median ready child RSS, excluding resource tracker | 121.7 MiB | 243.5 MiB |
| Median `start()` wall time | 8.020 s | 7.928 s |
| Observed `start()` range | 3.890–9.217 s | 4.706–12.586 s |
| Successful cold evaluator requests | 2 / 5 | 8 / 10 |
| Successful warm protocol requests | 20 / 50 | 50 / 50 |
| Median successful warm protocol request | 3.264 ms | 3.934 ms |
| Fully contained and cleaned generations | 5 / 5 | 5 / 5 |

Five of fifteen cold evaluator requests timed out at the existing 2.8-second runner limit. Successful cold calls took 2.189–2.881 seconds including return-path work. Thirty subsequent one-slot calls reported `daemon_hook_process_not_ready` after the timed-out worker was withdrawn; these failed observations remain in the artifact and are not counted as fast successful requests. Successful SessionStart responses explicitly reported `native_hook_event_unavailable`, consistent with an observation-only event. They are not evidence of native review coverage.

All ten shutdowns proved containment and left no guardian/evaluator children. Some failed runs needed up to 14.247 seconds to finish bounded replacement/containment cleanup. One-second idle samples showed no measurable child CPU increment at the process counter's resolution; this does not establish zero idle cost, long-duration stability, or adaptive-supervisor cost. The measurements ran under the shared measurement lock on this local Linux host. They include environment variance and are not portable release thresholds.

The first-request failures make an unconditional lazy-start change inappropriate in this tranche. RSP-092 now has explicit consumers and supported local startup/RSS evidence. RSP-093 still needs actual first Codex approval latency, reevaluation correctness after state changes, startup under backlog, worker failure/repair, and lifecycle tests on the supported installed platforms. The daemon/launcher qualification blockers documented elsewhere, including restricted socket operations, are not removed by a working multiprocessing Pipe.

**Inventory change and measurements.** `guard/aibom_cli.py::sync_aibom_snapshots` collects and projects snapshots, constructs atomic events, plans batches, serializes each final request, sends it, and maps acknowledgments before uploading accepted primary content. `guard/aibom_sync.py::_batch_inventory_events` previously serialized each singleton and each growing candidate batch. It even encoded the next oversized-by-count candidate before splitting a full three-event batch. The final transmission then encoded the batch again.

The candidate uses the production singleton serializer exactly once per event to measure its encoded size. It adds the exact default envelope and comma-space separator lengths when testing candidate batches. It retains event objects and order, quarantines an oversized event without splitting it, and preserves the count and byte ceilings. It does not retain serialized event bodies or introduce a cross-call cache. If the public CLI serializer seam has been replaced, the original serializer-driven planner remains in use because a custom envelope need not have additive lengths. Final JSON bytes, acknowledgment handling, primary content selection, retry behavior, and `client_unverified` provenance remain unchanged.

The three frozen synthetic workloads were measured five times per source, baseline then candidate. Timing covers batch planning plus final JSON encoding; fixture construction, independent byte/hash verification, and a separate allocation trace are outside those timed intervals. Each input hash and every final request-body hash matched across the two sources.

| Workload | Final body bytes | Median CPU, baseline → candidate | Median wall, baseline → candidate | JSON bytes processed, baseline → candidate |
| --- | ---: | ---: | ---: | ---: |
| Three small snapshots, 24 items each | 106,593 | 2.230 → 1.271 ms | 2.460 → 1.270 ms | 426,408 → 213,210 |
| Nine medium snapshots, 128 items each | 3 × 562,281 | 55.455 → 18.705 ms | 120.047 → 24.160 ms | 7,872,018 → 3,373,758 |
| Three large snapshots, 486 items each | 3 × 5,704,967 | 389.835 → 166.115 ms | 547.548 → 217.659 ms | 62,754,613 → 34,229,802 |

The separate encoder witness recorded 7 → 4, 21 → 12, and 9 → 6 JSON calls respectively. Peak tracked Python allocation was essentially unchanged: about 0.214 MB, 2.250 MB, and 22.820 MB. These measurements support less repeated serialization work; they do not establish an end-to-end inventory speedup, a statistical release SLO, or a Rust go/no-go result. The wall-time difference includes host variance, so CPU samples and the exact byte-work reduction are reported separately.

The same profiler also exercised real Hermes discovery and the production projection functions on 24, 128, and 486 synthetic skill directories plus a workspace `AGENTS.md`. Cisco scans were disabled. The stages reused captured detection/artifact inputs, so adding their medians is not a fresh-process end-to-end measurement.

| Skill files | Discovery and hashing CPU | Cloud artifact projection CPU | Snapshot assembly CPU | Wire projection and redaction CPU |
| --- | ---: | ---: | ---: | ---: |
| 24 | 39.7 ms | 0.5 ms | 189.8 ms | 82.4 ms |
| 128 | 233.3 ms | 0.6 ms | 812.4 ms | 394.4 ms |
| 486 | 789.8 ms | 0.4 ms | 2,552.4 ms | 1,887.8 ms |

Snapshot assembly and redaction dominate these local projection fixtures. Their semantics include content identity, safe path handling, trust metadata, and final leak checks. A replacement requires profiling their internal costs and proving exact output/availability parity before a native port is proposed.

The actual inventory refresh loop is `guard/daemon/server.py::_refresh_aibom_inventory_loop`; it resolves workspace binding and authorization, holds the cloud-sync lock, calls `sync_aibom_snapshots_if_due`, and records status/backoff. The cloud sync path does not own all local inventory SQL. `guard/consumer/service.py` records evaluated inventory artifacts and related capability, provenance, diff, and snapshot records; MCP tool calls and permission commands also call `GuardStore.record_inventory_artifact`. Those writes carry policy semantics. This audit did not combine them into a cross-artifact transaction or weaken their provenance.

RSP-130 remains partial. Remaining acceptance work is:

- Measure incremental invalidation/coalescing with real filesystem changes and unchanged-file reuse, across installed harnesses.
- Profile SQLite joins/upserts and transaction boundaries separately from traversal and projection. The current inventory upsert performs a preliminary `first_seen_at` lookup although the conflict clause already preserves that column; measure its contribution before prioritizing it or broader transaction batching.
- Measure Cisco scanner subprocess costs and cloud wait separately, including timeouts, partial acknowledgments, and retry/backoff.
- Compare any later optimized Python projection with a native candidate on the same frozen corpus before approving a port. Preserve exact content identity, redaction, errors, and `client_unverified` labeling.

**Validation and reproduction.** The focused inventory batching, CLI sync, content-upload batch, and new boundary suite passed: 56 tests. A final focused run after freezing the count comparison passed all 19 batching tests. Ruff, formatting, and `git diff --check` passed. Scoped BasedPyright for the production module and new tests reported zero errors; 35 private-usage/unknown/legacy typing warnings remain. No process-pool production code changed.

```sh
flock -n /workspace/scratch/c911dc702e23/performance-measurement.lock \
  .venv/bin/python scripts/profile_legacy_hook_pool.py --samples 5 \
  --output docs/guard/rust-performance/evidence/legacy-pool-local.json

flock -n /workspace/scratch/c911dc702e23/performance-measurement.lock \
  .venv/bin/python scripts/profile_inventory_components.py --samples 5 --label baseline \
  --output docs/guard/rust-performance/evidence/inventory-components-baseline.json

flock -n /workspace/scratch/c911dc702e23/performance-measurement.lock \
  .venv/bin/python scripts/profile_inventory_components.py --section batch --samples 5 --label candidate \
  --output docs/guard/rust-performance/evidence/inventory-components-candidate.json
```

Run the baseline command against the frozen baseline source and the candidate command against the recorded candidate source; do not relabel a later run. The profiler itself was introduced with the candidate, so copy that script into a baseline worktree without changing its production modules. Each report records its Git head and relevant production source hashes. Raw observations are in [legacy-pool-local.json](evidence/legacy-pool-local.json), [inventory-components-baseline.json](evidence/inventory-components-baseline.json), and [inventory-components-candidate.json](evidence/inventory-components-candidate.json).
