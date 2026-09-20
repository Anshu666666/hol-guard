# Current threshold and synchronous-posture reconciliation

This additive source review binds PR #2974 product `e44008445630aad28ccc291ec234f55a14892e6d`, tree `addf0c1daf8ceb6313d6805ee4d05e216d6fdac8`. It preserves the original PRD/TODO/Takeaway and their historical observations. It performs no benchmark, installed workload, product import or new test run.

## RSP-006: current executable thresholds

| Surface | Current predicate or scope | Source |
|---|---|---|
| Release warm native-client comparison | Pass if p95 ≤20 ms **OR** Python-reference/native p95 speedup ≥1.15 | `scripts/bench_guard_native_release_gate.py`: constants and `main` enforcement |
| Release cold one-shot comparison | Pass only if p95 ≤150 ms **AND** speedup ≥5 | Same `main`: two independent failures |
| Resident readiness | ≤400 ms, beginning at the first production adapter request after snapshot materialization | Same `_run_benchmarks` and `main` |
| Normalized daemon adapter smoke | 1000 ms warm/size/recovery/concurrency ceiling, derived from `HOOK_ENGINE_NORMAL_BUDGET_MS` | `scripts/native_slo_contract.py`, `guard/runtime/hook_review_engine.py` |
| Direct native c16 | Declared 100 ms p99 ceiling; active release runner reports `direct_concurrent_16: not_measured` and does not run this population | Release `main`; direct/adapter distinction in `native_slo_contract.py` |
| Original installed qualification | 50 ms p95/100 ms p99 at c1 for normal 1–16 KiB payloads, 200 ms p99 at c16, with original populations/comparators | Preserved original PRD; these are not replaced by ordinary smoke ceilings |

The release timer wraps `review_post_tool_native` and therefore measures **NATIVE_CLIENT**, including its Python native adapter. Its direct authenticated resident IPC timing is also a native-client diagnostic. It does not measure **KERNEL**, **DAEMON_INGRESS**, or **INSTALLED_LAUNCHER**. The installed SLO reporting code labels normalized HTTP and registered-argv measurements separately. A declared threshold is not a measured result.

`scripts/native_release_reporting.py` contains a separate v1 helper capable of formatting direct-concurrency fields. The active release benchmark neither imports nor calls it; its presence cannot turn `not_measured` into an executed c16 runner. The preserved older migration checklist has older absolute targets and remains archival wording, not a description of the current predicate.

The original §4 reference defect is addressed in current source: the benchmark uses a scripts-only child that explicitly constructs the Python semantic engine. Both benchmark arms validate route, verdict, model-output action and reason for benign and secret fixtures. An off-mode availability result or a payload-only response cannot pass that validator. The oracle is not imported by production `src` code. This is source reconciliation, not a fresh relative-speedup result or full qualification.

## RSP-022: actual synchronous caller and ownership

The compatibility command path `HookWorker._review_pre_tool_http` calls `hook_review_is_recording_only` synchronously before native review. That helper loads configuration using the worker's `config_reader`. `server_http._initialize_request_services` injects `HookConfigReadScope.read_toml`, which calls its held-file capture and parent validation. This differs from the ordinary raw native route's acknowledged snapshot mode and from the background policy publisher.

The I/O gate explicitly roots the recording-mode helper and all three injected `HookConfigReadScope` methods (`read_toml`, `__call__`, `_validate_held_parent`). It walks those roots separately and changes reachable `asynchronous_policy` observations to `synchronous_posture_config`. This prevents shared configuration parsing and secure file reads from being hidden by their publisher classification. Closed function/primitive allowances leave new unreviewed operations unclassified and failing. Current gate controls cover the actual source inventory and introduced source/decoding/compiler mutations.

`decision-critical-io.yml` selects PRs to both `main` and `release/3.2` without changed-file filters. It invokes the ownership gate, actual I/O inventory, privacy gate and existing mutation controls. The separate `rust-authority-ownership.yml` is also unfiltered; it does not itself call the I/O gate, so the two workflows must not be conflated.

## Scope and original dependencies

RSP-006's executable predicates and RSP-022's current source-classification requirement match the reviewed contract. One inline comment in `native_slo_contract.py::gate_results` still calls the release benchmark direct Rust timing and attributes native size ceilings to it. The included comment-only afterimage corrects that description; its Python AST is identical and all predicates remain unchanged. The documentary table above resolves the threshold wording without changing original archived files. The afterimage is prepared, not published to the product branch.

RSP-133's own workflow-selection requirement is supported by current broad native/ownership selection, expanded wrapper/publisher/evidence/benchmark paths, the permanent risk matrix and the already retained workflow/composition/terminal evidence. Its original dependencies are exactly RSP-006 and RSP-022; RSP-137 is not added.

Full dependency closure remains separately assessed. RSP-006 depends on RSP-003/RSP-005, whose current timing/semantic source implementations are mapped in the receipt; this review adds no new execution credit. RSP-022 depends on RSP-013/RSP-015. RSP-015 requires the complete current mode/posture, misses, integrity/size, permission, lifecycle and exit fixture inventory. The existing 118-case/46-mandatory renderer packet proves its declared renderer scope; it does not by itself establish that full fixture inventory. The owner explicitly confirmed that limit. Therefore this receipt supports the own-scope reconciliation while leaving complete RSP-015 dependency acceptance unassessed. It does not silently promote RSP-022/RSP-133 to dependency-complete status.
