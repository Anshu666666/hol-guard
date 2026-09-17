# HOL Guard Rust Performance: Implementation Takeaway Prompt

## Copy the prompt below into the implementation session

You are implementing the HOL Guard Rust Performance PRD and its 144-task TODO for hashgraph-online/hol-guard. Read those companion documents when they are supplied. This prompt preserves the essential audit findings and execution rules so you can begin correctly in a fresh session.



Your objective is to reduce actual installed tool latency, CPU use, and process-tree memory without losing protection, Watch behavior, availability behavior, approvals, evidence, package completeness, or community extension usability. Optimize repeated work and algorithms first. Port a component to Rust only when the adopted measurement and compatibility gates justify it.



## Source baseline and operating rules

The source review used main at 2e672d2d950c6ec471005ddba46e49bba16dc23b. Refresh current main and compare relevant changes before editing. The audited release/3.2 SHA was 4b89e0d2d496a85f04922b2e019a4aea15326bb9; it is not the implicit implementation target. Recheck draft PR [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797) and overlapping [#2807](https://github.com/hashgraph-online/hol-guard/pull/2807), [#2870](https://github.com/hashgraph-online/hol-guard/pull/2870), [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931), [#2948](https://github.com/hashgraph-online/hol-guard/pull/2948) and [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911).



Work in an isolated branch/worktree from the correct current target. Read repository instructions, pyproject.toml, rust/Cargo.toml, rust/rust-toolchain.toml, current CI workflows, and the existing ownership contracts. Resolve routine implementation choices yourself. Preserve unrelated work.



Do not create GitHub issues in hashgraph-online repositories. Do not merge or release just because this prompt requests implementation. Prepare reviewable changes and a draft PR when authorized by the implementation session; use its existing merge/release authorization if one is explicitly present. Never weaken CI or raise a performance threshold simply to get a pass.



Track TODO IDs RSP-001 through RSP-144. Use OPEN, IN_PROGRESS, DONE, DEFERRED and BLOCKED honestly. A measured no-go completes an investigation but does not mark an unimplemented port done. Dependent implementation tasks should be explicitly deferred when their go/no-go gate rejects the port. Continue independent work when one optional tranche is blocked.



## Facts you must not rediscover incorrectly

1. Rust migration is already substantial. The 10-crate workspace includes command/pretool evaluation, contracts, scanner/rules, secure file access, hook core, policy snapshots, runtime and Windows process support. NHD work merged through [#2682](https://github.com/hashgraph-online/hol-guard/pull/2682), [#2699](https://github.com/hashgraph-online/hol-guard/pull/2699), [#2713](https://github.com/hashgraph-online/hol-guard/pull/2713), [#2718](https://github.com/hashgraph-online/hol-guard/pull/2718), [#2719](https://github.com/hashgraph-online/hol-guard/pull/2719), [#2720](https://github.com/hashgraph-online/hol-guard/pull/2720) and [#2724](https://github.com/hashgraph-online/hol-guard/pull/2724). Do not propose this completed scope as a new migration.

2. Ordinary daemon native hooks go directly from server.py to the in-process HookWorker, then the Python native edge and a persistent Rust helper, then the Rust resident. Guardian/evaluator multiprocessing is not two extra hops for every ordinary native request. It still matters to selected compatibility and approval revalidation paths and idle startup memory.

3. The Rust helper is persistent. Do not claim a new Rust subprocess starts for every warm hook. Inside the persistent helper, discovery, socket connection and authentication still occur per request.

4. native_hook_edge.py::review_raw_hook_native calls native_runtime_status for each review. native_runtime.py::_validate_binary hashes the entire runtime executable before capability-cache lookup. This is actual repeated work, but removing attestation without equivalent identity binding is unacceptable.

5. daemon/hook_worker_native.py::_review_native_edge calls hook_review_is_recording_only, which invokes load_guard_config. Watch can also transform native results in Python. Current source therefore needs a more precise ownership contract than the old prose.

6. Availability behavior is event- and reason-specific. Current hook_availability_policy.py continues selected native-unavailable cases, preserves particular integrity/size denials, and treats permission/lifecycle events separately. Freeze the actual matrix; do not silently restore blanket fail-closed behavior or relax a completed native block as a performance change.

7. The retained Python native_runtime_resident.py is excluded from distributions. Deleting it is not a runtime speed improvement. The old hook ContentScanner/HookReviewEngine/reference evaluators are not ordinary native-hook bottlenecks.

8. guard-scanner is not the full repository secrets detector. The Python secrets CLI has richer providers, entropy, context, positions, HMAC and scan coverage semantics. Test names containing “native” do not prove Rust execution.

9. Command extension catalog presence is not native execution. The current catalog exports matcher kind and digest rather than a complete executable program. Extension Builder's “native” output is in-tree Python. Preserve the Python contribution flow while compiling a complete bounded matcher IR.

10. No new installed speedup was measured by the source review. Proposed targets are requirements to qualify, not evidence.



## Start with benchmark integrity

Read scripts/bench_guard_native_release_gate.py before running it. The warm production arm times review_post_tool_native, including the Python adapter/client but excluding the installed launcher and daemon HTTP path. Direct resident IPC is a separate diagnostic.



The reference sets HOL_GUARD_NATIVE=off, while ordinary off now produces an availability response unless an explicit test oracle is constructed. The benchmark only checks payload presence in its Python arm. Fix the reference construction and prove expected semantic route and verdict for both benign and malicious inputs. Never reopen a production Python fallback to make the benchmark work.



Current warm acceptance is p95 ≤20 ms OR ≥1.15x relative speedup. Cold is p95 ≤150 ms AND ≥5x. Readiness is 400 ms. Installed adapter limits are currently tied to the 1,000 ms hook budget. SLO prose and executable code disagree about a direct c16 gate. Correct labels and checks instead of repeating documentation claims.



Add four explicit boundaries: KERNEL, NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER. Include actual registered executable startup, final stdout/exit status, queue time, recovery and retries where relevant. Classify human and remote wait separately. A native-unavailable continuation must not count as an evaluated allow.



Use installed release artifacts and current production as the principal baseline. For a new Python-to-Rust kernel, also compare against optimized Python. Qualify per harness/event/platform with synthetic benign and malicious fixtures. Use c1/c4/c16/c64 plus offered-rate load. Report every attempt, rejection, deadline miss and failure, not just successful timings.



The PRD proposes 10,000 warm samples per priority route/platform across at least five runs, 100 cold launches and recoveries, and full-process-tree resource measurements. Two-sample CI smoke is not p99 proof. Record hardware, OS, builds, artifact/corpus digests and confidence. Baseline/candidate runs should alternate on the same machine.



For small ordinary hooks, proposed product targets are installed warm p95 ≤50 ms/p99 ≤100 ms at c1 and p99 ≤200 ms at c16. A selected optimization should deliver ≥30% lower relevant p95 or CPU with ≤5% regression in the other primary metric. Native ingress needs material memory or concurrency benefit. Validate applicability before committing thresholds; do not quietly relax them after a failure.



## First implementation tranches

A. Repair benchmark reference integrity and route documentation, then baseline the system.

B. Optimize Python signed-bundle indexing and lockfile single parsing.

C. Remove repeated runtime identity and mode/configuration work through an equivalent verified-generation and acknowledged-snapshot design.

D. Reduce repeated JSON, canonical identity, typed-result conversions, output copies and policy-map validation already in Rust.

E. Optimize compact evidence handoff, real journal/SQL batching and domain-specific policy invalidation.

F. Use the new evidence to choose one native installed launcher and one native package-format pilot. Expand only proven scopes.

G. Treat native extension execution as a separate compatibility tranche with its own performance/coverage proof.

H. Keep full MCP/daemon rewrites and broader scanner ports conditional.



## Exact source anchors

Hot path:

src/codex_plugin_scanner/guard/native_runtime.py::_validate_binary and native_runtime_status

src/codex_plugin_scanner/guard/native_hook_edge.py::review_raw_hook_native

src/codex_plugin_scanner/guard/daemon/hook_worker_native.py::_review_native_edge

src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py

src/codex_plugin_scanner/guard/daemon/server.py::_handle_runtime_hook_fast

native_resident_client.py and native_resident_stream.py

rust/crates/guard-runtime/src/managed_resident*.rs, resident_client.rs, resident_transport.rs and edge.rs



Already-Rust work:

edge.rs validates/reencodes and computes canonical identity more than once.

policy_enforcement_policy.rs validates whole action maps and normalizes harness aliases; compile immutable maps at snapshot admission while retaining per-request freshness/authority fences.

guard-hook-core/src/lib.rs copies/concatenates output; preserve exact Unicode/newline/hash behavior.

guard-scanner already caches compiled regexes. Any RegexSet/prefilter must preserve per-match suppression, document boundaries and early-exit semantics.



Package core:

guard/runtime/supply_chain_package_eval.py::_transitive_lockfile_results builds an index but still calls evaluate_cached_supply_chain_bundle for every dependency.

guard/runtime/supply_chain_bundle_runtime.py::evaluate_cached_supply_chain_bundle scans bundle.packages again.

guard/runtime/lockfile_parse_result.py validates then extracts, causing repeated parsing.

First use immutable verified bundle indexes and one input snapshot. Then consider proposed guard-package-core through one coarse bounded batch request.

Preserve 8 MiB/100,000-entry/250,000-node/depth-128 parser bounds, complete/source_hash/version/error state, ecosystem version semantics, stale emergency denies, bun.lockb fallback and final package launch revalidation.



Secrets and plugin scanning:

guard/secrets/secret_detection.py, secret_repository_scanner.py and secret_staged_scanner.py.

Batch Git object reads before attributing subprocess savings to Rust. Preserve staged-index bytes and path/commit occurrences when deduplicating blobs.

Preserve exits 0/2/3, HMAC/redaction and richer detector semantics.

Keep offline_archive_inspection.py/offline_archive_worker.py in a dedicated isolated process with digest/file identity, expansion bounds and launch binding. Do not move hostile parsing into the resident hook process.

Keep third-party scanner/network orchestration in Python unless profiling identifies local CPU work.



MCP:

guard/proxy/runtime_mcp.py repeatedly hashes immutable full tool catalogs; cache by validated generation.

guard/mcp_tool_calls.py computes risk categories repeatedly; reuse request-local facts when authority inputs are unchanged.

Preserve the final 5 ms quiet prewrite barrier unless an equivalent ordering proof replaces it.

Carry test_guard_runtime_mcp_saved_blocks.py catalog-change and spawn-time entrypoint-quarantine cases. Never replay an ambiguous tool write.



Extensions:

guard/runtime/command_rules.py and command_matcher_contracts.py define exported matcher metadata.

Build explicit versioned IR for all selected matcher families, not only basic token matching.

Preserve local opt-in, publisher trust, managed/local revisions, permission IDs, safe variants, uncertainty and strongest non-overridable floors.

Qualify command.ollama from contributor source through build/install/enable/native decision/receipt/disable/update.

No runtime arbitrary Python imports, per-rule IPC or required Rust toolchain for ordinary declarative contributors.



Background:

daemon/runtime_hook_evidence_writer.py performs foreground copies/serialization and per-record durable work despite dequeuing batches.

runtime_hook_evidence_journal.py rewrites remaining journal records on removal. Implement real bounded batching/checkpointing with crash proof.

native_policy_snapshot_publisher_inputs.py may recompile all registered workspace policies after unrelated database activity. Use precise revision/invalidation plus cross-process reconciliation.

Distinguish memory acceptance, journal durability and DB commit. Do not claim exactly-once durability that current submit does not promise.



## Nonnegotiable implementation constraints

Preserve package/executable/peer identity, private transport permissions, policy generation/scope/expiry/rollback protection, source identity and equivalence, approval challenge/consume/replay rules, and integrity-specific failures. A path/mtime-only identity cache is insufficient. Test same-size replacement, restored timestamp, permission/owner changes, signing, restart and concurrent upgrades.



Use one deadline and bounded work across all stages. Do not replay committed operations. Keep safe Rust as the default and the current locked toolchain. New transports and in-process bindings need explicit ABI, distribution, failure-containment and rollback choices.



Do not change decision coverage to win a benchmark. Incomplete or unsupported scans must remain distinct from clean. Keep diagnostics aggregate and bounded without raw secrets, commands, prompts, output or private paths.



## Verification and deliverables

The source review ran the following existing checks successfully; rerun them for changed code and extend them where current callers escape their scope:

python3 scripts/ci/python_hook_semantic_callgraph_gate.py

python3 scripts/ci/rust_authority_ownership_gate.py

python3 scripts/ci/rust_io_ownership_gate.py



Read the current CI files for the exact dependency setup and Rust/Python test commands. Run meaningful affected suites, installed native-wheel probes, actual launcher tests, policy/approval/source-mutation tests, and fault/recovery tests. Keep the test oracle independent. All supported targets need explicit coverage; a Linux pass is not a Windows pass.



For each PR provide: task IDs; exact base/head SHA; changed production route; compatibility results; test commands/outcomes; benchmark boundary and baseline/candidate digests; samples/confidence; latency/CPU/memory; unsupported/deferred scope; and rollback evidence.



The final result must distinguish implementation from activation and activation from measured benefit. Do not stop at writing a new crate or updating a TODO. Carry selected work through real caller integration, review and verification. If measurements reject a port, keep the useful algorithmic fix and document the no-go.



