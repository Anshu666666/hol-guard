# HOL Guard Rust Performance TODO

## How to execute this backlog

144 numbered tasks across 12 workstreams, grounded in main commit 2e672d2d950c6ec471005ddba46e49bba16dc23b. Read the companion PRD before implementation.



All tasks start OPEN. Mark a task DONE only when its acceptance condition has supporting code, test or measurement evidence. Use DEFERRED for a measured no-go, with a written reason; use BLOCKED for a missing dependency. A deferred investigation can be complete, but its implementation tasks must remain deferred rather than done.



P0 is the prerequisite measurement and contract work. P1 contains the first recommended optimizations. Larger P1/P2 Rust conversions require the PRD's go/no-go decision; this is not an instruction to port every listed component. Native extension execution is a separate compatibility tranche. Do not claim its product benefit as a measured latency result.



Dependencies below use stable task IDs. Workstreams can run in parallel once their explicit prerequisites are met. Shared contract, package, policy and transport edits require one integration owner. Existing field and function names are source navigation anchors; new crate/API names in the PRD are proposals.



Use existing meaningful tests before adding new ones. Add tests for new contract behavior, parity, fault boundaries and performance evidence integrity. Do not write assertion-only tests that merely repeat a new constant.



Preserve current Watch/availability behavior, verified identities, approval consume/replay rules and current installed distribution targets. Do not create GitHub issues. This document is an implementation plan; external merges/releases require authorization in the implementation session.



## Recommended first PRs

PR 1: benchmark reference correctness, timing boundaries and evidence labels (A, with route documentation from B).

PR 2: optimized Python signed-bundle indexing and single parse (E, before choosing Rust).

PR 3: generation-safe runtime identity and acknowledged posture optimization (C, with B).

PR 4: measured Rust allocation/JSON/policy changes (D).

PR 5: bounded evidence and policy invalidation improvements (K).

Then choose native launcher and package-core pilots using the actual measurements. Keep native ingress, offline kernels and full MCP rewrites conditional.



## A. Baselines and benchmark integrity

Priority: P0

Responsible role: Performance lead

Gate: Required before any major migration.

Source anchors: scripts/bench_guard_native_release_gate.py; scripts/bench_guard_native_installed_slo.py; scripts/native_slo_*.py; .github/workflows/native-wheel-ci.yml. PRD §§4–6; [S22](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/bench_guard_native_release_gate.py)–[S25](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-runtime-slo-proof.md).



### RSP-001. Pin the implementation source and artifact

Status: OPEN. Depends on: None.

Acceptance: Record current main SHA, package/runtime/rule digests, toolchains, OS, architecture and source changes since audited 2e672d2. State the actual branch before editing.



### RSP-002. Recheck active migration overlaps

Status: OPEN. Depends on: RSP-001.

Acceptance: Read current state and changed files for [#2807](https://github.com/hashgraph-online/hol-guard/pull/2807), [#2870](https://github.com/hashgraph-online/hol-guard/pull/2870), [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931), [#2948](https://github.com/hashgraph-online/hol-guard/pull/2948), [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911) and [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797). Record reuse or conflict resolution; do not revive superseded branches.



### RSP-003. Trace and name the four timing boundaries

Status: OPEN. Depends on: RSP-001.

Acceptance: Separate KERNEL, NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER in benchmark output and docs. Verify each timer's callers against source.



### RSP-004. Repair the Python semantic reference

Status: OPEN. Depends on: RSP-003.

Acceptance: Construct an explicit isolated benchmark-only oracle or equivalent pinned installed version. An off-mode availability response must fail the reference validation.



### RSP-005. Assert semantic work on both benchmark arms

Status: OPEN. Depends on: RSP-004.

Acceptance: Require expected route, verdict and reason class for benign and malicious fixtures. A payload-only check cannot pass. Never expose the oracle in production.



### RSP-006. Correct existing SLO descriptions

Status: OPEN. Depends on: RSP-003,RSP-005.

Acceptance: Document warm ≤20 ms OR ≥1.15x and cold ≤150 ms AND ≥5x as current script logic; distinguish 1000 ms adapter budget and absent direct c16 runner. Reconcile docs and code.



### RSP-007. Add actual installed launcher measurements

Status: OPEN. Depends on: RSP-003.

Acceptance: Start the registered executable/argv from the installed artifact; include interpreter/native startup, stdout and exit status. Keep normalized HTTP probes separately labeled.



### RSP-008. Add attributable phase measurements

Status: OPEN. Depends on: RSP-003.

Acceptance: Measure hashing, config lookup, JSON, admission, queue, native connection, evaluation, evidence submission and response. Export aggregate-only bounded fields.



### RSP-009. Create the workload and platform matrix

Status: OPEN. Depends on: RSP-007,RSP-008.

Acceptance: Cover sizes, events, allow/block/review/Watch/unavailable cases, source refs, c1/c4/c16/c64 and supported targets; classify missing routes explicitly.



### RSP-010. Add statistically meaningful qualification mode

Status: OPEN. Depends on: RSP-009.

Acceptance: Implement the PRD's warm/cold/recovery sample minima, alternating baseline/candidate blocks and per-route confidence intervals. Keep CI smoke labeled as smoke.



### RSP-011. Measure the full process tree and saturation

Status: OPEN. Depends on: RSP-009.

Acceptance: Sample private memory/RSS where supported, CPU/request, children, threads, handles, queueing and every attempted request. Add offered-rate load beside closed-loop waves.



### RSP-012. Freeze baseline and choose measured tranches

Status: OPEN. Depends on: RSP-005,RSP-010,RSP-011.

Acceptance: Record current production and optimized alternatives. Commit metric thresholds and go/no-go rules; exclude deferred conversions from delivery claims.



## B. Contracts and current behavior

Priority: P0/P1

Responsible role: Runtime and security maintainers

Gate: Prerequisite for changes to semantics, identity or transport.

Source anchors: guard/daemon/hook_worker_native.py; hook_availability_policy.py; native_hook_edge.py; rust/crates/guard-contracts; existing ownership manifests. PRD §§2,7,14; [S01](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-hook-data-plane-ownership.md)–[S06](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/edge.rs).



### RSP-013. Capture the real ordinary native call graph

Status: OPEN. Depends on: RSP-001.

Acceptance: Document direct in-daemon HookWorker dispatch and persistent helper reuse. Keep guardian/evaluator IPC only on verified compatibility/approval paths.



### RSP-014. Inventory every installed harness surface

Status: OPEN. Depends on: RSP-013.

Acceptance: Map actual generated launcher, aliases, pre/post support and observation-only routes. Preflight detection must not count as installed enforcement.



### RSP-015. Freeze Watch and availability response fixtures

Status: OPEN. Depends on: RSP-014.

Acceptance: Capture harness JSON and exit behavior for current mode/posture, native misses, integrity/size failures, permission requests and lifecycle events.



### RSP-016. Separate native verdict from delivered response

Status: OPEN. Depends on: RSP-015.

Acceptance: Define native decision, posture transformation, availability outcome and final harness response in evidence. Preserve accurate receipt attribution.



### RSP-017. Specify coarse request/result contracts

Status: OPEN. Depends on: RSP-012,RSP-016.

Acceptance: Add or extend versioned native schemas only for selected scope; declare fields, limits, unknown-field policy, capabilities and error classes.



### RSP-018. Define byte, Unicode and canonicalization behavior

Status: OPEN. Depends on: RSP-017.

Acceptance: Pin duplicate JSON rejection, number/null behavior, UTF-8, string versus byte limits, field ordering and digest domains with fixtures.



### RSP-019. Define deadline ownership

Status: OPEN. Depends on: RSP-017.

Acceptance: One caller deadline must cover setup, queueing, transport and evaluation. Define cancellation and late-result rejection without resetting budget.



### RSP-020. Define generation-bound identity rules

Status: OPEN. Depends on: RSP-017.

Acceptance: Specify executable/package/process/peer identity, policy scope and generation, expiry, and cache invalidation before accepting reuse.



### RSP-021. Define non-replayable request behavior

Status: OPEN. Depends on: RSP-019,RSP-020.

Acceptance: Document request commit points for approval, policy and forwarding operations. Ambiguous outcomes require explicit handling, not transparent replay.



### RSP-022. Expand source ownership gates

Status: OPEN. Depends on: RSP-013,RSP-015.

Acceptance: Follow the current recording-mode caller and proposed new routes; prevent synchronous configuration reads being mislabeled as background work.



### RSP-023. Build independent correctness vectors

Status: OPEN. Depends on: RSP-015,RSP-018.

Acceptance: Add expected outcomes for malicious and benign cases independent of Python equivalence; label every intentional behavior correction separately.



### RSP-024. Approve the technical contract through review

Status: OPEN. Depends on: RSP-016,RSP-021,RSP-022,RSP-023.

Acceptance: Resolve reviewer questions on current availability behavior, authority transfer, distributions and rollback. Do not infer safety from a passing old manifest.



## C. Repeated identity and posture work

Priority: P1

Responsible role: Native runtime engineer

Gate: Adopt only with equivalent identity protection and measured benefit.

Source anchors: guard/native_runtime.py::_validate_binary/native_runtime_status; native_hook_edge.py::review_raw_hook_native; daemon/hook_worker_native.py::_review_native_edge; native_policy_snapshot_publisher.py. PRD §7; [S02](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_worker_native.py),[S03](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py),[S05](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_runtime.py),[S11](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_hook_edge.py),[S21](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py).



### RSP-025. Profile executable validation on the ordinary route

Status: OPEN. Depends on: RSP-008.

Acceptance: Count status lookups, full executable bytes hashed and latency for warm/cold hooks. Do not confuse capability-cache hits with digest-cache hits.



### RSP-026. Choose a verified runtime-lifetime design

Status: OPEN. Depends on: RSP-020,RSP-025.

Acceptance: Compare retained attested process/session identity and safe native admission against current validation. Record platform-specific proof and limits.



### RSP-027. Implement generation-bound attestation reuse

Status: OPEN. Depends on: RSP-024,RSP-026.

Acceptance: Reuse only a verified generation. Bind package/version/digest/permissions/peer and invalidate on upgrades, replacements and identity failure.



### RSP-028. Test executable replacement defenses

Status: OPEN. Depends on: RSP-027.

Acceptance: Cover same-size mutation, restored timestamps, symlink/path rebinding, ownership/permission changes, stale manifests and concurrent replacement.



### RSP-029. Test signing and update transitions

Status: OPEN. Depends on: RSP-028.

Acceptance: Verify re-sign/freeze byte changes, manifest refresh, generation retirement, rollback and first request after update on every target.



### RSP-030. Measure request-time configuration loading

Status: OPEN. Depends on: RSP-008,RSP-015.

Acceptance: Count home/workspace config reads and their contribution in _review_native_edge, including Watch changes and cache-miss situations.



### RSP-031. Extend acknowledged posture binding if needed

Status: OPEN. Depends on: RSP-020,RSP-030.

Acceptance: Carry complete mode/posture semantics in an authenticated snapshot; define visibility only after correct resident acknowledgement.



### RSP-032. Remove redundant ordinary configuration rereads

Status: OPEN. Depends on: RSP-031.

Acceptance: Use the acknowledged request binding. Preserve workspace registration, first-use behavior and mixed control changes without stale-mode results.



### RSP-033. Move the small transformation layer only if selected

Status: OPEN. Depends on: RSP-024,RSP-032.

Acceptance: Implement the captured Watch/availability contract at the appropriate native boundary, with deterministic unavailable-runtime bridge behavior.



### RSP-034. Exercise policy and posture transitions under load

Status: OPEN. Depends on: RSP-032,RSP-033.

Acceptance: Test mode toggles, stricter workspace overlays, expiry, restart, failed publication and races. The adopted behavior matrix must remain intact.



### RSP-035. Qualify identity and posture improvements

Status: OPEN. Depends on: RSP-029,RSP-034.

Acceptance: Run installed before/after tests and process-tree metrics. Count integrity failures and unavailable continuations separately from evaluated allows.



### RSP-036. Retire redundant work and document proof

Status: OPEN. Depends on: RSP-035.

Acceptance: Remove only proven duplicated code; retain necessary validation on platforms without equivalent binding. Mark any failed optimization deferred.



## D. Work already inside Rust

Priority: P1

Responsible role: Rust core engineer

Gate: Preserve digest and semantic contracts; no speculative unsafe optimization.

Source anchors: rust/crates/guard-runtime/src/edge.rs, managed_resident.rs, resident_protocol.rs, resident_transport.rs, policy_enforcement_policy.rs; guard-hook-core/src/lib.rs; guard-scanner/src/lib.rs. PRD §8; [S06](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/edge.rs),[S12](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident_client_stream.rs),[S13](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident.rs),[S15](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-scanner/src/lib.rs),[S26](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/policy_enforcement_policy.rs),[S27](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-hook-core/src/lib.rs).



### RSP-037. Measure parsing, serialization and allocation counts

Status: OPEN. Depends on: RSP-008,RSP-018.

Acceptance: Use small and maximum-size envelopes; attribute client timeout parse, protocol parse, shutdown reparse and edge copies separately.



### RSP-038. Return typed lifecycle disposition

Status: OPEN. Depends on: RSP-037.

Acceptance: Eliminate the post-evaluation full request parse used only to detect shutdown, preserving shutdown authorization and response behavior.



### RSP-039. Reuse validated timeout metadata

Status: OPEN. Depends on: RSP-018,RSP-019,RSP-037.

Acceptance: Avoid full reparsing in client timeout handling while retaining strict framing, duplicate keys, limits and semantic validation.



### RSP-040. Compute canonical request identity once

Status: OPEN. Depends on: RSP-018,RSP-023,RSP-037.

Acceptance: Carry an immutable validated identity through evaluation and receipt creation; golden digests and approval bindings must remain identical.



### RSP-041. Keep PreTool results typed through receipt creation

Status: OPEN. Depends on: RSP-040.

Acceptance: Remove repeated typed→Value→typed conversions while retaining result-matrix validation and serialized output compatibility.



### RSP-042. Compile policy maps at snapshot admission

Status: OPEN. Depends on: RSP-020,RSP-024.

Acceptance: Validate keys/actions and canonical harness conflicts once per immutable generation; retain per-request authority, expiry and scope fences.



### RSP-043. Share immutable compiled policy state

Status: OPEN. Depends on: RSP-042.

Acceptance: Use appropriate shared ownership without copying maps per request; preserve atomic swaps and approval consume synchronization.



### RSP-044. Reduce post-tool output copying

Status: OPEN. Depends on: RSP-018,RSP-023.

Acceptance: Optimize traversal/concatenation/hash input while preserving newlines, ordering, character counts, truncation and source equivalence.



### RSP-045. Benchmark scanner prefilter alternatives

Status: OPEN. Depends on: RSP-012,RSP-023.

Acceptance: Compare existing OnceLock regexes with bounded prefilters/RegexSet on clean and matching text. Preserve per-match suppression and ordering.



### RSP-046. Preserve scanner chunk and deadline semantics

Status: OPEN. Depends on: RSP-019,RSP-044,RSP-045.

Acceptance: Test split tokens, multibyte boundaries and unrelated-document isolation. Ensure parsing/I/O/scanning consume the original remaining deadline.



### RSP-047. Run core parity and adversarial suites

Status: OPEN. Depends on: RSP-038,RSP-039,RSP-041,RSP-043,RSP-046.

Acceptance: Run command, rule-contract, source mutation, snapshot/approval and scanner suites applicable to the changed modules; investigate every difference.



### RSP-048. Qualify end-to-end benefit of core changes

Status: OPEN. Depends on: RSP-047,RSP-010.

Acceptance: Compare installed and native-client timings; a microbenchmark gain with a slower installed path does not justify adoption.



## E. Package core, algorithm first

Priority: P1 then conditional Rust

Responsible role: Supply-chain engineer

Gate: Rust must beat optimized Python and preserve completeness/authority.

Source anchors: guard/runtime/supply_chain_package_eval.py; supply_chain_bundle_runtime.py; lockfile_parse_result.py; package_intent*.py; guard/local_supply_chain.py; package_shim_gate.py. PRD §9; [S07](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py)–[S09](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/lockfile_parse_result.py).



### RSP-049. Inventory package-core production consumers

Status: OPEN. Depends on: RSP-001,RSP-008.

Acceptance: Trace package protect, shims, audit CLI, daemon and MCP package routes. Record local computation versus network or approval wait.



### RSP-050. Benchmark dependency and bundle cardinality independently

Status: OPEN. Depends on: RSP-049,RSP-010.

Acceptance: Cover absent/exact/unversioned/deny matches with 100/1000/10000 dependencies and independently scaled bundles; record CPU and full local evaluation.



### RSP-051. Build verified immutable bundle indexes in Python

Status: OPEN. Depends on: RSP-050,RSP-023.

Acceptance: Eliminate repeated full bundle scans; preserve canonical duplicates, unversioned risk selection, emergency denies and stale-bundle semantics.



### RSP-052. Parse each lockfile input once in Python

Status: OPEN. Depends on: RSP-051.

Acceptance: Return structured entries and validation/completeness from one parse, preserving JSONC/UTF-8/duplicate handling and current budgets.



### RSP-053. Share one immutable input snapshot per evaluation

Status: OPEN. Depends on: RSP-020,RSP-052.

Acceptance: Bind content bytes/hash/parser identity to evaluation, context and evidence; do not reuse by filename or timestamp alone.



### RSP-054. Rebaseline and decide whether Rust is justified

Status: OPEN. Depends on: RSP-053,RSP-012.

Acceptance: Compare current Python and optimized Python in real local package routes. Record port/no-port decision against PRD benefit threshold.



### RSP-055. Define native package batch schemas

Status: OPEN. Depends on: RSP-024,RSP-054.

Acceptance: Specify bounded PackageEvaluationRequestV1/ResultV1 with input, verified bundle and policy identities, findings and explicit completeness.



### RSP-056. Implement one native parser format end to end

Status: OPEN. Depends on: RSP-055.

Acceptance: Add proposed guard-package-core only after go decision. Validate and emit entries in one traversal under current byte/node/entry/depth limits.



### RSP-057. Implement native indexed bundle evaluation

Status: OPEN. Depends on: RSP-056.

Acceptance: Preserve ecosystem identity/version semantics, emergency deny precedence and trust freshness; never accept caller-supplied verified=true as proof.



### RSP-058. Integrate the coarse native call into a real surface

Status: OPEN. Depends on: RSP-057.

Acceptance: Wire package protect or audit to one native batch request, preserving final execution revalidation and all output/evidence fields.



### RSP-059. Expand format parity and malformed-input tests

Status: OPEN. Depends on: RSP-058.

Acceptance: Cover aliases, workspaces, transitive/local/git/optional dependencies, prereleases, truncation, stale bundles and explicit bun.lockb fallback.



### RSP-060. Qualify and activate only supported formats

Status: OPEN. Depends on: RSP-059,RSP-010.

Acceptance: Pass installed package-flow correctness and optimized-Python comparisons; publish native format coverage and unsupported routes accurately.



## F. Secrets and offline scans

Priority: P2 conditional

Responsible role: Scanner engineer

Gate: Keep richer detector contract and hostile archive isolation.

Source anchors: guard/secrets/secret_detection.py, secret_repository_scanner.py, secret_staged_scanner.py, cli.py; checks/security.py; scanner.py; guard/runtime/offline_archive_inspection.py. PRD §10; [S14](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py),[S15](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-scanner/src/lib.rs),[S29](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_detection.py)–[S31](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/offline_archive_inspection.py).



### RSP-061. Map rich secret detector capabilities

Status: OPEN. Depends on: RSP-001,RSP-023.

Acceptance: Compare provider rules, entropy, context, suppressions, positions, HMAC and evidence to guard-scanner. Record exact gaps before reuse.



### RSP-062. Baseline repository, staged and history workflows

Status: OPEN. Depends on: RSP-061,RSP-010.

Acceptance: Separate process startup, Git object I/O, detector CPU, bytes and files covered. Include small/large and repeated-blob workloads.



### RSP-063. Batch Git object reads in Python

Status: OPEN. Depends on: RSP-062.

Acceptance: Replace repeated size/blob subprocesses with a bounded reader. Preserve staged bytes, object identity, timeouts and child cleanup.



### RSP-064. Deduplicate blob scanning without losing occurrences

Status: OPEN. Depends on: RSP-063.

Acceptance: Reuse findings by immutable blob identity plus detector/policy configuration; report each path/commit occurrence and correct counters.



### RSP-065. Share secure traversal for plugin checks

Status: OPEN. Depends on: RSP-020,RSP-062.

Acceptance: Avoid repeated root enumeration and reads where checks permit shared immutable input. Preserve containment, exclusions and incomplete coverage.



### RSP-066. Rebaseline and approve only justified scanner ports

Status: OPEN. Depends on: RSP-064,RSP-065,RSP-012.

Acceptance: Compare optimized Python and intended native boundary, including startup and serialization; defer ports with no full-command benefit.



### RSP-067. Specify separate offline detector schemas

Status: OPEN. Depends on: RSP-024,RSP-061,RSP-066.

Acceptance: Preserve richer findings, deterministic ordering, caller HMAC and completeness; do not substitute the hook scanner output contract.



### RSP-068. Implement bounded native detector batches

Status: OPEN. Depends on: RSP-067.

Acceptance: Compile appropriate rules and parser logic, preserve Unicode/line counting/suppression, and reset overlap across logical files.



### RSP-069. Wire the real secrets CLI and exit behavior

Status: OPEN. Depends on: RSP-068.

Acceptance: Exercise installed hol-guard secrets and staged workflows. Preserve exits 0/2/3, default bounds and explicit user limits.



### RSP-070. Qualify hostile archive worker separately

Status: OPEN. Depends on: RSP-066,RSP-024.

Acceptance: Profile interpreter/member-loop cost; retain isolation, digest/inode binding, expansion checks and launch binding for any native worker.



### RSP-071. Run secret and scanner adversarial parity

Status: OPEN. Depends on: RSP-069,RSP-070.

Acceptance: Cover realistic/fixture credentials, unstaged changes, hardlinks/symlinks, invalid encodings, mutation, archive bombs and incomplete scans.



### RSP-072. Publish scanner go/no-go and coverage evidence

Status: OPEN. Depends on: RSP-071,RSP-010.

Acceptance: Report full CLI wall time and CPU versus optimized Python, complete finding equivalence, platforms and deliberately retained Python scopes.



## G. Native installed launchers

Priority: P1 conditional

Responsible role: Adapters and packaging engineer

Gate: Use actual installed entrypoints; preserve per-harness behavior.

Source anchors: guard/adapters/codex.py; claude_hook_argv.py; bounded_cli_hook_bridge.py; native_runtime.py; native-wheel-ci.yml. PRD §11; [S10](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_resident_stream.py),[S11](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_hook_edge.py),[S24](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/.github/workflows/native-wheel-ci.yml).



### RSP-073. Rank launcher cost by actual harness use

Status: OPEN. Depends on: RSP-007,RSP-012,RSP-014.

Acceptance: Use installed baseline measurements and explicit supported-route inventory; do not assume all adapters are Python command hooks.



### RSP-074. Design a package-bound native launcher command

Status: OPEN. Depends on: RSP-024,RSP-073.

Acceptance: Reuse existing runtime distribution and identity validation; specify argv, stdin, stdout, exit and environment contracts.



### RSP-075. Implement one canonical pre/post launcher

Status: OPEN. Depends on: RSP-074,RSP-015.

Acceptance: Start with the highest justified installed route and preserve response/continuation semantics without PATH lookup or auto download.



### RSP-076. Integrate registration and repair

Status: OPEN. Depends on: RSP-075.

Acceptance: Update generated hook entries, detect existing installs, and preserve idempotent reinstall/uninstall and exact package ownership.



### RSP-077. Verify no-environment installed selection

Status: OPEN. Depends on: RSP-076.

Acceptance: Clear development overrides and prove runtime origin plus actual registered executable use; source-checkout execution is insufficient.



### RSP-078. Port and qualify an alias-heavy harness

Status: OPEN. Depends on: RSP-077.

Acceptance: Exercise native Cursor/Copilot event and response forms, including permission and unavailable cases, not just normalized daemon JSON.



### RSP-079. Port and qualify Pi/OMP source references

Status: OPEN. Depends on: RSP-077.

Acceptance: Preserve reference identity, external-source permission, plaintext bounds, output equivalence and response schemas.



### RSP-080. Preserve approval continuation across launchers

Status: OPEN. Depends on: RSP-078,RSP-079,RSP-021.

Acceptance: Test review/pause/approve/revalidate/consume, expired approvals, restart and ambiguous completion without duplicate tool execution.



### RSP-081. Qualify wheels and frozen sidecars

Status: OPEN. Depends on: RSP-077,RSP-029.

Acceptance: Test Linux x64, macOS x64/arm64 and Windows x64 package/version/manifest binding and signing/freeze changes.



### RSP-082. Measure cold/warm launcher improvements

Status: OPEN. Depends on: RSP-080,RSP-081,RSP-010.

Acceptance: Apply actual launcher targets and include final response, setup and queue time; publish any platform or route misses.



### RSP-083. Expand route by route with declared support

Status: OPEN. Depends on: RSP-082.

Acceptance: Move only routes with parity and benefit proof; keep preflight-only/observation-only surfaces labeled correctly.



### RSP-084. Test launcher upgrade and rollback

Status: OPEN. Depends on: RSP-083,RSP-081.

Acceptance: Retire old registration/generation safely, preserve in-progress sessions and verify the prior tested native route can be restored.



## H. Native transport and narrower ingress

Priority: P2 conditional

Responsible role: Runtime transport engineer

Gate: Begin only if post-optimization profiles justify added protocol complexity.

Source anchors: rust guard-runtime managed_resident*, resident_client.rs, resident_transport.rs, resident_state_discovery.rs; guard/daemon/server.py; hook_process_*; native_resident_client.py. PRD §11; [S04](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/server.py),[S12](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident_client_stream.rs),[S13](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident.rs).



### RSP-085. Profile discovery/connect/auth versus evaluation

Status: OPEN. Depends on: RSP-035,RSP-048,RSP-010.

Acceptance: Measure platform-specific per-request work through the existing persistent helper and resident; count current socket opens.



### RSP-086. Choose connection reuse or ingress consolidation

Status: OPEN. Depends on: RSP-085,RSP-012.

Acceptance: Compare alternatives with full process-tree cost; do not port the entire administrative server to optimize hooks.



### RSP-087. Specify bounded native session protocol

Status: OPEN. Depends on: RSP-020,RSP-021,RSP-086.

Acceptance: Define generation/peer binding, framing, inflight limit, request correlation, idle timeout, cancellation and freshness checks.



### RSP-088. Implement generation-bound persistent connections

Status: OPEN. Depends on: RSP-087.

Acceptance: Reuse only within the authenticated scope and capability contract; bound pools, memory and lifetime.



### RSP-089. Exercise replacement and recovery races

Status: OPEN. Depends on: RSP-088,RSP-021.

Acceptance: Test restart, stale discovery, peer replacement, failed auth, reconnect, concurrent requests, cancellation and ambiguous commit.



### RSP-090. Prototype hook-only native ingress if selected

Status: OPEN. Depends on: RSP-086,RSP-024.

Acceptance: Preserve auth, context binding, scheduler/admission, response and evidence contracts while keeping product/admin APIs on their current owner.



### RSP-091. Preserve Windows and Unix transport guarantees

Status: OPEN. Depends on: RSP-089,RSP-090.

Acceptance: Test DACL/owner/SYSTEM rules, loopback authentication, exact package process, Unix private paths, permissions and peer identity.



### RSP-092. Audit the remaining Python process-pool callers

Status: OPEN. Depends on: RSP-013,RSP-011.

Acceptance: Enumerate compatibility and Codex approval revalidation consumers and measure idle/startup footprint before changing startup.



### RSP-093. Lazy-start or replace only proven pool consumers

Status: OPEN. Depends on: RSP-092,RSP-080.

Acceptance: Preserve first-approval latency, fresh reevaluation, containment and lifecycle cleanup; never claim ordinary-hook IPC removal here.



### RSP-094. Stress admission and fault containment

Status: OPEN. Depends on: RSP-091,RSP-093.

Acceptance: Use mixed large/small hooks at c16/c64, stalled clients, panic/worker failure and blocked I/O; require bounded failures and no cross-session leak.



### RSP-095. Qualify the transport benefit

Status: OPEN. Depends on: RSP-094,RSP-010.

Acceptance: Meet adopted p99/CPU/memory thresholds against the optimized current route; report all unavailable, rejected and timed-out work.



### RSP-096. Roll out or defer native ingress explicitly

Status: OPEN. Depends on: RSP-095.

Acceptance: Activate only proven routes/platforms with tested generation rollback; retain simpler current transport if benefit is insufficient.



## I. MCP local computation and proxy decision

Priority: P2 conditional

Responsible role: MCP runtime engineer

Gate: Optimize current state machine before authorizing a complete transport rewrite.

Source anchors: guard/proxy/runtime_mcp.py; guard/mcp_tool_calls.py; cli/commands_dispatch_proxy.py; tests/test_guard_runtime_mcp_saved_blocks.py. PRD §12; [S16](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/proxy/runtime_mcp.py),[S17](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/mcp_tool_calls.py).



### RSP-097. Trace actual stdio and remote MCP behavior

Status: OPEN. Depends on: RSP-002,RSP-003.

Acceptance: Reinspect [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931) and current dispatch; document catalog lifecycle, approvals, forwarding commit and response multiplexing.



### RSP-098. Benchmark Guard overhead separate from server wait

Status: OPEN. Depends on: RSP-097,RSP-010.

Acceptance: Measure startup, catalog hashing, classification, policy, barrier, child/network/human wait and serialization with identical synthetic traces.



### RSP-099. Cache immutable full-catalog fingerprints

Status: OPEN. Depends on: RSP-098,RSP-020.

Acceptance: Reuse canonical digest per validated catalog generation; preserve full-catalog binding and invalidation during pending approvals.



### RSP-100. Reuse request-local risk analysis

Status: OPEN. Depends on: RSP-099.

Acceptance: Compute categories/signals once for unchanged exact inputs; recompute after any authority/catalog/input change.



### RSP-101. Bound framing and buffering where required

Status: OPEN. Depends on: RSP-024,RSP-098.

Acceptance: Define limits and backpressure for lines, queues and response buffers without deadlocking notifications while approvals are pending.



### RSP-102. Preserve the final prewrite freshness barrier

Status: OPEN. Depends on: RSP-097,RSP-023.

Acceptance: Retain catalog invalidation during quiet drain and entrypoint-change quarantine. Removing a 5 ms wait requires an equivalent reviewed ordering design.



### RSP-103. Rebaseline optimized Python proxy

Status: OPEN. Depends on: RSP-100,RSP-101,RSP-102.

Acceptance: Measure actual proxy overhead and memory; distinguish deliberate waits and remote latency from local CPU before choosing Rust.



### RSP-104. Specify coarse native MCP facts contract if justified

Status: OPEN. Depends on: RSP-103,RSP-024.

Acceptance: Pass bounded catalog/request facts with immutable identities; keep credentials and remote session orchestration outside the kernel.



### RSP-105. Implement and integrate selected pure native kernels

Status: OPEN. Depends on: RSP-104.

Acceptance: Port canonicalization/risk evidence at one coarse boundary; preserve full policy/claim composition and redacted evidence.



### RSP-106. Test protocol and forwarding correctness

Status: OPEN. Depends on: RSP-105,RSP-021.

Acceptance: Cover IDs, notifications, cancellation, out-of-order replies, schema changes, EOF, slow consumers, package calls and no replay after ambiguous writes.



### RSP-107. Qualify native kernels against optimized proxy

Status: OPEN. Depends on: RSP-106,RSP-010.

Acceptance: Require measured benefit at the real proxy boundary with no catalog/approval/forwarding regressions.



### RSP-108. Record full proxy rewrite decision

Status: OPEN. Depends on: RSP-107.

Acceptance: Defer unless kernels and Python optimizations cannot meet adopted goals. If justified, require a separate ADR and complete protocol rollout scope.



## J. Native extension execution parity

Priority: Compatibility tranche with performance gates

Responsible role: Extension platform and Rust maintainers

Gate: Separate product coverage from speed claims; preserve contributor authoring.

Source anchors: guard/runtime/command_extensions.py; command_rules.py; command_matcher_contracts.py; command_extension_observations.py; extension_control_runtime.py; extension_builder/render_native.py; guard-command/src/pretool.rs. PRD §12; [S18](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_extensions.py),[S19](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/contracts/extensions/contribution.v1.schema.json),[S33](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_rules.py),[S34](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_matcher_contracts.py).



### RSP-109. Inventory matcher semantics and current native coverage

Status: OPEN. Depends on: RSP-014,RSP-001.

Acceptance: Enumerate all concrete matcher classes and safe variants; distinguish Python catalog presence from production Rust execution.



### RSP-110. Freeze extension outcome and control fixtures

Status: OPEN. Depends on: RSP-109,RSP-023.

Acceptance: Cover defaults, local opt-in, managed layers, permission IDs, uncertainty, overlaps, safe variants and hard floors.



### RSP-111. Define a bounded versioned matcher IR

Status: OPEN. Depends on: RSP-110,RSP-017.

Acceptance: Specify executable semantics, full config, rule/program digests and limits. Matcher kind+digest alone is not executable IR.



### RSP-112. Build trusted deterministic IR compilation

Status: OPEN. Depends on: RSP-111.

Acceptance: Compile supported reviewed definitions without arbitrary runtime Python imports. Reject unsupported types and emit per-rule coverage.



### RSP-113. Preserve the existing contribution and Builder flow

Status: OPEN. Depends on: RSP-112.

Acceptance: Keep python-module metadata and supported declarative authoring; normal contributors should not need a Rust toolchain.



### RSP-114. Implement native matcher primitives incrementally

Status: OPEN. Depends on: RSP-111,RSP-024.

Acceptance: Cover real operand/path-set/specialized matchers as well as basic combinators; unsupported must not become no-match/allow.



### RSP-115. Bind native program to control snapshots

Status: OPEN. Depends on: RSP-114,RSP-020.

Acceptance: Preserve catalog/trust identity, opt-in, independent revisions, durable commit-before-publish and equivocation rejection.



### RSP-116. Integrate native matching with one canonical command

Status: OPEN. Depends on: RSP-115.

Acceptance: Return complete observations, variants, uncertainty and redacted evidence. No per-rule IPC or duplicate independent parsing.



### RSP-117. Protect core floors and unknown-command behavior

Status: OPEN. Depends on: RSP-116,RSP-110.

Acceptance: Test that extension outcomes cannot weaken non-overridable native policy/security floors and unsupported families retain explicit handling.



### RSP-118. Qualify command.ollama end to end

Status: OPEN. Depends on: RSP-113,RSP-117.

Acceptance: Exercise contribution/build/install/enable/native review/receipt/disable/update/rollback; Python matcher tests alone cannot complete this task.



### RSP-119. Benchmark full catalog execution

Status: OPEN. Depends on: RSP-118,RSP-010.

Acceptance: Separate cold compile/load from warm evaluation; vary catalog/candidates/controls within valid combined limits and include false-review counts.



### RSP-120. Publish native extension coverage and diagnostics

Status: OPEN. Depends on: RSP-119.

Acceptance: Declare translated and unsupported matcher families, exact artifact/catalog versions and production route proof; do not call compatibility gain a measured speedup.



## K. Evidence, policy publication and inventory

Priority: P1/P2, optimize Python first

Responsible role: Daemon and storage engineer

Gate: Preserve durability and policy freshness; no disk wait on the native decision.

Source anchors: guard/daemon/runtime_hook_evidence_writer.py; runtime_hook_evidence_journal.py; store_native_decision_receipts.py; native_policy_snapshot_publisher_inputs.py; aibom_collection.py. PRD §13; [S20](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py),[S21](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py),[S32](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_journal.py).



### RSP-121. Measure foreground evidence submission cost

Status: OPEN. Depends on: RSP-008.

Acceptance: Attribute full payload copies/JSON before response, queue admission, native receipt validation and rejected work; use maximum envelopes.



### RSP-122. Use bounded compact evidence before queue admission

Status: OPEN. Depends on: RSP-121,RSP-016.

Acceptance: Avoid unnecessary full payload copying; preserve correlation/attempt identity and explicit aggregate degraded counters.



### RSP-123. Define persistence milestones and loss window

Status: OPEN. Depends on: RSP-024,RSP-121.

Acceptance: Document memory accepted versus journal durable versus DB committed; specify deduplication, crash cut points and single-writer ownership.



### RSP-124. Implement real SQL transaction batching

Status: OPEN. Depends on: RSP-123.

Acceptance: Group inserts within bounded latency/size limits; preserve uniqueness and per-record outcomes without silently changing durability promises.



### RSP-125. Replace per-record whole-journal rewrites

Status: OPEN. Depends on: RSP-123,RSP-124.

Acceptance: Use bounded checkpoint/segment compaction or equivalent; keep exact replay and sidecar consistency under crash and backlog.



### RSP-126. Exercise persistence fault recovery

Status: OPEN. Depends on: RSP-125.

Acceptance: Test duplicate IDs, SQLite busy/corrupt, read-only/full disk, truncated journal and death at append/commit/checkpoint; decisions must not be rerun.



### RSP-127. Introduce precise policy invalidation

Status: OPEN. Depends on: RSP-020,RSP-002.

Acceptance: Use domain revisions/dirty signals with cross-process and WAL-aware reconciliation; unrelated receipt writes must not trigger full recompilation.



### RSP-128. Bound workspace policy tracking

Status: OPEN. Depends on: RSP-127.

Acceptance: Measure 1/10/100 workspaces; coalesce compilation and define safe cache/registration lifecycle without losing active stricter overlays.



### RSP-129. Test mutation-to-enforcement freshness

Status: OPEN. Depends on: RSP-128,RSP-034.

Acceptance: Measure accepted change→compile→publish→ACK→first decision; cover lost watcher hints, restart, key change, expiry and rollout admission.



### RSP-130. Profile and optimize incremental inventory

Status: OPEN. Depends on: RSP-011,RSP-012.

Acceptance: Separate traversal, third-party scanner and cloud wait; coalesce changes and batch joins/upserts without changing client_unverified provenance.



### RSP-131. Qualify real receipt ingestion under mixed load

Status: OPEN. Depends on: RSP-126,RSP-129,RSP-130.

Acceptance: Drive actual native receipts alongside mixed pre/post hooks and policy updates; report fsyncs, bytes rewritten, queue age and process-tree resources.



### RSP-132. Decide whether native spool/compiler is still needed

Status: OPEN. Depends on: RSP-131,RSP-012.

Acceptance: Keep Python improvements if they meet targets; native spool requires writer fencing, and compiler port requires evidenced local CPU/ACK benefit.



## L. Release qualification and handoff

Priority: Required for selected scope

Responsible role: Release lead and independent reviewer

Gate: No migration completion claim without selected installed-route evidence.

Source anchors: .github/workflows/rust-runtime*.yml; native-wheel-ci.yml; rust-authority-ownership.yml; scripts/release/*native*; scripts/ci/*ownership*; relevant tests. PRD §§15–18.



### RSP-133. Audit workflow dependency selection

Status: OPEN. Depends on: RSP-006,RSP-022.

Acceptance: Ensure changes to native code, wrappers, publisher, evidence and benchmark helpers select the necessary checks; inspect combined workflow coverage.



### RSP-134. Run scope-appropriate Rust and Python validation

Status: OPEN. Depends on: RSP-133; all selected implementation tasks.

Acceptance: Run formatting/lint, crate tests, rule/command differential, adversarial, policy/approval and source mutation suites needed by the selected changes.



### RSP-135. Build and attest all selected release artifacts

Status: OPEN. Depends on: RSP-134,RSP-081.

Acceptance: Use locked dependencies and current toolchain; bind source/version/target/rule/runtime digests and verify post-sign/frozen manifests.



### RSP-136. Verify installed route and control-mode coverage

Status: OPEN. Depends on: RSP-135,RSP-015.

Acceptance: Exercise actual launchers, no-env auto, aliases, source refs, Watch, availability and approval flow from each selected package.



### RSP-137. Run full performance qualification

Status: OPEN. Depends on: RSP-136,RSP-010.

Acceptance: Use frozen targets and sample methodology against matching baseline artifacts on declared hardware; include every error/denial/retry.



### RSP-138. Run mixed offered-load and recovery soak

Status: OPEN. Depends on: RSP-137,RSP-131.

Acceptance: Include real evidence ingest, policy mutations, inventory, startup/restart and saturation; preserve responsiveness and bounded process resources.



### RSP-139. Verify update, downgrade and rollback behavior

Status: OPEN. Depends on: RSP-135,RSP-138.

Acceptance: Test mixed generations, in-progress requests, signing changes and installed registration; never reopen hidden Python semantic fallback.



### RSP-140. Verify evidence privacy and truthful status

Status: OPEN. Depends on: RSP-136,RSP-138.

Acceptance: Probe exported metrics, error paths and receipts for raw secrets, commands, output and private paths; separate availability continuations from evaluated allows.



### RSP-141. Reconcile current architecture and old PRDs

Status: OPEN. Depends on: RSP-136,RSP-137.

Acceptance: Update actual route graphs, authority/availability wording, capability coverage and SLO truth; mark obsolete claims superseded without inventing history.



### RSP-142. Complete independent review of the final head

Status: OPEN. Depends on: RSP-134,RSP-140,RSP-141.

Acceptance: Resolve review threads and required CI on the actual candidate SHA. Explain intentional behavior differences separately from performance changes.



### RSP-143. Prepare concrete canary and rollback evidence

Status: OPEN. Depends on: RSP-139,RSP-142.

Acceptance: Specify selected versions, platforms, cohorts, stop conditions and tested rollback. Publish or merge only within the implementation session's authorization.



### RSP-144. Publish an accurate implementation handoff

Status: OPEN. Depends on: RSP-137,RSP-138,RSP-139,RSP-140,RSP-141,RSP-142,RSP-143.

Acceptance: List selected/deferred tasks, artifacts, exact metrics and coverage, commands/results and rollback. No measured claim without attached evidence.



## Completion record for each PR

Record the affected task IDs, exact base/head SHA, changed production path, current/new behavior, fixture and platform coverage, benchmark boundary, baseline and candidate artifacts, sample counts, latency/CPU/memory results, unresolved limitations and rollback. Keep a direct link to each source/test result used to close a task.



Do not close a migration because code exists in a crate. Prove the intended installed caller selects it. Do not close performance qualification with two-sample smoke data, a disabled reference path, a historical PR metric, or a source-checkout-only run.



The final handoff must distinguish implemented, measured-deferred, not-started and blocked work. Preserve failed experiments and their conclusions without presenting them as shipped improvements.



