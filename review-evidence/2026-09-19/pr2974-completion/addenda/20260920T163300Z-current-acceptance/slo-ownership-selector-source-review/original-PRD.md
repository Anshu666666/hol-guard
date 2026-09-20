# HOL Guard Rust Performance PRD

## Decision

Prioritize the work around HOL Guard's existing Rust engine: remove repeated work from the installed hook path, move selected package and offline scanning kernels to Rust, and consolidate native transport only where installed-artifact measurements justify it. A repository-wide language rewrite is not the recommended program.



The first implementation tranche is measurement repair plus four concrete investigations: repeated executable attestation, per-hook configuration loading, repeated JSON and policy work already inside Rust, and repeated signed-package-bundle scans. These have source-visible costs. Their current share of production latency is not measured by this review.



## 1. Scope and source baseline

Repository: hashgraph-online/hol-guard.

Audited branch: main.

Audited commit: 2e672d2d950c6ec471005ddba46e49bba16dc23b.

Version: proposal 1.0, grounded in the source snapshot above.

Audience: the HOL Guard maintainers and the engineer or coding agent implementing this program.

Purpose: reduce user-visible tool latency, CPU usage, and the memory cost of installed Guard while preserving protection, Watch behavior, approval correctness, community contributions, and supported distribution formats.



GitHub metadata and relevant PRs were read through the GitHub connector. A read-only clone matched the exact commit. The review traced the main native hook route, Python transport and availability wrappers, Rust internals, package evaluation, secrets scanning, MCP proxies, extensions, policy publication, evidence persistence, and performance CI. This is a targeted architecture and source review, not a claim to have executed every production path or reviewed every line.



The snapshot contains 10 Rust crates, 103 Rust source files, and 1,208 Python source files under src. Physical line counts include comments, blank lines, and embedded tests. Language volume is not a measure of CPU consumption or remaining migration work.



The older release/3.2 branch is a separate line of work at 4b89e0d2d496a85f04922b2e019a4aea15326bb9. Its open draft aggregation PR [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797) is not the implicit base for this proposal. Reinspect the default branch and active PRs before implementing. This review creates a plan; it does not authorize a merge, deployment, release, or GitHub issue.



## 2. What already exists

The merged native hook program includes [#2682](https://github.com/hashgraph-online/hol-guard/pull/2682), [#2699](https://github.com/hashgraph-online/hol-guard/pull/2699), [#2713](https://github.com/hashgraph-online/hol-guard/pull/2713), [#2718](https://github.com/hashgraph-online/hol-guard/pull/2718), [#2719](https://github.com/hashgraph-online/hol-guard/pull/2719), [#2720](https://github.com/hashgraph-online/hol-guard/pull/2720), and [#2724](https://github.com/hashgraph-online/hol-guard/pull/2724). It introduced Rust raw-envelope handling, PreToolUse and PostToolUse evaluation, resident transport and lifecycle, authenticated policy snapshots, approval authority, source access, scanning, and native receipts. Reuse those components.



Existing crates have distinct responsibilities:

guard-command: command parsing, generic PreTool extraction, command and path floors.

guard-contracts: versioned requests, results, approvals, receipts.

guard-rules and guard-scanner: bounded hook content rules and scanning.

guard-secure-fs and guard-hook-core: source identity, bounded source reads, output extraction, post-tool review.

guard-policy-snapshot: canonical policy representation, cryptographic admission, snapshot contracts.

guard-rule-contract: shared rule contract checks.

guard-runtime: executable edge, resident, supervisor, policy store, and approvals.

guard-runtime-windows-process: Windows identity, permissions, and lifecycle support.



Python remains necessary for product control, multiple transport surfaces, package and offline scanning, proxy orchestration, storage, and CLI presentation. Some old Python hook evaluators are reference-only. The retained native_runtime_resident.py is excluded from built distributions. Deleting that source is maintenance work, not an installed latency improvement.



The ordinary daemon hook route currently runs server.py → HookWorker.review_http_payload → _review_native_edge → review_raw_hook_native → native_resident_client_request → a persistent Rust resident-client-stream helper → the Rust resident. The ordinary native route does not traverse the guardian/evaluator multiprocessing pool. That pool still exists for compatibility and selected approval revalidation, and is initialized at daemon startup.



Python native helpers are already persistent. Do not describe the current warm path as spawning Rust for every hook. Native socket discovery, connection and authentication still happen within the helper's per-request route. Prove the exact path for each harness instead of copying this one route onto every adapter.



Current source also contains Python Watch and availability behavior after native evaluation. _review_native_edge calls hook_review_is_recording_only, which loads configuration, and can transform a native result for Watch presentation. Current availability_harness_response continues selected unavailable cases while preserving designated integrity denials and permission-event handling. Historical ownership prose that describes every result as unconditionally native-authoritative or blanket fail-closed is insufficient to specify today's behavior. [[S01](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-hook-data-plane-ownership.md), [S02](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_worker_native.py), [S03](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py), [S04](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/server.py)]



## 3. Ranked decisions

### Priority 0: repair the performance evidence

The current relative Python benchmark does not prove that its reference performed semantic evaluation. Repair it before using its speedup ratio to justify a migration. Add installed launcher timing and attributable spans. This is a prerequisite for every major conversion.



### Priority 1: eliminate repeated native-path work

review_raw_hook_native calls native_runtime_status for each review. _validate_binary reads and SHA-256 hashes the entire candidate runtime executable. Native capabilities are cached, but that full identity hash occurs first. Investigate generation-bound attestation, preferably owned by Rust, with replacement and tamper defenses preserved.



Remove request-time configuration rereads by carrying the relevant mode and posture in an acknowledged, coherent policy snapshot. Port the small mode/availability transformation layer only when its exact behavior is captured in fixtures. Optimize duplicate JSON, hashing, extraction, and policy validation in Rust before adding more crates. [[S02](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_worker_native.py), [S03](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py), [S05](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_runtime.py), [S06](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/edge.rs)]



### Priority 1: optimize, then consider porting, the deterministic package core

_transitive_lockfile_results builds an index but still invokes a helper that scans the signed package bundle for each dependency. Lockfile validation and extraction can also parse the same document more than once. Fix these algorithms in Python first. Then compare a Rust batch parser and signed-bundle evaluator against that optimized baseline.



This is the strongest clearly separate Python compute candidate. Preserve network retrieval, cloud policy orchestration, entitlements, and reporting in Python initially. [[S07](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py), [S08](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_runtime.py), [S09](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/lockfile_parse_result.py)]



### Priority 1, conditional: native installed launchers

Replace Python bootstraps only for supported, installed hook entrypoints where cold-start profiles show material cost. Reuse the package-bound runtime and native transport. Preserve native harness envelopes, exit codes, approval continuation, runtime ownership, and frozen desktop packaging. Porting every CLI command is unnecessary. [[S10](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_resident_stream.py), [S11](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_hook_edge.py)]



### Priority 2, conditional: native ingress and persistent native connections

Consolidate the ordinary hot ingress and helper/resident connection path if process, scheduling, or connection costs dominate. Keep the Python control API initially. Avoid replacing the entire daemon server merely to reduce one hook route. Design connection generation, peer identity, policy freshness, deadlines, recovery, and admission together. [[S04](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/server.py), [S12](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident_client_stream.rs), [S13](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident.rs)]



### Priority 2, conditional: repository secrets and offline scanning kernels

The standalone secrets CLI remains Python despite test names containing “native.” Its detector has richer provider, entropy, context, location, and HMAC behavior than guard-scanner. Port shared deterministic work behind a separate versioned contract. Do not replace it with the current hook scanner and call that parity.



Broader plugin/archive scanning is a subsequent, separately measured slice. Keep third-party scanner integrations, external subprocess tools, and network intelligence orchestration in Python unless profiles establish a local bottleneck. [[S14](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py), [S15](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-scanner/src/lib.rs)]



### Priority 2: MCP local computation; full proxy rewrite deferred

MCP stdio and remote proxy paths still perform Python parsing, classification, policy calls, and forwarding. First remove repeated catalog hashing and duplicated risk extraction. Port coarse local kernels if they remain expensive. The existing final prewrite quiet period is a correctness barrier and cannot simply disappear in Rust. A complete Rust MCP proxy requires independent evidence and a protocol compatibility plan. [[S16](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/proxy/runtime_mcp.py), [S17](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/mcp_tool_calls.py)]



### Separate compatibility tranche: native extension execution

Python command extensions are not generally executed by the native hook classifier. A versioned declarative matcher representation may be necessary for consistent production extension behavior. Treat this as a compatibility and contributor-product requirement, with performance constraints, rather than claiming a measured Python hook bottleneck.



Keep community contributions and Extension Builder accessible. Compile supported matcher primitives during the trusted build or publication process; do not load arbitrary Python into the resident or make one IPC call per rule. [[S18](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_extensions.py), [S19](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/contracts/extensions/contribution.v1.schema.json)]



### Keep in Python or TypeScript initially

Keep dashboard rendering, ordinary CLI presentation, cloud HTTP clients, enrollment UX, package retrieval, release automation, tests and independent oracles, policy authoring, and administrative APIs in their current languages. Optimize evidence batching, policy invalidation, and inventory scheduling before considering a language change. Rust cannot remove remote network latency or SQLite commit work by itself. [[S20](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py), [S21](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py)]



## 4. Measurement integrity and current test limits

The source review ran three existing checks successfully: python_hook_semantic_callgraph_gate.py, rust_authority_ownership_gate.py, and rust_io_ownership_gate.py. The semantic gate reported 11 roots. The I/O gate reported 306 reachable functions in its configured analysis.



These are scoped static checks. They do not establish installed performance, all-harness semantic coverage, or absence of every Python decision path. The configuration loader can be categorized as asynchronous policy by the existing gate even when reached from the current Watch check. Expand gates to follow actual callers and new routes.



The following distinctions must be reflected in the updated benchmark documentation:

bench_guard_native_release_gate.py times review_post_tool_native for its production warm arm. That includes the Python native adapter/client. It bypasses the actual installed launcher and daemon HTTP ingress. Its direct resident IPC arm is diagnostic.

Warm release acceptance is p95 ≤20 ms OR a relative speedup ≥1.15 over the Python reference. It is not an unconditional 20 ms gate.

Cold acceptance requires both p95 ≤150 ms and a relative speedup ≥5. Readiness is limited to 400 ms.

The Python reference sets HOL_GUARD_NATIVE=off. The reviewed ordinary worker returns an availability response in that mode; the benchmark only checks that a payload exists. It does not assert a semantic oracle route and a correct semantic result. Repair this source-visible methodology defect before trusting the relative ratios.

native_slo_contract.py sets installed adapter warm, size, recovery, and c16 budgets from HOOK_ENGINE_NORMAL_BUDGET_MS, currently 1,000 ms. This is a ceiling, not a measured typical response time.

The timed warm and size-class samples use normalized daemon ingress. A separate installed-hook corpus supplies route-coverage checks; these checks do not establish per-launcher cold latency or per-alias/full-envelope latency distributions.

Native-wheel CI passes two warm iterations per route and two cold/recovery/readiness samples. This is useful smoke coverage; it is inadequate for strong per-route p99 claims.

The SLO prose describes a direct c16 p99 ≤100 ms gate, but the reviewed release-gate script contains no concurrent c16 runner. Resolve prose, executable checks, and actual timing boundaries together.

Windows has functional native-wheel coverage but is excluded from the installed SLO wave described by the current proof. Do not report a Windows performance pass until it is run. [[S22](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/bench_guard_native_release_gate.py), [S23](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/native_slo_contract.py), [S24](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/.github/workflows/native-wheel-ci.yml), [S25](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-runtime-slo-proof.md)]



No current installed speedup is claimed by this PRD. All new numeric targets below are proposed acceptance requirements, not results from this review.



## 5. Benchmark specification

Use four named timing boundaries and record which one every result measures:

1. KERNEL: in-process Rust evaluation, excluding transport.

2. NATIVE_CLIENT: authenticated client request through the resident response.

3. DAEMON_INGRESS: authenticated HTTP hook ingress through the serialized harness response.

4. INSTALLED_LAUNCHER: harness starts its installed hook executable through final stdout, exit status, or documented continuation result.



Measure cold process start, warm steady state, resident recovery, and full daemon startup separately. Human approval wait, remote-service wait, disk read time, and CPU evaluation time require separate attribution. Never subtract them silently from a user-visible result.



Required fixtures cover allowed, blocked, review-required, Watch, unavailable, malformed, expired-policy, integrity-failure, empty-output, output-reference, and oversized inputs. Allowed and blocked corpus decisions must be checked, not merely timed. Capacity results are separate from successful decisions; native-unavailable continuation must not masquerade as an evaluated allow.



Use synthetic source and commands. Keep command text, paths, secrets, raw outputs, tokens, and prompts out of exported artifacts. Aggregate dimensions may include platform, artifact digest, source commit, harness, event, size class, engine route, mode, result class, and bounded reason code.



Test 1 KiB, 16 KiB, 256 KiB, 1 MiB, and maximum supported input sizes. Preserve exact byte versus Unicode-character rules. Test concurrency 1, 4, 16, and 64, with both closed-loop latency and an arrival-rate load test. Report queueing and rejected admission so saturation cannot improve apparent latency by excluding failures.



Performance qualification must use release builds and installed artifacts on declared Linux x64, macOS x64, macOS arm64, and Windows x64 hardware. Record CPU model, core count, RAM, power mode, OS, interpreter/compiler version, build flags, package version, native digest, corpus digest, and background load. Compare baseline and candidate on the same host with alternating order. Keep raw synthetic observations privately available for reproducibility; publish bounded aggregate evidence.



Minimum qualification workload: 10,000 timed warm decisions per priority route and platform across at least five independent runs; 100 cold starts per priority launcher; 100 recoveries; 30 steady-state resource samples. Use at least 1,000 warm samples for remaining installed routes. Report sample counts and confidence intervals with a documented percentile estimator. A route without enough samples is unqualified for a tail claim. Do not pool unlike routes to hide a slow harness.



Use an explicit baseline artifact from current production and an optimized-Python baseline for new Python-to-Rust kernels. The Python semantic oracle is for parity and selected historical comparison, not the sole performance baseline. A 30% improvement means candidate p95 ≤0.70 × baseline p95. A 1.30× throughput increase and a 30% latency reduction are different quantities.



## 6. Proposed acceptance targets

These targets are intentionally distinct from current gates. Baseline work must confirm their applicability to the declared hardware and corpus before implementation is selected; do not quietly loosen a committed threshold to get green CI.



For 1–16 KiB ordinary, noninteractive hooks:

Installed launcher, warm at c1: p95 ≤50 ms and p99 ≤100 ms.

Installed launcher, c16: p99 ≤200 ms, zero request errors, and correct expected decisions.

Native client, warm at c1: p95 ≤20 ms as an absolute target after repairing the benchmark.

Cold native hook process: p95 ≤150 ms. Report full daemon startup and resident readiness separately; retain the current 400 ms readiness ceiling until a stricter target is evidenced. This preserves the adapter-first-request readiness boundary, which starts after snapshot fixture materialization. Measure full policy-ready daemon startup separately.

Selected hot-path tranche: at least 30% lower p95 or 30% lower process-tree CPU per request, with no more than 5% regression in the other primary metric. If the baseline already meets product targets and the predicted benefit is small, defer a large migration.

Optional native ingress tranche: at least 25% lower steady-state process-tree private memory or 30% lower p99 at c16, without weaker fault containment or decision behavior.



For package and offline kernels:

Compare 100, 1,000, and 10,000 dependency fixtures with independently varied advisory-bundle sizes.

Rust must beat optimized Python by at least 30% in end-to-end local evaluation p95 or CPU, including serialization and startup amortization. A fast microbenchmark with slower package-protect execution does not pass.

Preserve bounded memory and exact coverage/completeness status; no dropped dependency or finding can count as a performance improvement.

For repository secrets, qualify small and large file counts, cold and warm filesystem cache, staged-only runs, and many-small-file versus few-large-file workloads. Record both bytes/sec and full CLI wall time.



At c64, bounded overload is acceptable according to the existing admission contract. No hangs, unbounded allocation, deadlocks, leaked children, or cross-request replies are acceptable. Retain the installed short-load observed RSS growth gate of 12% and the separate long-soak growth gate of 50%; report their sampling boundaries. Additionally measure the full daemon/helper/resident process tree independently of the benchmark client. Do not replace process-tree growth with a single-process RSS claim.



## 7. Workstream A: identity, posture, and native-path ownership

Existing integration points: native_runtime.py::_validate_binary/native_runtime_status; native_hook_edge.py::review_raw_hook_native; daemon/hook_worker_native.py::_review_native_edge; daemon/hook_availability_policy.py::hook_review_is_recording_only; native_policy_snapshot_publisher*.py; Rust policy_store and edge modules.



Requirements:

A1. Attribute executable bytes hashed, status-validation calls, manifest reads, and configuration loads per ordinary hook.

A2. Introduce an attested runtime-generation handle only if the design preserves package version, runtime digest, rule digest, executable file identity, peer identity, target platform, and allowed ownership/permissions.

A3. A path string, size, mtime, or periodic timer alone is not a sufficient security identity cache. Test same-size replacement, restored timestamp, symlink replacement, permission change, signing-induced binary change, package upgrade, and concurrent replacement.

A4. Prefer an attested, running native process and a generation-bound authenticated connection. Keep mandatory validation where the platform cannot provide equivalent binding. Do not remove hashing just because it is expensive.

A5. Move ordinary mode/posture lookup onto the acknowledged snapshot and define how Watch changes become effective. Preserve policy generation, workspace scope, expiry, rollback protection, and startup behavior.

A6. Capture every current Watch, availability, integrity-failure, permission-request, PreToolUse, PostToolUse, and lifecycle result as a fixture before changing ownership.

A7. Implement any transfer of the small transformation layer to Rust as an explicit compatibility change. Rust unavailability still needs a deterministic launcher/bridge response; it cannot depend on an unavailable resident.

A8. Native decision receipts and the delivered harness decision must both remain explainable. Do not rewrite a Rust receipt to pretend it made a Python availability or Watch decision.

A9. Update ownership and call-graph checks to cover the real route. Passing a stale manifest is not proof.



## 8. Workstream B: optimize the Rust code already on the path

Existing integration points: edge.rs, strict_json.rs, managed_resident.rs, managed_resident_client_stream.rs, resident_protocol.rs, resident_transport.rs, policy_enforcement_policy.rs, guard-hook-core/src/lib.rs, and guard-scanner/src/lib.rs.



Requirements:

B1. Separate transport framing validation from semantic parsing. Pass validated metadata forward instead of reparsing the entire envelope for timeout and shutdown detection.

B2. Compute canonical request identity once per immutable evaluation input. Preserve exact canonical bytes, excluded fields, digest algorithms, duplicate-key rejection, approval binding, and receipt IDs.

B3. Keep typed PreTool results through validation and receipt construction; serialize at the boundary instead of converting typed values to generic JSON and back.

B4. Compile immutable policy action maps and harness aliases at snapshot admission. Preserve conflict rejection and selector validation. Use shared immutable state while retaining per-request expiry, generation, scope, revocation/authority, and approval consume fences.

B5. Reduce output copying while preserving exact concatenation order, newlines, Unicode character limits, truncation flags, source/output equivalence, and returned hashes.

B6. Evaluate regex prefilters or a RegexSet only against representative clean and matching inputs. Current guard-scanner already caches compiled regexes with OnceLock. A set is a possible prefilter, not a replacement for match-level sample suppression or contextual rules.

B7. Do not batch unrelated file contents as adjacent scanner chunks. Cross-chunk matching must remain within one logical input; reset overlap at document boundaries.

B8. Propagate one remaining deadline across parsing, identity work, scanning, and I/O. Do not reset the effective budget at each stage. Preserve unavoidable external watchdogs for blocking system calls.

B9. Avoid speculative SIMD, unsafe code, new allocators, or a new async runtime unless a measured bottleneck requires them. The workspace forbids unsafe code; retain that default.



## 9. Workstream C: package parsing and signed-bundle evaluation

Existing integration points: runtime/supply_chain_package_eval.py::_transitive_lockfile_results; runtime/supply_chain_bundle_runtime.py::evaluate_cached_supply_chain_bundle; lockfile_parse_result.py; runtime/package_intent*.py; package_shim_gate.py; local_supply_chain.py.



Proposed new component: guard-package-core. This name and its modules are proposed, not present in the audited tree.



Requirements:

C1. Establish an optimized-Python baseline with one verified bundle index per immutable bundle identity and one parse per lockfile input.

C2. Keep bundle signature, issuer/key, sequence/version, expiry, trust, and policy context bound to the indexed data. An unsigned cache cannot be an authority source.

C3. Define PackageEvaluationRequestV1 and PackageEvaluationResultV1 in guard-contracts. Use a coarse request for a bounded dependency batch or lockfile, not an IPC call per dependency.

C4. Input identity includes exact ecosystem, normalized name, version/range representation, registry/source identity, integrity when present, scope, policy generation, and verified bundle generation. Preserve ecosystem-specific semantics.

C5. Output includes expected decision, bounded reasons, matched evidence IDs, input and bundle digests, and completeness status. Missing, malformed, unsupported, truncated, or unresolved input must be distinguishable from a clean result.

C6. Port one format family at a time. Build semantic fixtures for the formats actually supported by the Python parser, including nested/transitive dependencies, workspaces, aliases, optional dependencies, local paths, git references, prereleases, and duplicate declarations.

C7. Do not silently treat npm, Python, Cargo, and other version schemes as interchangeable. Select parsers from existing supported formats and independently verify edge behavior.

C8. Leave fetch, refresh, auth, entitlement, and report rendering in Python initially. The native result must integrate into the real package-protect/shim/CLI flow.

C9. Compare full outcomes and evidence, not only allow/block. A stronger result caused by incomplete parsing is still a compatibility difference that must be reviewed.

C10. Preserve the current parser limits: 8 MiB input, 100,000 entries, 250,000 nodes, and depth 128. Preserve the current bounded parser time policy rather than applying the smaller hook-scanner limits. Retain stale-bundle emergency denies and final package execution revalidation.

C11. Stage shadow comparison on synthetic/test inputs without executing an install twice. Cut over only the supported native format scope; unsupported formats retain their existing explicit route and are reported as such.



## 10. Workstream D: offline secrets and scanner kernels

Existing integration points: guard/secrets/cli.py, secret_repository_scanner.py, secret_staged_scanner.py, secret_detection.py, scanner.py, and existing Rust scanner/secure-filesystem crates.



Proposed component: a dedicated offline-scanner module or crate sharing proven primitives where semantics match.



Requirements:

D1. Produce a detector capability matrix. Include provider rules, entropy, suppression, contextual signals, paths, line/column positions, severity, evidence identity, and redaction/HMAC.

D2. Preserve scan schemas, exit statuses, finding order/deduplication, include/exclude semantics, encoding treatment, ignore rules, and staged-content behavior.

D3. Batch files and amortize native startup. Keep bounded queues and maximum bytes per file/job. Track truncated or skipped coverage explicitly.

D4. Preserve the source identity contract and handle symlinks, changing files, unreadable files, hard links, nonregular files, Unicode names, and platform path semantics.

D5. Use bytes or bounded owned data across the language boundary. Do not cross once per regex or finding.

D6. Before a detector port, batch Git object reads. Current staged/history helpers launch git cat-file size and blob subprocesses per object. Deduplicate scanning of identical objects while preserving each path/commit occurrence and coverage counters. Preserve staged-index bytes when the working tree differs.

D7. Retain current secrets CLI exit behavior: incomplete/error 2, findings with --fail-on-findings 3, and a complete accepted scan 0. Current default scan bounds are 5,000 files, 2 MiB/file, 128 MiB total, 500 findings, and 500 commits. These are defaults, not a license to change explicit user bounds.

D8. For archive/plugin scans, bound entry count, uncompressed bytes, nesting, decode expansion, and time. Never execute or extract untrusted package content just to benchmark it.

D9. Keep hostile archive inspection in its dedicated isolated worker. Preserve no-network/read-only containment, immutable archive digest and file identity, expansion checks, and launch binding. Do not move hostile archive parsing into the resident hook process just to amortize startup.

D10. Third-party scanner output and network intelligence remain distinct evidence. A native lexical scanner cannot silently replace those capabilities.

D11. Accept a Rust implementation only after the richer Python semantics pass parity and the full command beats its optimized baseline.



## 11. Workstream E: launchers and native ingress

Requirements:

E1. Inventory actual installed launchers and native event aliases from harness contracts and generated adapter source. A registry entry or preflight detection is not installed enforcement.

E2. Start with one high-use canonical pre/post harness, then one alias-heavy harness, then Pi/OMP source-reference flow. Declare remaining routes explicitly.

E3. Package the launcher using the existing version-bound native distribution. Do not use PATH lookup or a runtime download in auto mode.

E4. Preserve stdin/stdout framing, response JSON, exit code, stderr discipline, environment isolation, cwd, home/guard-home binding, private source-reference rules, and harness deadline.

E5. Keep the existing owner-private Unix transport and Windows ownership/ACL/peer identity requirements. Named pipes are an option for an ADR, not an assumed migration requirement.

E6. If native connections are reused, bind them to executable and resident generation, policy context, protocol version, authenticated peer, and request correlation. Bound inflight work.

E7. Recover by retiring the old generation, draining or failing outstanding requests deterministically, and reconnecting. Never transparently replay an approval consume or action with an ambiguous outcome.

E8. For ordinary native ingress, consider bypassing Python HTTP only after profiling its share. Keep administrative APIs and control workers in Python. An additional always-running process must justify its memory cost.

E9. Lazy-start the Python compatibility pool only if all compatibility, diagnostic, approval-revalidation, and lifecycle consumers continue to work. Its absence on the ordinary path does not prove it can be deleted.

E10. Keep whole-process containment. A panic, poisoned state, blocked read, worker crash, oversized request, or flooded client must not destabilize unrelated sessions.

E11. An engine flag must be local/admin-controlled and versioned. Untrusted hook input must not select a weaker path. Production shadowing must not cause duplicate side effects.

E12. Rollback restores the prior tested native route for the affected scope. It does not automatically restore a Python hook semantic fallback.



## 12. Workstream F: MCP and native extension parity

MCP requirements:

F1. Cache immutable tool-catalog canonical digests by generation; retain entrypoint identity and catalog-change invalidation.

F2. Compute local risk facts once and reuse them for decision and summary.

F3. Measure the 5 ms final quiet barrier separately from CPU time. Preserve the final prewrite freshness check and quarantine behavior.

F4. Define a coarse native request containing bounded normalized tool facts and immutable catalog identity. Keep credentials and remote session state in the existing control path initially.

F5. Differential fixtures must cover JSON-RPC IDs, notifications, cancellation, malformed/oversized frames, catalog refresh during a request, startup changes, child EOF, write backpressure, remote HTTP semantics, and an ambiguous write outcome.

F6. A full Rust proxy is deferred unless optimized Python plus native kernels cannot meet the adopted target. Reinspect hosted MCP PR [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931) before planning transport work.



Extension requirements:

F7. The current catalog emits a matcher kind and digest; that is not a complete executable representation. Define an explicit, versioned, bounded matcher IR.

F8. Inventory all concrete matcher families, not just token-prefix rules. Include operand, path-set, PHP/curl, literal/prefix, and specialized safety semantics.

F9. Keep the existing Python contribution authoring flow initially. Generate native IR from declarative matcher configuration during a trusted build. Do not infer arbitrary Python semantics or execute contributor modules as part of an untrusted runtime import.

F10. Bind catalog, rules, publisher identity, opt-in state, entitlement/control state, policy generation, and effective matcher version. Preserve built-in versus community trust distinctions and local versus managed authority.

F11. An extension must not weaken non-overridable native floors. Unsupported matcher families and unknown commands remain explicitly unsupported/reviewed under the declared contract.

F12. Qualify a representative community extension, including command.ollama, from contribution source through compiled artifact, install, enable, native decision, receipt, disable, upgrade, and rollback. A Python unit test or catalog listing is not proof of native execution.

F13. Keep extension compatibility status and attribution visible in existing diagnostics; do not require community authors to manage a Rust toolchain for ordinary declarative contributions.



## 13. Workstream G: background CPU and storage

Evidence disk persistence is already outside the native decision. Foreground queue submission still deep-copies and serializes activity payloads before the response is written, so asynchronous persistence is not zero-cost on the hook path. Bound admission and derive compact facts before full copies where the contract permits. Its current max_batch grouping does not necessarily mean batched durable writes: the writer can fsync a journal and commit SQLite for each record, then reread/rewrite the journal during removal. Implement true transaction grouping and bounded journal compaction before considering Rust.



Distinguish accepted-in-memory, journal-durable, and database-committed status. Submission currently returns before journal durability, so do not promise exactly-once durable receipt acceptance.



Preserve decision_id deduplication, crash recovery, replay, disk-full/corrupt/busy behavior, durable boundaries, and bounded loss/degradation metrics. Moving persistence onto the synchronous hook deadline is prohibited.



The policy publisher polls and can recompile workspace policies after broad database changes, including receipt activity. Introduce narrowly scoped policy versions or a precise dirty signal with a safe reconciliation path. Unrelated evidence writes should not force policy recompilation. Preserve rollout admission, managed overlays, workspace precedence, monotonic snapshots, acknowledgement, and last-known-good behavior.



Inventory and filesystem discovery need an attributed cold/incremental profile. Improve exclusions, reuse verified file identities, coalesce changes, and perform bounded incremental refresh before proposing a Rust walker. Never cache a clean result across an unaccounted content or policy change. [[S20](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py), [S21](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py)]



## 14. Cross-cutting contracts and security compatibility

All new boundaries use explicit schema versions and capability negotiation. Reject or explicitly route unsupported schemas. Bound input bytes, output bytes, recursion, entries, elapsed time, memory, queues, and inflight requests. Keep numeric types, null handling, UTF-8, duplicate JSON keys, canonicalization, and error classes defined.



Separate four results: native evaluated decision, mode/posture transformation, transport availability result, and delivered harness response. A native-unavailable continuation is not an evaluated allow. Keep existing product behavior unless a separate behavior change is explicitly accepted.



Authentication, signature checks, peer/executable identity, source identity, policy generation, expiry, approval challenge binding, replay prevention, and final consume fences are invariants. Optimize their repeated representation and lifecycle, not their existence.



Use safe Rust by default. Avoid a new embedded Python interpreter in the resident. For new offline kernels, first compare the existing versioned subprocess transport against a coarse in-process binding. PyO3 adds a distribution/ABI and fault-isolation choice; it is not assumed to be faster end to end. Record the chosen boundary and rejected alternative in an ADR.



Tests must include independently specified malicious and benign expected outcomes. Differential equivalence to Python alone is not sufficient when Python behavior is wrong. Any intentional behavior correction needs its own documented expectation and must not be hidden inside the performance change.



## 15. Delivery sequence and stopping rules

Phase 0: repair benchmark reference integrity, timing labels, and actual-route documentation; collect baselines and freeze targets.

Phase 1: remove repeated identity/configuration/JSON/policy work and optimize package indexes and background invalidation. Ship independently reviewable changes.

Phase 2: qualify one native installed launcher and one package-core format end to end. Promote only if both correctness and benefit gates pass.

Phase 3: expand proven package/offline scanner formats and launcher routes. Start native ingress only if Phase 1 profiles still justify it.

Phase 4: deliver native extension parity as a separately tracked compatibility tranche; qualify MCP kernels. Full MCP/control-daemon rewrites remain deferred unless measurements change the decision.

Phase 5: cross-platform installed artifacts, load/recovery/soak, documentation reconciliation, and rollout evidence.



Every conversion has a go/no-go record: workload, baseline/candidate artifact, correctness result, user-visible metric, CPU, memory, operational cost, supported platforms, and a decision. If Rust fails to outperform optimized Python by the adopted threshold, keep the algorithmic improvement and defer the port. A documented no-go is a completed investigation, not a failed engineering outcome.



## 16. CI, packaging, and rollout

Retain and adapt the current rust-runtime, native-wheel, authority, rule-contract, differential, adversarial, recovery, and platform workflows. Do not bypass them by weakening assertions, inflating deadlines, or removing test cases.



New performance qualification should run on predictable hardware. Ordinary pull requests can use bounded smoke tests; a release candidate needs statistically meaningful qualification. Record exact candidate SHA and artifact digest. A pass from a previous commit or a source checkout does not qualify a changed installed wheel.



Use the existing Rust toolchain and Cargo.lock, and check current rust-version before adding APIs or dependencies. Package Linux x64, macOS x64/arm64, and Windows x64 according to existing supported targets. Recheck wheel manifests after signing or freezing changes bytes. Inspect frozen desktop sidecars, upgrade, uninstall, and repair flows.



Separate algorithmic fixes, new contracts, native kernels, transport changes, and rollout. Each PR description must say what path changed, what behavior remained equivalent, what measurement improved, what corpus/platform was tested, and what remains unsupported. Resolve code review and required CI on the final head. Do not create GitHub issues. This planning package itself creates no PR or release.



Rollout uses explicit canary scope and a versioned rollback route. A qualifying result is a shipped native path actually selected by the intended installed launcher, with correct decisions and attributable performance evidence. Code merged without route activation does not complete a migration.



## 17. Active overlap and documentation reconciliation

Recheck these open PRs before touching overlapping files:

[#2807](https://github.com/hashgraph-online/hol-guard/pull/2807): Windows native state/lifecycle and soak measurement.

[#2870](https://github.com/hashgraph-online/hol-guard/pull/2870): secret reads, approval identity and consumption.

[#2931](https://github.com/hashgraph-online/hol-guard/pull/2931): hosted/remote MCP behavior.

[#2948](https://github.com/hashgraph-online/hol-guard/pull/2948): policy rollout-state admission.

[#2911](https://github.com/hashgraph-online/hol-guard/pull/2911): CodeSage Python reference rules and native extension coverage.

[#2797](https://github.com/hashgraph-online/hol-guard/pull/2797): release/3.2 aggregation into main.



Older rust-runtime-hardening and migration TODOs include obsolete branch, authority, fallback, and SLO statements. Mark the relevant claims superseded, retain their historical context, and point implementers to current executable contracts plus this program. Do not reopen old task IDs solely because their checkboxes remain unchecked.



## 18. Definition of done

The selected scope is complete only when:

Actual installed routes are inventoried and the declared native paths are selected without development overrides.

Expected decisions, Watch transformations, availability cases, receipts, approvals, and source/package identities match the adopted contracts.

Qualification compares current production and optimized alternatives, with verified semantic routes and correct outcomes.

Per-route/platform latency, CPU, process-tree memory, recovery, saturation, and coverage results meet committed targets.

No secret-bearing payloads appear in exported evidence.

Required CI and review pass on the exact implementation head; native artifacts pass installation and update tests.

Documentation matches the code, unresolved scope is explicit, and rollback is tested.

Deferred ports have a reason supported by measurements; they are not claimed as delivered.



## 19. Source references

All S-series code links refer to the audited commit. Function names are navigation anchors; line numbers may move after a rebase.

[[S01](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-hook-data-plane-ownership.md)] Existing ownership documentation and harness route limitations: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-hook-data-plane-ownership.md)

[[S02](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_worker_native.py)] Current Watch/native wrapper: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_worker_native.py)

[[S03](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py)] Current event-specific availability and configuration lookup: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py)

[[S04](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/server.py)] Actual daemon routing and worker startup: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/server.py)

[[S05](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_runtime.py)] Runtime executable validation: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_runtime.py)

[[S06](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/edge.rs)] Rust identity/JSON and policy work: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/edge.rs)

[[S07](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py)] Transitive package evaluation: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py)

[[S08](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_runtime.py)] Signed-bundle lookup: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_runtime.py)

[[S09](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/lockfile_parse_result.py)] Lockfile parse completeness, bounds, and validation: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/lockfile_parse_result.py)

[[S10](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_resident_stream.py)] Python native stream lifecycle: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_resident_stream.py)

[[S11](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_hook_edge.py)] Python native request boundary: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_hook_edge.py)

[[S12](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident_client_stream.rs)] Rust resident-client stream: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident_client_stream.rs)

[[S13](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident.rs)] Rust managed resident discovery and request transport: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident.rs)

[[S14](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py)] Repository secrets scanner: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py)

[[S15](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-scanner/src/lib.rs)] Existing Rust hook scanner: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-scanner/src/lib.rs)

[[S16](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/proxy/runtime_mcp.py)] MCP runtime proxy: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/proxy/runtime_mcp.py)

[[S17](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/mcp_tool_calls.py)] MCP risk evaluation: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/mcp_tool_calls.py)

[[S18](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_extensions.py)] Python command extensions: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_extensions.py)

[[S19](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/contracts/extensions/contribution.v1.schema.json)] Contribution contract: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/contracts/extensions/contribution.v1.schema.json)

[[S20](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py)] Evidence writer: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py)

[[S21](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py)] Policy publication inputs: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py)

[[S22](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/bench_guard_native_release_gate.py)] Actual release benchmark and reference route: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/bench_guard_native_release_gate.py)

[[S23](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/native_slo_contract.py)] Installed SLO contract: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/native_slo_contract.py)

[[S24](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/.github/workflows/native-wheel-ci.yml)] Native wheel CI workload: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/.github/workflows/native-wheel-ci.yml)

[[S25](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-runtime-slo-proof.md)] SLO prose to reconcile against executable code: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/docs/guard/native-runtime-slo-proof.md)

[[S26](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/policy_enforcement_policy.rs)] Rust policy-map validation and aliases: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/policy_enforcement_policy.rs)

[[S27](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-hook-core/src/lib.rs)] Rust output extraction: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-hook-core/src/lib.rs)

[[S28](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/ci/rust_io_ownership_gate.py)] Static ownership gate: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/scripts/ci/rust_io_ownership_gate.py)

Primary technical references: RegexSet behavior, including lack of match-position output: [Open source](https://docs.rs/regex/latest/regex/struct.RegexSet.html)

Primary technical reference for coarse Python/Rust bindings and conversion overhead: [Open source](https://pyo3.rs/main/performance)



[[S29](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_detection.py)] Rich secrets detector: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_detection.py)

[[S30](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_staged_scanner.py)] Staged Git object reader: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/secrets/secret_staged_scanner.py)

[[S31](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/offline_archive_inspection.py)] Isolated offline archive inspection: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/offline_archive_inspection.py)

[[S32](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_journal.py)] Evidence journal durability and removal: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_journal.py)

[[S33](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_rules.py)] Extension rule export: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_rules.py)

[[S34](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_matcher_contracts.py)] Matcher contract canonicalization: [Open source](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/command_matcher_contracts.py)



