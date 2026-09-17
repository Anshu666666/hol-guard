# MCP stdio rebaseline and native-kernel decision

This is the frozen prefilter-era record through `d811b08f0`. The later [request-facts correction and separate rebaseline](rust-performance-mcp-request-facts.md) implements reuse within each unchanged authority preparation and adds near-frame-ceiling memory probes. Those probes identify a remaining large-input facts candidate; this earlier decision does not establish a native no-go for that newly measured scope.

The current tranche retains the Python MCP proxy with two targeted corrections: idle server notifications are forwarded promptly, and risk classification skips regex scans only when an exact necessary condition proves they cannot match. The original rebaseline exposed a real 128 KiB classification bottleneck; its conservative local-computation share was 60.61%, so the smaller ordinary fixtures could not justify a blanket native-kernel no-go. The subsequent baseline/candidate comparison below measures the Python correction at the actual stdio route before making the conditional native decision.

The investigation also found and fixed a forwarding defect: server notifications remained queued while the client was idle. `serve()` now sends those frames through the existing bounded multiplexer during its 100 ms idle poll. An actual pipe regression verifies that a `notifications/tools/list_changed` frame reaches an idle client and invalidates authority before the client sends its next request. Queue ceilings, nested-operation budgets, write retirement, approval checks, and the final 5 ms prewrite quiet barrier remain in place.

## Boundary and repeatability

The initial measured runtime is commit `c8f017831`, based on `fb8d57a8efc3`. The risk-prefilter candidate is `d811b08f0`. Exact source digests are in [the initial case evidence](../../release-metadata/mcp-stdio-rebaseline.json) and [the paired correction evidence](../../release-metadata/mcp-risk-prefilter-comparison.json). The harness starts a real `CodexMcpGuardProxy.serve()` process, a real synthetic child, and a client connected by real pipes. Its client-to-response timer includes frame parsing and writing, catalog and request identity, classification, policy lookup, receipt persistence, child wait, and complete response forwarding. The installed CLI bootstrap is outside this boundary. Worker spawn-to-initialize and Guard import time are recorded separately. Each fixture supplies a stable current-config provider and a real temporary Guard store under a default warn or review policy; this does not measure a large user policy database or configuration-file reload cost.

Five independent process blocks alternate cached and deliberately uncached catalog modes, with 10, 100, and 1,000 tools and 100 measured calls after one first-call warmup in each process. The uncached mode disables the existing immutable-catalog digest cache; it is a controlled counterfactual, not an earlier released build and not a native implementation. Separate processes cover 16 and 128 KiB text payloads, instrumentation, 20 ms child delay, catalog refreshes, and delayed approval outcomes. Responses carry both `content` and `structuredContent`, so returned frames are larger than their text payloads.

The first 19 completed cases used one outer measurement lock. A deliberate pause started the next worker only far enough to record that it had processed zero protocol requests, then released the outer lock. Validated checkpoint resume completed the remainder using a separate flock acquisition for each case. The raw evidence retains this control event. No timed decision was interrupted, failed sample dropped, or completed fixture rerun to improve its result.

Platform: Linux x86_64, Python 3.12.14. The host was shared. Timing variation remained substantial despite serializing measured workloads. Workspace disk pressure and neighboring artifact maintenance, including Rust target relocation, also occurred during this campaign. The v1 records contain complete case summaries rather than per-request timestamps, so exact maintenance overlap cannot be reconstructed. Percentiles use nearest rank; the ranges below describe the five observed blocks and are not confidence intervals. Instrumented runs attribute costs and are kept separate from uninstrumented latency comparisons. Adverse ordinary controls are retained and prevent a general performance qualification claim.

## Complete stdio route

All values below are milliseconds. The p95 column is the median of five per-process p95 values, followed by their observed range. CPU is the median process-tree CPU per call, including the proxy and child, sampled from OS counters across the session.

| Catalog tools | Cached p95, median (range) | Uncached p95, median (range) | Cached tree CPU/call | Uncached tree CPU/call |
| --- | --- | --- | --- | --- |
| 10 | 245.53 (68.42–454.45) | 245.43 (73.65–522.00) | 72.77 | 87.23 |
| 100 | 257.85 (83.23–374.92) | 394.14 (116.18–463.87) | 73.27 | 103.86 |
| 1,000 | 233.80 (68.91–468.70) | 237.31 (129.80–1,478.78) | 71.49 | 131.58 |

Every cached/uncached pair has identical complete response traces, guard-decision counts, notification counts, catalog-generation observations, and exact forwarded ID sequence. Integer and string JSON-RPC IDs retain their type. The benchmark rejects missing, duplicated, reordered, blocked, or altered successful responses instead of treating them as fast samples.

For cached ordinary cases, spawn-to-initialize had a median of 3,528.41 ms and a range of 2,313.22–13,321.82 ms. Guard imports alone ranged from 1,756.64 to 12,882.09 ms. These are source-worker startup observations and do not establish an installed-launcher startup SLO.

## Local CPU and deliberate waits

The following values are mean main-thread CPU milliseconds per call from separate instrumented runs. Nested phase costs are subtracted from the enclosing phase. Parent CPU includes all threads of the proxy process; it is shown as a separate denominator. The conservative local-work column sums catalog hashing, classification, request identity, **all** observed JSON serialization, and otherwise unattributed Guard computation. Including all serialization and unattributed computation deliberately overstates the work available to a pure facts kernel.

| Catalog / text payload | Parent CPU | Catalog hash | Classification | Policy/state lookup | Receipt/result persistence | Conservative local work (share) |
| --- | --- | --- | --- | --- | --- | --- |
| 100 / 1 KiB | 56.58 | 0.01 | 1.31 | 29.80 | 21.87 | 3.75 (6.63%) |
| 100 / 16 KiB | 75.34 | 0.01 | 12.06 | 37.52 | 21.43 | 15.06 (19.99%) |
| 100 / 128 KiB | 158.27 | 0.02 | 87.28 | 32.30 | 18.49 | 95.93 (60.61%) |
| 1,000 / 1 KiB | 63.54 | 0.03 | 1.52 | 37.01 | 21.07 | 4.16 (6.54%) |

The 128 KiB stress input must remain visible: at 60.61%, this first profile demonstrated a local classification bottleneck. Two category derivations remain in an ordinary call: one for approval-context identity and one for current policy evaluation. The earlier optimization avoids further recomputation for decision summaries. The correction below retains both authority boundaries and accelerates their underlying classification without caching request facts or changing the policy-version/hash schema.

## Large-payload correction and paired rebaseline

A separate component profile of 20 classifications of a 128 KiB lowercase synthetic payload took 0.970 seconds before the correction. Regex search accounted for about 68% and IP candidate detection for about 20%. After the correction the same diagnostic took 0.185 seconds. The [baseline component profile](../../release-metadata/mcp-risk-component-baseline.txt) and [candidate component profile](../../release-metadata/mcp-risk-component-candidate.txt) retain the function counts and timing output. These component timings identify the algorithmic work; they are not the end-to-end qualification result.

Literal alternatives now generate both their authoritative regex and a cheap substring precondition from the same bounded static definition. The original regex still decides the result whenever any alternative occurs. The IP prefilter skips extraction only when a string has no dot, no IPv6 compression marker, and fewer than seven colons. Camel-case normalization skips substitution only for already-lowercase strings. The static definition cache is bounded to 128 entries and holds no user request text. Independent differential execution of the frozen old module verified all 3,008 cases for exact risk categories, approval hashes, and complete policy decisions. Additional fixtures compare the few expanded optional regex alternatives with their original expressions and cover Unicode, IP forms, boundaries, adversarial markers, and large inputs.

Five independent fresh-process blocks alternate the frozen baseline and candidate for 1, 16, and 128 KiB payloads with a 100-tool catalog. Each cell contains one first-call warmup and 100 measured calls. Six additional processes attribute phases separately. The worker hashes the actually imported runtime and risk module, and the runner rejects an unexpected source or a source change during a cell. Every measured response, decision count, notification count, catalog-generation observation, and forwarded ID sequence matches its paired source. Negative changes below are improvements. Percentages are computed within each block, then summarized across the five blocks; host variation is retained.

| Text payload | Baseline p95, median ms | Candidate p95, median ms | Paired p95 change, median (range) | Paired tree CPU change, median (range) |
| --- | --- | --- | --- | --- |
| 1 KiB | 90.74 | 216.25 | 162.43% (10.90% to 452.61%) | 73.61% (2.91% to 127.32%) |
| 16 KiB | 194.35 | 173.23 | -32.14% (-69.63% to 98.95%) | -29.63% (-44.26% to 49.87%) |
| 128 KiB | 518.15 | 275.06 | -43.00% (-81.98% to -22.73%) | -46.25% (-67.53% to -36.41%) |

The 128 KiB fixture reduced process-tree CPU in all five blocks, but the ordinary controls are materially adverse. These measurements do not pass a general non-regression gate. The separate profiles below show a smaller classification cost and substantial variation in policy/state and receipt costs; they do not establish the cause of every uninstrumented regression or erase those results.

The following separate profiles distinguish the actual facts/identity phases from a generous sum that additionally includes **all** JSON serialization and unattributed Guard computation. Those extra phases include work a pure facts kernel could not remove. Parent CPU remains the denominator; adding child CPU to the denominator would reduce these shares.

| Source / payload | Parent CPU, mean ms | Classification | Policy/state | Receipt/result | Facts + identity (share) | Plus all JSON and other Guard (share) |
| --- | --- | --- | --- | --- | --- | --- |
| baseline / 1 KiB | 94.20 | 1.53 | 41.45 | 40.95 | 2.23 (2.36%) | 5.14 (5.46%) |
| candidate / 1 KiB | 32.75 | 0.31 | 18.89 | 11.43 | 0.54 (1.66%) | 1.64 (5.01%) |
| baseline / 16 KiB | 43.74 | 6.94 | 21.48 | 12.36 | 7.28 (16.64%) | 8.91 (20.36%) |
| candidate / 16 KiB | 50.02 | 1.83 | 28.78 | 15.66 | 2.36 (4.72%) | 4.55 (9.09%) |
| baseline / 128 KiB | 173.73 | 114.22 | 32.19 | 16.64 | 115.13 (66.27%) | 122.17 (70.32%) |
| candidate / 128 KiB | 69.82 | 12.19 | 31.00 | 16.84 | 12.96 (18.57%) | 19.54 (27.99%) |

The measured final quiet wait averaged 5.15–5.32 ms across ordinary profiles, while its configured duration remains exactly 5 ms. The interval is a freshness barrier and was never disabled or subtracted from complete-route latency. Child, approval, and barrier phases are measured separately:

| Control | Complete-route p95 | Quiet wait, mean | Child response wait, mean | Inline approval wait, mean |
| --- | --- | --- | --- | --- |
| child delay 20 ms | 1,184.49 | 6.04 | 28.52 | 0.00 |
| catalog refresh every 5 calls | 95.45 | 5.28 | 2.55 | 0.00 |
| approval accept | 125.94 | 5.15 | 0.83 | 30.50 |
| approval cancel | 222.69 | 0.00 | 0.00 | 31.19 |
| approval invalidate | 337.61 | 5.15 | 0.00 | 84.28 |

The approval client waits 30 ms after receiving a real `elicitation/create` request. Cancellation preserves the existing queued-review outcome. Invalidation sends a real child catalog notification during the pending approval and waits until the client receives it before accepting. The proxy then requires reapproval and forwards zero calls from that fixture. Approval-phase wall time includes polling and local work in that exchange; it is not a measurement of human reaction time.

## Existing remote helper

The current `RemoteGuardProxy.forward()` helper was exercised separately through actual loopback HTTP, with 0 and 20 ms synthetic server delay. Exact JSON bodies and 204 notification semantics passed. This does not exercise TLS, credentials, a live external server, or hosted MCP draft [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931); it does not add remote catalog or approval behavior that is absent from this helper.

| Declared server delay, ms | HTTP roundtrip p95, ms | Client-thread CPU, mean ms | Measured server wait, mean ms |
| --- | --- | --- | --- |
| 0 | 2.91 | 1.62 | 0.08 |
| 20 | 25.42 | 2.79 | 20.13 |

## Memory and correctness

Across cached ordinary cases, sampled process-tree private USS peaked between 73.98 and 81.16 MiB. The largest increase between the after-catalog and final-response samples was 1.69 MiB. The report also contains summed RSS and process counts. RSS sums can count shared mappings more than once; USS measures private pages. Samples occur after catalog delivery and each response, so these are observed peaks, not allocation high-water marks or long-soak leak qualification. The proxy also retains benchmark observation records, which contribute to its measured footprint.

The five-block prefilter comparison recorded these ranges of sampled peak private USS. They show the footprint at each payload size without treating a sampling result as a memory qualification pass.

| Text payload | Baseline sampled peak USS range, MiB | Candidate sampled peak USS range, MiB |
| --- | --- | --- |
| 1 KiB | 75.64–85.37 | 75.30–77.45 |
| 16 KiB | 76.43–77.65 | 75.95–77.57 |
| 128 KiB | 78.29–79.68 | 78.23–80.10 |

The initial stdio matrix verified 3,362 successful forwards, 4 cancelled approvals, and 4 catalog-invalidated approvals, with zero unexpected outcomes. The separate prefilter comparison verified another 3,156 successful forwards across 36 cells, with all 18 source pairs matching exactly. All complete response bodies, `_meta`, structured content, ID types, and child forwarding order were checked. The two HTTP controls each verified 21 ordinary replies and one 204 notification. No raw arguments, command lines, paths, credentials, receipts, or catalog text are exported in the report.

Before the risk correction, focused validation passed 32 framing/actual-stdio tests, two checkpoint/resume integrity tests, and 140 existing proxy, approval, final-prewrite, package, launch-identity, catalog-cache, request-facts, and remote HTTP regressions. After the correction, 183 focused tests passed in 144.64 seconds, including the new adversarial risk fixtures and all actual-stdio/approval cases. These cover the existing EOF, malformed/oversized frame, backpressure, pending-approval invalidation, and ambiguous-write/no-replay behavior alongside the new idle-notification regression. Actual Windows execution is still outside this evidence; existing simulated Windows framing tests are not presented as Windows qualification.

## Tranche decision

The original [PRD §6](rust-performance/PRD.md#6-proposed-acceptance-targets) requires at least 30% lower end-to-end p95 or process-tree CPU for a selected hot-path tranche, with no more than 5% regression in the other primary metric. The proposed native contract covers pure request/catalog facts, while credential handling, current authority, approval lifecycle, persistence, remote session orchestration, and the 5 ms freshness barrier stay in the control path. After the Python correction, the observed facts/identity shares are 1.66% for 1 KiB, 4.72% for 16 KiB, and 18.57% for the 128 KiB stress input. These are mean CPU shares, not a bound on p95 or every possible payload shape.

RSP-098 and RSP-103 have reproducible full-route diagnostic measurement, phase attribution, process-tree CPU and memory observations, independent process blocks, and explicit wait controls. RSP-104/RSP-105/RSP-107 remain conditional; no native facts kernel is selected by this tranche. RSP-108 records continued deferral of a full proxy rewrite under original PRD §12 F6. At this frozen source revision, RSP-100 was limited to summary reuse: two derivations across distinct approval-identity and current-policy boundaries were observed. Its subsequent correction and evidence are recorded separately in the linked follow-up.

Observed latency still needs attention: policy/state lookup and receipt persistence are the largest measured local costs in the ordinary profiles. A future selection should first trace those costs on installed target machines and representative user workloads. Reopen a native facts proposal if a bounded exact-input interface plus boundary costs can demonstrate the original 30% improvement with parity; reprofile unusually large or frequently changing catalogs and adversarial text rather than extrapolating this synthetic corpus to every MCP workload. The 100 samples per uninstrumented process and 20 per diagnostic profile are below the original release tail-gate minima. No installed CLI, c16/c64, long-soak, or platform release qualification is claimed. The current report does not loosen any acceptance threshold or turn noisy shared-host timings into a release pass.

Reproduce from the repository with development dependencies installed:

```bash
PYTHONPATH=src .venv/bin/python scripts/profile_guard_mcp_session.py --matrix --samples 100 --lock-file /tmp/hol-guard-performance.lock --json release-metadata/mcp-stdio-rebaseline.json
```

For the source comparison, materialize the baseline commit in a separate checkout and use a new output path; the runner refuses to overwrite earlier attempts:

```bash
PYTHONPATH=src .venv/bin/python scripts/compare_guard_mcp_risk.py --baseline-src /path/to/c8f017831/src --candidate-src "$PWD/src" --samples 100 --lock-file /tmp/hol-guard-performance.lock --json release-metadata/mcp-risk-prefilter-comparison.json
```

The bounded component diagnosis can be reproduced for either checkout with `PYTHONPATH=/path/to/source/src .venv/bin/python scripts/profile_guard_mcp_risk_component.py` under the same measurement lock. Component and phase profiles must remain separate from uninstrumented qualification samples.

The initial `profile_guard_mcp_session.py --matrix` command supports `--resume` for a compatible successful prefix. Resume rejects platform, interpreter, fixture, source, and recorded-failure mismatches. The source-comparison runner requires a new output path and has no resume mode. Matrix failures return nonzero and preserve attempted/completed counts. A whole-response deadline bounds notification loops; discarded worker stderr cannot fill an undrained pipe and bias the timing.
