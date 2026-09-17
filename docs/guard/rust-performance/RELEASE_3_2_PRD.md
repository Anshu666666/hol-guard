# Release/3.2 Rust performance implementation PRD

Reduce the latency, CPU and memory HOL Guard adds to real developer tool calls
while preserving its decisions, delivered responses, approval authority, artifact
trust and evidence. A Rust conversion must earn selection through comparable
real-route measurements. Optimal performance and release qualification remain
unestablished.

The original [PRD](PRD.md) and all [144 TODO criteria](TODO.md) remain normative.
This addendum specifies the current implementation, priority decisions and exit
work without changing their IDs, titles, acceptance conditions or dependencies.
The [execution ledger](EXECUTION_LEDGER.md) records **85 DONE / 22 OPEN / 29 BLOCKED / 8 DEFERRED**.
RSP-071 closes only its original source/adversarial case-coverage criterion after the actual supported Windows reader cases pass. Its RSP-069/RSP-070 dependencies, native/installed qualification, documented platform limits and failed archive exact-result gate remain unchanged; all other statuses are preserved.

## Users and observable outcomes

Developers receive the same enforcing, Watch or availability response through
their installed harness with lower overhead. An approval resolves only its
original live request under current authority. Maintainers can identify, update
and roll back the exact installed artifact. Operators receive bounded queues,
resources and recovery with truthful health and private evidence under load.

## Source and evidence

The [seventh CI evidence](SEVENTH_CI_EVIDENCE.md) records **41 terminal first-attempt workflows: 34 successful and 7 failed**
at PR head `79cb6921ff722a597b545350485864dcd9310bdc`, tree `f158652293b1e10931122db6ccf48e33f5dd3c38`. GitHub tested merge
`b06b8db2f6fbd9d8f87e5e724e117748f57aea75` has the same tree and a distinct build identity.
The later implementation checkpoint `8dc0831dbeab56c497f855b4d50289383425ef7c`, tree `93d1c84cbc7f54ecf0539f892bfbbbf2f0bbff6d`,
requires its own published-source CI. All seven historical cohorts remain
separate; failed, censored and unoffered work retains its original denominator.

| Workstream | Seventh observation and practical limit |
| --- | --- |
| Main CI and security | All 96 pytest shards pass. Main has 114 jobs: 109 successful, two failed and three skipped. Windows packaged bootstrap rejects a pre-existing nonprivate Guard directory. Sonar stops on a service HTTP 500 before a new analysis or gate result. All four security jobs, I/O ownership and Rust authority ownership pass. All 195 Main artifacts are present and unexpired. |
| Installed native launcher | All fifteen POSIX jobs complete: 1,320/1,320 attempts including 1,200 timed observations. All native p95 series exceed 50 ms. Five Windows jobs fail in synthetic fixture teardown before measurement: 440 planned attempts remain unoffered, with no observation archive. Real Windows private-producer tests pass. Production selection remains off. |
| Dormant native source pilot | All four jobs stop at a stale discovery.py source commitment before the source/Rust gates. The regenerated fixture changes only that commitment; all response, signed, body and wire vectors remain identical. Later source needs its own execution. |
| Scanner | Four Rust and 174 Python checks pass. The original Python executable read reports metadata_writable before experiment preflight or any of the 24 timed offers: zero offered, zero completed, 24 unoffered. Public and encrypted evidence uploads succeed; collection and aggregation remain failed. The corrected Windows reader/route selection passes 17 supported source cases; 25 explicit POSIX-only skips remain excluded. This is not native regex execution on Windows. No finding-heavy benefit or installed native selection follows. |
| Package | Five comparable Python protect pairs retain median wall 8,904.153534 → 326.290654 ms and CPU 7,808.830 → 318.823 ms, with median paired reductions 96.3355230483%/95.9201319796%. All ten phase workers complete. Cardinality retains 36 candidate and 24 baseline completions plus twelve baseline workers censored at 15 seconds; formats retain 20 candidate and 18 baseline completions plus two frozen Composer failures. The original keep-Python decision remains unchanged. |
| MCP | 30 workers and 10,080 outcomes complete with zero failures across eight five-block comparisons. All 80 warm resource windows complete; ten separate lifecycle rows retain 13 missing samples and 39 descriptor denials. The existing decision remains unchanged; installed/cross-platform qualification and native selection remain unproved. |
| Installed native wheel | Linux and both Macs pass all 14 installed smoke gates; qualification remains false. Linux c16 completes 16 native requests with zero errors. At c64, it retains 62 native results and two explicit overloads, with no fail-safe or None results and all 64 requests accounted for. The Linux soak completes 100,000 requests and responses plus 250,000 receipts, with zero errors, 17,765 health checks and no health failures. RSS grows by 3.2749%, with one daemon and a stable PID. Its p95 of 522.36 ms is judged against the 4,500 ms diagnostic bound, not the ordinary 50 ms target. Windows retains the original five-second corpus HTTP timeout after a separate standalone 21/21 normalized native-decision pass. That earlier probe also retains a separate receipt-failure counter of five; passing decisions do not establish clean receipt persistence. |
| Indexed qualification and nonpriority tails | All four immutable wheels build. Linux smoke completes one block per arm, each with 38 series and 136 numeric observations. The separate aggregate reports comparison_available=true; sampling, program qualification and overall qualification remain false. Both Mac candidates complete 38 series and 136 observations, while their frozen baselines fail during DNS construction. Windows baseline completes 386 daemon and 62 registered-launcher cases, then fails route-count validation in batch 27, c16 Claude PreToolUse: all 16 requests are offered and observed, after 26 validated batches and 66 retained numeric values. Windows candidate completes 28 daemon cases and fails case 29, review/small Claude PreToolUse, before any numeric observations; HTTP does not return, and no native-bridge witness is retained. Neither Windows failure proves a narrower exception class or timeout cause. Linux and ARM scenarios pass. Windows disabled publication lacks an ACK; Intel enabled readiness exceeds 400 ms. Linux and Windows tail comparisons complete both arms. Mac candidates complete, but their baselines fail DNS before offers. Twelve of 16 planned timed tail observations are retained; four remain unattempted. |
| Packaging and release | PyPI builds and verifies distributions with hashes/SBOMs. Desktop validation passes. Actual publication, release, containers and desktop publication skip; no release is published. |

## Conversion decisions and priorities

| Priority / component | Release 3.2 decision | Exit requirement |
| --- | --- | --- |
| P0 / existing native decision, authority and transport | Finish the integrated Rust path and remove demonstrated avoidable work while preserving authority. | Comparable installed ordinary-hook, approval, mutation/recovery, offered-load and process-tree resource acceptance. |
| P0 / dormant native launcher | Keep production activation off while completing the four-target experiment and reviewed transport correction. | Actual Windows parity/setup, all required semantic/lifecycle cases and unchanged absolute/relative latency and CPU gates. |
| P1 / finding-heavy offline scanner | Keep selection open; complete the optimized-Python/native same-work experiment after strict toolchain admission. | Comparable 24-attempt smoke, then deliberate full 840-attempt experiment, equivalent findings/limits/exits and original benefit gate. |
| P1 / package path | Retain optimized Python under the original measured decision. | Reopen only a coarse native model/identity/result operation justified against the optimized real Python route; preserve missing frozen work and noncomparability. |
| P1 / installed tails and lifecycle | Complete exact-artifact qualification with comparable frozen arms. | Complete resource windows, original sample minima, aliases/source references/approval, signing/frozen manifests and live update/rollback. |
| Conditional / MCP and archive | Retain the measured Python boundaries and explicit native deferrals. | A future selected port needs original same-work benefit, parity, resource and installed qualification; no port is inferred from a deferral. |

The [package decision](package-native-selection-decision.md),
[MCP decision](mcp-native-selection-decision.md) and
[scanner/archive decision](scanner-current-decision.md) retain their exact
historical evidence and reopening conditions. A measured deferral is a decision;
it does not implement an optional port or satisfy its conditional native parity.
The full source map and ownership boundaries remain in [CURRENT_CONTRACT](CURRENT_CONTRACT.md).

## Functional and trust requirements

1. Keep the Rust resident responsible for the ordinary semantic decision.
   Preserve exact policy/program/catalog binding, authenticated peer and process
   identity, generation, expiry, mutation fences and replay protection through
   finalization. Metadata hints cannot confer content authority.
2. Record native verdict, resident-acknowledged posture, availability and the
   delivered harness response separately. Preserve the existing response matrix.
3. Bind approval to its original waiter, request and deadline; re-evaluate current
   authority before atomic consumption. Never replay an ambiguously delivered MCP write.
4. Preserve strict parsing, Unicode/CRLF behavior, limits, complete findings,
   source references, HMAC, suppression, provenance and exits 0/2/3. An incomplete
   scan or omitted dependency cannot become a successful benchmark observation.
5. Bind source, artifact/runtime/program, interpreter, dependencies, workload and
   host cohort. Execute measured wheels outside source checkouts using the actual
   registered executable and argv with development overrides cleared.
6. Retain offered, failed, late, censored and unoffered work, bounded private
   evidence and complete resources. Missing counters remain missing.
7. Prove signed/frozen installation, live update and rollback on the tested
   artifacts. Source tests and stopped replacement cannot supply that proof.

## Performance acceptance

| Scope | Unchanged acceptance |
| --- | --- |
| Ordinary installed priority hooks, 1–16 KiB, warm c1 | p95 ≤50 ms and p99 ≤100 ms |
| Ordinary installed priority hooks, c16 | p99 ≤200 ms, zero errors and correct decisions |
| Native client / cold native / daemon readiness | p95 ≤20 ms / p95 ≤150 ms / 400 ms barrier |
| Independent comparisons | At least five alternating independent pairs and required confidence intervals |
| Per required qualification scope | 10,000 warm priority, 1,000 other, 100 cold/recovery observations and at least 30 valid resource samples |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU reduction; at most 5% regression in the other primary metric |
| Optional native ingress | At least 25% private-memory or 30% c16 p99 reduction with equivalent decisions and containment |
| Optional package/offline conversion | At least 30% benefit over optimized Python on the same real route including startup/boundary costs |
| Resource growth | Existing 12% short-load and 50% long-soak RSS limits at their original scopes |

The original PRD resolves any abbreviated requirement. Keep KERNEL,
NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER separate; registered process
startup is included in the last boundary. Cold launcher, cold resident,
readiness and recovery are distinct series. Exercise Linux x64, macOS Intel,
macOS ARM and Windows x64, with 1 KiB, 16 KiB, 256 KiB, 1 MiB and maximum
payloads at c1/c4/c16/c64 and offered-rate load. Include generator/queue delay
and all terminal outcomes. Bounded c64 overload remains visible in conservation.
General Darwin process-tree CPU remains unavailable where reaping is ambiguous.

## Implementation and acceptance work

| Later source change | Resulting behavior | Required next evidence |
| --- | --- | --- |
| Synthetic discovery fixture cleanup | After the original byte and signature assertions, the finally block removes only synthetic daemon state before global daemon retirement. Unrelated retirement remains exercised on both normal and assertion-failure exits. | Actual Windows source/launcher rerun; this does not repair the separate real existing-directory bootstrap failure. |
| Claude fixture source commitment | The existing generator rebinds only discovery.py's changed bytes; all semantic, signed, response, body and wire vectors remain unchanged. | Four-target source/Rust gates on the newly published source. |
| Original installed-corpus failure context | Each original request retains a finite harness/event and validated-prefix witness if it raises; the same exception, single call and five-second transport timeout remain. Private URL, payload and exception text are excluded. | A fresh Windows observation identifying the request; the historical timeout cause remains unknown. |
| Scanner private interpreter | Integrated source 8dc0831dbeab56c497f855b4d50289383425ef7c reuses the existing owner-private byte-identical interpreter-copy helper after frozen uv sync, inside the unchanged five-minute setup step. The hosted interpreter is untouched. Before/after invocation, version, prefix, stdlib and venv-config identity match; original strict executable admission remains. The encrypted setup record is required for verified collection and bound to the measured interpreter hash and worker commitment; only its digest is public. | Actual pinned-uv/hosted-runner setup and comparable 24-attempt smoke; local correctness and source review do not supply measurements or satisfy the full five-run minimum. |
| Explicit Windows parent provisioning | Explicit manager setup verifies trusted ownership and retained identity, changes only the existing parent DACL under exclusive access, and then restores the verified binding. Existing child and key bytes and ACLs are preserved. Generic helper defaults and strict discovery readers remain unchanged. | Actual Windows child-preservation regressions, unchanged frozen bootstrap and installed launcher; local tests alone cannot establish Windows behavior. |
| Dormant native HTTP socket buffering | The dormant client sets TCP_NODELAY on the existing validated loopback stream before challenge or hook writes. Wire bytes, proof headers, socket reuse, authentication and absolute deadlines remain unchanged; production registration stays off. | Fresh paired installed measurements on all targets remain required. Six correctness tests using the exact production HTTP module pass; this does not establish a full runtime build or latency improvement. See the reviewed transport change in native-claude-launcher-design.md. |

1. **Verify the new source in GitHub.** Run scope-appropriate Python/Rust checks and the unchanged ownership/security gates on the exact publication. Confirm corrected fixture execution on actual Windows and all four dormant-pilot targets. Retain seventh Main's independent packaged-bootstrap and Sonar-service failures; historical green jobs do not approve later bytes.

2. **Complete Windows setup and launcher proof.** The reviewed explicit manager-setup correction provisions an existing Guard directory only after verifying its trusted owner and retained identity. It applies a private parent DACL under exclusive access while preserving child and key bytes and ACLs. Execute the new Windows regressions, the unchanged frozen bootstrap and the installed launcher experiment. Strict private discovery producers and readers, including rejection of existing untrusted keys, remain unchanged. Keep synthetic teardown and real bootstrap defects separate; retain all 440 unoffered seventh Windows attempts.

3. **Measure the native launcher transport correction.** The reviewed TCP_NODELAY change addresses small HTTP header and body writes on the dormant validated loopback client; it is a concrete optimization candidate, not a proven cause of seventh-cohort latency. Preserve exact wire, authentication and deadline behavior, then measure the next installed cohort. Keep all fifteen completed POSIX jobs and their failed 50 ms p95 gates. Do not activate the pilot until parity, benefit, complete resources and lifecycle acceptance pass. The source evidence is recorded in native-claude-launcher-design.md.

4. **Admit and complete scanner measurements.** The seventh original read identifies metadata_writable on the hosted Python executable. Execute the integrated private-interpreter fixture correction (8dc0831dbeab56c497f855b4d50289383425ef7c) in the next exact-source GitHub run; the original hosted executable and strict admission remain unchanged. Inspect comparable 24-attempt smoke before deliberately selecting the full 840 attempts. Preserve findings, ordering, HMAC, suppression, cache identity, incomplete scans, exits and all failures. Keep seventh all-24-unoffered evidence immutable; setup alone is not a timing or native-selection result.

5. **Resolve installed qualification and resource failures.** Linux installed smoke and its 100,000-request, 250,000-receipt soak pass at seventh source; this does not qualify mixed offered load on all platforms or ordinary 50 ms latency. The separate Linux one-pair indexed aggregate is comparable. Both Mac candidates complete, but their baselines fail DNS construction. Windows baseline retains 386 completed daemon cases, 62 completed registered-launcher cases, 26 validated numeric batches and 66 numeric values before batch 27 fails route validation despite 16 offered and 16 observed requests. Windows candidate retains 28 completed daemon cases, then fails the review/small Claude PreToolUse case 29 with no returned HTTP status, native-bridge witness or numeric values. Diagnose these failures separately from the native-wheel corpus five-second HTTP timeout, Windows disabled publication without an ACK, and Intel enabled readiness at 469.786 ms. Preserve original single calls and deadlines; no narrower Windows indexed exception class or timeout cause is established. General Darwin CPU remains unavailable when reaping is ambiguous. Complete posture, expiry, restart, lost-hint, receipt, resource and original full-sample obligations; do not substitute smoke or availability for native success.

6. **Preserve measured no-selection decisions.** Package's separate seventh Python improvement and phase attribution do not replace or pool the original decision. Keep all twelve censored baseline workers and two frozen slash-qualified Composer failures. Do not alter the frozen baseline or workload to manufacture comparability. MCP keeps its original decision and incomplete lifecycle resources. Archive retains its isolated Python worker, integrity reads, expansion bounds and all failed/time-limited inspections.

7. **Finish original release acceptance.** Complete all 144 original criteria at their literal scopes: installed ordinary/alias/source/approval and availability coverage, posture/expiry/restart/lost-hint races, mixed offered load, resource/receipt obligations and original sample minima. Verify signed/frozen artifact identity, live update, in-flight generations and changed-program rollback. Obtain final-head CI and independent latest-push human/code-owner approval, then prepare a concrete qualified canary and rollback before any final release approval request.

Full nonpriority tails require their deliberate 320-job selection. Scanner
smoke has 24 attempts; the full plan has 840 attempts across 35 collection shards, seven
fixtures, five runs, two cache states, six pairs and two arms, retaining the
120-second CLI and 30-second native deadlines. Smoke cannot satisfy full minima.

## Validation and release decision

At local integration `0cde30ac220ba52863b013707df567e0ce681d76`, the combined 18-module correctness suite passed **498 tests**, with **10 explicit Windows/platform skips**. The separate I/O ownership suite passed **30 tests**. Ruff lint and formatting passed for all 15 changed Python files; scoped CI-level type checking passed for eight source/protocol modules; Rust 1.88 formatting, the four-source Claude launcher fixture freshness check, same-base authority ownership and the privacy gate passed. Full collection succeeded with **22,578 cases and 24 protected invariants**. All **394 frozen evaluator source commitments** match exactly, with no corpus evaluation or regeneration. The six focused Rust HTTP/response module tests previously passed under Rust 1.88.0; their exact production module bytes still match this integration. Those six checks were a standalone module build, not a full runtime-crate or platform build. The following evidence-only commit `3eb1cea3c565821c40a36c95fedac54149185312` changes two documentation files and no tested source. Gitleaks 8.24.2 scanned the exact release-base-to-immutable-source range: 1,267 commits and approximately 52.08 MB, with zero findings. No local performance run was performed. Actual Windows execution, a full native runtime build and installed latency/resource qualification of the new source require the forthcoming published-source CI.

The [release review](RELEASE_REVIEW.md) and [takeaway prompt](TAKEAWAY.md) define
the remaining execution. Require complete comparable performance/semantic/resource
evidence, final-source CI, independent latest-push human/code-owner approval,
tested signed/frozen live rollback and a concrete canary with stop conditions.
The PR remains a draft; merge, production activation and release are incomplete.

The 42 [individually reviewed Sonar findings](../security/sonar-release-32-review.md)
remain unapplied. Sixth analysis succeeded and its quality gate failed. Seventh
analysis instead stopped on a Sonar service HTTP 500 before producing a new
analysis or gate result; no historical numeric conditions become current.
Automatic approval review rejected the project-specific external lookup because
it would disclose private project, PR and issue identifiers without explicit
authorization. The specific permission request for fresh checks and verified
individual false-positive dispositions remains pending. Do not retry that action
through CI or another route without approval. No comments, exclusions, severity
changes or quality-threshold changes are authorized by that pending request.
