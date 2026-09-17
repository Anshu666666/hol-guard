# Takeaway prompt: finish HOL Guard release/3.2 performance work

Continue the user's authorized implementation through GitHub. Reduce actual
tool-call latency and CPU while preserving Guard's decision, posture, approval,
artifact and evidence contracts. Complete the original [PRD](PRD.md), its
[release addendum](RELEASE_3_2_PRD.md) and the remaining [144 TODO criteria](TODO.md).
Use [execution-ledger.json](execution-ledger.json) as the status/evidence index.
Original IDs, titles, acceptance and dependencies are immutable. A measured
release deferral is a decision; an unbuilt port is not an implementation, and
smoke is not qualification. Do not create GitHub issues or overwrite another
writer's work. Continue already authorized work without repeated confirmation.

## Recover the exact state

Read repository instructions, [RELEASE_REVIEW](RELEASE_REVIEW.md),
[CURRENT_CONTRACT](CURRENT_CONTRACT.md), [FOURTH_CI_EVIDENCE](FOURTH_CI_EVIDENCE.md)
and the next workstream's decision note. Preserve the immutable
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md) and
[third](THIRD_CI_EVIDENCE.md) reports and the historical portion of
[EXECUTION](EXECUTION.md). Their uses of “current” refer to their recorded source.

This handoff's implementation cutoff is `872b0517b5596f8c19abd0fce185c7e14983cc20`, tree
`581e5cb30bd0082abf0356b5931b26d5ef204903`. Local branch: `work/rsp-performance-finalization-32`.
Owned publication: [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970),
head `codex/release-3.2-rust-finalization`, base `release/3.2`. Refresh its actual
head, base, checks and review threads before acting; the measurement checkpoint
below is not necessarily the live head.

The latest fully reviewed measured checkpoint is
`2ebb01ff356101aea8d658ce639fe2c87188bd0d`, tree
`1c41bef1979ead9e50ee406a60505ce6894aa461`. Its PR merge
`d769f9722d34e98cadea058e01575b48ab24f053` has the same tree and the release
base/candidate as parents. Keep explicit candidate and merge build identities
distinct. Forty terminal workflow instances have 35 successes and five failures.
Six later label-only workflow instances are recorded separately in that
report; they offered no benchmarks or release builds. Both smoke labels are
now staged for this source, while all full-collection labels remain absent.
Later source fixes do not inherit those results. Keep every failed/cancelled
attempt and exact artifact hash; never rewrite old failed manifests as successful.

Frozen baseline: `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1.
Main was last verified at `05fa4760df8401b9710bf098adb4fbb2dc4ff389`; release base
at `4b89e0d2d496a85f04922b2e019a4aea15326bb9`. Use Rust 1.88.0 and locked
dependencies. Check dirty files and active worktree ownership; do not repeat
integrated cherry-picks. PR #2954 belongs to another writer. Selective reviewed
reuse is permitted; whole-branch overwrite or an unreviewed merge is not.

For Git Data API publication, bind the exact intended committed tree, use the
actual owned remote head as parent, verify the returned tree SHA and advance
only the owned branch without force. Local historical ancestry is not
automatically the intended publication history. Keep code, evidence, ledger,
PR description and this prompt consistent at the final publication.

## Execute in dependency order

1. **Verify corrected source on CI.** Fourth Main had 106 successful, six skipped
   and two failed jobs. One package attribution test rejected a negative total;
   95 of 96 pytest shards passed. All 96 duration artifacts uploaded, including
   shard 91, but aggregate duration validation and Sonar were skipped. The test
   now executes the actual fresh worker CLI and still rejects invalid totals;
   the original negative value/cause is unknown. Require actual final-source
   tests and duration aggregation. The 42 individually reviewed
   [Sonar dispositions](../security/sonar-release-32-review.md) remain unapplied.
   Use authenticated individual dispositions if access exists; never weaken
   detectors, fixtures, exclusions or the quality gate to suppress a failure.
2. **Execute corrected launcher/pair admission.** All four fourth-source
   immutable-wheel builds passed. Linux and Windows pair recording confused
   Cargo triples with resident `ARCH-OS` labels; the
   [fixed association](qualification-target-identity.md) retains full artifact
   identity. All 20 Claude experiment jobs failed the related manifest check
   before offers; each encrypted one failure summary but none reached
   measurement journals. The [launcher correction](claude-launcher-target-identity-diagnosis.md)
   binds required `manifest_target` and independently checks compiled arch/OS/ABI.
   Keep `native-claude-launcher-experiment` explicit. Verify real registration,
   no-env package origin, parity, native routes and both evidence uploads.
   Production activation requires benefit and complete package/lifecycle proof.
3. **Read failure facts before choosing another production fix.** Linux's c64
   wave returned 64 responses but only 32 native-resident decisions among 48
   allows; Windows had ordinary unavailability and another conservation failure.
   Intel exceeded its separate 1,000 ms adapter gate at 1,014.141 ms. The
   [capacity witness](native-capacity-none-witness.md) retains original None
   results and potentially stale client codes without another native call.
   ARM completed 386 daemon and 62 registered cases before c16 Codex PostToolUse
   rejected extra stdout fields; 16 calls were offered and three returns retained.
   The [failure-only shape witness](fourth-installed-failure-observations.md)
   preserves the rejection and accepted schemas. Intel's Pi digest-mismatch case
   returned an error object before receipt validation with about 2,980 ms left.
   Exact underlying causes remain unproved. Do not infer native allow from
   continuation, guess a pool fix, or change deadlines/counters to pass a gate.
4. **Validate posture and resource corrections.** Ordinary native requests use
   their resident-ACKed posture. Fresh local Watch cannot transform an older
   enforcing result or bypass its command-control fence. Preserve in-flight
   binding, strict workspace composition, expiry, invalidation and wrong/stale
   ACK rejection; availability policy stays unchanged. Run actual installed
   transitions on the final artifact. The [Darwin collector](darwin-resource-accounting.md)
   uses Mach ticks, integer subtraction, native birth/timebase identity and
   transitive reap accounting. Run own-clock, nested and ignored-child witnesses
   on both Macs. Missing CPU stays missing; Linux fake-ABI tests do not close
   RSP-011 or prove Mac process-tree performance.
5. **Complete one scanner selection experiment.** The [scanner decision](scanner-current-decision.md)
   retains seven nonqualifying clean states and missing finding-heavy timings.
   Use the integrated [collector contract](scanner-regex-pilot-ci.md).
   Begin with `scanner-regex-pilot-smoke`: working_provider_large, run zero, two
   cache states and six alternating pairs = 24 planned timed CLI attempts.
   Inspect real preflight findings/HMAC/ordering/exits 0/2/3, containment and
   sealed retention before deliberate `scanner-regex-pilot` full selection.
   The fixed full plan is seven fixtures × five independent runs × two states
   × six pairs × two arms = 840 planned attempts in 35 jobs. Original CLI/native
   deadlines are 120/30 seconds; controller/job caps remain explicit. Unverified
   eviction stays unavailable. All failed and unoffered work is retained.
   Success justifies the next native qualification step, not production
   activation. A completed nonqualifying result supports the documented release
   deferral; do not restart an open-ended profiling program.
6. **Preserve measured release decisions.** The [package decision](package-native-selection-decision.md)
   retains optimized Python. Fourth-source protect wall/CPU medians changed
   from 8,785.843/7,739.458 ms to 327.344/319.842 ms across five independent pairs.
   All ten phase workers completed. Guard Python contributes 37.31%/51.75% of
   instrumented protect/evaluator exclusive CPU; Pydantic has zero observed calls.
   No parser-only Rust port is selected. Reopened coarse model/identity/result
   work must beat optimized Python under the actual 30%/5% gate. Preserve
   12 censored cardinality attempts, two baseline Composer failures and the
   None-version boundary. The [MCP decision](mcp-native-selection-decision.md)
   retains its separate second-checkpoint cohort, small pure residuals and
   store/persistence/barrier costs; newer results do not erase incomplete
   lifecycle windows or peak-memory regression. Retain the isolated Python
   archive worker: RSP-070 profiling is complete, but two measured timeouts and
   absence of native comparison remain. Keep all integrity reads, identity,
   containment and expansion bounds. These are not failed Rust benchmarks.
7. **Collect installed coverage deliberately.** The separate
   [nonpriority smoke](nonpriority-installed-tails.md) uses
   `rust-nonpriority-tail-smoke`: one Cursor beforeShellExecution.global route
   on four platforms, pair zero. It offers 16 timed and 16 preflight calls if
   every arm completes. Smoke takes precedence for this companion and cannot
   meet full acceptance. Inspect it before removing the smoke selection and
   deliberately applying both `rust-nonpriority-tails` and
   `rust-performance-qualification` for the 320-job full companion. Main priority
   mode stays independent. Normal PR/schedule activity must not enable the full
   companion. Preserve command, callback, preflight and observation-only scopes.
8. **Finish qualification and release gates.** Both Mac frozen baselines still
   stop in socket.getfqdn construction. Read retained resolver evidence before
   any bounded runner correction; never patch baseline source or invent
   readiness. Linux/ARM/Windows candidate Ollama/Builder scenarios passed,
   Windows with 22 native cases; Intel took 403.453 ms against 400 ms. Every
   indexed pair and aggregator failed, and transitions were skipped. Collect
   full samples only with comparable admitted arms and verified containment.
   The stopped-artifact probe has five phases, ten registered cases and a third
   installation; it cannot prove live generations, signing/frozen updates or
   changed-program rollback. Finish mixed load/mutation/recovery, receipt
   durability, signed/frozen identity and exact tested rollback. Final required
   CI and independent latest-push code-owner approval remain separate protected
   requirements. Prepare the concrete candidate/cohort/stop/rollback result
   before seeking any final external approval.

## Preserve the decision and trust contracts

Keep KERNEL, NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER timing separate.
The installed launcher starts the actual registered executable and arguments,
includes startup, writes real stdin and validates stdout and exit. HTTP-only
observations cannot fill that series. Cold launcher, whole-daemon startup,
readiness and resident recovery are distinct measurements.

Ordinary HTTP hooks enter HookWorker and the persistent native helper; verified
compatibility and legacy revalidation have separate Python paths. Reuse the
existing Rust decision core, trusted command compiler and bounded scanner. Owned
uncertainty for unsupported semantics cannot become silent no-match. Preserve
native verdict, posture transformation, availability outcome and delivered
response as four facts. Watch is not a native-evaluated allow. Ordinary
unavailable continuation and PostToolUse empty output keep their harness
contracts; no new Python semantic fallback or blanket denial is authorized.

Retain authenticated peer and live process/image identity, exact source content,
policy/program/catalog binding, generation, expiry and replay protection. Cache
only within proved authority; stat metadata is an invalidation hint. Mutations
close the fence before durable effects; finalization rechecks current authority.
Recovery binds the previous floor, key and epoch. Immutable Windows API metadata
reuse never caches an owner, ACL, file content or live authorization decision.

Approval belongs to the original live waiter, exact request and original
deadline. Native Codex completion re-evaluates current authority and verifies
signed consume/replay binding. Unsigned terminal state cannot authorize reuse.
Ordinary approval handling and exported native challenge/claim/consume APIs
remain distinct. Never replay an ambiguously delivered MCP write. Preserve
framing, queue limits, catalog invalidation during approval and the final 5 ms
freshness barrier.

Memory admission, durable journal, SQLite commit and checkpoint are distinct
milestones. Replayed evidence deduplicates the stable attempt without repeating
authorization. Missing SQLite VFS/fsync/physical-byte measurements stay missing.

## Qualify performance and evidence honestly

| Required scope | Unchanged acceptance |
| --- | --- |
| Ordinary 1–16 KiB priority installed hooks, warm c1 | p95 ≤ 50 ms; p99 ≤ 100 ms |
| Priority installed hooks, c16 | p99 ≤ 200 ms; zero errors and correct decisions |
| Native client / cold native / readiness | p95 ≤ 20 ms / p95 ≤ 150 ms / 400 ms barrier |
| Priority samples | 10,000 warm observations across at least five independent alternating runs; 100 cold starts and recoveries; at least 30 steady-state resource samples per required scope |
| Other installed routes | At least 1,000 warm observations per route/platform |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU reduction; no more than 5% regression in the other primary metric |
| Optional ingress | At least 25% private-memory or 30% c16 p99 reduction, preserving containment and decisions |
| Native package/offline work | At least 30% benefit against the optimized Python real route, with original parity/regression safeguards |
| Resource growth | Existing 12% short-load and 50% long-soak RSS limits at their actual sampling scopes |

Use Linux x64, Mac Intel, Mac ARM and Windows x64 installed wheels outside source
checkouts, with no development origin override. Bind source, artifact, runtime,
rule/program/catalog, workload, interpreter, dependencies and host cohort.
Post-sign/frozen bytes need their own identities. Report percentile estimators
and required confidence intervals; pooled calls are not independent runs.

Exercise 1 KiB, 16 KiB, 256 KiB, 1 MiB and maximum payloads at c1/c4/c16/c64,
including offered-rate load. Retain every offer, admission, completion, timeout,
rejection, failure and late result. Offered-to-terminal latency includes queue
and generator delay. Late completion cannot overwrite timeout. c64 may reject
bounded overload; it may not hide errors, hang, leak or mix replies.

Separate generator resources from the daemon/helper process tree. Missing CPU,
RSS, private memory, descriptors or Windows handles cannot become zero or a
successful resource window. Human/network waits and instrumentation stay
explicit. The first Linux legacy soak's 528.06 ms p95 and two-observation
launcher smokes do not satisfy the installed-priority targets.

Upload bounded reconstructed public aggregates and authenticated encrypted
private evidence. Retain interrupted numerical journals and bind the exact
bytes read during aggregation to sealed archive receipts. Verify authorized
recovery without logging private records or recovery keys; preserve actual
Windows ACL and process-containment failures. Archive limits remain 256 flat
files, 32 MiB per file and 128 MiB total. The fixed indexed plan fits those limits;
custom expanded plans require a fresh capacity check.

## Required delivery

The current ledger is **83 DONE / 24 OPEN / 29 BLOCKED / 8 DEFERRED**. A source, pinning, coverage
publication or accurate handoff criterion can be complete while its original
installed, signing, approval and rollout dependencies remain open. Do not count
documentation as RSP-137–143 release completion. Update the PRD addendum, all
144 ledger rows, current contract, evidence links, PR description and this prompt
together. Report exact source/artifact identities, selected/deferred work,
commands/results, failed scopes and tested/unexecuted rollback. Continue useful
authorized work; if an external gate truly blocks completion, identify the
concrete action and reason without presenting the program as finished.
