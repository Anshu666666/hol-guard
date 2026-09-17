# Continue HOL Guard Rust performance work on release/3.2

Complete the user's authorized implementation using GitHub. Deliver the original
[PRD](PRD.md), its [release addendum](RELEASE_3_2_PRD.md), and all 144 [TODO](TODO.md)
acceptance conditions. Use the [machine ledger](execution-ledger.json) for current
status and evidence. Preserve original task IDs, titles, acceptance and
dependencies. Do not replace unmet acceptance with smaller smoke tests, mark an
unbuilt conditional port DONE, or claim a release while its gates remain open.
Do not create GitHub issues. Continue already authorized implementation without
repeated confirmation; protected merge approval is a separate final requirement.

## Establish the exact state

Read repository instructions, [RELEASE_REVIEW](RELEASE_REVIEW.md),
[CURRENT_CONTRACT](CURRENT_CONTRACT.md), [SECOND_CI_EVIDENCE](SECOND_CI_EVIDENCE.md),
[FIRST_CI_EVIDENCE](FIRST_CI_EVIDENCE.md)
and the relevant workstream reports. [EXECUTION](EXECUTION.md) preserves older
attempts; historical uses of “current” belong to their recorded source.

This handoff's source cutoff is `599509be545b9992076d7f9f71dd19ecfd34bbc2`, tree `55b05ef94f1f379fd0cf2762e3f1f394a2771b24`, before the
handoff edits. The integration branch is `work/rsp-performance-finalization-32`.
The isolated publication is [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970),
branch `codex/release-3.2-rust-finalization`, targeting `release/3.2`.
Its latest measured publication is `24ba2d130a90f36b676139f03cabea98a2c3b00e`,
with 39 terminal workflows: 32 successful and seven failed. Include the invalid
qualification-YAML push run with zero jobs in that denominator. Main CI itself
had 114 jobs: 110 passed, three skipped and one Sonar gate failed. Refresh the
live head and CI; never attribute those measurements to a later tree. Preserve
first-checkpoint `107606388...` and its 19 public reports unchanged.

The frozen baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package
3.0.1. Release base was last checked at `4b89e0d2d496a85f04922b2e019a4aea15326bb9`;
main at `05fa4760df8401b9710bf098adb4fbb2dc4ff389`. Use Rust 1.88.0 and locked
dependencies. Preserve release behavior and the reviewed lineage. PR #2954 has
another writer; selective reviewed reuse is permitted, whole-tree overwrite or
an unreviewed merge is not. Check dirty files and agent ownership before editing;
do not cherry-pick already integrated changes.

Before publication, compare the exact intended Git tree, refresh the owned
remote branch, and use a non-forced update. When publishing through Git Data API,
use the latest owned remote head as parent and verify the returned tree SHA
against the committed local tree. Historical local ancestry is not automatically
the intended publication ancestry. Preserve the measured checkpoint and exact
artifact byte hashes in the first-CI evidence directory.

## Execute the next work in order

1. Reconcile the owned publication with this source and any later independently
   reviewed fixes, then publish exact matching code and documents. Inspect actual
   workflow admission first: `a886a89bc` repairs job-level `runner.temp` scopes
   after the second qualification workflow ran zero jobs. `ca772a069` stamps the
   pinned Gitleaks version without relaxing its check. Validation-only follow-up
   `a86ee9736` fixes the MCP self-comparison and adds real signed-marker guard
   regressions, with seven focused tests passing. Read the exact 42-finding
   [Sonar disposition review](../security/sonar-release-32-review.md) before
   applying individual false-positive dispositions through authenticated Sonar
   access. They remain unapplied; do not alter fixture URLs/seeds, production
   guards, exclusions or thresholds merely to silence them. Run fresh analysis
   and the original full scans and gates.
   A source correction does not change any historical workflow conclusion.
2. Read the next four-platform native-wheel diagnostics before choosing a fix.
   At `24ba`, Linux failed RSS warmup route proof; Mac ARM `cursor/5m` and Mac Intel
   `pi/1m` each saw a native call without an admitted result. `7e2739fc4` now retains
   bounded wave counters and before/after thread-local client failure context;
   stale context is not proof of a new attempt. Windows's corrected binary-LF
   and base-interpreter RSS fixture and `8bab03d5f` witnessed Job process chains
   need actual Windows execution. Keep exact count, route, resource and deadline
   assertions; none of those platform failures is an accepted sample.
3. Investigate the remaining deferred-backfill failure, not the repaired storage
   burst. The original 24-request burst now passes unchanged 1.75-second client,
   1.6-second response and 0.5-second health assertions. `599509be5` prepares only
   admitted oracle code/immutable manifest before readiness; current config,
   authority, stores and approvals remain request-local. The subsequent broader
   run retained 91 passes and one eight-second backfill capacity-wait failure.
   An instrumented isolated pass did not explain it. Preserve all earlier outcomes
   and original startup/review limits; RSP-134 remains a final-head gate.
4. Execute the implemented, separate installed experiments. Enable the existing
   `native-claude-launcher-experiment` same-repository PR label before the next
   eligible publication. Compare actual optimized Python/native Pre/Post argv in
   the same opt-in installed wheel, retaining registration, response, route and
   artifact identities plus both uploads. Default 20 samples per arm/event are
   exploratory; 2,000 per job across five jobs are needed even for the c1 sample
   denominator. Production registration and default capability stay off. The
   independent stopped-artifact transition job runs with the qualification label:
   five phases, ten registered cases, exact indexed wheels, third environment and
   candidate-locked dependencies. It has not executed. Do not present stopped
   replacement as live update, signing, frozen packaging or downgrade support.
5. Run the new package phase job and interpret second-checkpoint component data.
   `4a1349d57` supplies eight candidate validation/attribution workers and a
   separate baseline/candidate pair of explicit npm `*` requests through the real
   resolver/protect route. The original 567-case manifest and production semantics
   remain unchanged. Bare requests use the unchanged literal `latest` shortcut;
   the None-version highest-risk kernel is another boundary. Keep the two
   baseline Composer coverage failures and twelve 15-second whole-worker censored
   cardinality attempts noncomparable. Instrumentation cannot supply headline
   latency or a native benefit decision.
6. Use the corrected, authenticated MCP v2 reconstruction as the optimized Python
   source-component baseline: 30 workers, 240 sessions, 10,080 calls, intervals
   per trace from five independent paired runs and 80 complete warm windows. The original
   strict-finalizer failure stays failed; `1498e2264` repairs only two finite
   resource fields. Keep ten incomplete lifecycle records and 16 missing samples
   visible. Parent CPU is not whole-tree CPU, loopback service is not remote
   latency, and synthetic approval delay is not human time. RSP-098/103 can close
   this literal scope. Follow the measured [MCP selection decision](mcp-native-selection-decision.md):
   RSP-104/105/107 are deferred for release 3.2, RSP-108 records the full-proxy
   deferral, and RSP-106 remains unchanged. Tiny pure residuals relative to
   store/composition/persistence and the unchanged 5.11 ms barrier support that
   scope decision. No Rust candidate was measured; do not describe it as a failed
   native benefit gate. Reopen only on the documented new residual/selection
   evidence; installed/platform acceptance remains independent.
7. Preserve the unresolved frozen Mac startup boundary. First-checkpoint reverse
   lookups timed out while numeric lookup completed and the PTR fixture saw no
   OS queries. The registration/libSystem/self-test observability is integrated,
   but invalid second-checkpoint YAML produced no new paired resolver report.
   Inspect actual next-run evidence before changing an OS fixture. Do not patch
   the baseline wheel, substitute candidate behavior, change readiness targets
   or extend deadlines. Continue the candidate only after verified containment.
8. Complete the reviewed nonpriority-tail companion still under implementation:
   sixteen routes and 320 full collection jobs are planned, not integrated at
   this cutoff. Then execute the required full indexed qualification with
   `rust-performance-qualification` or manual qualification mode. Preserve five
   alternating same-runner pairs, 10,000 priority/1,000 other samples, 100 cold
   starts/recoveries, resource minima, estimators and every failed offer. A
   collection pass, a performance pass and program completion are different.
9. Select or defer conditional Rust tranches only from measured comparisons
   against optimized Python under the original criteria. Finish signed/frozen
   artifacts, first hook after update/rollback, mixed mutation/recovery/receipt
   evidence, independent review and the concrete canary/rollback plan. Update
   all affected ledger entries with exact provenance. Final independent code-owner
   approval remains a protected action; source contributors cannot supply it.

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

Finish by refreshing the PRD addendum, all 144 ledger records and this prompt.
The current 74 DONE / 30 OPEN / 37 BLOCKED / 3 DEFERRED is an honest checkpoint,
not an acceptable substitute for completion. RSP-007/015/047/098/103/140 close
literal measurement/fixture/core/component/privacy criteria, and RSP-108 records
a decision. The three measured MCP deferrals are not implementations. They do not
close dependent installed benefit or RSP-134 exact-head validation. Keep each
unresolved dependency explicit. No agent may supply or impersonate independent
code-owner approval.
