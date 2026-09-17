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
[CURRENT_CONTRACT](CURRENT_CONTRACT.md), [THIRD_CI_EVIDENCE](THIRD_CI_EVIDENCE.md),
[PACKAGE_PHASE_CI_EVIDENCE](PACKAGE_PHASE_CI_EVIDENCE.md) and the relevant
workstream reports. [FIRST_CI_EVIDENCE](FIRST_CI_EVIDENCE.md),
[SECOND_CI_EVIDENCE](SECOND_CI_EVIDENCE.md) and [EXECUTION](EXECUTION.md) preserve
historical observations; their uses of “current” belong to the recorded source.

This handoff's source cutoff is `6c7c3097d566da35812d087d1dadae1fba8823de`, tree `87828bda11b356fa9ba982f3d47fffc96a05451c`,
before these handoff edits. Integration is `work/rsp-performance-finalization-32`.
The owned publication is [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970),
branch `codex/release-3.2-rust-finalization`, targeting `release/3.2`.
The latest observed publication is `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`;
its native-wheel/daemon-edge jobs identify merge
`c855bae3e83579587d229c83b597dc1cbc1d4bb6`. The third report records 43 terminal workflow instances: 36 successful, five
failed and two skipped. Preserve individual attempts and artifact identities.
Later source fixes have not inherited an installed pass or native benefit.
Preserve the immutable first107 and second24ba reports and their original
artifact bytes; neither historical failed projection nor cancelled attempt may
be relabeled as successful after a source correction.

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

1. Publish the coherent reviewed source with exact matching code and documents,
   after checking dirty files, agent ownership, actual remote head and Git tree.
   Do not duplicate integrated tranches. At d0e, all 96 pytest jobs passed, but
   Main CI failed duration aggregation and Sonar: shard 91's telemetry was
   omitted when an installed-proof fixture cleared environment overrides. The
   reporter now binds its destination before tests begin. Require all original
   duration artifacts on the next run. Apply only the 42 individually reviewed
   [Sonar dispositions](../security/sonar-release-32-review.md) through
   authenticated access; they remain unapplied. Do not weaken detector rules,
   exclusions, thresholds or fixtures to silence the gate. Older storage-burst
   and backfill observations remain historical; do not invent a new failing
   test when the current pytest matrix passed.
2. Inspect actual next-run Mac bridge and Windows launcher diagnostics before
   selecting a production correction. Mac ARM OMP/5 MiB and Intel Kimi/250 KiB
   returned no admitted raw edge in 30/108 ms with 2,938/2,927 ms remaining;
   client context was absent before and after. The new fixture observes exact
   status/envelope/client/decode/receipt stages, with no extra authority I/O,
   request, parsing, retry or deadline. Projection errors and overlapping
   contexts report partial/unavailable observation without changing requests.
   Windows passed its 30 memory tests and 21-decision default-auto corpus, then
   failed registered Claude PostToolUse native-route proof. Its new exception
   retains finite response and before/after route evidence. Neither failure has
   a source-proven production cause; do not assume home resolution, timeout or
   a native source-read defect. Separate daemon-edge/Windows resident passes
   cannot qualify these installed failures.
   Run the separate [raw UTF-8 observations](installed-raw-utf8-fixture.md) when
   their installed scenario is reached. Retain exact bounded capture prefixes,
   exit/I/O/containment facts and missing native evidence before interpreting
   platform codec behavior. The report remains unqualified and does not alter
   the original sixteen text cases or their gates; review actual platform
   delivery profiles before claiming malformed-byte parity.
3. Keep qualification run `35233473603` attempt 1 and attempt 2 distinct.
   Attempt 1 was cancelled during build by an unrelated label; unique run/attempt
   concurrency now prevents that cancellation. Attempt 2 ran three POSIX builds
   and attempted collection despite Windows's `archive_source_changed` export
   failure. All four pair jobs failed; Linux and Mac ARM candidate Ollama/Builder
   scenarios passed; Intel's Builder passed but enabled-control Ollama readiness
   failed at the original 400 ms limit, and Windows lacked its bundle.
   Aggregators failed and artifact transitions skipped. Linux baseline completed
   386 daemon and 26 registered cases before reviewed-output digest failure; Mac
   baselines stopped during `socket.getfqdn` construction. Candidate arms reached
   real daemon cases before native unavailability. Read those exact retained
   logs and resolver reports before choosing the next bounded correction. The
   [host-workspace fixture correction](registered-host-workspace-fixture.md) now
   supplies missing real host `cwd` identically to both arms; explicit conflicting
   context stays intact. It addresses only the Linux frozen-baseline Codex benign
   1 MiB missing-context path. Require its actual rerun and preserve every other
   unresolved failure. Do not patch the frozen baseline,
   replace readiness targets, guess DNS configuration or extend deadlines.
   Continue another arm only after verified containment. Windows path/descriptor
   `ctime` domains are corrected using fresh handle metadata, with full identity,
   owner/DACL, ancestry and change checks retained; the corrected export needs
   actual CI.
4. Rerun the explicitly opted-in installed Claude experiment after its admitted
   uv-alias and Windows evidence corrections. All 20 first-run jobs failed
   before measurement: 15 POSIX builders and five Windows journal/archive tests.
   The canonical private interpreter must remain the executable selected through
   every accepted alias. Preserve exact wheel/source/dependency binding, real
   registered argv, response/exit parity, native routes, failed attempts and both
   uploads. Production registration and default feature stay off. Read the
   [actual Windows baseline ranking](installed-launcher-baseline-ranking.md):
   Claude is not uniformly the most expensive measured route; Codex PostToolUse
   is higher at c16 in that retained block. Do not claim a native benefit,
   launcher-only CPU attribution or stable cross-platform ranking from it.
5. Execute the bounded package residual collector extension on the same six
   profile invocations and ten-worker job. The first actual phase job completed
   all workers with matching semantics and one parse/batch/index per route;
   82–86% of exclusive calling-thread CPU remains unnamed. Fixed origins and an
   encrypted top-50 projection should classify that existing measured share,
   without expanding inputs, changing intervals or supplying new headline
   timings. The actual explicit-`*` pair made 100 GETs per arm through the real
   resolver/protect route and selected concrete 2.0.0. Bare literal `latest` and
   None-version highest-risk kernel semantics are distinct and unchanged.
   Preserve 12 censored baseline cardinality workers and two baseline Composer
   failures. D0e's five-pair protect improvements are optimized Python evidence,
   not a native comparison. Select or defer RSP-054 only with a justified coarse
   boundary and the original 30% criterion; parser-only benefit is unproven.
6. Retain the measured [MCP release decision](mcp-native-selection-decision.md).
   The corrected second-checkpoint v2 evidence includes 30 workers, 240 sessions,
   10,080 calls, five independent pairs and 80 complete warm windows. Its original
   finalizer stays failed even though newer MCP workflow `35233473439` succeeded.
   Keep cohort-specific lifecycle failures visible: ten incomplete records with
   16 missing samples in 24ba and 18 in d0e; nine descriptor-error rows in each.
   D0e has 80 complete warm windows with 129–326 samples and zero missing readings;
   it does not erase those lifecycle failures. The earlier sampled peak-memory
   increase remains measured evidence. Parent CPU is not whole-tree CPU, loopback is not remote
   service latency, and controlled approval delay is not human time. Tiny pure
   residuals beside store/composition/persistence and the unchanged 5.11 ms
   barrier justify RSP-104/105/107's measured deferral and RSP-108's recorded
   full-proxy decision. RSP-106 remains separate. No Rust candidate was measured;
   reopen only for the documented new residual or coarse-kernel evidence.
7. The [nonpriority-tail companion](nonpriority-installed-tails.md) is integrated,
   with no completed observations yet. Start with a manually selected one-route
   smoke and inspect registration, semantic, native and containment outcomes.
   Full 16-route/four-platform/five-pair collection is 320 jobs plus aggregators,
   requiring explicit `rust-nonpriority-tails` and `rust-performance-qualification`
   PR labels, or the corresponding deliberate dispatch. It reserves up to
   64,000 runner-minutes through job caps; that is not measured cost or duration.
   Do not start the full companion merely because ordinary smoke or scheduled
   qualification is enabled. Preserve independent ordinary, intrinsic-review,
   observation-only and unsupported registrations; do not make Windows ZCode
   or a frozen baseline delivery failure pass by editing its command.
8. Complete full indexed qualification and the independent stopped-artifact
   transition job after interpreting the retained failed attempts. Keep five
   alternating same-runner pairs, 10,000 priority/1,000 other observations,
   100 cold/recovery observations, resource minima, confidence intervals and
   every failed offer. Smoke, successful scenario collection and qualified
   performance are different outcomes. The transitions retain original indexed
   wheels, a third installation, candidate-locked dependencies, five stopped
   phases and ten registered cases. They have not executed successfully. Stopped
   replacement cannot stand in for live update, signing, frozen packaging or
   program/version downgrade. Preserve original worker, command and archive
   limits and require both encrypted and public retention.
9. Close remaining conditional ports only with their original parity, resource
   and optimized-Python benefit evidence. Finish signed/frozen artifact identity,
   first hook after update/rollback, mixed offered load/mutation/recovery, durable
   receipts and the concrete canary/rollback plan. Update all 144 ledger records
   with exact provenance. RSP-024's technical review, RSP-073's bounded ranking and
   RSP-074's launcher design do not close RSP-012, RSP-134 or RSP-142. Independent final-head
   code-owner approval remains a separate protected action; contributors cannot
   supply or impersonate it.

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
The current 77 DONE / 30 OPEN / 34 BLOCKED / 3 DEFERRED is an honest checkpoint,
not an acceptable substitute for completion. RSP-024 records the technical
contract review, RSP-073 the bounded installed ranking/inventory and RSP-074 the
package-bound launcher design; their
original dependencies remain unchanged. Earlier literal measurement, fixture,
core, component and privacy closures and RSP-108's recorded decision do not
close dependent installed benefit, exact-head validation or human final-head
approval. The three measured MCP deferrals are not implementations. Keep every
unresolved dependency explicit and finish the authorized work without weakening
its acceptance conditions.
