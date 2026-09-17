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
[CURRENT_CONTRACT](CURRENT_CONTRACT.md), [FIRST_CI_EVIDENCE](FIRST_CI_EVIDENCE.md)
and the relevant workstream reports. [EXECUTION](EXECUTION.md) preserves older
attempts; historical uses of “current” belong to their recorded source.

This handoff's source cutoff is `c964a61a3a4c19d721358e69c400d6059dfd1156`, tree `96143b80f7f1b41e7ceff1a98a7ad9ee81fbd6f1`, before the
handoff edits. The integration branch is `work/rsp-performance-finalization-32`.
The isolated publication is [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970),
branch `codex/release-3.2-rust-finalization`, targeting `release/3.2`.
Its last measured head is `107606388ad55f924a4e2924b4ff84e5fa08e6ff`, with
39 terminal workflows: 33 successful and six failed. Refresh the live head and
CI; never attribute those measurements to a later tree.

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

1. Publish the reviewed source and reconciled documents to PR #2970. Inspect
   the new main CI, secret scan, four-platform native-wheel and paired smoke
   results. Integrated corrections cover runtime-keyword/parser/Mac fixtures,
   authenticated expiry renewal, Windows CPU/RSS and immutable FFI definitions,
   private POSIX interpreters, failure journaling and indexed pair orchestration.
   A local correction is not a successful installed rerun.
2. Diagnose the remaining 24-request locked-storage burst. The original combined
   batch had 575 passes, seven skips and seven failures. Six PID-fixture failures
   were repaired with a focused 61-pass/two-skip rerun; the HTTP response timeout
   at 1.75 seconds remains unresolved. Retain the 1.6-second latency assertion
   and original production deadlines. Capture the blocking boundary and fix its
   cause; a passing isolated retry does not erase the original failed batch.
3. Preserve the unresolved frozen Mac baseline. Earlier diagnostics show legacy
   and reverse calls entered and timed out while numeric calls took 47–66 ms;
   no OS query reached the local PTR responder. New registration/libSystem
   diagnostics are integrated. Inspect their actual results before changing an
   OS fixture. Do not patch the frozen wheel, substitute candidate semantics,
   extend a deadline or qualify an incomplete pair. Continue the candidate only
   after verified containment of the failed baseline worker.
4. Complete the independently reviewed bounded experiments being prepared:
   same-wheel optimized-Python versus explicit native Claude registration;
   optimized package phase attribution; and stopped-artifact transition probes.
   Check whether newer commits already integrate them. Keep native Claude off
   by default until real lifecycle, binding, parity and benefit gates pass.
   Stopped-process artifact replacement is narrower than live upgrade, signing,
   frozen packaging or changed-program rollback.
5. Run MCP v2 and the corrected package matrix. MCP v2 includes five independent
   paired-run intervals, an attributed loopback service and warm resources
   sampled before teardown. Package comparisons must use optimized Python as
   the native comparator. Preserve baseline Composer failures and censored
   cardinality cells. Attribute input/hash, decode/parse/model/index, matching
   and finalization work without moving setup-only verification into the timed
   production route. Instrumented phase runs are separate from headline timing.
6. Once collection and scenario blockers are understood, execute full indexed
   qualification using the `rust-performance-qualification` PR label or the
   workflow's manual `qualification` mode. The fixed plan builds each platform
   once, then runs five same-runner B/C pairs in alternating order. Do not change
   sample counts, percentile estimators, independent-run requirements, worker
   deadlines or product thresholds to get a green job. Successful collection,
   accepted performance and program completion are separate results.
7. Use actual comparable measurements to implement or defer the remaining
   conditional Rust tranches. Finish signed/frozen artifacts, first hook after
   update/rollback, mixed mutation/recovery/receipt evidence, independent review
   and the concrete canary/rollback plan. Update every affected task with exact
   source and evidence. Request required human approval only when the final
   change and its outstanding protected action are concrete and reviewable.

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
The current 67 DONE / 36 OPEN / 41 BLOCKED / 0 DEFERRED is an honest checkpoint,
not an acceptable substitute for completion. Keep each unresolved dependency
explicit. No agent may supply or impersonate independent code-owner approval.
