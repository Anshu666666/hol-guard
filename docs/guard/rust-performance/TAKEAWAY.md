# Takeaway prompt: finish HOL Guard release/3.2 performance work

Continue the user's authorized implementation through GitHub. Reduce actual
tool-call latency and CPU while preserving decision, posture, approval, artifact
and evidence contracts. Complete the original [PRD](PRD.md), its
[release addendum](RELEASE_3_2_PRD.md) and all remaining [144 TODO criteria](TODO.md).
Use [execution-ledger.json](execution-ledger.json) as the status/evidence index.
Original IDs, titles, acceptance and dependencies are immutable. An unbuilt port
is not implementation; a measured deferral is a decision; smoke is not qualification.
Continue useful authorized work without repeated confirmation. Do not create
GitHub issues, send comments or overwrite another writer's work.

## Recover the exact state

Read repository instructions, [RELEASE_REVIEW](RELEASE_REVIEW.md),
[CURRENT_CONTRACT](CURRENT_CONTRACT.md), [SIXTH_CI_EVIDENCE](SIXTH_CI_EVIDENCE.md)
and the next workstream's decision note. Historical uses of current refer to
their recorded source. Preserve all six historical cohorts and the historical
portion of [EXECUTION](EXECUTION.md).

Implementation cutoff `ab06f959bf58fae9006137a4aa21398110dc2409`, tree `34f22d781012a71723b5d377f6817ba86b5bf1f1`.
Local integration branch `work/rsp-performance-finalization-32`.
Owned [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970):
head `codex/release-3.2-rust-finalization`, base `release/3.2`, draft at this
checkpoint. Refresh actual head, base, checks and review threads before acting.
The measured checkpoint below is not necessarily the live branch head.

The [sixth CI checkpoint](SIXTH_CI_EVIDENCE.md) binds measured PR head
`9d3907a2e6ed1ec201281901cb878836a7dad32d`, tree `833ea191211db2a0613db8520d072f5edf485380`. Its tested merge
`64164db9cd11e3d05182a99dba100daa6011c83d` has the same tree and a distinct build identity.
All 41 first-attempt workflow instances are terminal: **35 successful and six failed**.
Main passed all 96 pytest shards; its remaining failure is the Sonar quality gate.
Publish to PyPI built and verified distributions and retained hashes/SBOMs, but
publication, release and container jobs skipped. No release was published.
The later implementation checkpoint below requires its own CI. Preserve the
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md),
[third](THIRD_CI_EVIDENCE.md), [fourth](FOURTH_CI_EVIDENCE.md) and
[fifth](FIFTH_CI_EVIDENCE.md) cohorts as separate historical evidence.

Frozen baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1.
Last verified main `05fa4760df8401b9710bf098adb4fbb2dc4ff389` and release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9`. Use Rust 1.88 and locked dependencies.
Check dirty files and active worktree ownership. PR #2954 is another writer's
branch; reuse only selectively reviewed changes. Do not repeat integrated
cherry-picks or publish the entire local historical ancestry inadvertently.

For Git Data API publication, bind the exact intended committed tree to the
actual owned remote head, verify every blob and returned tree SHA, recheck the
branch and advance without force. Pin docs to an immutable code checkpoint;
keep final code, evidence, ledger, PR description and prompt coherent.

Keep native-claude-launcher-experiment, rust-nonpriority-tail-smoke and
scanner-regex-pilot-smoke selected for bounded observation. Full
rust-performance-qualification, rust-nonpriority-tails and scanner-regex-pilot
are absent. Do not infer full collection from these smoke labels. Preserve
failed first attempts when rerunning; retries never replace their evidence.

## Execute in dependency order

1. **Execute the corrected source.** Sixth Main passes all 96 pytest shards,
   quality, aggregate CI and duration aggregation. Security and both ownership
   workflows pass. Later changes need exact-source checks, including the new
   real Windows producer tests and corrected reader IDs. Observe the actual
   Sonar gate under the permission boundary below; no historical values or
   source-only tests supply green final CI.
2. **Resolve native authority and load failures.** The periodic shared-refresh
   fix preserves real exclusive mutation while avoiding unchanged exclusive
   reads. Re-execute Intel Cline Post failures whose original typed mutation
   errors occurred with ample budget and no receipt. The historical lock holder
   was not captured. Separately inspect Linux c64: 64 responses, 32 native,
   15 fail-safe, 17 overload and 15 raw None; old reasons were truncated. The
   final witness projection now retains bounded reasons. Linux indexed c16
   Codex Post batch 36 completed; a later load-profile route check failed with
   no retained wave/deltas. Do not conflate these observations or count
   availability as native allow.
3. **Finish Windows and the dormant launcher.** Sixth all five Windows native
   preflights fail, with no timed offers. Independent observation passes Guard
   directory security, reads, state authentication and peer identity but rejects
   key/state security. Source separately shows a missing producer DACL.
   Fresh private creation is integrated; existing keys are neither repaired nor
   rotated. Run actual Windows tests and installed retry before calling the
   cohort repaired. All five Linux jobs complete, but complete native p95
   series remain above 50 ms. Two ARM measurements fail. Production activation
   remains off until parity, benefit, complete resources and lifecycle pass.
4. **Finish comparable baseline and tail setup.** Sixth Linux/Windows
   nonpriority workers and aggregates pass, with two preflight and two timed
   calls per arm. Both Windows arms report 17,174,360,064 RAM bytes. Both Mac
   candidate arms complete; authenticated private evidence puts baseline
   failure at getfqdn/HTTPServer construction before registration or offers.
   Twelve of sixteen timed observations are accepted; four remain unattempted.
   Resolver registration/self-test passes, but actual OS probes send no query
   and time out. File cleanup and OS registration retirement differ. No
   defensible environment-only repair is established. Preserve frozen bytes,
   semantic workload and product deadlines; retain absent comparison honestly.
5. **Complete the scanner experiment.** Sixth passes four Rust and 95 Python
   tests, including five actual-native input cases, then fails at
   python_executable_identity_failed. All 24 planned attempts are unoffered.
   The new 17-code diagnostic is from the original read and adds no retry,
   reread, toolchain copy or relaxed admission. Inspect the fresh bounded smoke
   before choosing a correction. Verify findings, ordering, suppression, HMAC,
   fallback, cache state, exits 0/2/3 and retained failures. Only comparable
   smoke permits deliberate 840-attempt selection across seven fixtures, five
   runs, two cache states, six pairs and two arms in 35 jobs. Retain 120-second
   CLI and 30-second native deadlines. A complete nonqualifying experiment can
   support deferral; zero offers cannot decide conversion. RSP-071 has Linux
   and both Mac 42-case reader passes; Windows remains pending its corrected
   fixture, with 25 explicit POSIX skips and the documented ancestor limitation.
6. **Qualify resources, posture and semantic edges.** Sixth Mac known-child
   tests pass once/twice witnesses; general Darwin CPU remains unavailable.
   Do not divide counters by two, loosen 2 ms lower/20 ms upper witness bounds
   or turn missing readings into zero. ARM completes 136 numeric observations
   but retains Codex continuation/input, registered-route and mixed receipt/
   resource failures. Diagnose each from its exact retained evidence.
   RSP-034 still requires installed mode changes, stricter overlays, expiry,
   invalidation, replacement and in-flight races under one resident-ACKed binding.
7. **Preserve measured no-selection decisions.** Package retains its fourth
   decision. The separate sixth complete-v3/complete-v1 cohort has five pairs:
   wall median 8,765.804810 → 320.749072 ms and CPU 7,750.150 → 312.036 ms;
   median paired reductions 96.3404978500%/95.9716882649%. All ten phase workers
   complete; Guard Python shares 42.3513%/54.2777% and Pydantic zero are
   instrumented attribution, not attainable Rust speedup. Keep twelve censored
   baselines and two Composer failures. Frozen slash-qualified transitive
   rejection has no same-work fixture correction. RSP-059 closes only its
   named source criterion; saved v2 approvals cannot authorize v3 parsing.
   Reopening coarse native model/identity/result work requires the original
   optimized-Python comparison. MCP keeps its 24ba decision and incomplete
   lifecycle resources. Archive keeps its isolated Python worker and all
   integrity reads; 510 calls include two fail-closed timeouts and no native comparison.
8. **Finish qualification and release.** Four immutable builds do not qualify
   four failed indexed pairs. ARM/Windows scenarios pass; Linux/Intel readiness
   failures remain under 400 ms acceptance. Full tails need deliberate 320-job
   selection and admitted comparable arms. Complete all original warm/cold/
   recovery/resource minima, installed approval/source/alias coverage, mixed
   offered-load/mutation/recovery and durable receipts. Sixth stopped transitions
   skip; no live update, signing/frozen or changed-program rollback is proven.
   Require final-head CI and independent latest-push human/code-owner approval.
   Prepare a concrete qualified canary, stop conditions and tested rollback
   before requesting any final external release approval.

The 42 [individually reviewed Sonar findings](../security/sonar-release-32-review.md)
remain unapplied. The sixth Sonar analysis succeeded, but the actual quality
gate failed; fresh numeric conditions and exact remote issue identities have
not been retrieved. Do not reuse historical gate values as current. Automatic
approval review rejected the project-specific Sonar lookup because it would
send private project, PR and issue identifiers to an external service without
explicit authorization. The specific user permission request for fresh checks
and verified individual false-positive dispositions remains pending at this
checkpoint. Do not retry that action through CI or another route without that
approval. No exclusions, quality thresholds, severity changes or comments are
part of the proposed disposition.

If specific Sonar authorization later arrives, recheck the exact 42-item
manifest, current analyzed revision, rule/component/line and complete source
hashes before any write. Use only allowed individual false-positive transitions,
with no comments, exclusions, gate edits or arbitrary findings. The API provides
no atomic expected-analysis precondition: serialize the operation, check drift
before/after and stop on ambiguous outcomes or permission failure. Do not retry
ambiguous writes. Existing analysis-token success does not prove issue-admin
permission. The unchanged quality-gate check must still run and determine its
own result; disposition errors keep the job failed.

## Integrated source and validation

| Correction after sixth CI | Resulting behavior | Evidence still required |
| --- | --- | --- |
| Periodic command-control refresh | An unchanged authenticated read retains a shared lease. Only the existing mutation-required sentinel triggers a fresh exclusive read after releasing the shared lease. | Re-execute the installed Intel failures; their exact historical lock holder was not observed. Real mutation remains exclusive. |
| Windows discovery producers | Newly created key/state files use a private DACL and retained ancestor handles; fresh setup creates missing directories privately. Existing keys are not repaired, rotated or newly attested. | Actual Windows producer and dormant-launcher execution; legacy files may remain unsupported by the pilot. |
| Windows reader-test identifiers | Finite pytest IDs preserve the complete 65,543-byte fixture without overflowing Windows environment-variable limits. | Actual Windows rerun of the reader and route cases. |
| Capacity evidence export | The final report retains bounded closed-form None witnesses instead of losing them to nested privacy truncation. | A fresh failing or passing observation; the old 15 reasons cannot be recovered. |
| Scanner executable admission evidence | The original failing read retains one of 17 public reason codes and bounded private numeric metadata. | Fresh smoke to identify the cause; admission rules, reads, retries and deadlines are unchanged. |

The integrated 19-module correctness suite passed 617 tests with seven explicit Windows-only skips. The final exception-import follow-up passed 63 tests with four Windows-only skips, and the complete I/O ownership module passed all 30 tests, including current-source graph validation and a content-read rejection regression. These suites overlap and are not added together. Final full collection finds 22,518 cases and all 24 protected invariants. All 24 changed Python files pass Ruff check/format; all 15 changed source/protocol modules have zero type errors at the CI error level. Same-release-base authority, full I/O ownership and privacy gates pass. The exact immutable-source-range Gitleaks scan passes with zero findings. All 394 frozen evaluator source commitments remain unchanged, so the earlier 51,000-case differential evidence needs no regeneration. Independent source and evidence reviews cleared the changes. No local performance workload was run; actual Windows execution, later published-source CI, installed qualification and human approval remain separate.

These are source correctness results. They do not qualify later published bytes,
Windows execution, installed benefit or a complete release. Inspect the live
head and its actual artifacts before changing a ledger status.

## Preserve authority and evidence

Ordinary HTTP hooks enter HookWorker and the persistent native helper; verified
compatibility and legacy revalidation have separate Python paths. Reuse the
existing Rust decision core, trusted command compiler and bounded scanner.
Unsupported semantics retain owned uncertainty. Native verdict, acknowledged
posture, availability and delivered response are separate facts; Watch is not
native-evaluated allow. Preserve harness JSON/exit contracts without a Python
semantic fallback or new blanket denial.

Keep authenticated peer and live process/image identity, exact content,
policy/program/catalog binding, generation, expiry and replay protection.
Mutations close the fence before durable effects; finalization rechecks current
authority. Metadata invalidates caches but cannot authorize content. Windows
API-definition reuse never caches an owner, ACL or live authorization decision.
Approval belongs to the original waiter and deadline. Native Codex completion
re-evaluates current authority and verifies signed consume/replay binding.
Never replay an ambiguously delivered MCP write; preserve framing, queue limits,
catalog invalidation and the final 5 ms freshness barrier.

Memory admission, journal durability, SQLite commit and checkpoint are distinct
milestones. Replayed evidence deduplicates the attempt without reauthorizing it.
Missing SQLite VFS/fsync/physical-byte measurements stay missing.

## Performance and delivery contract

| Required scope | Unchanged acceptance |
| --- | --- |
| Ordinary 1–16 KiB priority installed hooks, warm c1 | p95 ≤50 ms and p99 ≤100 ms |
| Ordinary 1–16 KiB priority installed hooks, c16 | p99 ≤200 ms, zero errors and correct decisions |
| Native client / cold native / readiness | p95 ≤20 ms / p95 ≤150 ms / 400 ms barrier |
| Independent sampling | At least five alternating independent pairs with required confidence intervals; 10,000 warm priority, 1,000 other, 100 cold/recovery observations and at least 30 valid resource samples per required scope |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU reduction; at most 5% regression in the other primary metric |
| Optional ingress | At least 25% private-memory or 30% c16 p99 reduction, preserving containment and decisions |
| Native package/offline work | At least 30% benefit against the optimized Python real route, including boundary/startup costs and original parity safeguards |
| Resource growth | Existing 12% short-load and 50% long-soak RSS limits at their actual sampling scopes |

Use installed wheels outside source checkouts on Linux x64, Mac Intel, Mac ARM
and Windows x64, with no development-origin override. Bind exact source,
artifact/runtime/program, workload, interpreter, dependencies and host cohort.
Post-sign/frozen bytes need their own identities. Report required percentile
estimators and confidence intervals; pooled calls are not independent runs.
Exercise 1 KiB, 16 KiB, 256 KiB, 1 MiB and maximum payloads at c1/c4/c16/c64 plus
offered-rate load. Retain every offer, admission, completion, timeout, rejection,
failure and late result; queue and generator delay remain in terminal latency.
Separate generator resources from daemon/helper tree CPU and memory. Missing
readings never become zero or a successful resource window.

Retain bounded reconstructed public aggregates and authenticated encrypted
private evidence, including interrupted numeric journals and exact bytes read
during aggregation. Verify authorized recovery without logging payloads or keys.
Keep 256 flat files, 32 MiB/file, 128 MiB total and actual Windows private ACL/
containment requirements. Expanded custom plans need a fresh capacity check.
Respect the shared measurement lock; do not run local performance workloads or
concurrent collectors that contaminate measurements.

The current ledger is **84 DONE / 23 OPEN / 29 BLOCKED / 8 DEFERRED**. Source, pinning, coverage publication and
accurate handoff may be complete while dependent installed, signing, approval
and rollout criteria remain open. Update the PRD addendum, all 144 ledger rows,
contract, evidence links, PR description and prompt together. Report exact
source/artifact identities, selected/deferred work, commands/results, failed
scopes and tested versus unexecuted rollback. Do not present documentation as
RSP-137–143 completion or end useful implementation at a status refresh.
