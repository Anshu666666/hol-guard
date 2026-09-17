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
[CURRENT_CONTRACT](CURRENT_CONTRACT.md), [FIFTH_CI_EVIDENCE](FIFTH_CI_EVIDENCE.md)
and the next workstream's decision note. Preserve the immutable
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md) and
[third](THIRD_CI_EVIDENCE.md) and [fourth](FOURTH_CI_EVIDENCE.md) reports and the historical portion of
[EXECUTION](EXECUTION.md). Their uses of “current” refer to their recorded source.

This handoff's implementation cutoff is `d06d8093bb1744ff22fcaf65fcfd1e908c989c2d`, tree
`9b2caee188ace6c0bc97379e08708f7f4019d4e0`. Local branch: `work/rsp-performance-finalization-32`.
Owned publication: [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970),
head `codex/release-3.2-rust-finalization`, base `release/3.2`. Refresh its actual
head, base, checks and review threads before acting; the measurement checkpoint
below is not necessarily the live head.

The [fifth CI checkpoint](FIFTH_CI_EVIDENCE.md) records measured PR head
`96a69725eab018674174dabc6f205a4087d6ff4b`, tree `7da3dcf25df5dc75b61f773c40a3a4dd96bbf2fa`.
Its merge `c9a4b508ec5e9f5e6526990f9a3fad8c8b97646d` has the same tree and distinct build identity.
All 41 workflow instances are terminal: **33 successful and eight failed**.
Successful authorization-only publish workflows did not publish a release.
Later source corrections require new CI; earlier
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md),
[third](THIRD_CI_EVIDENCE.md) and [fourth](FOURTH_CI_EVIDENCE.md)
cohorts retain their original identities and failed observations.

Keep native-claude-launcher-experiment, rust-nonpriority-tail-smoke and
scanner-regex-pilot-smoke selected for the next bounded observation. Full
rust-performance-qualification, rust-nonpriority-tails and scanner-regex-pilot
are absent. Keep old label-only events separate from measured workflow cohorts.
Do not erase a failed attempt, substitute a retry for it or infer release from
an authorization-only publish job.

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

1. **Get exact-source CI through collection and ownership.** Fifth Main had
   nine successful, three failed and seven skipped jobs; none of the 96 pytest
   shards ran. The temporary scanner-helper import path now restores itself,
   and full local collection plus all 24 protected invariants pass. The missing
   benchmark-crate ownership mapping is also corrected. Require fresh tests,
   duration aggregation and the actual quality gate. All 42 reviewed
   [Sonar dispositions](../security/sonar-release-32-review.md) remain unapplied;
   use authenticated individual dispositions if available. Never weaken the
   detector, fixtures, exclusions or quality gate.
2. **Diagnose the four real candidate failures.** Every fifth indexed candidate
   failed PostToolUse response validation with an admitted runtime, no accepted
   receipt and substantial budget left. Cases: Linux omp.block.1m, ARM
   cursor.benign.max, Intel pi.benign.1k and Windows codex.benign.1k. The old
   witness reported other. The next source adds exact recognition of 34 already
   public native command-control errors; it changes no production behavior or
   acceptance. Select a narrow production correction from that observation,
   then re-run its relevant parity/authority tests and bounded installed scope.
   Do not guess a scheduler change or turn availability into native allow.
3. **Finish the dormant launcher experiment.** Fifth real offers reached nine
   successful jobs and 11 failed jobs, with all archives retained. Six POSIX
   failures match the fixed native_post_tool_unavailable response; all five
   Windows failures match discovery unavailable. These source-response hash
   matches identify the response class, not its underlying cause. Read the
   [diagnostic scope](claude-discovery-diagnostics.md). The next Windows fixture
   observes fixed directory/key/state ACL and bounded-loader status before
   offers with no repair, retry, authority claim or budget change. Actual native
   benefit, complete parity and artifact lifecycle are required before activation.
4. **Inspect corrected smoke artifact and hardware admission.** All four
   ordinary aggregators and the successful Linux tail's aggregate failed the
   verified singleton extraction layout. Exact-name downloads now preserve the
   required named root in smoke; full pattern logic and strict identity remain.
   Windows tail workers completed native calls but hardware RAM was null, which
   fails surface_tail_hardware_count_invalid. Actual RAM is now collected via
   locked psutil, with missing/invalid values still rejected. Both old Windows
   arms remain failed; retained private worker success cannot establish its
   unretained outer exit status. Both Mac baselines still fail getfqdn despite
   visible resolver registration and passing UDP self-test. No OS query reached
   the fixture. File removal does not prove OS registration retirement. Preserve
   per-attempt facts and the frozen baseline; only an evidenced environment-only
   remedy is appropriate before a comparable rerun.
5. **Complete the bounded scanner decision experiment.** Fifth smoke built the
   binary and passed four Rust plus 69 actual bridge/collector tests, then failed
   before source identity/preflight: zero offered, zero complete, all 24 planned
   attempts unoffered. Exact prior setup subcheck remains unknown. Executable
   admission now supports legitimate immutable toolchain ownership/linking;
   finite setup stages and attempt-bound retention are integrated. Re-run
   scanner-regex-pilot-smoke: working_provider_large, run zero, two cache states,
   six alternating pairs, two arms. Verify real findings, ordering, suppression,
   HMAC, fallback, exits 0/2/3 and all evidence. Only then consider explicit full
   selection: seven fixtures × five independent runs × two states × six pairs ×
   two arms = 840 attempts in 35 jobs. Keep 120/30-second CLI/native deadlines,
   containment and original benefit thresholds. Unverified eviction remains
   unavailable. A completed nonqualifying experiment supports a recorded
   release deferral; no indefinite profiling or premature activation. The
   [working-file correction](scanner-working-file-contract.md) now covers the
   identified invalid UTF-8, hardlink/contained-or-escaping symlink and
   deterministic replacement/growth/read-failure source cases. Admitted changes
   produce incomplete coverage and exit 2, preserving earlier findings. Initial
   exclusions and HMACs stay unchanged. RSP-071 remains OPEN: run its five new
   actual-native parity cases and relevant platform checks, preserve the
   documented Windows ancestor limitation and distinguish staged immutable
   objects and archive witnesses. Historical samples do not qualify new reads.
6. **Keep resource accounting truthful and qualify posture.** Actual Mac checks
   found approximately double ignored-child CPU accumulation. General Darwin
   tree CPU now stays unavailable with darwin_reaped_cpu_ambiguous; memory and
   private diagnostics remain. Never divide all counters by two, expand the
   original 2 ms lower/20 ms upper discrepancy bounds or call resource windows complete.
   Verify actual known-child checks on both Macs and find defensible general
   accounting before closing RSP-011. Ordinary requests still use one correct
   resident-ACKed posture for evaluation, command-control lease and delivery.
   Execute real installed mode changes, stricter overlays, expiry, invalidation,
   replacement and in-flight races. Source tests do not close RSP-034.
7. **Preserve measured no-selection decisions and finish actual parity.** Package
   Rust remains unselected on its fourth-cohort decision. Separate fifth pairs
   show wall 11,735.251 → 274.568 ms and CPU 5,930.041 → 245.011 ms; all ten phase
   workers completed. Retain 13 censored baselines and two baseline Composer
   failures. Guard Python origin shares are 41.9683%/53.6792%, Pydantic calls zero;
   these are not an attainable speedup bound. Current complete-v3 fixes malformed
   Bundler spec completeness and avoids unsupported bun.lockb content reads in
   manifest discovery. Preserve the actual v2-to-v3 saved-approval invalidation
   and [supported parity scope](package-format-parity-coverage.md); the prior baseline-v1/candidate-v2
   timings do not measure this change. Keep RSP-059 source-test acceptance
   separate from conditional native deferrals. Reopened coarse immutable
   model/identity/result work must beat optimized Python under the original
   30%/5% gate. MCP retains its corrected 24ba decision; later successful
   components do not erase incomplete lifecycle resources. Archive profiling is
   complete, but two measured timeouts and no native comparison remain. Retain
   the isolated Python worker, integrity reads and expansion/identity bounds.
8. **Complete installed qualification and release evidence.** Fifth Linux,
   ARM and Windows Ollama/Builder scenarios each passed 22 native cases. Intel
   failed disabled readiness at 523.888 ms against 400 ms; Builder passed.
   Four immutable builds and successful individual scenarios do not qualify
   failed pairs. Tail smoke has two timed observations per arm, far below 1,000;
   deliberate full selection has 320 collection jobs and follows admitted smoke.
   Complete priority/cold/recovery/resource minima only on comparable artifacts.
   The stopped-artifact probe is not live generation, signing/frozen or changed
   program rollback proof. Finish mixed offered load, mutation/recovery, receipt
   durability, installed approval/source/alias coverage and exact tested rollback.
   Required final CI and independent latest-push human/code-owner approval remain
   external acceptance gates. Prepare a concrete qualified candidate/cohort/
   stop/rollback result before any final approval request.

Fifth Linux native-wheel CI passed all 14 installed smoke gates and its 100,000-request/250,000-receipt soak, with zero errors, 18,484 successful health checks, one stable daemon and 3.4097% sampled RSS growth. Its soak p95 was 551.88 ms under the unchanged 4,500 ms soak ceiling; the separate registered Claude PostToolUse smoke had only two observations and p95 354.188 ms. Neither series qualifies the original installed-priority targets.

The fifth report contains historical source evidence. Source corrections in
this handoff need their own results. Continue useful authorized implementation;
preserve all original 144 criteria and update evidence/status only when their
literal scope is established.

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

The current ledger is **84 DONE / 23 OPEN / 29 BLOCKED / 8 DEFERRED**. A source, pinning, coverage
publication or accurate handoff criterion can be complete while its original
installed, signing, approval and rollout dependencies remain open. Do not count
documentation as RSP-137–143 release completion. Update the PRD addendum, all
144 ledger rows, current contract, evidence links, PR description and this prompt
together. Report exact source/artifact identities, selected/deferred work,
commands/results, failed scopes and tested/unexecuted rollback. Continue useful
authorized work; if an external gate truly blocks completion, identify the
concrete action and reason without presenting the program as finished.
