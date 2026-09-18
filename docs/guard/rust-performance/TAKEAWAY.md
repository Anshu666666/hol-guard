# Continue HOL Guard release/3.2

Continue the authorized implementation through @GitHub and the existing
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970). Reduce real
tool-call overhead while preserving decisions, approvals, posture, artifact
trust and evidence. The original [PRD](PRD.md), [144-task TODO](TODO.md) and their
definitions remain authoritative. Read [CURRENT_CONTRACT](CURRENT_CONTRACT.md),
[RELEASE_REVIEW](RELEASE_REVIEW.md) and [execution-ledger.json](execution-ledger.json).

Current ledger: **94 DONE / 16 OPEN / 26 BLOCKED / 8 DEFERRED**. RSP-134 is completed for the validated selected
implementation; 008/012/025/085 retain their earlier bounded closures. Future
selected implementation requires its own validation. Full qualification,
activation, merge and release remain incomplete.

The [twelfth CI cohort](TWELFTH_CI_EVIDENCE.md) is terminal: **42 original first-attempt workflows, 37 successful and five failed**, at PR head `7eeb28f3ec3a2fdf320e52ad9f01430546226b42`, tree `e3265c7a4d23284dbae09e99b96442036726f71b`. Its distinct equal-tree PR merge is `4ca765c0c6ff06a5b6afb27545ed4ac8aec8ea79`. Main passes all 96 pytest shards; ordinary Sonar analysis succeeds and the quality gate fails. Full qualification remains false.

The later implementation checkpoint is `3eb670b0ba14928d8ed2b26cf5db97cd88cbead2`, tree `3efd465d518594c202f8ba51b571c08948707bfb`. It adds diagnostic evidence attribution, original-failure observations and future archive-key custody; it changes no production `src/` or `rust/` files. It requires its own platform execution. All twelve measured cohorts, their failed/censored/unoffered work and prior supplemental label events remain separate. Public commitments are not privately authenticated samples; no twelfth private archive was recovered in this workspace.

## Resume from the actual published state

The implementation source checkpoint is `3eb670b0ba14928d8ed2b26cf5db97cd88cbead2`, tree `3efd465d518594c202f8ba51b571c08948707bfb`.
Documentation publication is a later commit; retrieve the current PR head,
base, checks and review threads before editing. Work on the owned branch
`codex/release-3.2-rust-finalization` targeting `release/3.2`. PR #2954 belongs
to another writer. The resumed local branch was `work/rsp-resume-32`, directly
based on the published head; never push unrelated ancestry or force-update it.
Frozen comparison source `2e672d2d950c6ec471005ddba46e49bba16dc23b` remains immutable.

The next diagnostics are already implemented; do not reimplement them from
older handoffs. Read [their bounded contract](foreground-evidence-and-failure-observability.md).
They observe evidence validation/serialization, a Mac native stack, rejected
Claude after-route counters, and the original recovery stop/bridge. Collect
their new-source outcomes before assigning causes or making a new cost claim.

## Next work, in order

1. **Execute and inspect the new diagnostics.** Retain the first new-source CI attempts. Authenticate the phase-group journals with the matching saved recipient, including maximum envelopes and original rejected-work scope. The generic public overview still truncates deep phase metrics. Inspect the bounded Mac stack without inferring causation from frame presence alone. Distinguish original recovery stop/bridge evidence and rejected-launcher snapshots from later cleanup/global counts.

2. **Resolve baseline and installed failures with evidence.** Both frozen Mac indexed baselines still stop in constructor `getfqdn`; no OS correction is established. The twelfth Intel wheel fails recovery, the Windows installed Claude job rejects `{}`, and Windows indexed native route accounting fails. Linux/Intel settings exceed the original 400 ms barrier. Do not patch the frozen baseline, retry away failures or relax a deadline. A proved environment correction must be predetermined for both arms in a new cohort.

3. **Choose transport work from complete costs.** RSP-011 still needs complete process-tree resources and passing offered-rate work; all five completed twelfth offered-rate arms fail. Use 008/025/085's bounded attribution to investigate platform-specific executable proof and authenticated session reuse under RSP-086. Preserve peer/process/package/generation/expiry/replay/freshness binding. Inclusive wall spans are neither CPU nor attainable savings. RSP-087's protocol implementation stays conditional on the selection decision.

4. **Complete installed behavior and artifact lifecycle.** Finish no-environment registered launchers, aliases, source references, Watch/availability, approvals, mutation→publish→ACK→first-decision freshness, and real evidence ingest under mixed load. Verify signed/frozen artifacts, live update, mixed generations and changed-program downgrade/rollback. Source tests, component timings and stopped replacement do not satisfy those tasks.

5. **Retain measured conversion decisions.** Keep optimized Python for package/MCP and the scanner default. Twelve package baseline cardinality cells remain censored; None-version kernel results do not supply full-evaluator coverage. Reopen a Rust boundary only with complete comparable real work and the original 30% benefit/5% regression gate. Native ingress, spool and compiler remain conditional on their original measured acceptance.

6. **Complete final CI, review and release evidence.** RSP-142 remains blocked by required final-source checks and review, including the ordinary Sonar gate. RSP-143 needs qualified versions/platforms/cohorts, stop conditions and tested rollback. Full nonpriority tails require the deliberate 320-job selection. The earlier full scanner experiment already completed 840 attempts; its result does not qualify installed hooks or all platforms. No merge, activation or release completion is claimed.

## Preserve the original gates

| Scope | Unchanged acceptance |
| --- | --- |
| Ordinary installed priority hooks, 1–16 KiB, warm c1 | p95 ≤50 ms and p99 ≤100 ms |
| Ordinary installed priority hooks, c16 | p99 ≤200 ms, zero errors and correct decisions |
| Native client / cold native / daemon readiness | p95 ≤20 ms / p95 ≤150 ms / 400 ms barrier |
| Independent comparisons | At least five alternating independent pairs and required confidence intervals |
| Per required qualification scope | 10,000 warm priority, 1,000 other, 100 cold starts, 100 recoveries and at least 30 valid resource samples |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU reduction; at most 5% regression in the other primary metric |
| Optional native ingress | At least 25% private-memory or 30% c16 p99 reduction with equivalent decisions and containment |
| Optional package/offline conversion | At least 30% benefit over optimized Python on the same real route including startup/boundary costs |
| Resource growth | Existing 12% short-load and 50% long-soak RSS limits at their original scopes |


Keep KERNEL, NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER separate.
Registered process startup belongs to installed launcher timing. Exercise all
four targets, original sizes/concurrency/offered-rate conditions and terminal
outcomes. Native verdict, acknowledged posture, availability and delivered
response are different facts. Missing CPU, frames, observations or counters
remain missing. Agent review is not final human/code-owner approval.

## Validation, custody and publication

At immutable source `3eb670b0ba14928d8ed2b26cf5db97cd88cbead2`, **471 tests pass across 21 focused modules**; Ruff lint and formatting pass for all 25 changed Python files, and `git diff --check` passes. File hashes are unchanged throughout that final combined run and match the source commit. The relevant archive, wrong-key, recipient, workflow, resolver, foreground-evidence, launcher and recovery regressions are included. Independent reviews corrected reader-context work leakage, the sampler EOF/exit distinction, recovery snapshot races and actual stop-state projection. New helper paths are selected by the existing qualification workflow; Main and native-wheel workflows retain their normal PR triggers. Gitleaks 8.24.2 scans the exact new source delta (one commit, 104,113 reported bytes) with zero findings. No local performance workload ran. [Validation receipt](evidence/source-3eb670b0/validation.json).

RSP-134 is DONE only for this validated selected implementation. Its original scope includes the successful source-bound Rust/differential/adversarial/policy/mutation suites at the preceding publication and the passing checks for this scripts-only delta. Future selected code requires its own checks. Sonar, required final-source CI, human/code-owner review and full installed qualification remain separate requirements under RSP-142 and their original tasks.

Verify each artifact's exact source/run/attempt, API ZIP digest and member
bounds before recovery. The active future recipient is
`db2d2f3b5002f740768855101840eb4a02ee146d0838d92f8611256f93a7379e`.
Its separately saved offline file is `HOL_Guard_qualification_recovery_2026-09-18.pem`.
Retrieve that saved file when needed; do not print or commit its bytes. It was
round-trip verified before adoption. The former recipient's private key was
not recovered after the workspace reset; the new key cannot decrypt twelfth or
earlier archives. Previously published authenticated findings keep their
original provenance. Never call an unrecovered public summary authenticated.
The existing deep public phase overview can truncate metrics; read the
authenticated group journals before adjudicating RSP-121. The recovery key
affects diagnostic archive encryption, not runtime signing or policy authority.

Check for an active measurement lock before any local performance workload;
do not delete a lock to proceed. No local performance workload ran in this
checkpoint. Keep original attempted/failed/late/censored/unoffered counts.
Do not repeat the completed 840-attempt scanner experiment without a new
source concern. The four selected diagnostic labels remain unchanged, with
full-qualification labels absent. Every later run is a distinct cohort.

Keep source pins, ledger, PR description and handoff coherent. Publish only
reviewed intended changes atop the freshly read remote head, without force.
Preserve all original criteria/dependencies and historical reports. Do not
claim optimal performance, all 144 tasks, merge or release without their evidence.

The 42 [previously reviewed Sonar findings](../security/sonar-release-32-review.md) remain unapplied. Twelfth ordinary analysis succeeds and the quality gate fails; no fresh numeric conditions or individual dispositions were queried. Automatic approval review rejected the project-specific external lookup because it would disclose private project, PR and issue identifiers without explicit authorization. The specific request remains pending; it does not authorize a lookup through another route, comments, exclusions, severity changes or altered thresholds. Ordinary unchanged CI analysis and GitHub job-log review remain separate.
