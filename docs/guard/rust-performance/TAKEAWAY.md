# Continue HOL Guard release/3.2

Continue the authorized implementation through the owned GitHub PR. Reduce real
tool-call overhead while preserving decisions, approvals, posture, artifact trust
and evidence. The original [PRD](PRD.md), [144-task TODO](TODO.md) and immutable
task definitions remain authoritative. Read [CURRENT_CONTRACT](CURRENT_CONTRACT.md),
[RELEASE_REVIEW](RELEASE_REVIEW.md) and the [ledger](execution-ledger.json) before editing.

Current ledger: **93 DONE / 17 OPEN / 26 BLOCKED / 8 DEFERRED**.

RSP-008 now closes its literal phase-measurement/aggregate-export criterion, and RSP-025 closes warm/first-hook executable-validation counting on all four candidate targets. RSP-012 and RSP-085 retain their previously completed record/decision and same-request attribution criteria. All original dependencies remain unchanged. RSP-011 remains OPEN for complete process-tree resources; RSP-086 and full installed qualification remain BLOCKED. None of these measurement closures selects a new Rust transport or qualifies a release.

Full qualification, activation, merge and release remain incomplete.

The [eleventh CI evidence](ELEVENTH_CI_EVIDENCE.md) records **42 terminal first-attempt workflows: 37 successful, 5 failed and 0 skipped**
at PR head `23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d`, tree `e3fa69336ff37d8e91add1ecd0a5a89b5cca35d9`. The equal-tree PR merge
`fb6112dd964df5b88e90e43e04229a4d6914f7e6` is a distinct build identity. Each report retains whether its workflow
checked out the PR head or that merge. The later implementation checkpoint
`65391c1972248a48aafddfff093f9cfa995f60ce`, tree `0f11fb9e6d44b159a6b2a6c0ea78e30693cf6cca`, preserves these measurements as historical evidence;
its later path-admission test fixture requires execution at the new publication. Shipping code and benchmark instrumentation remain unchanged from the measured source. All eleven
cohorts and prior supplemental label events remain separate. The native-client
profiler belongs to the original eleventh 42; no eleventh supplemental event is pooled
into that census. Failed, censored and unoffered work keeps its original denominator.

The live [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970) may
advance after this checkpoint. Recheck its head, base, checks and review threads;
never relabel older measurements as evidence for a later publication. The later
path-admission change is confined to a test fixture; it and subsequent evidence/docs
do not repair the failed full qualification or establish new production behavior.
Frozen baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b` (package 3.0.1)
remains immutable.

## Next work, in order

1. **Restore comparable Mac baselines.** Capture and inspect a bounded native-stack observation
   of the existing five-second libSystem probe to localize constructor `getfqdn`
   blocking. Preserve its timeout and frozen source. No underlying OS fix is
   established; do not repeat ineffective PTR maintenance or infer a cause from
   elapsed time alone. Then collect missing comparable arms for RSP-011/048/137.

2. **Choose the next optimization from measured costs.** RSP-086 requires comparing
   connection reuse or ingress alternatives with full process-tree cost.
   Finish RSP-011's full-tree resources and offered-rate accounting before
   asserting that comparison.
   Authentication and executable validation justify investigation; inclusive wall
   spans are neither CPU nor removable overhead. RSP-087 remains conditional on
   that decision: specify peer/generation binding, framing, inflight limits,
   correlation, idle timeout, cancellation and freshness before implementation.
   Keep existing Linux live-proof reuse and unsupported-platform validation intact.
   A capability-cache hit does not prove executable-digest reuse.

3. **Finish installed semantics and lifecycle.** RSP-077–080/091/136 require actual
   no-environment registered executables, alias/source forms, approvals and
   transport guarantees. RSP-129 requires mutation→publish→ACK→first-decision
   freshness; RSP-121/131 require foreground evidence cost and real receipt ingest
   under mixed load. Preserve unavailable outcomes separately from evaluated allows.
   RSP-029/135/139 still require signing/freeze binding and live update/downgrade/
   rollback, including generations and in-flight requests. Source tests or stopped
   replacement do not complete these criteria.

Keep [package](package-native-selection-decision.md), [MCP](mcp-native-selection-decision.md)
and [scanner](scanner-current-decision.md) production defaults at their measured
decisions. Native launcher, ingress, spool and compiler selection remains
conditional. Reopen a port only against optimized Python on the same complete
route; do not rewrite the administrative server to optimize hooks.

## Preserve the original gates

Ordinary priority launchers retain warm-c1 p95 ≤50 ms/p99 ≤100 ms and c16
p99 ≤200 ms with correct decisions and zero errors. Native-client p95 remains
≤20 ms, cold-native p95 ≤150 ms, readiness ≤400 ms. Require five independent
alternating pairs, 10,000 warm priority observations per required route/platform,
1,000 for other routes, 100 cold starts, 100 recoveries and at least 30 valid
resource samples, with original confidence intervals and sampling rules.

Selected hot changes require ≥30% p95 or process-tree CPU improvement with ≤5%
regression in the other primary metric. Optional ingress requires ≥25% private
memory or ≥30% c16 p99 improvement; optional kernels must beat optimized Python
by ≥30% including boundary/startup costs. Keep the separate 12% short-load and
50% long-soak RSS limits. Bounded c64 overload remains visible; missing Darwin
CPU remains unavailable. Smoke success never replaces these qualification gates.

## Evidence, validation and publication

Use [ELEVENTH_CI_EVIDENCE](ELEVENTH_CI_EVIDENCE.md) and linked workstream notes for
results, rather than copying their tables here. Preserve all prior cohorts,
first-attempt failures and offered/unoffered denominators. Artifact metadata,
verified ZIP bytes, producer receipts and authenticated recovery are distinct
custody levels. Eleventh profile public corroboration does not repeat the
[tenth authenticated RSP-085 recovery](native-client-profile-tenth-ci.md).

The revised symlink-path fixture passes all **13 selected existing endpoint tests** (102 deselected), Ruff, formatting and independent source review. The validated test bytes match this immutable implementation. Shipping source and benchmark instrumentation are unchanged from the eleventh measured source; the earlier 378-test/22-module validation remains at its original checkpoint. No local performance or soak workload ran. Gitleaks 8.24.2 scans the exact release-base-to-source range `4b89e0d2d496a85f04922b2e019a4aea15326bb9..65391c1972248a48aafddfff093f9cfa995f60ce`: **1,275 commits, 65,184,983 bytes, zero findings**. The later fixture still requires actual CI; all previous failed invocations and qualification limits remain.

RSP-134/142 require the final candidate's appropriate suites, required checks and
independent latest-push human/code-owner approval. Agent reviews do not supply
that approval. RSP-143 requires a concrete qualified canary, stop conditions and
tested rollback before final release approval.

Work only on owned files/branches after checking dirty and sparse worktrees.
Publish to `codex/release-3.2-rust-finalization` targeting `release/3.2`; PR #2954
belongs to another writer. Bind the intended committed tree to the freshly read
owned remote head, verify Git Data API blobs/tree, recheck drift and advance
without force. Never push unrelated local ancestry. Keep source pins, ledger,
PR description and handoff coherent; retain locked dependencies and Rust 1.88.
Do not change original criteria or declare all 144 tasks, merge or release complete.

Respect the active performance-measurement lock; do not run local performance
workloads or delete the lock. Keep private evidence sealed, bounded and bound to
its source and run. Verify ZIP digests and member limits before extraction; never
publish private payloads, paths or keys. The four selected diagnostic labels and
absent full-qualification labels are recorded in the release review; changes or
retries create separate cohorts.

The 42 [individually reviewed Sonar findings](../security/sonar-release-32-review.md)
remain unapplied. Eleventh ordinary analysis and quality gate skip after a failed Main
dependency. Tenth ordinary analysis succeeds and its unchanged quality gate fails;
ninth analysis and gate also skipped. Eighth
analysis/gate and seventh service HTTP 500 remain distinct historical outcomes.
The eleventh workflow provides no Sonar analysis or gate result; no new numeric conditions are inferred.
Automatic approval review rejected the project-specific external lookup because
it would disclose private project, PR and issue identifiers without explicit
authorization. The specific permission request for fresh checks and verified
individual false-positive dispositions remains pending. Do not retry that action
through CI or another route without approval. No comments, exclusions, severity
changes or quality-threshold changes are authorized by that pending request.
