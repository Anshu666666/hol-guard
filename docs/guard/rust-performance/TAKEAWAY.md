# Continue HOL Guard Rust performance work on release/3.2

Continue the user's authorized implementation end to end using GitHub. Deliver
the original [PRD](PRD.md) and all 144 [TODO](TODO.md) requirements; do not replace
their acceptance conditions with source tests or a narrower smoke gate. This is
an implementation continuation, not a new proposal. Complete authorized work
without repeatedly requesting permission, while respecting protected merges and
independent code-owner approval. Do not create GitHub issues.

## Establish the exact starting point

Read applicable repository instructions, the PRD/TODO, [release review](RELEASE_REVIEW.md),
[execution ledger](execution-ledger.json), [current contract](CURRENT_CONTRACT.md)
and workstream evidence before editing. The release review is the latest dated
checkpoint; [EXECUTION](EXECUTION.md) preserves earlier attempts and provenance.
Check HEAD, dirty files and agent ownership. Do not overwrite another worker's
changes or cherry-pick already integrated commits.

This handoff was reviewed on 2026-09-17 at local integration
`ce8fce7f504bd67c213d67a60fbca34da724d25e`, tree
`f1b272cbe8ba4762083ef05ddd5d22ece9d95f82`. Scheduler, Watch, capability,
Composer, dormant Claude pilot and package/pilot workflows are integrated.
Later deliveries may exist. The production comparison
baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1;
use Rust 1.88.0 and locked dependencies. Preserve release-only behavior and the
reconciled main lineage; a fresh merge of squashed history is not a safe shortcut.

Refresh GitHub heads, checks, review threads and approval before publication.
PR #2954 has another writer and is reported at `ae339`; coordinate or use the coordinator's isolated branch,
and verify the exact uploaded Git tree before advancing a remote. The latest
reviewed remote `5ee52a03e62b9e4940063b348185bedaddf0cb53` has **32 successful and
four failed workflows**, not a qualified release. Foundation PR #2951 still
requires independent approval at its recorded checkpoint; refresh that status.
No agent may supply or impersonate the required human approval.

## Preserve the implemented contracts

Ordinary HTTP hooks enter the daemon HookWorker and persistent native helper.
Compatibility and legacy revalidation retain their Python pool. Native command
execution has a trusted compiler, 29 reviewed operations, 86 extensions, 291
rules, 304 permissions and 2,242 nodes, pinned to CPython 3.12/UCD 15 semantics.
Unsupported/context-heavy behavior is owned uncertainty, never silent no-match.
Component coverage is not full Python equivalence or installed activation proof.

Keep authentication, live process/image identity, exact source content, expiry,
policy/program/catalog identity and replay protection. Control mutations close
the authenticated fence before durable effects. Shared request leases exclude
mutation through finalization; recovery binds the exact previous floor, key and
epoch. Signed managed source context prevents catalog replacement or deletion
from restoring an old enabled control. Stat metadata only invalidates authority
caches; it cannot create authority.

Ordinary resolved approvals and native Codex browser completion bind exact
request, current policy/runtime/command observations and live waiter context.
Codex performs fresh native revalidation and verifies signed consumed authority;
unsigned terminal state cannot authorize replay. Its six-field identity and
original deadline remain exact. The exported native v3/v4 challenge/claim/consume
APIs are separate; do not describe ordinary approval reuse as their consumption.

Preserve evaluated verdict, posture transformation, availability result and
delivered harness response as four distinct facts. Watch delivery is not a
native allow. Ordinary unavailable PreToolUse continuation with warning and
PostToolUse empty output must retain their established harness contracts.
Do not add a Python semantic fallback or blanket unavailable-deny behavior.

Receipt migration 28 retains command binding. Memory admission, durable journal,
SQLite commit and checkpoint are distinct milestones; replay deduplicates stable
attempts without reevaluating decisions. Retain MCP frame/queue bounds, terminal
uncertain writes, catalog invalidation during approval and the final 5 ms quiet
barrier. Never replay an ambiguously delivered tool write.

## Resolve current failures before broadening scope

1. Resolve the decision-report fresh-process test failure and run final CI.
   Five tests pass, including exact reproducibility/source binding; one metrics
   test exceeded its unchanged 60-second deadline in both the batch and isolated
   rerun. Cause is unproven. Only three runtime source hashes changed; all
   nonbinding report fields remain identical. Regenerate if bound source changes;
   do not bypass checks or relabel the failed batch as green.
2. Rerun the exact scheduler failure. The integrated fix stops unchanged queued
   waiters from notifying one another and preserves byte-waiter notifications.
   Partial-header ownership, exact-entry eviction, bounded permit handoff and
   Windows source-handle corrections are integrated. Focused regressions do not
   prove the installed load or platform matrix passes.
3. Rerun installed Watch and capability-dependent source contracts after their
   integrated corrections. Composer now preserves ASCII vendor-qualified
   identities, including emergency denies. The frozen baseline's source refusal
   remains a refusal; the candidate handle-bound path requires its own complete
   review and identity witness. Never count unsupported reads as successful scan
   timing. Preserve Linux resident-authority and macOS Intel source-witness
   failures until the exact repaired artifacts pass.
4. Keep the macOS baseline DNS stall unresolved. Both latest artifacts prove
   the PTR experiment installed and cleaned up but received zero packets; all
   legacy probes timed out. This does not identify the OS resolver defect.
   Publish the composed call-start/reverse/numeric diagnostics without patching
   the baseline, changing DNS locally or extending deadlines. The completed audit
   confirms the existing numeric TCPServer bind fix is integrated; actual macOS
   efficacy still needs CI. Candidate continuation after a contained baseline
   failure is also implemented. Retain the failed comparison.
5. Execute the integrated four-platform dormant Claude correctness workflow and
   package workflow. All four launcher peer findings are closed; the feature
   remains off with no registration change. Prove installed behavior and benefit
   before activation. Finish assigned benchmark corrections for common workload
   identity versus Windows arm coverage, per-observation private journaling and
   explicit Windows job CPU accounting. Inspect ownership before editing.

## Qualify the real boundary and retain every attempt

Use separately installed release artifacts outside source checkouts on Linux
x64, macOS x64, macOS arm64 and Windows x64. Remove development overrides.
Record source, package, target, manifest, runtime, rule/program/catalog, corpus,
compiler/dependency and host identities, including post-sign/frozen bytes.
Compare baseline and candidate on the same declared hardware in alternating
order. Unknown build identity cannot qualify a release.

The frozen requirements remain:

| Scope | Requirement |
| --- | --- |
| Ordinary noninteractive 1–16 KiB installed hooks, warm c1 | p95 ≤50 ms; p99 ≤100 ms |
| Same installed hooks, c16 | p99 ≤200 ms; zero request errors; correct decisions |
| Native client warm c1 / cold native / resident readiness | p95 ≤20 ms / p95 ≤150 ms / ≤400 ms |
| Priority route/platform samples | 10,000 warm decisions across ≥5 independent runs; 100 cold starts per priority launcher; 100 recoveries; 30 steady-state resource samples |
| Remaining installed routes | At least 1,000 warm samples per route/platform |
| Selected hot tranche | ≥30% lower p95 or process-tree CPU/request; ≤5% regression in the other primary metric |
| Optional ingress | ≥25% lower process-tree private memory or ≥30% lower c16 p99, preserving containment and decisions |
| Resource safeguards | Existing 12% short-load RSS-growth and 50% long-soak growth gates, with their actual sampling scopes |

Report confidence intervals and the percentile estimator. Separate KERNEL,
NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER observations; HTTP requests
cannot substitute for real registered argv/stdin/stdout/exit execution. Keep
cold executable start, full daemon startup, readiness and recovery separate.
Human/network wait and instrumentation need explicit attribution, never silent
subtraction. Old relative-speedup alternatives and 1,000 ms diagnostic gates do
not replace these targets.

Exercise 1 KiB, 16 KiB, 256 KiB, 1 MiB and maximum inputs at c1/c4/c16/c64,
including closed-loop and offered-rate load. Keep every offered, admitted,
completed, failed, rejected, timed-out and late attempt. Offered-to-terminal
latency includes generator/queue delay; late completion cannot overwrite timeout.
c64 permits bounded overload, not hangs, leaks, cross-request replies or hidden
errors. Collect daemon/helper/resident resources separately from the driver.

Join registered surfaces, controlled approvals, malformed inputs, Watch,
unavailable/integrity/expiry cases, mixed mutation-to-ACK-to-first-enforcing
receipt, ingestion, inventory and restart/recovery evidence. Resident restart
does not prove whole-daemon restart. Missing SQLite VFS/fsync/physical-byte
metrics remain unavailable, not zero. Keep diagnostic phase runs separate from
headline timing. Upload only bounded public aggregates and encrypted private
evidence; verify authorized recovery and actual Windows ACL/ABI behavior.

## Select remaining Rust work from comparable evidence

Use the optimized Python package matrix, rich scanner/CLI baseline, archive and
isolated MCP reports linked from the release review. Compare 100/1,000/10,000
dependencies with independently varied bundle sizes. Preserve 8 MiB inputs,
100,000 entries, 250,000 nodes, depth 128 and bounded parser deadlines. Include
serialization/startup amortization and actual full command behavior in any
native comparison. Composer's frozen baseline omission is a coverage failure,
not a fast equivalent result.

RSP-052, RSP-062 and RSP-128 source criteria do not close their dependent installed
gates. RSP-070 remains open: the archive diagnostic retained two unexpected
timeouts among 510 inspections. Unbuilt package, rich-detector, MCP, inventory,
spool/compiler or ingress ports need a measured go/no-go; neither DONE nor
DEFERRED follows from language preference. Preserve regressions, incomplete
coverage and false-review differences. Finish exact-head CI/review, signed and
frozen installation/update/rollback, canary scope and rollback evidence before
claiming release completion. Keep the machine ledger current without rewriting
the original PRD or TODO criteria.
