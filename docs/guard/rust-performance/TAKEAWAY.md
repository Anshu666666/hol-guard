# Complete HOL Guard Rust performance execution on release/3.2

Continue the user's authorized takeover of [Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1)
and implementation [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954).
The exact conversation, its title and linked PRD/TODO/Takeaway documents were
reviewed in full. Finish implementation, measurement, validation, concrete review
and permitted GitHub publication. Do not restart completed work, ask for already
granted authorization, create GitHub issues or weaken acceptance to fit results.
The target is `release/3.2`. Required independent approval remains a real gate.

Read the original `PRD.md` and `TODO.md`, then `EXECUTION.md`,
`CURRENT_CONTRACT.md`, `EXECUTION_LEDGER.md`, `execution-ledger.json` and relevant
linked workstream evidence. All 144 original requirements remain intact. Their
full dependency prose is in `original_dependencies`; RSP-134 includes all selected
implementation tasks. Preserve those fields and thresholds when updating status.

## Establish the actual source and artifact

This documentation checkpoint covers `4ea1f8f76049cc8bf5b69b34078da42bb14c6ead` on
`codex/rsp-takeover-qualification-20260917`, dated 2026-09-17. Inspect actual
HEAD, branch, status and worktree ownership before editing; later work may already
be integrated. Use isolated worktrees and one owner per shared boundary.

Baseline is `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1,
Rust 1.88.0 and diagnostic CPython 3.12.14 with locked dependencies. Original
release target is `4b89e0d2d496a85f04922b2e019a4aea15326bb9`. Release already
contains squashed main lineage; preserve release-only controls/UI and carried
main authority without blindly re-merging.

The last published implementation preceding this checkpoint is
`5ee52a03e62b9e4940063b348185bedaddf0cb53`, Git tree
`7580ea94e4847762df8eb8eed6dfefc26a692551`, verified identical to local c0445a0db.
Foundation #2951 is e449594e86c717e66e14598a4130475de79c536f with normal
protected auto-merge enabled; approval remains missing. Refresh GitHub heads,
base, checks, reviews, threads and rules before publication/merge claims. Verify
uploaded Git tree equality; commit metadata alone can change a SHA.

## Preserve implemented contracts

Ordinary daemon hooks directly use HookWorker and the persistent native helper.
The legacy pool remains for compatibility/legacy revalidation; native Codex live
completion has a direct finalizer. Live Linux image reuse requires a previously
verified exact generation; replacements and unsupported systems fully validate.
Acknowledged observe mode avoids one reread; enforcing posture transfer remains
separate open work. Stat-only identity or cached publication is never authority.

Command activation requires native program-v1 and control-fence-v1 capabilities,
verified trust/catalog/program/control identity and the live SH/EX protocol.
Retain immutable inputs, generation/revision floors, complete observations and
full durable receipt bindings. The catalog has 86 extensions/291 rules/304
permissions/2,242 nodes, with CPython 3.12/UCD15 semantics and explicit owned
uncertainty. Read exact program/catalog hashes from EXECUTION.md.

Codex's actual browser waiter binds its process/start, home/workspace, immutable
request and original deadline. Fresh native review and verified receipt precede
atomic existing local Allow once consumption under the SH lease. Recheck waiter
and deadline after durable completion; native block/uncertainty remains restrictive.
Authenticated ambiguous replay cannot create a second claim. Claude resolve/retry
and the separate native v3/v4 challenge APIs are different paths. The four installed
expiry/restart/stricter-policy/ambiguous-response scenarios are implemented and
134 source tests passed; actual host runs remain required. Their expiry case
covers browser wait, not the separate 15-minute stored approval TTL. Hook fixtures
do not execute the reviewed Codex tool.

Resident PostToolUse Watch reports the intrinsic native verdict/plain reason;
Python changes delivered allow/warn behavior. Do not apply direct-hook observe
prefixes to the resident edge. Keep native evaluated allow, review/block, Watch
delivery and availability continuation separate. Windows source-reference opens
remain deliberately unsupported/fail-closed in both pinned artifacts. Exact
refusal evidence cannot pass full source identity/content or timing gates.

Preserve package verified indexes and one immutable parse/snapshot, Git object
batching and rich finding occurrence/HMAC/completeness, SQL atomicity and journal
replay. Queue accepted, journal durable, SQL committed and checkpointed are distinct.
MCP keeps exact input/catalog/authority revalidation, terminal bounded I/O and the
5 ms final quiet barrier; human/network waits cannot become a kernel speedup.

## Finish the active work and diagnose the next host run

Read current owner commits and checkpoints before redoing any item:

1. Complete package controls and the bounded benchmark-only npm lockfile native
   pilot against optimized Python. The 36-cell matrix has 31 complete comparable
   pairs and five incomplete pairs; preserve four baseline 120-second timeouts,
   the other baseline harness error and candidate cell-30 error. Compare the
   entire public result and all persisted evidence columns. Keep policy, trust,
   freshness and evidence authority in Python; include IPC/startup in route cost.
2. Complete rich scanner full-CLI comparison with the ASCII ≤4 MiB native span
   extractor. Python retains the full finding/HMAC/context/coverage contract;
   non-ASCII/large inputs fall back explicitly. Keep small-control regressions,
   eviction failures and the interrupted relocation sample. Post-relocation
   executable-backed cohorts must remain separately identified. No activation
   follows a microbenchmark or unqualified/confounded result.
3. Complete MCP optimized actual-stdio five-block rebaseline and profiles.
   RSP-100 remains open because categories are still derived twice for one
   ordinary request. Any reuse must consume one owned immutable exact-input
   snapshot, preserve ordering, validate binding and recompute after mutation or
   fresh authority/catalog preparation. Never cache a policy verdict across wait.
4. Run the integrated paired driver, Watch fix, both-arm failure accounting,
   flat Codex fault proofs and full failure diagnostics on actual GitHub hosts.
   Linux launcher and Intel source-witness failures need their actual sanitized
   reason/action/route/sample evidence; do not guess or suppress failures.
5. Diagnose macOS HTTPServer `socket.getfqdn` startup. The previous exact PTR
   resolver experiment installed/cleaned successfully but received zero packets;
   all before/after/cleanup lookups timed out. Read-only resolver-selection and
   self-probe diagnostics are added. Do not patch the baseline, switch production
   transport, flush/restart services speculatively or raise the 400 ms budget.
6. Run the integrated installed artifact replacement/rollback probes with exact baseline
   API/schema handling. The baseline lacks the candidate receipt getter and
   native command programs; candidate errors must never use a legacy fallback.
   A third isolated environment may test stopped same-version artifact replacement
   without altering paired benchmark installations. Version/program downgrade,
   live mixed generations, in-progress requests, signing and enrollment require
   their own actual evidence and cannot be inferred from that narrower probe.
7. Verify the scheduler correction on GitHub: dispatch now broadcasts only after
   actual admission/expiry progress and still wakes released byte reservations.
   The deterministic regression failed before the fix; the exact 48-review test
   passes with unchanged 10-second queue/6-second runner budgets. Preserve the
   original failed run; its sole cause is not proven by the available counters.

The archive investigation is complete for its declared profiling scope: 508/510
expected results, two restrictive timeouts and an earlier warmup timeout retained,
60 profiles and hostile binding/isolation witnesses. Retain the current isolated
worker; this is neither a successful full SLO run nor proof that an entire native
worker could never help. Conditional ports follow the original PRD decision rule.
A native pilot is not mandatory for every optional port, but measured coverage and
predicted benefit must support a deferral; large unmeasured cases remain open.

At 5ee, all 36 workflows completed: 32 successful, four failed. Paired run
35213401779 failed all targets before complete paired sampling. Linux/macOS ARM
Ollama overall probes pass with 22 native cases each; Windows late readiness is
406.0 ms and Intel enabled readiness 430.438 ms. Builder passes all four. Native
wheel Linux/Intel witnesses fail; Desktop/CI also report stale command-source
bindings and one scheduler deadline. Source fixes are integrated, not yet passing
host evidence. Earlier 42579 failures and subsequent artifacts remain retained.

Local AF_UNIX creation is denied, so do source tests/builds locally and real
installed daemon/launcher execution on supported GitHub hosts. Protect benchmark
provenance: serialize competing CPU/I/O work through the measurement lock; do not
move executables or caches under an active run. Retain all interrupted attempts.

## Qualify the frozen candidate without weakening the PRD

Build separately installed locked baseline/candidate artifacts on Linux x64,
macOS x64, macOS ARM and Windows x64; clear development overrides and prove exact
source/package/runtime/rule/program/manifest identities, including signing/freeze
where applicable. Run the committed CLI/workflow arguments rather than guessing
obsolete helper names. Smoke remains smoke. Apply `rust-performance-qualification`
only after the candidate is stable; any code/dependency change requires renewed
qualification on its resulting head.

- Installed warm c1 p95 ≤50 ms/p99 ≤100 ms; c16 p99 ≤200 ms with zero errors.
- Native client p95 ≤20 ms; cold native p95 ≤150 ms; readiness ≤400 ms.
- At least five alternating independent runs; 10,000 priority warm decisions,
  1,000 other-route decisions, 100 priority cold starts, 100 recoveries and
  30 resource observations in the PRD's specified scopes, with intervals.
- Selected hot tranche ≥30% p95 or CPU benefit and ≤5% regression in the other
  primary metric. Optional ingress ≥25% private memory or ≥30% c16 p99 benefit.
  Preserve existing RSS-growth safeguards.

Retain offered/admitted/completed/failed/rejected/timed-out/late outcomes and
original terminal outcomes. Scheduled-offer latency includes generator and queue
wait. Keep routes/platforms independent; no pooling slow cells, baseline edits,
unavailable-to-allow substitution or discarded failures. Require actual harness
JSON/exit, native route/verdict/reason and durable binding-aware receipts. Report
unsupported metrics explicitly; journal fsync evidence is not SQLite VFS fsync.

Complete actual no-env launchers, aliases, source refs, Watch, malformed input,
availability and approval, host activation, whole daemon restart, mixed soak,
saturation/process resources and required signing/update/downgrade transitions.
Existing 1000 ms diagnostic checks and historical warm/cold gate logic do not
replace the product thresholds. A qualified subset is not program completion.

## Complete review, documentation and release

Run meaningful formatting/lint/type, Rust crate, Python, differential, adversarial,
source mutation, control/floor/approval/receipt recovery, MCP and workflow-selection
checks appropriate to every selected change on the actual final combined source.
Inspect exported metrics, errors and receipts for secrets, raw command/output and
private paths, retaining only necessary bounded proof. Preserve all intentional
behavior corrections separately from performance claims.

Update all 144 task records and regenerate the Markdown ledger with exact evidence,
counts, unresolved dependencies and original-field integrity. Keep EXECUTION,
CURRENT_CONTRACT and this prompt aligned with the selected source and dated actual
GitHub state. At this checkpoint the count is 64 DONE/40 OPEN/40 BLOCKED; those
numbers do not claim release completion. RSP-144 stays open until final evidence,
conditional decisions and release state are delivered.

Obtain final Greptile 5/5 and required independent CODEOWNER approval through the
actual review process, resolve threads and required CI on the published head.
Foundation's protected auto-merge does not waive implementation approval. Never
fabricate approval, self-approve as the author or bypass the release ruleset.

Prepare exact qualified candidate/prior artifact manifests, platform/harness
canary cohorts, stop conditions and tested rollback. Restore verified package,
registration and acknowledged policy only after retiring the affected generation.
Never lower persistent floors or reopen hidden Python fallback; never retry
ambiguous tool execution automatically. Finish all concrete authorized work before
reporting an external blocker. Final delivery must link PRs, exact qualified head,
artifacts, coverage, metrics/intervals/misses, tests and rollback evidence, with
implementation, qualification, merge and release status stated separately.
