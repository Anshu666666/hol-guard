# Complete HOL Guard Rust performance execution on release/3.2

Continue the user's authorized takeover of [Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1)
and implementation [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954).
The exact conversation, its title and linked PRD/TODO/Takeaway documents were
reviewed in full. Finish implementation, measurement, validation, concrete review
and permitted GitHub publication. Do not restart completed work, ask for already
granted authorization, create GitHub issues or weaken acceptance to fit results.
The user explicitly requests no questions and continuation until the work is complete.
The target is `release/3.2`. Required independent approval remains a real gate.

Read the original `PRD.md` and `TODO.md`, then `EXECUTION.md`,
`CURRENT_CONTRACT.md`, `EXECUTION_LEDGER.md`, `execution-ledger.json` and relevant
linked workstream evidence. All 144 original requirements remain intact. Their
full dependency prose is in `original_dependencies`; RSP-134 includes all selected
implementation tasks. Preserve those fields and thresholds when updating status.

## Establish the actual source and artifact

This documentation checkpoint covers `7befd329a00f9689b6d648750e64f58082e8986d` on
`codex/rsp-takeover-pilots-20260917`, dated 2026-09-17. Inspect actual
HEAD, branch, status and worktree ownership before editing; later work may already
be integrated. Use isolated worktrees and one owner per shared boundary.

Baseline is `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1,
Rust 1.88.0 and diagnostic CPython 3.12.14 with locked dependencies. Original
release target is `4b89e0d2d496a85f04922b2e019a4aea15326bb9`. Release already
contains squashed main lineage; preserve release-only controls/UI and carried
main authority without blindly re-merging.

The last published implementation preceding this checkpoint is
`abf319d5a345d761d88e26ba787026e98370c26f`, Git tree
`62eb319323cc7c9de7513af6ef7f05009d411189`. Paired candidate wheels explicitly
build abf; actual native-wheel build `70b456e93a77fff48522ee7aa6ddeec6d157f6e6`
has the same tree. Prior compatible wheels retain their actual a224 build and
associated ae head separately; never substitute a mutable latest artifact.
Foundation #2951 is e449594e86c717e66e14598a4130475de79c536f with normal
protected auto-merge enabled; approval remains missing. Refresh GitHub heads,
base, checks, reviews, threads and rules before publication/merge claims. Verify
uploaded Git tree equality; commit metadata alone can change a SHA.

## Preserve implemented contracts

Ordinary daemon hooks directly use HookWorker and the persistent native helper.
The legacy pool remains for compatibility/legacy revalidation; native Codex live
completion has a direct finalizer. Live Linux image reuse requires a previously
verified exact generation; replacements and unsupported systems fully validate.
All ordinary native evaluation and Python delivery use the same acknowledged
posture without a fresh configuration read. Unacknowledged Watch edits cannot
weaken enforcement. Actual installed transition/load qualification remains open.
Stat-only identity or cached publication is never authority.

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

1. Retain the completed package correction and scoped native parser no-go. All
   30 pilot/control pairs, 15 correction pairs and five direct original-deny pairs
   are retained. The primary native workload regresses CPU 11.03% and wall 16.31%.
   The original 36-cell matrix includes 27 full evaluator attempts and nine separate
   unversioned API diagnostics; RSP-050's literal full-route unversioned slice stays
   open. Actual bare npm targets normalize to `latest`, not `None`; preserve the
   six-call witness and do not invent a name-only production route to close a row.
2. Retain the scanner's final scoped no-go: 30 corrected-reader pairs preserve
   all 680 rich findings and improve mean CPU 31.6%, but p95 wall regresses 13.5%.
   Keep all 24 attempted states, unavailable evictions, interrupted/confounded
   cohorts and the separate executable-provenance correction. Production keeps
   the descriptor-bound, size-limited Python reader and explicit incomplete
   coverage. Actual abf native-bundled wheels pass all 28 semantic cases on each
   of Linux and both macOS hosts: 84 passes with no skips. Windows raises
   `PackageNotFoundError` at initial attestation, before any identity or case.
   Preserve its exact CRLF probe digest. Run the source-tested environment/reader
   corrections on a fresh hosted artifact; do not relabel the failed attempt.
3. Preserve the completed MCP B/C/D and native experiments. Production retains
   B; C and universal D regress supported inputs. The native four-category helper
   completes 68 cells, 1,692 forwards and 34 exact pairs but fails the original
   30% benefit / 5% nonregression gate. Near-limit Unicode median CPU improves
   29.711838%, below 30%; adverse blocks and ordinary/early-positive controls
   remain visible. External 4 MiB framing, the separate 16 MiB whole private
   packet bound, inherited deadline and all IPC/helper CPU costs remain explicit.
   RSP-098/103/104/108 are complete in their documented source or decision scope;
   RSP-105/107 activation and positive qualification are deferred for this tested
   boundary. RSP-106's existing scope is unchanged. RSP-100 stays OPEN: one
   private owned-generation implementation attempt is active, with no claimed
   result. Preserve public copy/match fallback, callback mutation order, exact
   forwarded params and browser/store/claim authority composition. Review and
   measure the actual candidate before changing production selection.
4. Complete actual posture, expiry, recovery and route-conservation qualification
   on the next hosted artifacts. The four posture groups require full authenticated
   ACKs and durable receipts under concurrent Claude/Codex Pre/Post load. Retain
   the earlier failed source attempt and its 111 passing corrected checks as
   historical snapshots. Abf Windows baseline passes enforce-to-Watch and expiry
   but fails restart, strict-workspace ACK and blocked-publication witnesses;
   no candidate all-group pass exists. Keep the original 3 s TTL, operation budgets
   and protected command binding. Linux baseline correctly rejects the shared
   interpreter target's mode 0777. The new disposable-venv setup copies identical
   bytes to a private owned 0755 interpreter, preserves the shared target and
   pyvenv configuration, and requires real ABI/SQLite/SSL/prefix and unchanged
   installed-validator checks. Actual hosted proof is pending; do not chmod shared
   files, alter wheel bytes, weaken validation or relax route conservation.
5. Preserve the macOS resolver findings. The exact daemon fixture calls
   `_receive(30.0)` during construction; failure JSON does not record observed
   elapsed startup time. Separate read-only libc lookup probes each have a
   five-second bound. Numeric lookup passes, system name lookups time out without
   responder packets, and selected root-owned resolver configuration is unchanged.
   `scutil` selection listing does not prove query routing or reachability flags.
   One ARM stack sample identifies allowlisted lookup frames; three other samples
   time out. Cleanup passes, but no resolver repair is proven. Do not patch the
   pinned baseline, speculate about service repair or raise the 400 ms readiness
   budget. Continue from the retained actual diagnostic output.
6. Preserve both rollback sequences. Exact candidate/prior-a224/candidate stopped
   replacement passes all three phases on each Unix host. Original 2e downgrade
   rejects the candidate's combined protected command schema; all six receipts
   and authority bytes survive, but legacy stop returns 2 and quiescence remains
   unverified. Expected-negative acceptance stays false and candidate restore was
   not attempted. The producer-aware containment certificate remains design work;
   retiring the outer process alone cannot prove detached native clients and
   supervisors are gone. Keep protected floors and registration intact. The suite
   still requires seven positive phases and one verified expected negative.
   Prior artifact discovery runs inside its mandatory 15-second contained check;
   independent paired/Ollama/scanner checks retain their own outcomes. Windows
   has no transition JSON after cleanup and reporter failures. Run its source
   fixes on new hosts. Same-version stopped transitions do not establish live,
   in-progress, changed-version/program, signing or enrollment rollback.
7. Run the resulting head's required checks and the pinned CodeQL diagnostics.
   Foundation has 179 check records: 159 successful, 19 skipped and one failed
   external CodeQL check reporting two high alerts. Abf's separate external
   CodeQL check reports three new high alerts even though its Actions analysis
   workflow succeeds. Neither alert set has exact source attribution yet; do not
   assume all were introduced by this PR. The implemented diagnostic selects six
   source/language jobs across fixed e449 and abf, preserving observed settings
   and retaining raw SARIF in Actions artifacts with no Code Scanning/database
   upload. Retrieve actual findings, investigate them and fix any substantiated
   defects before claiming a clean security gate. The latest local manifest pins
   42-file Ruff/format passes, 147 passing integration tests and 1,253 production
   files with zero type errors and 20,229 nonfatal warnings. Preserve the initial
   formatting refusal and CRLF diff-check failure; the latter's interpretation
   fix changes no retained artifact bytes. This finite evidence is not a full-suite
   or installed pass, and older 585/111 snapshots remain separate.
8. Complete installed qualification of the implemented private Linux Claude
   Pre/Post launcher. Its authenticated package/registration boundary, original
   challenge/POST and contained completion exist in the current runtime. The final
   component snapshot passes 81 Python and 12 Rust tests; later helper corrections
   and selection checks have separate 43-test and 27-test results. Do not describe
   those as a full rerun of the earlier snapshot. The installed probe requires
   actual native transport, exact wheel/daemon receipt identity and route
   conservation; no installed parity or paired benefit result exists yet. Keep
   detailed HTTP framing/timeout conformance limits visible. Default registration
   and signed Desktop selection do not select this pilot.

The archive investigation is complete for its declared profiling scope: 508/510
expected results, two restrictive timeouts and an earlier warmup timeout retained,
60 profiles and hostile binding/isolation witnesses. Retain the current isolated
worker; this is neither a successful full SLO run nor proof that an entire native
worker could never help. Conditional ports follow the original PRD decision rule.
A native pilot is not mandatory for every optional port, but measured coverage and
predicted benefit must support a deferral; large unmeasured cases remain open.

At abf319, all 36 workflows completed: 31 successful and five failed. The separate
[all-attempt check inventory](evidence/takeover-abf319/github-check-inventory.json)
has 199 records: 163 successful, 23 skipped, 12 failed and one cancelled. The latest
197-record view omits two earlier successful Gitar attempts. Legacy CodeRabbit
explicitly skipped review because the PR is draft. Both arms were attempted on all four platforms, with one completed Windows baseline
smoke block, every candidate block failed and no complete pair. Linux/ARM pass
22 Ollama cases each; Intel and Windows retain readiness failures after ten/two
cases. All four Builder checks pass. The Linux native-wheel SLO smoke and
100,000-request/250,000-receipt soak pass with zero errors and stable daemon
identity, while `qualification_complete` remains false. The macOS native-wheel
source-reference failures, candidate missing-native results, zero-case Windows
scanner failure and failed legacy quiescence remain independent observations.
Read the canonical [abf manifest](evidence/takeover-abf319/manifest.json) and keep
ae, 5ee and 42579 records historical. Use the [reconstruction manifest](reproducibility/manifest.json)
for exact measured source/harness scopes; historical collector attribution gaps
remain unresolved. Later source fixes require actual new-head artifacts and checks.

Local AF_UNIX creation is denied, so do source tests/builds locally and real
installed daemon/launcher execution on supported GitHub hosts. Protect benchmark
provenance: serialize competing CPU/I/O work through the measurement lock; do not
move executables or caches under an active run. Retain all interrupted attempts.

Read the concrete CANARY_ROLLBACK_PLAN.md and canary-rollback-manifest.json before
advancing any cohort. Exact prior artifacts and stop conditions are recorded;
candidate identities, actual qualification/rollback and activation remain pending.

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
GitHub state. At this checkpoint the count is 74 DONE/31 OPEN/29 BLOCKED/10 DEFERRED; those
numbers do not claim release completion. Scoped conditional package, scanner and
MCP production ports are deferred after their measured no-go decisions. RSP-144
stays open until final evidence,
conditional decisions and release state are delivered.

Obtain final Greptile 5/5 and required independent CODEOWNER approval through the
actual review process, resolve threads and required CI on the published head.
Foundation's protected auto-merge and recorded Greptile 5/5 do not clear its
CodeQL failure or supply independent last-push CODEOWNER approval. Neither does
a successful Actions workflow clear abf's separate CodeQL application failure. Never
fabricate approval, self-approve as the author or bypass the release ruleset.

Prepare exact qualified candidate/prior artifact manifests, platform/harness
canary cohorts, stop conditions and tested rollback. Restore verified package,
registration and acknowledged policy only after retiring the affected generation.
Never lower persistent floors or reopen hidden Python fallback; never retry
ambiguous tool execution automatically. Finish all concrete authorized work before
reporting an external blocker. Final delivery must link PRs, exact qualified head,
artifacts, coverage, metrics/intervals/misses, tests and rollback evidence, with
implementation, qualification, merge and release status stated separately.
