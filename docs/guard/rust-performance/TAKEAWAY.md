# Continue HOL Guard Rust performance execution on release/3.2

Use the following prompt to resume the authorized implementation. It supersedes
this file's original proposal-only prompt; the original PRD and all 144 TODO
acceptance criteria remain unchanged. This is a continuation, not permission to
start over, weaken the targets or declare source tests to be installed acceptance.

---

You are continuing the user's authorized request: review HOL Guard, determine
which remaining Python work should move to Rust for performance, and complete the
PRD/TODO end to end on `release/3.2` using GitHub. Continue implementation,
validation, concrete review preparation and permitted publication autonomously.
Do not stop at a plan, ask for authorization already given, or redo completed
native ports. Respect independent code-owner approval and branch protection;
never fabricate it or treat automation as that approval.

Read these files before making changes:

1. `docs/guard/rust-performance/PRD.md` and `TODO.md`: original requirements and
   144 acceptance conditions. Preserve their requirements and thresholds.
2. `EXECUTION.md`, `CURRENT_CONTRACT.md`, `EXECUTION_LEDGER.md` and
   `execution-ledger.json`: current architecture, provenance, evidence and open
   obligations. Every original acceptance/dependency is retained in the JSON.
3. The linked workstream reports for the files you will touch, plus applicable
   repository instructions. Do not apply another workstream's tests or timing
   claims to a changed tree without verification.

## Establish the exact current tree

The documentation cutoff is local integration
`264da76d3bca7a1a4f4970834291ca48d7c7a3c2`, branch `work/rsp-performance-32`,
workspace `rsp-integration-32`. The docs branch is `rsp/execution-ledger-final`.
Other workstreams were still delivering commits. Inspect `git status`, branch,
HEAD and worktree ownership before editing. Preserve unrelated/uncommitted work;
coordinate shared files and use isolated worktrees for independent tasks.

Baseline is `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1,
Rust 1.88.0 with locked dependencies and diagnostic CPython 3.12.14. The original
release branch was `4b89e0d2d496a85f04922b2e019a4aea15326bb9`; the reconciled
foundation is `c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8`. Release contains a
squashed main lineage. Preserve release-only control/UI/schema behavior and
carried main authority changes; do not blindly re-merge or revive superseded PRs.

Use GitHub to refresh exact PR heads, checks, threads, approval and release
rulesets before making current-state claims:

- [Foundation PR #2951](https://github.com/hashgraph-online/hol-guard/pull/2951)
  targets `release/3.2`; reported head
  `e449594e86c717e66e14598a4130475de79c536f` had 25 successful workflows and
  33 resolved threads. Independent last-push code-owner approval was missing.
- [Implementation PR #2954](https://github.com/hashgraph-online/hol-guard/pull/2954)
  had reported remote head prefix `92cf3c72d80d`, older than the docs cutoff.
  Local mixed, J118, binding/receipt and nonpriority launcher followups must be
  reconciled with the actual published tree. When GitHub commit metadata changes
  a SHA, verify exact Git tree equality rather than assuming source equivalence.
- [Performance run 35201516872](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516872)
  selected four targets and failed before complete qualification. Linux/Windows
  baseline 1 MiB `.txt` fixtures missed source classification; macOS ARM stalled
  in reverse DNS during HTTP server construction. Intel diagnosis was pending.
  Get complete logs and preserve each failed attempt in the qualification record.

Also retain the separate Linux/Windows 17-case installed status/real-child
identity successes in [wheel run 35201516674](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516674),
jobs `105137144858`/`105137144563`, observed build SHA
`73f34ba984ff01563257599692cce33098014bdf`. EXECUTION.md records runtime and
manifest hashes. Those jobs later failed default-auto hooks; signing and
cross-release rollback were not exercised. This does not establish all-platform
identity or hook qualification, and a differing source head requires explicit
artifact reconciliation.

Reported observations are dated 2026-09-17, not a promise of current remote state.
No merge, canary or release completion has been established.

## Preserve what is already implemented

The ledger currently records 62 DONE, 41 OPEN, 41 BLOCKED and zero DEFERRED.
A source/specification task can be DONE while its installed qualification remains
blocked. Do not relabel an unbuilt conditional Rust port as DONE or DEFERRED.

- Native core avoids redundant parsing/copies and shares immutable compiled
  policy. Ordinary hooks use direct in-daemon HookWorker dispatch and a persistent
  native helper; compatibility/Codex revalidation still use the Python pool.
- Linux live-process attestation reuses only an already fully verified owned
  image on supported filesystems, with exact start/parent/image/package/manifest
  binding. New spawns fully validate before frames. Unsupported platform or
  filesystem proof retains full hashing. Stat metadata alone is never authority.
- Acknowledged authenticated observe mode avoids one redundant configuration
  read. Enforcing/missing-binding paths retain current config visibility; do not
  transfer that authority without an explicit equivalent transition contract.
- The trusted command compiler and Rust interpreter implement all 29 reviewed
  operations. The source catalog has 86 extensions, 291 rules, 304 permissions
  and 2242 nodes; 26 matcher families are instantiated. One canonical command
  feeds indexed/memoized evaluation and complete observations. Profile is
  CPython 3.12/UCD15. Context-heavy or unsupported behavior is owned uncertainty,
  never silent no-match. Read the exact program/catalog digests in EXECUTION.md.
- Production J activation requires both program-v1 and control-fence-v1
  capabilities, verified trust/catalog/program/control identity, and the live
  SH/EX authority protocol. Mutations close a durable authenticated marker before
  SQL/key effects. Recovery binds an exact predecessor floor; no revision rollback
  or historical-proof key substitution. Signed source manifest context prevents
  managed enables from being restored by mutable-manifest deletion/replacement.
- Ordinary local approval continuation is resolved-row reuse under the shared
  mutation fence, bound to exact native policy/program/observation and request
  context. It is not the exported native v3/v4 one-time challenge/claim/consume
  path. Tests of those separate APIs do not prove ordinary launcher consumption.
- Complete optional command binding survives receipt persistence through
  migration 28 and `GuardStore.get_native_decision_receipt()`. Queue acceptance,
  journal durability, SQL commit and checkpoint remain distinct. Stable attempts
  deduplicate replay; recovery never re-runs the decision engine.
- Package indexes/captured-content views, Git object batching/blob reuse, MCP
  catalog/request reuse and bounded I/O, SQL transaction/journal batching, precise
  DB/WAL reconciliation and per-call inventory root coalescing are implemented.
  Keep their security/completeness semantics and existing regression coverage.
- MCP has 4 MiB UTF-8 frames, 64/16 MiB child queue, 64/8 MiB per-direction reply
  buffers and bounded deadlines/operation counts. Overload is terminal, preserves
  uncertain delivery and prevents later forwards. Keep notification invalidation
  during approval and the 5 ms final prewrite quiet barrier.

## Finish concrete integration and correctness work first

Check whether these delivered/pending workstreams are already in the current
integration. Do not cherry-pick twice or overwrite their owners' edits:

1. Baseline corpus fix `e7c3a86cb` and numeric HTTP bind/startup repair. Keep
   baseline source and runtime pinned. Fix the fixture/environment or production
   defect in its proper owner, never monkeypatch the baseline or raise readiness
   to hide a stall. Diagnose all four logs, including default-auto hook failures.
2. Controlled ordinary launcher approval helper `7b2113f2e`, with 19 real-store
   tests: canonical harness aliases, exact new native artifact/action identity,
   ambiguous-row refusal and retained late durable outcomes. Integrate its sibling
   DaemonFixture dispatch and qualification route tests. Exercise real approval,
   denial, expiration/restart and stale-binding behavior; label the actual local
   reuse path accurately. Current Claude ask → local resolve → retry is distinct
   from Codex registered browser-wait allow: local resolution produces retry-only
   `hookAttached=False`, and actual Codex finalization rejects
   `exact_approval_authority_missing`. Implement the proper production authority
   handoff and regression separately; a fixture cannot add fabricated
   `approval-gate-once` or one-time native authority to make the case pass.
3. Mixed runner `a5d2ffeda` and its minimal DaemonFixture delegate. Root owns
   `native_slo_qualification_run.py` integration. Call
   `run_mixed_scenario(session, raw_file=..., receipt_profile="candidate")`
   with a fresh normal DaemonFixture, and explicitly select
   `receipt_profile="baseline_2e672d2"` only for the pinned baseline arm.
   Candidate must use the complete binding-aware receipt getter. The baseline
   path may validate legacy rows only when the installed baseline lacks that
   getter; candidate errors cannot fall back or strip fields.
4. Registered nonpriority probe `264da76d3`: repair Copilot response shape and
   use the real Cline default home layout. Preserve genuine configured argv,
   aliases, permission/exit behavior and platform shell semantics. Unsupported
   Windows ZCode marker interpretation cannot be "fixed" by changing the tested
   argv. Complete declared host/route cases; preflight or callback discovery is
   not enforcement activation. Coordinate adapter-owner followups first.
5. J118 installed probe `1b59b2d3b`, complete receipt support `58548bb2e` and
   ordinary approval binding `017214841`. Run wheel-only CLI/MCP Builder and
   Ollama enable/review/receipt/disable lifecycle on each platform. Settings
   rollback is narrower than a changed package/program artifact update/rollback;
   implement the latter for RSP-118/139. Interactive/system-keychain enrollment
   and dormant native approval APIs remain separate declared scope.
6. Inventory followups `16001f0f5`, `1f6b21e73`, `6aacf9770`, `b37edef16` and
   command diagnostic source `d9802fac2` plus its measured report. Reconcile
   paths/commits before citing them as integrated. Preserve source limitations:
   unchanged inventory refresh still rehashes; controlled HTTP waits are not cloud
   timing; fewer SQL queries do not prove fewer transactions or throughput gains.

Complete missing scenario implementation and observability where required.
The mixed runner currently restarts the Rust resident, not the whole Python
fixture daemon. It measures actual journal writes/fsync and SQLite transaction
counts, but SQLite VFS bytes/fsync remain null. Add justified instrumentation or
record the unmet acceptance; never convert unsupported metrics to zero/pass.
Its 30-second default and 1000 ms inherited diagnostic latency check are not the
PRD mixed soak or frozen product budget.

## Run qualification without changing its meaning

Build baseline and candidate as separately installed, locked artifacts for Linux
x64, macOS x64, macOS arm64 and Windows x64. Clear development runtime overrides
and run isolated installed workers outside the checkout. Record exact package,
source, target, rule, runtime, manifest and command program/catalog identities,
including signed/frozen manifests where applicable. Local build_sha=unknown
binaries and the baseline-binary status component cannot qualify the final J tree.

Use the committed qualification CLI and its current `--help`; inspect workflow
arguments instead of guessing a command against changing helpers. Keep smoke
runs labeled smoke. Freeze and record the candidate before enabling the full
`rust-performance-qualification` run; a later code/dependency change requires
renewed qualification on the resulting exact head.

Preserve these PRD gates and independent route/platform series:

- Installed warm c1 p95 ≤50 ms, p99 ≤100 ms; c16 p99 ≤200 ms without errors.
- Native client p95 ≤20 ms; cold native p95 ≤150 ms; readiness ≤400 ms.
- At least five alternating independent runs; 10,000 priority warm decisions,
  1,000 other-route decisions, 100 priority cold starts, 100 recoveries and
  30 resource observations in their specified scopes. Keep confidence intervals.
- Selected hot tranche: at least 30% p95 or CPU benefit and no more than 5%
  regression in the other primary metric. Optional ingress: at least 25% private
  memory or 30% c16 p99 benefit. Retain existing RSS-growth safeguards.

Existing script gates warm ≤20 ms OR ≥1.15x and cold ≤150 ms AND ≥5x, and the
1000 ms adapter diagnostic budget, are distinct historical gates. Passing them
does not substitute for the PRD installed targets.

Retain every offered, admitted, completed, failed, rejected, timed-out and late
attempt. Scheduled-offer-to-terminal latency includes generator lateness and
queue wait; request-only latency is a separate metric. A timeout's terminal
outcome cannot be replaced by a later completion. Separate measured native allow,
Watch delivery, review/block and unavailable continuation. Assert actual route,
verdict/reason, final harness JSON and exit behavior, plus genuine committed
receipt identities. Do not pool routes, discard slow/failing baseline cells,
substitute HTTP for registered startup or count unavailable work as enforcement.

Measure independent daemon/helper/resident and driver resource series; execute
mixed pre/post load, control changes, first enforcement, real receipt ingestion,
inventory and restart/recovery. Preserve queue age/depth witnesses and private
bounded raw ledgers. Probe real Windows lock/pipe semantics and Unix peer/path
identity. Complete frozen source-ref, aliases, fault and approval coverage and
actual package update/downgrade/signing/registration restoration transcripts.

## Resolve conditional Rust scope from evidence

The Python package 98.22% CPU diagnostic improvement, narrower identity gain,
Git/MCP/inventory reductions and native command component gains are useful source
evidence. None proves an unbuilt native package/offline-scanner/MCP/inventory/
spool/compiler/launcher/ingress implementation would meet its coarse-boundary
benefit gate. Rebaseline optimized Python, choose a bounded native pilot where
justified, test full contract parity and compare actual local/installed cost.
Record measured go or no-go with artifact identities and limits. Do not manufacture
a no-go by declining to build or measure, and do not broaden a migration simply
because Rust is available. Preserve the richer offline secret detector contract.

## Complete review and release evidence

Run appropriate format/lint/type, Rust crate, Python, command differential,
adversarial, source mutation, authority/floor/approval, receipt/crash, MCP and
workflow-selection checks on the exact final combined source. Existing per-owner
passes are evidence of their commits, not the later tree. Resolve every difference
or intentional behavior change explicitly. Scan final exported results/errors for
raw secrets, command/output and private paths; retain only bounded necessary data.

Refresh GitHub checks/threads/approval on the final published head. Obtain the
required independent code-owner approval through the actual reviewer process;
no agent or bot approval substitution and no branch-protection bypass. Prepare a
concrete qualified candidate/prior-version artifact manifest, platform/harness
cohorts, stop conditions and tested rollback. Never lower persistent floors or
reopen hidden Python semantic fallback to make downgrade work. Ambiguous tool
execution must not be retried automatically.

Update all 144 ledger entries with exact code, tests, installed results, measured
native selections/no-go decisions and remaining blockers. Do not change original
acceptance to fit partial delivery. The final user handoff must link PRs and
Actions artifacts, identify the exact published/qualified tree, show per-route
metrics and intervals including misses, state merge/approval status separately,
and include tested rollout/rollback evidence. If an external review is the last
blocker, finish the concrete reviewable work first and explain the exact ruleset
requirement; do not present unfinished implementation as waiting only on approval.
