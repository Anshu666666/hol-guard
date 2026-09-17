# Rust performance execution for release/3.2

This record implements the original [PRD](PRD.md) and [144-task TODO](TODO.md).
Their acceptance conditions, dependency text and performance thresholds are
unchanged. The exact source conversation is [Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1),
verified by its title, full conversation, linked documents and implementation
[#2954](https://github.com/hashgraph-online/hol-guard/pull/2954). The user's later
instruction authorizes this session to take over implementation through GitHub
on `release/3.2`. The original proposal-only wording does not narrow that scope.

This checkpoint reconciles local source `591d5c81e6bb341c6c3271332f3a6615a01bc748`, dated
2026-09-17. That source and its scoped-config validation are not a new published
artifact or hosted pass; publication and fresh analysis remain pending. The ledger records
**74 DONE, 31 OPEN, 29 BLOCKED and 10 DEFERRED**. These are individual acceptance
records, not a release-completion percentage. Installed qualification, review
and rollout remain incomplete. [TAKEAWAY.md](TAKEAWAY.md) is the current execution
prompt; obsolete checkpoint instructions remain available in Git history.

The [machine ledger](execution-ledger.json) retains all original fields and the
complete dependency prose for every task, including RSP-134's requirement to
validate **all selected implementation tasks**. The [rendered ledger](EXECUTION_LEDGER.md)
shows current evidence and unresolved direct dependencies on DONE records.
`OPEN` can contain tested implementation awaiting broader acceptance. `BLOCKED`
identifies a missing prerequisite or external requirement. A conditional
migration may be deferred when measured current behavior and the PRD decision
rule justify it; neither an unbuilt port nor a small-input result supplies that
justification automatically.

## Source and publication identity

| Identity | Recorded value |
| --- | --- |
| Audited production baseline | `2e672d2d950c6ec471005ddba46e49bba16dc23b` |
| Original release/3.2 target | `4b89e0d2d496a85f04922b2e019a4aea15326bb9` |
| Main lineage already carried by release squash | `c996b1d243ddafe8bef04d26ba939615edebb1e7` |
| Reconciled local foundation | `c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8` |
| Foundation, current shared-reader publication | [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951), `a7b675a84b732ead542cdf77e5153c57b4257d9b`; new CodeQL analysis has ten open alerts |
| Foundation, earlier retained checks | `e449594e86c717e66e14598a4130475de79c536f` |
| Last published implementation before this checkpoint | [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954), `9db62e8844c2ba2627f55b6b00e58cb5b175185d` |
| Verified published Git tree | `47ba580366672b3b92cb46e6bb1d19c670444e94` |
| Actual native-wheel build at that checkpoint | GitHub test-merge `c9859a5b5d04526fa7e663d7c494e442ee4298c4`, same Git tree; paired candidate wheels explicitly build `9db62e884` |
| Current local source cutoff | `591d5c81e6bb341c6c3271332f3a6615a01bc748`; final scoped-source checks retained, publication and fresh hosted analysis pending |
| Package / Rust / diagnostic Python | `3.0.1` / `1.88.0` / CPython `3.12.14`, locked dependencies |

The release branch contains a squash of earlier main changes. Reconciliation
preserves release-only Everyday Mode schema/density/stale-write behavior, Fleet,
Common CLI and network/sandbox presentation alongside current main authority.
Do not blindly merge an already-carried main lineage. GitHub-created commits may
have different metadata from local commits; publication verifies exact Git tree
identity before advancing the remote branch without force.

The overlap decisions below retain their dated source audit; refresh heads and
changed files before acting on any of these PRs.

| PR and observed head | State | Treatment |
| --- | --- | --- |
| [#2807](https://github.com/hashgraph-online/hol-guard/pull/2807), `91f26d74f3148826b73730722c92e9d6b23794ff` | Open | Preserve Windows handle cleanup and fully populated RSS baseline invariants already present in the audited source; do not replace them with a two-worker baseline. |
| [#2870](https://github.com/hashgraph-online/hol-guard/pull/2870), `c6d71e84b7eae8a79b82d6c46143ef95da169fbd` | Closed, unmerged | Superseded by #2950; do not revive. |
| [#2950](https://github.com/hashgraph-online/hol-guard/pull/2950), `47b4ff21cdb89c70633c57d0a438f5739f316a98` | Merged into main | Current main secret-read and one-time approval behavior is carried by the foundation. |
| [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931), `ac31b5de7a61f87b9dbd89626bbc79fd6008968b` | Open draft | Hosted remote HTTP MCP is not assumed shipped. Preserve future catalog/policy integration seam without importing draft behavior. |
| [#2948](https://github.com/hashgraph-online/hol-guard/pull/2948), `a6d24bdbaaa88e7541399cca013e01866360f427` | Open | Unpublished generic-v2 admission work is separate. Runtime identity caching cannot treat cached publication state as fresh authority. |
| [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911), `ea472d8d67a8539dca7de02096634bb770a36b0f` | Open | CodeSage explicitly describes Python-reference-only coverage. Do not add it to native coverage without importing, compiling and qualifying its contribution. |
| [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797), `4b89e0d2d496a85f04922b2e019a4aea15326bb9` | Open draft | Release-to-main aggregate; this implementation targets its release branch rather than replacing that PR. |

## Implemented behavior and evidence limits

| Workstream | Current implementation and evidence | Remaining acceptance |
| --- | --- | --- |
| Benchmark integrity | Independent scripts-only Python oracle; intrinsic native verdict and delivered harness response; registered argv; separate kernel/client/ingress/launcher timers; frozen per-route corpus; bounded failed-attempt and resource ledgers | Exact artifact execution and full sampling on every declared platform |
| Rust core | Typed lifecycle/results, strict bounded parsing, immutable compiled policy, borrowed identities and fewer output copies; [47 allocation components](../native-allocation-performance.md), 30 observations each | Final combined-source validation and installed benefit |
| Package | Verified immutable bundle indexes, captured bytes, one parse per supported JSON/JSONC/TOML/Yarn/pnpm/Bundler format and atomic evidence; unique bundle identities validate once | Actual npm lock-v3 source-route pilot fails its benefit gate and remains inactive. Original matrix has 27 full evaluator attempts and nine unversioned API diagnostics; the literal unversioned full-route slice remains open. |
| Offline scanner | Bounded Git streams, shared immutable traversal, lazy context and descriptor-bound working reads preserve rich findings and explicit incompleteness | Native extraction remains inactive after its final CPU −31.6% / p95 wall +13.5% result. Latest 9db installed scanner retains 107 passing rows, one failed row and four unreached cases; corrected Windows fixture execution is pending. |
| Archive worker | [510 actual isolated calls and 60 profiles](archive-worker-qualification.md); 508 exact outcomes, two fail-closed timeouts plus an earlier warmup timeout retained; 330 hostile cases remain non-clean | Retain current isolated worker in measured scope; no qualified native worker or whole-worker no-go |
| MCP | Bounded framing, catalog identity, idle notifications and optimized B remain selected. C/D/native and the private owned-preparation E experiments are complete | E records one derivation and exact forwarding in its 64 selected historical cells; later method-selector mutation review limits the broader claim. F run1 stopped at 19 completed/one failed/44 never-attempted cells; no complete performance gate or activation. B still derives categories twice; RSP-100 stays OPEN. |
| Private Claude launcher | Existing runtime contains the authenticated private Linux Pre/Post launcher; component snapshots and later integration tests remain separately identified | Actual 9db installed PreToolUse completes 30 Python and 30 native launches; Python PostToolUse then fails its eleventh attempt after ten completions. Zero full blocks, no complete benefit selection or activation; broader conformance and platform/signing gates remain. |
| Runtime identity and posture | Verified live Linux generation reuse on supported filesystems, complete validation on replacement/unsupported systems; all ordinary native evaluation and delivery consume the same acknowledged posture without config rereads | Signing/frozen artifacts, installed transitions and benefit remain separate |
| Command extensions | Trusted compiler, bounded typed Rust interpreter, indexed matching and complete observations, authenticated control fence, durable complete receipts; [638 catalog/control combinations](../native-command-matrix-performance.md) | Final activated contribution lifecycle, exact installed benefit and update/downgrade proof |
| Approval | Codex's genuine waiting process receives fresh native review under the SH control lease and atomic existing local Allow once consumption; authenticated terminal replay, process/deadline checks and restrictive native failures | Four installed fault scenarios implemented and 134 focused tests pass; actual host results remain required |
| Evidence and inventory | Compact facts, atomic SQL batches, append/checkpoint replay, stable attempts, precise DB/WAL reconciliation, captured inputs and one positive root discovery per call | Installed contention/soak, unavailable VFS measurements and real cloud/Cisco/incremental evidence |
| Mixed and registered routes | Real hook/control/ACK/receipt/inventory/recovery runners; historical abf Linux soak retains 100,000 requests and 250,000 receipts | Latest 9db Linux capacity conservation and Intel SLO gates fail; ARM SLO smoke and Windows ordinary installed checks keep their narrower passing scopes. No full mixed offered-load, recovery or resource qualification. |
| Ollama and Builder | Actual 9db ARM passes all 22 Ollama cases; all four Builder installation checks and compatible stopped rollback sequences pass | Linux/Intel/Windows Ollama enabled readiness fails after two retained cases. Every original-baseline strict quiescence sequence still fails; live/in-progress/version/signing and full lifecycle qualification remain open. |

The command catalog has 86 extensions, 291 rules, 304 permissions and 2,242
nodes: 29 reviewed operations, 26 instantiated matcher families, 249 declarative
and 42 compatibility rule identities, plus four rule-less GitHub permissions.
Its semantic profile is **CPython 3.12 / UCD 15**. Unsupported or context-heavy
behavior retains owned uncertainty. The program digest is
`4df5208d0dc05ceaadb1de6a6d8f6d3f9e5395dffcf992640fed87b82a0df1c9`;
the catalog digest is
`232ff389ca607b805118a02bd9560e972453f9a406188237037138f4834faf11`.
Each final installed artifact must prove its actual identities.

The 98.22% package CPU reduction in the earlier 1,000-by-1,000 diagnostic and
72.28% status-component CPU reduction with the same baseline native binary are
scoped component results. They do not establish final launcher latency or predict
all cardinalities. The package matrix retains four 120-second baseline timeouts,
one other baseline harness error and the candidate's separate cell-30 harness
error; no incomplete pair receives a speedup or parity result. Later passing
reproductions cannot repair those observations.

The [package selection report](../rsp-package-native-selection.md) retains all
30 native/control pairs, including 29 complete public-result/evidence comparisons
and one failed baseline. The primary parser-heavy case regresses CPU by 11.03%
and wall time by 16.31%; the largest exact case improves CPU by 25.20%, below the
30% benefit gate. The scoped native parser is not selected. The separate five-pair
original-baseline deny correction improves CPU by 44.52% and wall by 42.12% using
arm medians. Neither report supplies installed or cross-platform qualification.
The [real unversioned-route witness](../rsp-package-unversioned-route.md) preserves
six actual evaluator calls and three exact original/optimized comparisons. Bare
npm tokens normalize to `latest`; no production cached-bundle call passes `None`.
The existing nine name-only API measurements do not satisfy full-route acceptance.

The native scanner experiment is deliberately outside production entry points.
It supports ASCII documents up to 4 MiB and returns bounded candidate spans;
Python owns provider classification, context, rich findings, HMAC and completeness.
Non-ASCII or larger inputs explicitly use the current Python path. An interrupted
measurement during build-target relocation remains failed and unqualified; later
cohorts record the changed executable backing separately. No failing or confounded
sample is silently discarded. The final corrected-reader confirmation retains
30 pairs/60 full CLI calls and all 680 exact rich findings. Mean process-tree CPU
ratio is 0.684238; p95 wall ratio is 1.134770. Both the point gate and conservative
interval gate fail, so production keeps the optimized Python scanner. Its
[decision and coverage](../evidence/rsp-scanner-native-regex-decision-linux.json)
include paired intervals and explicit installed/platform limits. A separate
provenance correction records the observed overlay executable device without
rewriting the raw cohort or attributing an unknown restoration event.

The [installed scanner report](../rsp-scanner-installed-qualification.md) retains
all original local and hosted attempts. At 9db, each Unix host passes all 28
retained-Python cases. Windows now attests its wheel/modules and both actual PE
launchers, then records 23 passing rows, one failed row and four unreached cases.
Across this attempt the raw totals are **107 passed, one failed, four unreached**.
The old catch-all relabeled a completed history row when later fixture setup
failed; its original failed status remains in those totals. The next fixture's
reserved `nul.ts` filename is a source-supported likely portability trigger,
without the original Git operation/stderr needed to prove that exact cause.
The probe-only filename and phase-accounting correction passes 54 source tests;
new Windows execution remains required. Earlier abf's 84 Unix passes and Windows
zero-case attestation failure stay attached to that earlier artifact. No native
detector is selected. Output capture limits still apply after child exit and do
not constitute a live temporary-file growth quota.

The [MCP native experiment](../rust-performance-mcp-native-text.md) is complete:
68 retained cells, 1,692 forwards and 34 exact pairs. Five-block near-limit
ASCII median improvements are 24.95% p95 and 14.65% tree CPU; Unicode improves
22.75% and 29.711838%, respectively. Neither reaches 30%, and individual blocks
and ordinary/early-positive controls regress. The helper remains inactive.
Its full route includes normalization, private encoding, both IPC directions
and helper CPU. Two forced-native oracles each cover the same 3,008 distinct
cases, with exact categories, approval hashes and complete decisions; they do
not establish 6,016 distinct fixtures or installed qualification.

RSP-098/103 source measurements, RSP-104's bounded native prototype contract
and RSP-108's continued full-rewrite deferral are complete. RSP-105/107 activation
and positive qualification remain deferred for that tested native boundary;
RSP-106 keeps its existing current-proxy correctness scope.

The subsequent [owned-preparation E experiment](../rust-performance-mcp-owned-preparation.md)
is now implemented and measured. All 64 cells and 32 paired public traces
complete, with 1,108 forwards and notifications. E records exactly 554 admissions,
category derivations, completed preparations and writes bound to the exact encoded
bytes in those selected cells. The historical tests cover public fallback, callback
order and fresh policy/catalog/browser/store/claim authority. Unsupported, package and busy routes
use B. The 119-test source gate includes 96 full-authority cases; the separate
3,008-case public oracle and three overlapping harness tests are not extra unique
full-authority cases. The initial zero-cell incomplete export remains retained.

Later independent review identified a counterexample outside E's historical
selected cases: its final protected writer is selected from mutable method text.
The initial [F fork](../mcp-streaming-preparation-pilot-boundary.md) retained that
selector, and two actual child-pipe regressions showed a changed plain method
being forwarded and a hostile method invoking its callback. This limits frozen
E's earlier mutation-safety claim; the 64 selected cells, source/test/report and
raw bytes remain unchanged. They cannot establish universal alias safety.

F now selects the admitted frame by object identity, then preserves complete
binding and actual-wire checks. Its
[retained source gate](evidence/mcp-stream-binding-feasibility/manifest.json)
passes 44 tests in 11.39 seconds, including the corrected selector cases, real
nested normal/error restoration and unrelated replies. The 96 authority/browser
comparisons are within those tests, not additive. Independent source review
found no remaining blocker for this bounded inactive candidate. Initial
collection failure, 39-test pass and two failed selector regressions remain.
Its isolated allocation feasibility used an earlier instrumented prototype;
those observations are neither final-F route timings nor process RSS. There is
no installed/platform qualification or activation from that source gate. The
separately prepared fixed worker/collector has now produced a stopped route attempt.

The [F run1 report](../rust-performance-mcp-streaming-preparation.md) retains
19 completed cells, one failed baseline dense-integer cell and 44 never attempted.
Completed cells verify 400 responses/forwards/progress notifications (B 198, F 202)
from 401 total attempted calls. F records 202 admissions, category derivations,
preparations and bound writes. Nine complete pairs independently match; the
collector emitted zero comparisons because its final loop was never reached.
The last completed F cell remains unpaired. No diagnostic profile or five-block
gate ran, and no retry, resume or E-result pooling occurred. Failed-cell zero
observed forwards does not prove no forwarding: missing/unreadable ledgers also
produce zero. Discarded stderr, ambiguous worker detail and absent pre-run OOM
counters leave the EOF cause unresolved. Complete before/after export/dependency
proofs, all adverse cells and exact five-Python-source reconstruction remain in
the [42-artifact evidence package](evidence/mcp-streaming-run1/manifest.json).
This attempt uses exact 5a source; it does not measure the later 591 config scope.

General E activation is rejected. Five-block median p95/tree-CPU changes are
−47.36%/−40.00% at 1 KiB and −54.54%/−9.09% at 128 KiB, preserving real positive
narrow observations. Unicode and dense inputs improve only 9.80%/10.67% and
0.99%/3.05%; individual blocks regress. Dense and nested profile worker peaks add
32.50 and 55.31 MiB. Large-cell p95 is the maximum of three warm observations;
reported ranges are not confidence intervals. Cold-plus-warm tree CPU and warm
client latency have different scopes. Shared-host variation in unchanged work
limits attribution, and source/fixture filesystem differences remain explicit.
**B remains the default and RSP-100 remains OPEN**. The completed experiment is
neither an unattempted design nor proof that every future narrow selection fails.

The [private Claude component history](claude-native-launcher-pilot.md) retains
81 Python/12 Rust tests, later 43 helper tests and 27 builder/runner tests at their
separate exact snapshots. Its old installed-pending wording is superseded by the
[actual 9db installed receipt](evidence/takeover-9db62e/perf-linux-installed-claude-launcher-pilot.json).
That receipt binds the real candidate package/runtime and completes 30 Python
and 30 native PreToolUse launches with exact contracts and native-resident routes.
The next Python PostToolUse cell attempts 11 and completes ten before
`priority_launcher_unexpected_reason`. Zero full blocks complete; scope,
qualification and activation flags remain false. Partial timing/CPU and the failed
attempt stay recorded without a full five-block benefit decision. New bounded
[edge-stage diagnostics](native-edge-return-diagnostic.md) preserve the original
budgets and semantics; they cannot explain this earlier failure retrospectively.
Default registrations and signed Desktop selection do not select the pilot.

The [installed posture contract](installed-posture-transition-contract.md) now
exercises four real installed daemon groups under concurrent Claude/Codex Pre/Post
load: enforce/Watch and resident restart, a first stricter workspace, genuine
publication-lock timeout with automatic recovery, and short-lived renewal/expiry.
Every observed decision binds to independently authenticated acknowledged authority
and a complete durable receipt; intrinsic block and Watch delivery remain distinct.
The earlier frozen posture source suite passed 111 tests. Its initial
95-pass/1-fail attempt and unchanged diagnostic are retained; no actual 400 ms
recovery result is inferred.

The [canary and rollback plan](CANARY_ROLLBACK_PLAN.md) names exact historical
wheel/build/tree identities, four platform cohorts, original sample and metric
gates, stop conditions and stopped-transition commands. Its historical machine manifest keeps
candidate identity pending and qualification, activation and tested-cohort rollback
false. Actual 9db compatible stopped replacement now passes on all four hosts;
that limited evidence does not qualify a canary or the failed legacy sequence.
Live/signing/version transitions and independent final approval remain prerequisites.

## Production contracts that qualification must preserve

Ordinary HTTP hooks dispatch directly to the in-daemon HookWorker and persistent
native helper. Compatibility and legacy Codex paths retain their Python pool;
the new native Codex completion path has its own direct finalizer. Stat metadata
alone is never runtime authority. Policy/program/catalog/control bindings and
SH/EX mutation fencing remain live, including stricter-policy and recovery floors.

Claude local resolve-and-retry and Codex browser-wait continuation are distinct.
Codex continuation binds the original process/start identity, immutable request,
workspace/home and deadline; performs fresh native evaluation and verified receipt
readback; and atomically consumes the existing local approval once under the
control lease. A late completion cannot become a valid delivered allow even after
a durable consume. Ambiguous retries return the authenticated prior completion
only under the same binding. This does not invoke the separate native v3/v4
challenge/claim/consume APIs. Installed fixtures stop at the registered-hook
boundary and do not claim to execute Codex's reviewed tool.

Resident PostToolUse Watch keeps its intrinsic native decision and plain reason;
Python transforms delivery to allow/warn without inventing direct-hook observe
prefixes. Availability continuation is recorded separately from native-evaluated
allow. Existing harness-specific availability policy remains unchanged.

Both pinned artifacts deliberately reject full source-reference opens on Windows
in the native non-Unix secure-open implementation. The harness records that exact
refusal separately; it cannot qualify source content, identity or successful
source timing. A pathname fallback or an unavailable-to-allow conversion is not
a repair. [Windows reference scope](windows-reference-qualification.md) records
the remaining all-platform qualification gap.

Queue acceptance, journal durability, SQL commit and checkpoint are different
states. Candidate receipts require all command bindings; only the exact audited
baseline may use its complete legacy schema. SQLite VFS bytes/fsync remain
unavailable rather than zero. Mixed offered-to-terminal latency includes scheduler
lateness and queue wait; timeout outcomes cannot be replaced by later success.

## Exact published CI observation and pending verification

The latest retained published checkpoint is 9db62e884. Its
[complete inventory](evidence/takeover-9db62e/github-check-inventory.json) records
**37 Actions workflows: 34 successful, three failed**. The separate population
of **207 completed check attempts has 178 successful, 20 skipped and nine failed**.
Main CI has 110 successful jobs, three skipped and one failed Sonar job. Desktop,
Windows cross-platform checks and all four Security Gates jobs pass. CodeRabbit's
successful commit status explicitly says draft review was skipped; it is not an
independent completed review.

The [canonical 9db manifest](evidence/takeover-9db62e/manifest.json) preserves all
53 JSON members from eight API-digest/size-verified ZIPs, their unchanged decoded
values, eight canonical scanner/build records and five wheel-member hashes.
Paired wheels build the exact PR head; native-wheel records attest the real
GitHub test-merge c9859a5b5d04526fa7e663d7c494e442ee4298c4. Their Git tree is
47ba580366672b3b92cb46e6bb1d19c670444e94, with independently verified test-merge
parents. Prior rollback wheels retain actual a224 build and exact per-target
hashes. A PR head alone is not artifact identity.

| Workflow / target | Actual 9db observation | Remaining proof |
| --- | --- | --- |
| [Paired 35239001782](https://github.com/hashgraph-online/hol-guard/actions/runs/35239001782), all hosts | Both arms attempted; all eight fail their first block. | No complete pair, speedup or whole-program qualification. |
| Baselines | Linux Codex benign 1 MiB action mismatch; macOS getfqdn startup deadline; Windows cold native stop containment failure. | Preserve each semantic/setup failure and original bounds. |
| Candidates | Linux Cursor empty-output and ARM Cursor benign 256 KiB route mismatches; Intel initial hook-process capacity unavailable; Windows Cline benign maximum route mismatch. | New stage/capacity observers are source-tested and await actual hosted results. Missing earlier native reasons remain unknown. |
| Linux interpreter setup | Both paired and independent transition environments prove same-byte private 0755 interpreter copies, unchanged pyvenv/ABI/SQLite/SSL/prefix, and unchanged installed-validator acceptance. | This successful fixture repair does not erase later baseline/candidate failures; the shared interpreter is unchanged. |
| macOS resolver | Selected owned configuration and direct UDP self-probes pass; numeric libc controls pass, system lookups time out without responder packets; cleanup passes. | No resolver repair. Original daemon construction bound is 30 seconds; separate lookup bounds are five seconds. New hosts/DNSService observation is pending. |
| Ollama / Builder | ARM passes 22 Ollama cases; Linux/Intel/Windows retain two cases then fail enabled readiness at 400.108/407.413/407 ms. All four Builder checks pass. | The readiness gate stays 400 ms; prior cohorts cannot replace failures. |
| Scanner | All Unix 28-case probes pass; Windows attests the installed wheel and both PE launchers, then records 23 passes, one failed row and four unreached cases. | Fresh corrected Windows link/encoding/mutation coverage is required. |
| Private Linux Claude | Both 30-launch PreToolUse arms pass, then Python PostToolUse fails its eleventh attempt after ten completions. | Zero full blocks, incomplete native/post/fault scope and no complete selection gate. |
| Compatible stopped rollback | Candidate/prior-a224/candidate passes all three phases on all four platforms with protected state, receipts, registrations and authenticated retirement. | Same-version stopped replacement does not qualify live/in-progress/version/signing/enrollment transitions. |
| Original-baseline rollback | All hosts pass clean baseline, candidate upgrade and reinstall; downgrade rejects protected binding. Receipts/authority remain, legacy stop returns 2. | Strict quiescence and expected-negative acceptance remain false on every host; no candidate restoration occurred. |
| [Native wheel 35239001886](https://github.com/hashgraph-online/hol-guard/actions/runs/35239001886) | Windows ordinary installed scope and ARM SLO smoke pass; ARM qualification flag stays false. | Linux capacity conservation and Intel SLO gates fail as detailed below; no full qualification. |

Linux's 64-request native-wheel capacity wave retains 36 allows, including 22
native-resident and 14 native fail-safe routes, plus 28 explicit overloads and
zero transport errors. The native overload counter does not increase. The 14
fail-safes cannot be credited as evaluated native allows or silently renamed
as overload. Original individual response reasons/client codes were not captured.
The new [capacity diagnostic](native-capacity-diagnostic.md) collects bounded
failure facts on future runs without changing load or acceptance.
Intel retains recovery of 1,120.758 ms against 1,000 ms, resident-share and
safe-corpus failures with one fail-safe. Its separate capacity wave conserves
32 resident allows and 32 explicit engine bypasses; that pass does not repair
its other SLO failures.

Earlier [abf evidence](evidence/takeover-abf319/manifest.json) remains historical:
36 workflows with 31 successes/five failures; 199 all-attempt checks with
163 successes, 23 skips, 12 failures and one cancellation. Its latest 197-check
view omitted two earlier successful Gitar attempts. Its Linux narrow soak passed
100,000 requests and 250,000 receipts, its Unix scanners passed 84 cases, and
Windows scanner/transition failures preceded the later setup corrections.
Neither those passes nor [ae](evidence/takeover-ae33987/manifest.json),
[5ee](evidence/takeover-5ee52/manifest.json) or [42579](evidence/takeover-42579/manifest.json)
results replace the latest failed attempts. Source
[reconstruction](reproducibility/README.md) and the
[E supplement](reproducibility-owned-preparation/README.md) preserve exact
measured scopes; unresolved older collector attribution remains explicit.

The [transition contract](installed-artifact-transition-contract.md) still
requires seven positive phases and one strictly verified expected negative.
Four compatible successes do not close the original-baseline sequence. The
[negative-attempt review](../rsp-baseline-negative-quiescence-review.md) explains
why detached native producers require authenticated retirement before restore;
outer process exit, absent files or a single empty census are insufficient.
No protected field or persistent floor is removed to run the old baseline.
The [canary plan](CANARY_ROLLBACK_PLAN.md) remains preparation, with no activated
or qualified cohort.

The [combined d4e13547f validation](evidence/hosted-integration-d4e13547f.json)
passes **317 tests in 52.59 seconds of pytest time**, 26-file Ruff/format, and
unfiltered type analysis of all 1,253 production files with zero errors and
20,232 nonfatal warnings (149.889 seconds reported by the type tool).
Workflow-policy, authority, semantic and I/O ownership gates pass. This source
precedes the separate CodeQL root-checkout correction and its 134-test gate,
and the later config-source changes and their combined 88-test gate.
The 317 tests overlap earlier component suites; their counts are not additive.
The subsequent config-integrated 5da39f986 source passes unfiltered production
analysis of 1,254 files with zero errors/20,236 warnings in 136.815 tool seconds,
and the authority/semantic gates. Its I/O ownership gate fails on 15 new
unclassified filesystem sites in `config_source_io.py`. That failure remains
a retained failed attempt. The
[correction receipt](evidence/config-integrated-5da39f986.json) adds six exact
function/primitive classifications and protects the exact helper path. It keeps
these operations reachable as `synchronous_posture_config`, with no exclusion
or product-source change. The existing I/O/architecture suite passes 46 tests in
99.32 seconds, including actual `validate(ROOT)` and negative inventory cases;
Ruff/format and one contract type file pass with zero errors/warnings. Finite
independent review is clear. The production type/authority/semantic results stay
bound to unchanged 5da source. The 317/67/88/F44/46 test populations remain
separate and overlapping; no aggregate or installed qualification is claimed.
The manifest retains exact source and log hashes, not full log contents, and
provides no hosted execution or release qualification credit.

The earlier [bbe742e91 validation](evidence/pilots-checkpoint/source-validation.json)
retains 42-file Ruff/format passes, 147 integration tests and 1,253 production
type files with zero errors and 20,229 nonfatal warnings, including its initial
format and CRLF diff-check refusals. It is not a fresh full-source pass. Later
E, scanner fixture, macOS lookup, edge and capacity checks retain their own exact
sources and results. E's 119-test gate and three overlapping targeted tests are
not 122 unique tests. The edge report records 83 tests and six-script types with
zero errors/217 warnings; macOS diagnostics record 56 tests and zero type errors/
46 warnings. Source tests do not produce new hosted results. The older
[proof checkpoint](evidence/proof-checkpoint/source-validation.json) remains a
separate history rather than another test of the current source.

Security gates remain separate. Foundation's retained external CodeQL check
reports two high alerts; abf and the latest
[9db CodeQL check](https://github.com/hashgraph-online/hol-guard/runs/105262485275)
report three while their Actions analysis workflows succeed. The
[immutable-source diagnostic](codeql-foundation-diagnostic.md) has its own
[six exact retained archives](evidence/codeql-35239002083/manifest.json): 17
foundation and 18 implementation Python findings, zero Actions/JavaScript
findings. All 17 common rule/fingerprint pairs match, with one additional
implementation authority-key identifier result. First-run Python logs show the
current helper was also extracted outside each nested pinned tree, so exclusive
source extraction was not proved. The source review preserves public-checksum,
guessable-argv and pathname-race limits, plus the real inherited fast legacy
OAuth-secret verifier. That first capture could not obtain original alert IDs.
The later [actual PR-reference API correlation](../security/codeql-pr-alert-correlation.json)
now identifies open Python alerts [343](https://github.com/hashgraph-online/hol-guard/security/code-scanning/343)
and [344](https://github.com/hashgraph-online/hol-guard/security/code-scanning/344)
at `config.py:495/498` on both PR refs, plus implementation alert
[356](https://github.com/hashgraph-online/hol-guard/security/code-scanning/356)
at `native_command_control_authority.py:83`. Each has matching rule/location and
exact sink-file bytes with one retained SARIF result. The API supplies no SARIF
fingerprint or full taint path, so that stronger equivalence is not claimed.
The inventory also retains inherited Actions alerts 288/289 separately. No alert
was changed at that first capture. The later
[verified disposition](../security/codeql-356-disposition.json) dismisses only
356 as a false positive at 2026-09-17T17:38:43Z after review of generated 32-byte
authority keys and their role as continuity identifiers in separately
HMAC-authenticated records. A fresh PR-2954 c985 merge-ref read confirms 356
dismissed while 343/344 and inherited Actions 288/289 remain open. The global
update response names a later PR-2970 instance; all eight relevant source files
are verified byte-identical to 9db. Original failed checks remain historical;
the config-source correction below and a fresh overall security gate remain
separate from the disposition.
The [config-source correction](../security/config-source-confinement.md) now
addresses the separate pathname reads at the two open config alerts. Ordinary
loading and native publication share fixed-basename, held-directory/file capture;
unsafe or inaccessible sources raise rather than silently supplying defaults.
The inclusive 1 MiB TOML ceiling is a new ordinary-loader input limit, matching
existing safe-file/publisher bounds without altering performance thresholds.
Intentional directory aliases, logical path spelling, precedence and managed
policy remain unchanged. Windows uses existing no-reparse/locked handles and
still needs its actual-host test; there is no insecure pathname fallback.
The [publisher correction](../security/config-source-publisher-confinement.md)
hashes/parses the captured bytes and immediately withdraws `_acked` under its
condition lock on rejection at any of the three config capture sites, before
cache comparison. Nine tests cover a prior valid ACK followed by linked,
oversized or unreadable home/current/legacy workspace config without an observer
or additional transport call. This source correction does not close alerts
343/344 by itself. The subsequent
[foundation CodeQL analysis](https://github.com/hashgraph-online/hol-guard/actions/runs/35257569810)
on merge ref `72ea27ac1d847f5f03a23d956b31261315420000` reports those two old
alerts fixed, but introduces eight new `py/path-injection` findings in
`config_source_io.py`. Together with two inherited Actions findings, ten alerts
remain open for that reference, including eight new high-severity Python findings.
The later local scoped-capture correction is described below; no new dismissal or
fresh passing analysis is claimed, and the hosted gate remains unclean.
The new implementation head still needs its own hosted analysis; earlier 9db
open-alert observations are retained at their historical scope.

The [shared-reader validation](../security/config-source-validation.json) passes
67 tests with one actual-Windows-only skip, two-file types with zero errors/61
warnings and Ruff/format. Its conflict-free
[foundation application](../security/config-source-foundation-validation.json)
at `29088826f251f60d9a40f3a2fb48f9853f9b53fb` separately passes 67 tests/one skip.
The [combined publisher gate](../security/config-source-publisher-validation.json)
passes 88 tests/one skip in 6.64 seconds, five-file Ruff/format and three-file
types with zero errors/80 nonfatal warnings. These populations overlap; do not
sum them or promote them to a new full-source gate. The earlier alias/assertion
failures and disk-full attempt remain recorded, with the complete disk-full log
retained. The successful retry kept the original `/tmp` fixture location.

The final local [scoped-config receipt](../evidence/daemon-scoped-config-validation/manifest.json)
binds source `591d5c81e6bb341c6c3271332f3a6615a01bc748` and 44 retained artifacts.

Local source 591d5c81 pins the trusted configured home alias to its construction-time
canonical home and compares the admitted workspace parent before opening a config leaf.
Authorization uses held-parent metadata under existing hook-root/owned-temporary rules.
The same capture/reader is carried through publisher, daemon worker, hook-process CLI,
package reload, persisted approval and remote command/resume paths. Publisher reuse
requires the same capture object; rejected scoped capture withdraws ACK. Missing-parent
semantics remain empty input, not authorization of an absent path; standalone unscoped
CLI behavior is unchanged. This binds a canonical path and held directory during
capture, not an inode across process launches. Fresh foundation/implementation analysis
and actual Windows/installed qualification remain pending; no new alert dismissal is
claimed.

The retained 591d5c81 source validation records boundary/remote 137 passed and one
skipped; server scope 12 passed, one skipped and 102 deselected; an initial ownership
result of 46 passed/one failed on exported tomllib-helper classification, followed by
one passing actual-inventory correction and 98 passed/one skipped across
parser/config/source/reconciliation after extraction. Native authority and Python
semantic gates pass; 82 workflow-permission tests pass. Full production typing before
the two-file parser extraction covers 1,255 files with zero errors/20,241 warnings.
Final two production plus two gate files have zero errors/68 warnings; inverse
reconstruction proves the other 1,253 production files unchanged from the full run.
These populations overlap and are not summed. Initial failures, a 180-second lock
timeout with no tests executed, a wrong pytest path with no tests executed, and the
first verifier lint failure remain retained. Hosted and installed qualification are not
established.

The root-checkout correction stages the exact collector outside, preserves the
workflow definition, places the pinned tree at the actual extractor root and
checks cwd/root/hashes/cleanliness. Its 134 tests pass in 3.64 seconds with
lint/type/policy; corrected hosted extraction remains pending. The
[9db Sonar check](https://github.com/hashgraph-online/hol-guard/runs/105267394714)
reports new security and reliability C against A; its other conditions pass,
including 82.3% new coverage, zero duplication and all hotspots reviewed.
The [42-finding Sonar review](../security/sonar-rsp-9db-review.json) changes only
two deterministic generator paths to test classification, retains test analysis,
and proposes six exact runtime false-positive dispositions. The later
[inline disposition record](../security/sonar-reviewed-inline-dispositions.json)
implements four exact line-and-rule comments for those six findings after
independent positive/negative-path review. Current source hashes and unchanged
Python ASTs are recorded; all runtime guards and other rules remain in scope.
No external issue-state transition or fresh quality-gate pass is claimed.

The new [macOS DNSService diagnostic](macos-dnsservice-diagnostic-contract.md)
adds bounded hosts/configuration/callback observations after qualification;
it changes neither hosts/service/cache state nor the immutable baseline. Local
native-daemon AF_UNIX restrictions remain an environment limitation in the
recorded attempts. No source or synthetic listener test supplies a missing
actual installed daemon result. New code and diagnostics require new hosted
artifacts and checks.

## Frozen qualification and release gates

| Boundary or evidence | Original requirement |
| --- | --- |
| Installed warm c1 | p95 ≤50 ms; p99 ≤100 ms |
| Installed c16 | p99 ≤200 ms; zero errors |
| Native client / cold native | p95 ≤20 ms / p95 ≤150 ms |
| Readiness | ≤400 ms after fixture materialization; full startup separately reported |
| Sampling | At least five alternating independent runs; 10,000 priority warm, 1,000 other-route, 100 priority cold, 100 recoveries and 30 resource observations in their specified scopes |
| Selected hot tranche | ≥30% p95 or CPU benefit, ≤5% regression in the other primary metric |
| Optional ingress | ≥25% private-memory or ≥30% c16 p99 benefit; existing RSS-growth safeguards remain |

Build separately installed locked baseline/candidate artifacts for Linux x64,
macOS x64, macOS ARM and Windows x64. Clear development overrides and retain
package/source/runtime/rule/program/manifest identities, complete attempts and
independent driver/daemon/helper/resident resources. Keep error, rejection,
timeout, late and unsupported outcomes in their declared route/platform series.
Historical warm ≤20 ms OR ≥1.15x, cold ≤150 ms AND ≥5x and 1000 ms diagnostic
adapter gates are not substitutes for the PRD.

Only a stable candidate may enter the full `rust-performance-qualification`
label mode. Any code/dependency change requires qualification of the resulting
head. Source implementation remains to be completed where the ledger says so;
missing installed measurements are not the only outstanding work. Conditional
ports must follow optimized-baseline profiling and the original decision rule;
large unmeasured workloads cannot inherit a small-workload no-go.

Foundation #2951 now publishes the shared-reader fix at
`a7b675a84b732ead542cdf77e5153c57b4257d9b`, with exact branch readback. Its new
CodeQL analysis fixes old 343/344 but reports eight new path findings and two
inherited Actions findings; all ten remain open in that retained hosted observation. Local 591 scoped
capture and propagation fixes require newly published foundation/implementation
analysis; no additional alert has been dismissed. Earlier e449's
179 check records remain **159 successful, 19 skipped and one failed CodeQL
check** at that historical scope. Protected auto-merge and Greptile 5/5 still do
not supply the required independent last-push CODEOWNER approval. The separate
abf and 9db application checks retain their three-high-alert failures despite
successful CodeQL Actions workflows; 9db Sonar also remains failed. Implementation
#2954 remains draft pending coherent final code, passing required checks, final
Greptile review and independent approval.
The [release ruleset](https://github.com/hashgraph-online/hol-guard/rules/14511015)
requires strict `quality`, resolved conversations and one independent last-push
code-owner approval, with stale approvals dismissed and no configured bypass
actors. Automated reviews and the author's own approval cannot satisfy it.

Prepare a candidate/prior-version manifest, per-platform/harness internal canary
cohorts, stop conditions and an actual rollback transcript before activation.
Stop on semantic mismatch, replay, stale stricter policy, leaked private evidence,
identity failure, unsupported capability, unbounded queues or failed route/resource
gates. Retire affected generations, restore verified package and registration,
then verify the restored runtime and acknowledged policy on new requests. Never
lower persistent floors or reopen hidden Python fallback; ambiguous tool
execution is not automatically retried. No merge, canary or release completion
is recorded at this checkpoint.
