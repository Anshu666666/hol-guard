# Rust performance execution for release/3.2

This record implements the original [PRD](PRD.md) and [144-task TODO](TODO.md).
Their acceptance conditions, dependency text and performance thresholds are
unchanged. The exact source conversation is [Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1),
verified by its title, full conversation, linked documents and implementation
[#2954](https://github.com/hashgraph-online/hol-guard/pull/2954). The user's later
instruction authorizes this session to take over implementation through GitHub
on `release/3.2`. The original proposal-only wording does not narrow that scope.

This checkpoint reviews source through `7befd329a00f9689b6d648750e64f58082e8986d` on
`codex/rsp-takeover-pilots-20260917`, dated 2026-09-17. The ledger records
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
| Foundation | [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951), `e449594e86c717e66e14598a4130475de79c536f` |
| Last published implementation before this checkpoint | [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954), `abf319d5a345d761d88e26ba787026e98370c26f` |
| Verified published Git tree | `62eb319323cc7c9de7513af6ef7f05009d411189` |
| Actual native-wheel build at that checkpoint | GitHub test-merge `70b456e93a77fff48522ee7aa6ddeec6d157f6e6`, same Git tree; paired candidate wheels explicitly build `abf319d5a` |
| Current source cutoff | `7befd329a00f9689b6d648750e64f58082e8986d` |
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
| Offline scanner | Bounded Git object streams, immutable blob reuse, shared traversal, lazy full-file context and a descriptor-bound working reader with explicit mutation/incomplete behavior | Final native source comparison gives CPU −31.6% and p95 wall +13.5%, so extraction stays inactive. Actual abf retained-Python scanner passes 84 cases on three Unix hosts; Windows fails before its first case. Source fixes need a fresh hosted attempt. |
| Archive worker | [510 actual isolated calls and 60 profiles](archive-worker-qualification.md); 508 exact outcomes, two fail-closed timeouts plus an earlier warmup timeout retained; 330 hostile cases remain non-clean | Retain current isolated worker in measured scope; no qualified native worker or whole-worker no-go |
| MCP | Immutable catalog digest, bounded protocol queues/deadlines, idle notification draining and literal prefilters; completed B/C/D and 68-cell native experiment retain exact outcomes | C and universal D activation regress supported inputs. The native text helper also fails its 30%/5% gate; production retains B. RSP-100 private owned-generation work is active with no claimed result; installed/platform qualification remains separate. |
| Private Claude launcher | Implemented Linux Pre/Post command, authenticated package/registration, original challenge/POST and contained completion; final component snapshot passes 81 Python and 12 Rust tests | Later helper integration has separate focused validation. Actual installed wheel parity, route conservation, cold/warm benefit and broader platform/signing/rollback remain pending; no default registration selects the pilot. |
| Runtime identity and posture | Verified live Linux generation reuse on supported filesystems, complete validation on replacement/unsupported systems; all ordinary native evaluation and delivery consume the same acknowledged posture without config rereads | Signing/frozen artifacts, installed transitions and benefit remain separate |
| Command extensions | Trusted compiler, bounded typed Rust interpreter, indexed matching and complete observations, authenticated control fence, durable complete receipts; [638 catalog/control combinations](../native-command-matrix-performance.md) | Final activated contribution lifecycle, exact installed benefit and update/downgrade proof |
| Approval | Codex's genuine waiting process receives fresh native review under the SH control lease and atomic existing local Allow once consumption; authenticated terminal replay, process/deadline checks and restrictive native failures | Four installed fault scenarios implemented and 134 focused tests pass; actual host results remain required |
| Evidence and inventory | Compact facts, atomic SQL batches, append/checkpoint replay, stable attempts, precise DB/WAL reconciliation, captured inputs and one positive root discovery per call | Installed contention/soak, unavailable VFS measurements and real cloud/Cisco/incremental evidence |
| Mixed and registered routes | Actual hook/control/ACK/receipt/inventory/recovery runners and registered route probes; abf Linux native-wheel soak passes 100,000 requests and 250,000 receipts | The narrower soak does not complete mixed offered-load, all-platform resources, whole daemon restart or the original frozen qualification minima |
| Ollama and Builder | Actual abf Linux/ARM pass 22 Ollama cases each; all four Builder checks pass; compatible stopped rollback passes on three Unix hosts | Intel/Windows retain readiness failures. Original-baseline quiescence, Windows transition, live/in-progress/version/signing and final lifecycle qualification remain open |

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

The installed scanner probe binds case success to complete semantic validation.
Its [installed report](../rsp-scanner-installed-qualification.md) retains all 28
local pure-wheel cases and the original build-tool limitation. Actual abf
native-bundled wheels then pass those 28 cases on each of Linux, macOS ARM and
macOS Intel: **84 passes, no skips**. Both console entrypoints, staged bytes,
all 17 providers, limits, HMAC, links, encoding, history and mutation are covered.
Windows raises `PackageNotFoundError` during initial attestation, before any
identity or scanner case; its CRLF probe digest is retained. The environment
correction needs a fresh hosted attempt. These are retained-Python functional
checks, with no native detector activation. Capture limits apply after process
exit and do not constitute a live child-output disk quota.

The [MCP native experiment](../rust-performance-mcp-native-text.md) is complete:
68 retained cells, 1,692 forwards and 34 exact pairs. Five-block near-limit
ASCII median improvements are 24.95% p95 and 14.65% tree CPU; Unicode improves
22.75% and 29.711838%, respectively. Neither reaches 30%, and individual blocks
and ordinary/early-positive controls regress. The helper remains inactive.
Its full route includes normalization, private encoding, both IPC directions
and helper CPU. Two forced-native oracles each cover the same 3,008 distinct
cases, with exact categories, approval hashes and complete decisions; they do
not establish 6,016 distinct fixtures or installed qualification.

RSP-098/103 source measurements, RSP-104's bounded prototype contract and
RSP-108's continued full-rewrite deferral decision are complete. RSP-105/107
activation and positive qualification are deferred for this tested boundary.
RSP-106 keeps its existing current-proxy correctness scope. **RSP-100 remains
OPEN**: B still derives categories separately for approval identity and fresh
policy. A private owned-generation implementation attempt is active outside
this frozen source cutoff, with no claimed implementation or measured result.
The [ownership audit](../mcp-request-facts-ownership-audit.md) preserves public
copy/match fallback, callback mutation ordering, browser/store/claim composition
and exact forwarding binding. The final 5 ms freshness barrier is unchanged.

The [private Claude launcher](claude-native-launcher-pilot.md) is implemented
and component-tested, with no default selection. The final component snapshot
passes 81 Python and 12 Rust tests; later handoff/type corrections pass 43
focused tests and the independent builder/runner selection passes 27 tests.
Those later checks do not relabel the earlier snapshot as a complete native
rerun. Its installed probe is integrated, but actual wheel identity, daemon
receipts, route conservation and paired benefit remain pending. Unsupported
HTTP framing and detailed timeout outcomes retain their stated conformance
limits. A synthetic authenticated listener cannot supply an installed result.

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
gates, stop conditions and stopped-transition commands. Its machine manifest keeps
candidate identity pending and qualification, activation and tested rollback false.
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

At `abf319d5a345d761d88e26ba787026e98370c26f`, all 36 workflows completed:
**31 successful and five failed**. The [all-attempt check inventory](evidence/takeover-abf319/github-check-inventory.json)
is a separate population: **199 records, with 163 successful, 23 skipped, 12 failed
and one cancelled**. The latest view has 197 records and 161 successes because it
omits two earlier successful Gitar attempts; its other counts are unchanged.
Legacy CodeRabbit explicitly skipped review because the PR is draft. The CodeQL
application check reports three new high severity alerts. A
successful CodeQL Actions workflow does not clear that application failure.
This checkpoint remains smoke, with no complete paired platform comparison.
The [canonical abf manifest](evidence/takeover-abf319/manifest.json) retains all
51 JSON members from eight exact workflow archives, unchanged decoded values,
original and retained hashes, and five wheel-member hashes. Eight scanner/build
records retain their existing canonical locations. Earlier [ae](evidence/takeover-ae33987/manifest.json),
[5ee](evidence/takeover-5ee52/manifest.json) and [42579](evidence/takeover-42579/manifest.json)
attempts remain historical evidence.

| Workflow / target | Actual abf observation | Remaining proof or source correction |
| --- | --- | --- |
| [Paired qualification 35229526455](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526455), all platforms | Both arms attempted everywhere. Only Windows baseline completed one smoke block; every candidate block failed. | No complete pair, speedup or full qualification is inferred. New source requires freshly built artifacts. |
| Same run, Linux baseline | The unchanged validator rejects the current-owned interpreter symlink target at mode 0777. | Disposable venv provisioning now copies identical bytes to a private owned 0755 interpreter and checks real ABI/SQLite/SSL/prefix behavior plus the installed validator; shared source, permissions and trust rules remain unchanged. Hosted proof is pending. |
| Same run, macOS baselines | `getfqdn` stalls during daemon-fixture construction. The exact helper waits with `_receive(30.0)`; failure JSON does not report observed construction duration. | Separate read-only libc probes each have a five-second bound. Selected root-owned resolver configuration and `scutil` listing do not prove actual query routing or reachability. No resolver repair is proven. |
| Same run, candidate route failures | Linux `omp.PostToolUse.block.max`, ARM `cursor.afterShellExecution.block.max` and Windows `claude-code.afterWriteFile.alias.1k` lack a native result. Intel fails hook-process-capacity startup at its deadline. | Preserve route conservation and actual failures. Bounded diagnostics and the private Claude installed probe require a new hosted attempt. |
| Same run, Ollama and Builder | Linux/ARM pass 22 Ollama cases each. Intel fails disabled readiness at 527.241 ms after ten cases; Windows fails enabled readiness at 407 ms after two. All four Builder checks pass. | Keep the 400 ms readiness gate. Earlier ae four-host successes cannot replace current partial failures. |
| Same run, scanner | Linux/ARM/Intel pass 28 cases each; Windows fails initial distribution attestation before any case. | Keep all 84 passes and the zero-case failure. Windows environment/reader corrections are source-tested, with new hosted execution pending. |
| Same run, compatible rollback | Candidate/prior-a224/candidate passes all three stopped phases on all three Unix hosts. | This is same-version 3.0.1 artifact replacement. Live, in-progress, changed-version/program, signing and enrollment transitions remain unqualified. |
| Same run, original-baseline downgrade | Clean baseline, upgrade and reinstall pass. Downgrade rejects `native_policy_snapshot_unknown_field`; six receipts and protected authority survive, but legacy stop returns 2. | Quiescence is unverified, expected-negative acceptance remains false and candidate restoration was not attempted. Detached native producers require the separate containment design; outer-process retirement alone is insufficient. |
| Same run, Windows transition | Cleanup is unverified, followed by exception-reporting import failures; no transition JSON is uploaded. | Preserve original job logs. Case-insensitive executable selection and scoped reporter fixes need actual hosted execution. |
| [Native wheel 35229526436](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526436) | Linux/Windows workflow scopes pass. Linux completes 100,000 requests and 250,000 receipts with zero errors/health failures and a stable daemon. Both macOS jobs fail a large source-reference witness without a native result. | The record keeps `qualification_complete:false`. The narrower soak does not complete mixed offered-load, all-platform resources or the frozen sampling minima. |

Paired candidate wheels explicitly build abf. Native-wheel artifacts report the
actual GitHub test-merge build `70b456e93a77fff48522ee7aa6ddeec6d157f6e6`; both
have Git tree `62eb319323cc7c9de7513af6ef7f05009d411189`. Compatible prior wheels
retain their separate actual build `a224cc2e01e1eb8d74182fa32d78f46e9b417348`,
associated ae PR head and exact artifact hashes. A PR head alone is insufficient
artifact identity. [Reconstruction recipes](reproducibility/README.md) preserve
exact measured source and collector scopes against public bases; unresolved
historical collector attribution remains explicit.

The [transition acceptance contract](installed-artifact-transition-contract.md)
requires seven positive phases across two isolated sequences and a strictly
verified expected-negative legacy downgrade. The abf compatible sequence passes;
that does not repair the failed legacy sequence. The [negative-attempt review](../rsp-baseline-negative-quiescence-review.md)
records why the original baseline's detached client/supervisor graph requires
producer-aware retirement before restore. It is a design requirement, not a
passing containment certificate. Never remove protected fields or lower floors
to make the old baseline run. Historical wheel selection remains a separate
15-second contained child inside the mandatory transition check; independent
paired, Ollama and scanner checks still retain their own results.

The [latest source validation](evidence/pilots-checkpoint/source-validation.json)
pins `bbe742e91ed1ecc407837677f92517e213791114` and records 42 changed Python
files passing Ruff and formatting, **147 integration tests passing in 7.76 seconds
of pytest time**, and all 1,253 production files passing the unfiltered type gate
with zero errors and 20,229 nonfatal warnings. The type tool reports 150.299 seconds
(153.987 seconds wall time). Authority, semantic, I/O ownership and workflow-policy
gates pass. This finite integration set is not a full-suite or installed pass.
The initial one-blank-line formatting refusal remains separate. A later aggregate
attempt failed `git diff --check` on two exact retained Windows CRLF artifacts;
file-specific interpretation was corrected with all artifact bytes unchanged,
and the final diff check passes. The manifest keeps those attempts and their
lossless logs. Production source did not change after the recorded validation.
The earlier [proof checkpoint](evidence/proof-checkpoint/source-validation.json)
keeps its 585-pass/eight-failure attempt, 111 corrected checks and later 67 checks
at their own snapshots; they are not new tests of this checkpoint.

Foundation and implementation have distinct unresolved security checks.
[Foundation check 105075778732](https://github.com/hashgraph-online/hol-guard/runs/105075778732)
reports two high severity alerts; [abf check 105229882410](https://github.com/hashgraph-online/hol-guard/runs/105229882410)
reports three new high severity alerts. The exact findings and introduction point
remain unknown; a full PR analysis can surface pre-existing findings. The
[CodeQL diagnostic](codeql-foundation-diagnostic.md) implements six jobs:
Actions, JavaScript and Python for each immutable e449 and abf source. It retains
the observed settings and raw SARIF in Actions artifacts with no Code Scanning
or database upload. The 121-test expanded source validation does not resolve either alert set;
actual runs, source attribution and any required correction remain pending.

The local environment denies AF_UNIX socket creation. Source tests and builds can
run here; actual installed daemon/launcher qualification must run on supported
GitHub hosts. This limitation is not a production failure observation or permission
to change the runtime transport.

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

Foundation #2951 retains normal protected auto-merge and Greptile 5/5, but its
179 check records are **159 successful, 19 skipped and one failed CodeQL check**.
Its two high alerts and required independent last-push CODEOWNER approval remain
open. The separate abf application check reports three high alerts despite its
successful CodeQL Actions workflow. Implementation #2954 remains draft pending
coherent final code, passing required checks, final Greptile review and approval.
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
