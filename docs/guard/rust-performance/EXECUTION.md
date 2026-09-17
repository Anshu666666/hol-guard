# Rust performance execution for release/3.2

This record implements the original [PRD](PRD.md) and [144-task TODO](TODO.md).
Their acceptance conditions, dependency text and performance thresholds are
unchanged. The exact source conversation is [Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1),
verified by its title, full conversation, linked documents and implementation
[#2954](https://github.com/hashgraph-online/hol-guard/pull/2954). The user's later
instruction authorizes this session to take over implementation through GitHub
on `release/3.2`. The original proposal-only wording does not narrow that scope.

This checkpoint reviews source through `ffec9b2d384e3a5069544d4428d0e4b3ddfaa74b` on
`codex/rsp-takeover-proof-20260917`, dated 2026-09-17. The ledger records
**70 DONE, 33 OPEN, 33 BLOCKED and 8 DEFERRED**. These are individual acceptance
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
| Last published implementation before this checkpoint | [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954), `ae33987d0c8675c36a77375e03419aee920825f6` |
| Verified published Git tree | `f292bc95eb53af29162fcc8ea7e46a4b213803b7`, identical to local `8aa2b63ee33bdebbb170678f500b0405bb3bea58` |
| Current source cutoff | `ffec9b2d384e3a5069544d4428d0e4b3ddfaa74b` |
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
| Offline scanner | Bounded Git object streams, immutable blob reuse, shared traversal, lazy full-file context and a descriptor-bound working reader with explicit mutation/incomplete behavior | Final 30-pair rich-CLI comparison gives CPU −31.6% and p95 wall +13.5%; standalone span-extraction subprocess remains inactive. Both installed console entrypoints pass28 local pure-wheel cases; actual four-host native-wheel qualification remains pending. |
| Archive worker | [510 actual isolated calls and 60 profiles](archive-worker-qualification.md); 508 exact outcomes, two fail-closed timeouts plus an earlier warmup timeout retained; 330 hostile cases remain non-clean | Retain current isolated worker in measured scope; no qualified native worker or whole-worker no-go |
| MCP | Immutable catalog digest, bounded protocol queues/deadlines, real idle notification draining and literal risk prefilters; 41 baseline stdio cells with 3,370 attempts and no unexpected outcomes | First exact-facts candidate preserves semantics but regresses 128-KiB p95 by 47.79% and CPU by 17.22% against optimized Python. Structural candidate also regresses dense supported shapes. Runtime wiring is restored to optimized Python; explicit facts/native experiments remain active. |
| Runtime identity and posture | Verified live Linux generation reuse on supported filesystems, complete validation on replacement/unsupported systems; all ordinary native evaluation and delivery consume the same acknowledged posture without config rereads | Signing/frozen artifacts, installed transitions and benefit remain separate |
| Command extensions | Trusted compiler, bounded typed Rust interpreter, indexed matching and complete observations, authenticated control fence, durable complete receipts; [638 catalog/control combinations](../native-command-matrix-performance.md) | Final activated contribution lifecycle, exact installed benefit and update/downgrade proof |
| Approval | Codex's genuine waiting process receives fresh native review under the SH control lease and atomic existing local Allow once consumption; authenticated terminal replay, process/deadline checks and restrictive native failures | Four installed fault scenarios implemented and 134 focused tests pass; actual host results remain required |
| Evidence and inventory | Compact facts, atomic SQL batches, append/checkpoint replay, stable attempts, precise DB/WAL reconciliation, captured inputs and one positive root discovery per call | Installed contention/soak, unavailable VFS measurements and real cloud/Cisco/incremental evidence |
| Mixed and registered routes | Actual hook/control mutation/ACK/first receipt/inventory/resident recovery; genuine priority/nonpriority registrations, approval and malformed-input helpers integrated | Host activation, whole daemon-process restart, full resources and long soak remain incomplete |
| Ollama and Builder | Wheel-only contribution and Builder probes, strict build/runtime/package identity, complete receipt binding | All four ae hosts pass 22 native Ollama cases and Builder; old-baseline downgrade rejects stronger authority, with compatible rollback still open |

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

The installed scanner probe binds its case status to complete semantic validation,
not merely a zero process exit. Its [local installed report](../rsp-scanner-installed-qualification.md)
retains all28 passing pure-wheel cases and the exact module, probe and wheel hashes,
as well as the initial build-tool limitation. Both console entrypoints, staged
bytes, all17 provider formats, default/explicit limits, HMAC, links, encoding,
history and mutation are covered. The four hosted native-wheel receipts remain
required; the temporary-file capture limit is a post-exit parsing bound, not a live
child-output disk quota.

The [installed posture contract](installed-posture-transition-contract.md) now
exercises four real installed daemon groups under concurrent Claude/Codex Pre/Post
load: enforce/Watch and resident restart, a first stricter workspace, genuine
publication-lock timeout with automatic recovery, and short-lived renewal/expiry.
Every observed decision binds to independently authenticated acknowledged authority
and a complete durable receipt; intrinsic block and Watch delivery remain distinct.
The frozen source suite passes111 tests. An earlier95-pass/1-fail attempt and its
unchanged diagnostic are retained; no actual400ms recovery result is inferred.

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

At `ae33987d0c8675c36a77375e03419aee920825f6`, all 36 workflows completed:
**30 successful and six failed**. This is smoke, not frozen full qualification.
The [installed fixture follow-up](installed-fixture-ae-followup.md) retains all
eight baseline/candidate failure leaves. The [ae manifest](evidence/takeover-ae33987/manifest.json)
retains all 47 JSON members from eight exact workflow archives with unchanged
decoded values, original/retained hashes and five binary-member hashes. Earlier [5ee evidence](evidence/takeover-5ee52/manifest.json)
and [42579 evidence](evidence/takeover-42579/manifest.json) remain historical.

| Workflow / target | Observed result | Source action or remaining proof |
| --- | --- | --- |
| [Paired qualification 35217841349](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841349), all four candidates | Short-lived expiry renewal omitted the existing protected command binding; runtime correctly rejected removal | Preserve the full existing binding and original budgets; require accepted ACK and authenticated readback. New host evidence remains required. |
| Same run, Linux baseline | Exact interpreter-permissions integrity rejection | Retain finite reason and read-only mode/ownership classes; no permission repair or baseline change is inferred. |
| Same run, Windows baseline | Recovery sample 0 fails | Retain serial sample and actual delivery/route evidence through a scoped context; no retry or deadline change. |
| Same run, both macOS baselines | `getfqdn` stalls; exact root-owned resolver selected, direct UDP probe passes, no libc-origin packets arrive | Baseline and readiness budget unchanged. A bounded read-only owned-child lookup/stack witness is integrated for the next host run; actual cause remains unknown. |
| Same run, Ollama and Builder | All four hosts pass 22 installed native Ollama cases and Builder | Full changed-program/version/signing/in-progress rollback remains separate. |
| Same run, artifact transitions | Linux and both macOS hosts pass baseline upgrade and same-candidate reinstall; six receipts survive strict original-baseline downgrade, which then fails readiness; Windows lacks completed initial worker evidence | Preserve stronger command floor, prove failed-start containment and restore candidate; add a third exact compatible prior-candidate wheel for functional rollback. |
| [Native wheel 35217841356](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841356) | Windows/ARM pass; Linux/Intel fail capacity route conservation | Keep exact conservation; add bounded route, delivery, native-health and transport-error evidence to identify the mismatch. |
| [CI 35217841260](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841260) | Collection imports the wrong `ci` package; scheduling-sensitive job 105190459240 passes | Remove scanner test's global `sys.path` mutation. Full combined collection now succeeds with 21,035 tests and six existing deselections. |
| [I/O ownership 35217841406](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841406) and [authority ownership 35217841390](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841390) | Experimental scanner crate lacks an explicit ownership entry | Add benchmark-only ownership without activating any hook route; permanent gate passes against release base. |
| [Security Gates 35217841449](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841449) | Four source-file SHA-256 values match the generic-key detector | Verify exact published bytes and add only four exact finding fingerprints; Gitleaks 8.24.2 rescans 1,257 commits with zero findings. |

The native-wheel run uses a GitHub test-merge build (`a224cc2e01e1eb8d74182fa32d78f46e9b417348`),
while paired qualification explicitly checks out ae33987. Each artifact must retain
its observed source/build/tree identity. PR head alone is insufficient.

The original baseline has no command-program schema and cannot authenticate the
candidate's combined protected command floor. Removing that field or resetting
its floor would invalidate the downgrade test. Its failure remains a retained
negative result. The [explicit transition acceptance contract](installed-artifact-transition-contract.md)
requires seven positive phases across two isolated sequences and one strictly
verified expected-negative legacy downgrade. It checks exact compatible prior
wheels, registration, all receipts, protected authority and authenticated
containment before restoring the candidate. The original failed phase and its
four-of-five positive counter remain false/incomplete; separate suite acceptance
cannot describe the old baseline as functional. Historical wheel selection runs
in a separate15-second contained child inside the mandatory transition check.
Missing, changed or incorrectly identified bytes fail that check; paired, Ollama
and scanner checks remain independently attempted and aggregate failure is retained.
Actual new host evidence is pending.
Both original wheels are version 3.0.1; same-version artifact replacement does
not establish version/program, signing, enrollment or live-generation rollback.

Current source preserves both attempted arms, bounded failure evidence and every
incomplete comparison. The new expiry/recovery diagnostics do not make earlier
failures pass. The acknowledged-posture and exact MCP facts changes also require
qualification of the final combined artifacts. The latest production type gate has zero errors; its unfiltered diagnostic
warnings remain explicit in the source validation manifest. Production source is
unchanged since that type check;
focused source, pilot and boundary tests retain their own recorded scopes.
Combined fixture checks pass 149 tests for expiry/recovery/capacity, installed
transitions and workflow/ownership selection. A separate integrated production
run passes 68 tests with 55 explicit native-example/environment skips; those skips
are not native passes. The built pilot's earlier explicit-binary tests remain
separate evidence. The permanent ownership gate passes against the release base.
The [combined source validation](evidence/proof-checkpoint/source-validation.json)
retains the585-pass/eight-failure initial attempt,111 passing corrected checks,
67 final scanner/ordering checks and64-file Ruff/format verification. The earlier
collection of21,278 selected tests is collection evidence, not a full-suite pass.

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

Foundation #2951 has normal auto-merge enabled and previously verified 25 green
workflows, 33 resolved threads and Greptile 5/5. It still needs independent
CODEOWNER approval of the last push. Implementation #2954 remains draft pending
coherent final code, passing checks, final Greptile review and required approval.
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
