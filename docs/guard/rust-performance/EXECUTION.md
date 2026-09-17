# Rust performance execution for release/3.2

This record implements the original [PRD](PRD.md) and [144-task TODO](TODO.md).
Their acceptance conditions, dependency text and performance thresholds are
unchanged. The exact source conversation is [Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1),
verified by its title, full conversation, linked documents and implementation
[#2954](https://github.com/hashgraph-online/hol-guard/pull/2954). The user's later
instruction authorizes this session to take over implementation through GitHub
on `release/3.2`. The original proposal-only wording does not narrow that scope.

This checkpoint reviews source through `4ea1f8f76049cc8bf5b69b34078da42bb14c6ead` on
`codex/rsp-takeover-qualification-20260917`, dated 2026-09-17. The ledger records
**64 DONE, 40 OPEN, 40 BLOCKED and 0 DEFERRED**. These are individual acceptance
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
| Last published implementation before this checkpoint | [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954), `5ee52a03e62b9e4940063b348185bedaddf0cb53` |
| Verified published Git tree | `7580ea94e4847762df8eb8eed6dfefc26a692551`, identical to local `c0445a0db64804b4ee22f96820f357320726036b` |
| Current source cutoff | `4ea1f8f76049cc8bf5b69b34078da42bb14c6ead` |
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
| Package | Verified immutable bundle indexes, captured bytes, one parse per supported JSON/JSONC/TOML/Yarn/pnpm/Bundler format, atomic evidence; 36-cell matrix completed with 31 comparable pairs and five incomplete pairs retained | Corrected controls and bounded native npm format pilot; no activation claim |
| Offline scanner | Bounded Git object streams, immutable blob reuse, shared traversal, lazy full-file context; benchmark-only ASCII native span extractor keeps Python rich finding/HMAC/completeness ownership | Full-command pilot comparison is active; small staged controls regress, no global benefit claim |
| Archive worker | [510 actual isolated calls and 60 profiles](archive-worker-qualification.md); 508 exact outcomes, two fail-closed timeouts plus an earlier warmup timeout retained; 330 hostile cases remain non-clean | Retain current isolated worker in measured scope; no qualified native worker or whole-worker no-go |
| MCP | Immutable catalog digest, bounded protocol queues/deadlines, real idle notification draining and literal risk prefilters; 41 baseline stdio cells with 3,370 attempts and no unexpected outcomes | Optimized route comparison active; duplicate category derivation remains RSP-100 OPEN |
| Runtime identity and posture | Verified live Linux generation reuse on supported filesystems, complete validation on replacement/unsupported systems; acknowledged observe avoids a reread | Enforcing posture transfer, signing/frozen artifacts and platform transitions remain separate |
| Command extensions | Trusted compiler, bounded typed Rust interpreter, indexed matching and complete observations, authenticated control fence, durable complete receipts; [638 catalog/control combinations](../native-command-matrix-performance.md) | Final activated contribution lifecycle, exact installed benefit and update/downgrade proof |
| Approval | Codex's genuine waiting process receives fresh native review under the SH control lease and atomic existing local Allow once consumption; authenticated terminal replay, process/deadline checks and restrictive native failures | Four installed fault scenarios implemented and 134 focused tests pass; actual host results remain required |
| Evidence and inventory | Compact facts, atomic SQL batches, append/checkpoint replay, stable attempts, precise DB/WAL reconciliation, captured inputs and one positive root discovery per call | Installed contention/soak, unavailable VFS measurements and real cloud/Cisco/incremental evidence |
| Mixed and registered routes | Actual hook/control mutation/ACK/first receipt/inventory/resident recovery; genuine priority/nonpriority registrations, approval and malformed-input helpers integrated | Host activation, whole daemon-process restart, full resources and long soak remain incomplete |
| Ollama and Builder | Wheel-only contribution and Builder probes, strict build/runtime/package identity, complete receipt binding | Linux/macOS ARM pass the 5ee lifecycle probe; Windows/Intel exceed readiness; no four-platform package/program rollback pass |

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

The native scanner experiment is deliberately outside production entry points.
It supports ASCII documents up to 4 MiB and returns bounded candidate spans;
Python owns provider classification, context, rich findings, HMAC and completeness.
Non-ASCII or larger inputs explicitly use the current Python path. An interrupted
measurement during build-target relocation remains failed and unqualified; later
cohorts record the changed executable backing separately. No failing or confounded
sample is silently discarded.

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

At `5ee52a03e62b9e4940063b348185bedaddf0cb53`, all 36 workflows completed:
**32 successful and four failed**. This is smoke, not frozen full qualification.
All16 JSON members are retained in [5ee evidence](evidence/takeover-5ee52/manifest.json). Earlier failures remain in [42579 evidence](evidence/takeover-42579/manifest.json).

| Workflow / target | Observed result | Source action after that run |
| --- | --- | --- |
| [Paired qualification 35213401779](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401779), Linux and Windows | Baseline Watch oracle expected fields/reasons that the resident edge does not produce | Correct intrinsic/delivered expectations; retain reason hashes |
| Same run, macOS ARM and Intel | Baseline HTTPServer construction stalls in `socket.getfqdn`; before/after/cleanup DNS probes time out; exact resolver receives zero packets | Keep 400 ms readiness and baseline unchanged; add read-only resolver configuration/selection and responder self-probe diagnostics |
| Same run, Ollama | Linux and ARM complete 22 native cases and overall verification; Windows late stale-write readiness 406.0 ms, Intel enabled readiness 430.438 ms; all four Builder probes pass | Preserve completed cases and exact failing phase even when a later readiness bound fails |
| [Native wheel 35213401455](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401455) | Windows/ARM pass; Linux registered launcher route witness and Intel full-source witness fail | Add bounded actual verdict/reason/route/process/sample/progress JSON; exact cause awaits next host run |
| [Desktop 35213401527](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401527) and [CI 35213401782](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401782) | Command fixture source bindings stale; CI also records one 48-review scheduler deadline failure | Regenerated only source-binding metadata with unchanged decisions; fix proven idle-wake rebroadcast loop; exact48-way test passes with unchanged budgets; original CI sole cause remains unproven |

The wheel run's observed build SHA `caf8b4bfa714eba56f30401ef244bbf6a72b7d75`
is a GitHub test-merge commit. It is not the explicit 5ee checkout used by paired
qualification; never identify artifacts by PR head without verification.

The stopped artifact transition probe is now integrated with five phases: baseline, candidate upgrade, same-candidate reinstall, baseline artifact rollback and candidate restore. A third isolated environment retains one protected authority, unchanged original registration and complete prior receipts. Exact-build-gated legacy readback handles the baseline without dropping candidate bindings. Every replacement requires witnessed retirement. Both versions are3.0.1; version/program downgrade, live mixed generations, signing and enrollment remain explicitly unqualified pending their own evidence.

Current source additionally attempts both arms of a failed pair, retains completed
opposite-arm evidence and emits an incomplete-pair report without manufacturing
a comparison. Source tests verify installed failure JSON and flat Codex fault
proof survive real aggregate sanitization. These repairs require new host runs;
they do not make the earlier failures pass.

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
