# Rust performance execution for release/3.2

This is the implementation record for the original [PRD](PRD.md) and
[144-task TODO](TODO.md). Their requirements are unchanged. The user subsequently
authorized completing the work in `release/3.2`; the old proposal-only wording
does not limit that authorization. [TAKEAWAY.md](TAKEAWAY.md) is now the current
continuation prompt; its original proposal version remains in Git history.
No merge, canary deployment or release completion is recorded here.

This audit covers source at `264da76d3bca7a1a4f4970834291ca48d7c7a3c2`
on local branch `work/rsp-performance-32`, dated 2026-09-17. The documentation
worktree is `rsp/execution-ledger-final`. There are **62 DONE, 41 OPEN and
41 BLOCKED** acceptance records, with **0 DEFERRED**. These are task statuses,
not a percentage of production qualification.

The current [execution ledger](EXECUTION_LEDGER.md) records acceptance evidence
and missing dependencies for every task. `OPEN` can include tested code whose
broader acceptance still requires installed measurements. `BLOCKED` means a
dependency is unmet. `DEFERRED` is reserved for a measured no-go; an unbuilt
optional Rust component is not automatically a completed investigation.

## Source and reconciliation

| Identity | Value |
| --- | --- |
| Audited/current-main implementation baseline | `2e672d2d950c6ec471005ddba46e49bba16dc23b` |
| Original release/3.2 target | `4b89e0d2d496a85f04922b2e019a4aea15326bb9` |
| Main lineage already carried by release squash | `c996b1d243ddafe8bef04d26ba939615edebb1e7` |
| Local reconciled foundation | `c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8` |
| Published foundation PR | [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951), base `release/3.2` |
| Foundation remote head at reported refresh | `e449594e86c717e66e14598a4130475de79c536f` |
| Implementation PR | [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954), reported remote head prefix `92cf3c72d80d` |
| Source audited for this ledger | `264da76d3bca7a1a4f4970834291ca48d7c7a3c2` |
| Local implementation branch | `work/rsp-performance-32` |
| Baseline package version | `3.0.1` |
| Rust toolchain | `1.88.0`, locked workspace dependencies |
| Baseline diagnostic Python | CPython `3.12.14`, locked dependencies |
| Baseline local native target | `x86_64-unknown-linux-gnu` |
| Baseline native runtime bytes | `6,171,560` |
| Baseline runtime SHA-256 | `d3b3613713db36ea5ac836288a33ea03ab1d5e309cb3bba3575c0e315eb0a8b3` |
| Baseline rule digest | `be109c23448f016c3168ac2cf6ff04e75f0857616ffd5ae8a8028f3105c37305` |

The release branch contains a squash of earlier main work. The original and
squashed trees were compared before selecting the already-carried main lineage
as the reconciliation base. A normal merge would have treated already-present
changes as unrelated conflicts. The foundation preserves release-only Everyday
Mode schema/density/stale-write behavior, Fleet, Common CLI and network/sandbox
presentation while incorporating the current main authority implementation.
GitHub commits created from the tested tree can have different author metadata
and SHA from local integration commits; every uploaded tree is checked for exact
Git tree identity before the remote branch is advanced.

Overlaps below retain the GitHub observations recorded on 2026-09-17. They are
a dated reconciliation record; refresh the exact heads before final publication:

| PR and observed head | State | Treatment |
| --- | --- | --- |
| [#2807](https://github.com/hashgraph-online/hol-guard/pull/2807), `91f26d74f3148826b73730722c92e9d6b23794ff` | Open | Preserve Windows handle cleanup and fully populated RSS baseline invariants already present in the audited source; do not replace them with a two-worker baseline. |
| [#2870](https://github.com/hashgraph-online/hol-guard/pull/2870), `c6d71e84b7eae8a79b82d6c46143ef95da169fbd` | Closed, unmerged | Superseded by #2950; do not revive. |
| [#2950](https://github.com/hashgraph-online/hol-guard/pull/2950), `47b4ff21cdb89c70633c57d0a438f5739f316a98` | Merged into main | Current main secret-read and one-time approval behavior is carried by the foundation. |
| [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931), `ac31b5de7a61f87b9dbd89626bbc79fd6008968b` | Open draft | Hosted remote HTTP MCP is not assumed shipped. Preserve future catalog/policy integration seam without importing draft behavior. |
| [#2948](https://github.com/hashgraph-online/hol-guard/pull/2948), `a6d24bdbaaa88e7541399cca013e01866360f427` | Open | Unpublished generic-v2 admission work is separate. Runtime identity caching cannot treat cached publication state as fresh authority. |
| [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911), `ea472d8d67a8539dca7de02096634bb770a36b0f` | Open | CodeSage explicitly describes Python-reference-only coverage. Do not add it to native coverage without importing, compiling and qualifying its contribution. |
| [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797), `4b89e0d2d496a85f04922b2e019a4aea15326bb9` | Open draft | Release-to-main aggregate; this implementation targets its release branch rather than replacing that PR. |

## Implemented work and evidence

Source implementation and installed acceptance are separate. A compiled catalog
and tested native interpreter now exist; neither their presence nor a component
speedup establishes a successful registered hook on every release platform.

| Workstream | Implemented behavior | Evidence and remaining acceptance |
| --- | --- | --- |
| Benchmark integrity | Isolated semantic oracle, frozen expectations, registered launcher execution, paired samples, independent resources and offered-rate accounting | `scripts/qualify_guard_native.py` and `native_slo_*`; source tests pass. Final corpus, mixed and approval runner integration and installed execution remain. |
| Rust core | Typed lifecycle/results, one request identity, strict timeout/discard parsing, immutable compiled policy and reduced copying | Core and adversarial source suites pass at recorded commits; final combined-head validation and installed benefit remain. |
| Package evaluation | Verified immutable indexes, one captured-content/parsed input view and atomic evidence batches | [Package report](../rsp-package-performance.md): local 1,000-by-1,000 diagnostic CPU median 6812.312 → 121.574 ms (98.22% reduction). Some cardinality baselines time out; no native package pilot or measured port/no-port decision exists. |
| Offline scans | Bounded Git object streams, immutable blob finding reuse and shared plugin traversal | [Scanner report](../rust-performance-scanner-review.md): source CLI and finding parity, with full installed workflow/platform qualification and any native rich-detector comparison outstanding. |
| MCP | Immutable full-catalog digest, request-local classification, bounded frames/queues/responses and terminal I/O cleanup | [Framing contract](../../mcp-framing-bounds.md): real POSIX pipe and protocol tests; 5 ms final barrier retained. Windows execution and optimized proxy rebaseline remain; no native rewrite benefit claim. |
| Evidence and policy | Compact facts, bounded atomic SQL batches, append/checkpoint replay, stable attempt identity, precise DB/WAL reconciliation and captured workspace content | [Background report](../rust-performance-background.md): fault/mutation tests and diagnostics. Mixed installed resource and durability observations remain. |
| Runtime identity and posture | Reuse of an already verified Linux live image on supported filesystems; full validation elsewhere; acknowledged observe avoids redundant config read | [Identity report](../rsp-runtime-identity-performance.md): 72.28% lower median status-component CPU with the same baseline Rust binary; final hook/signing/platform transitions are separate. |
| Native command extensions | Trusted deterministic compiler, typed bounded Rust interpreter, candidate indexing, complete observations, control fence and durable receipt binding | [Program report](../native-command-program-performance.md), [authority protocol](../rust-native-command-control-binding.md): source differential and crash/recovery evidence; final installed activated coverage remains. |
| Remaining Python pool and inventory | Actual compatibility/Codex callers measured; positive collection discovery coalesced within one call; AIBOM retry ACK preserved | [Pool audit](legacy-pool-and-inventory-audit.md), source `06616ec80`. First real approval and broader incremental/scanner/cloud cost remain; no unsupported ordinary-hook pool-removal claim. |
| Mixed workload | Actual daemon hooks, public control updates, matching ACK, first enforcing receipt, real committed receipt identities, inventory and Rust resident recovery | `scripts/native_slo_mixed.py`, integration `a5d2ffeda`, 58 focused tests. Scheduled-offer latency includes queue/scheduler delay. Full runner integration, daemon-process restart, soak and unavailable persistence metrics remain. |
| Registered surfaces and approval | Actual nonpriority registration readback, exact response checks; ordinary local allow reuse bound to policy/program/observation under SH fence | [Surface report](registered-surfaces-smoke.md), `264da76d3` and `017214841`; adapter/layout defects and actual host/approval execution remain. Local resolved reuse is not exported native v3/v4 one-time consumption. |
| Ollama and Builder | Wheel-only contribution/Builder/control lifecycle probe, full command receipt readback and strict artifact identity | [Installed J118 protocol](../installed-native-ollama-qualification.md), `1b59b2d3b`, `58548bb2e`; 49 focused tests after approval-binding fix. Actual four-platform lifecycle, changed program/package update and rollback remain. |

The command program covers 86 extensions, 291 rules, 304 permissions and
2,242 nodes: 29 reviewed matcher types, 26 instantiated families, 249 declarative
and 42 compatibility rule identities, plus four rule-less GitHub permissions.
Its semantic profile is **CPython 3.12 / UCD 15**. Unknown/context-heavy
compatibility has owned uncertainty; unsupported Unicode capability is explicit.
This is not a claim of complete Python equivalence or parity across Python versions.
The program digest is
`4df5208d0dc05ceaadb1de6a6d8f6d3f9e5395dffcf992640fed87b82a0df1c9`;
the catalog digest is
`232ff389ca607b805118a02bd9560e972453f9a406188237037138f4834faf11`.
These source identities must be checked against each final installed artifact.

The source evidence includes 828 complete declarative observation cases,
187 option vectors, 1,571 operand/structured cases, 212 Common CLI cases,
721 remaining-family cases (seven declared Unicode capability errors),
193 compatibility vectors and 123 independently checked GitHub capabilities.
Reserved component admission measurements improved p50/p95 from
144.36/365.63 ms to 43.80/58.83 ms after removing redundant compilation/copies.
This is cold component admission, not daemon readiness or installed hook latency;
the older diagnostic baseline binary hash was not retained. Warm five-command
and later cardinality/allocation work must retain their own provenance.

A RegexSet prototype regressed the sample-heavy scanner diagnostic and was not
adopted. Native package, rich offline detector, new launcher, additional native
connection/ingress, MCP kernel, inventory, spool and compiler ports remain behind
their respective measured benefit gates. Optimized Python is the comparison
baseline. No optional unbuilt native port is marked DONE or DEFERRED merely
because an algorithm improvement was valuable.

## Source cutoff and pending integration

The ledger is tied to the source tree above. The following independently delivered
followups were reported after that cutoff; verify integration and re-run their
required checks before treating them as properties of a later candidate:

- `e7c3a86cb`: repair the frozen source fixture extension without changing the
  pinned baseline implementation. Numeric HTTP bind/startup repair is separate.
- `7b2113f2e`: controlled launcher approval helper, 19 real-store tests; canonical
  harness and exact new-row/action identity, bounded waits and retained late
  durable outcome. Root must integrate sibling dispatch/qualification hooks.
  The source-supported Claude retry path does not establish Codex browser-wait
  continuation: native local resolution yields retry-only `hookAttached=False`,
  and Codex finalization rejects `exact_approval_authority_missing`. A separate
  production authority/continuation correction and installed regression remain.
- `16001f0f5`, `1f6b21e73`, `6aacf9770`, `b37edef16`: inventory fixture, SQL
  attribution and corrected report. Positive per-call discovery/ACK production
  fixes are already integrated at `06616ec80`. Later measured root discovery
  walks fall from 24/128/486 to one; unchanged refresh still hashes every file.
  The SQL report removes one redundant SELECT per write, retains transaction
  counts and does not claim general throughput improvement. Successful Cisco
  engines, actual cloud latency, event-driven cross-refresh reuse and native
  comparison remain absent.
- `d9802fac2`: expanded command matrix/allocation diagnostic source, with reserved
  measurement and report followups still being produced. Source correctness rows
  are not timing or installed evidence.

## Behavior corrections kept separate from optimization

The foundation fixes a generic native request that paired an otherwise benign
command with an independent sensitive file target: the path now retains its
review floor. AIBOM exports redact URL credentials. Copilot uninstall reports
incomplete cleanup when unauthenticated legacy state cannot safely authorize a
configuration rewrite. An AWS credential-read matcher excludes access-key
deletion so the existing provider-specific destructive rule retains ownership.

The scanner reports missing or corrupt historical Git objects as incomplete.
Package input budgets now produce explicit incomplete outcomes; an unavailable
exact content hash blocks rather than presenting a placeholder as valid approval
identity. Package evidence writes become atomic rather than partially committed.
These are intentional correctness changes, with their own regression tests.

Ordinary native unavailability continues to use the current harness-specific
availability policy. A blanket new fail-closed policy is outside this performance
change. The [current contract](CURRENT_CONTRACT.md) records that distinction.

## Qualification and release gate

Qualification must build the baseline and candidate as separate installed native
wheels on Linux x64, macOS x64, macOS arm64 and Windows x64. The workflow pins
source and dependency locks, verifies package/runtime/rule identities and clears
development runtime overrides. Frozen/post-sign distribution evidence is a
separate requirement where that distribution changes.

The same-repository PR label `rust-performance-qualification` selects the full
qualification job; ordinary PR runs are explicitly smoke. Apply the label only
to a stable candidate. Any subsequent code or dependency change requires renewed
qualification on the resulting head. Qualification reports must include every
attempt, failure, timeout, rejection and recovery, and mark unavailable resource
metrics explicitly. A per-route pass cannot stand in for all-platform acceptance.

At the root agent's reported GitHub refresh on 2026-09-17,
[run 35201516872](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516872)
at remote head `92cf3c72d80d` selected all four targets but did not qualify them.
Linux and Windows baseline 1 MiB source cases returned an unexpected continuation:
the `.txt` fixture is outside the frozen source classifier, while `.rs` exercises
the intended source scan. macOS ARM logs identify reverse DNS during HTTP server
construction; macOS Intel diagnosis was pending. These are failures to resolve,
not grounds to patch the pinned baseline, loosen readiness or count missing data
as passing. Later local commits also require a new exact-head run.

A separate, later-reported installed identity result is evidence-ready for two
platforms. In [native wheel run 35201516674](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516674),
Linux job `105137144858` and Windows job `105137144563` each passed all 17
`probe_installed_runtime_identity.py` cases before subsequent default-auto hook
failures. The probe reports scope `installed_status_and_real_stdio_child`;
cross-release upgrade/rollback and signing are explicitly not exercised. The
observed capability build SHA is
`73f34ba984ff01563257599692cce33098014bdf`, package 3.0.1. Do not equate that
artifact identity with a different source head without tree/artifact verification.

| Observed artifact | Runtime bytes / SHA-256 | Manifest SHA-256 |
| --- | --- | --- |
| Linux x64; uploaded artifact `10488336777` | 12,239,840 / `b68c975462f71339f4342e6dec70cd79c9702bf38777477dcf54e642422c5c55` | `a7ec7e7f69f712a0ac4b2951c76dfdbb1d3f64a540c455a0d0ec0e8e92a312f4` |
| Windows x64 | 11,287,040 / `17ccfc7fa6243d990e31475fbb16d564d0428e85ce059cfae59f8dccb940b7e7` | `ac5209f08b73d97516a4526e3848d216c2d42220f3a2c11b2b764e866b5a9efb` |

These log observations were supplied by the package owner during this audit;
retain/download their job artifacts for the final release evidence. macOS
identity logs had not been reviewed. A different identity job (`105137131940`)
failed pytest plugin import before collection (`No module named tests`), which
is a harness failure, not an observed identity-contract failure. Neither that
failure nor the two passing identity probes determines final hook acceptance.

The foundation PR's reported head
`e449594e86c717e66e14598a4130475de79c536f` had all 25 workflows successful and
33 review threads resolved. Independent code-owner approval of the last push
remains required. This is a dated report from the coordinating agent's refresh;
re-query GitHub before stating the current check/approval state.

The frozen targets remain those in the PRD: warm installed c1 p95 <= 50 ms and
p99 <= 100 ms; c16 p99 <= 200 ms without errors; native client p95 <= 20 ms;
cold native p95 <= 150 ms; existing readiness bound 400 ms. A selected hot tranche
needs at least 30% p95 or CPU benefit with no more than 5% regression in the other
primary metric. Optional ingress needs at least 25% private-memory or 30% c16 p99
benefit. Current RSS-growth gates remain intact. Use at least five alternating
independent runs, 10,000 priority warm decisions, 1,000 other-route decisions,
100 priority cold starts, 100 recoveries and 30 resource observations as specified
per scope in the PRD. Do not pool routes to conceal a miss.

This workspace has not established a successful installed daemon/socket matrix.
Source tests, one-shot timings and installed status/stdio component probes retain
their stated boundaries. They do not replace registered launcher, resident
recovery, source-ref, approval, signing or process-tree release evidence.

The mixed runner reports its narrower observed checks separately from full
qualification. It preserves every offered/admitted/completed/failed/rejected
attempt, scheduled-offer-to-terminal latency and real committed receipt IDs.
Candidate receipts require the binding-aware getter; only explicit
`baseline_2e672d2` may validate complete legacy rows with its installed validator.
Journal writes/fsyncs are instrumented; SQLite VFS bytes/fsync are unavailable,
not zero. A 30-second scenario and the inherited 1,000 ms diagnostic adapter
budget do not replace the frozen sample minima, 50/100/200 ms product targets,
longer mixed soak or actual daemon-process restart.

Remaining implementation is concrete: finish and test runner/approval dispatch,
repair corpus/server startup, Codex review continuation authority and adapter
response/layout defects, complete
missing route/host and lifecycle/fault scenarios, and add any observability
needed for required metrics. Then perform optimized-baseline/native comparisons
for conditional ports. Missing qualification is not the only remaining work.

## Canary, rollback and final handoff

Before activation, record the exact qualified candidate and prior known-good
package/runtime/rule/program digests per platform. Begin with an internal cohort
for each selected harness, then broaden only after installed contract, resource,
policy freshness and approval metrics remain within the frozen gates. Count
evaluated allows, review/block outcomes and availability continuations separately.

Stop on any new semantic mismatch, approval replay, secret-bearing exported
evidence, stale stricter policy, identity failure, unsupported native capability
claim, unbounded queue or violated route/resource target. Retire the affected
generation, restore the prior verified package and registration through the
existing ownership-aware installer, and confirm new requests use the restored
runtime and acknowledged policy. Never downgrade a persistent revision floor or
silently reopen Python semantic fallback to make rollback appear successful.
In-flight requests receive their defined completion/unavailable result; ambiguous
tool execution is not retried. An actual rollback transcript is required before
RSP-139/143 can be closed.

The release ruleset requires a pull request, passing `quality`, resolved threads
and an independent code-owner approval of the last push. Stale approvals are
dismissed; there are no configured bypass actors. Local parallel review and
automated bots do not supply the missing independent approval. Merge status must
be reported separately from implementation and qualification status.

The final handoff must update all 144 records with exact code/test/measurement
references; list selected, measured-deferred and blocked scope; link final PRs
and Actions artifacts; report metric intervals and route/platform misses; and
include the tested canary/rollback versions. The implementation is not complete
while that evidence is missing.
