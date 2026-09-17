# Rust performance execution for release/3.2

This is the implementation record for the [PRD](PRD.md), [144-task TODO](TODO.md)
and original [takeaway prompt](TAKEAWAY.md). Those three documents preserve the
audited proposal. The implementation session subsequently authorized completing
the work in `release/3.2`; its old proposal-only wording is not a request to stop
implementation. No release deployment is recorded here.

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
| Foundation with initial review/CI fixes | `c62a3e0aa2a68d7a6eb6f83ae39295a3b0a9316a` |
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

Overlaps were rechecked through GitHub on 2026-09-17:

| PR and observed head | State | Treatment |
| --- | --- | --- |
| [#2807](https://github.com/hashgraph-online/hol-guard/pull/2807), `91f26d74f3148826b73730722c92e9d6b23794ff` | Open | Preserve Windows handle cleanup and fully populated RSS baseline invariants already present in the audited source; do not replace them with a two-worker baseline. |
| [#2870](https://github.com/hashgraph-online/hol-guard/pull/2870), `c6d71e84b7eae8a79b82d6c46143ef95da169fbd` | Closed, unmerged | Superseded by #2950; do not revive. |
| [#2950](https://github.com/hashgraph-online/hol-guard/pull/2950), `47b4ff21cdb89c70633c57d0a438f5739f316a98` | Merged into main | Current main secret-read and one-time approval behavior is carried by the foundation. |
| [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931), `ac31b5de7a61f87b9dbd89626bbc79fd6008968b` | Open draft | Hosted remote HTTP MCP is not assumed shipped. Preserve future catalog/policy integration seam without importing draft behavior. |
| [#2948](https://github.com/hashgraph-online/hol-guard/pull/2948), `a6d24bdbaaa88e7541399cca013e01866360f427` | Open | Unpublished generic-v2 admission work is separate. Runtime identity caching cannot treat cached publication state as fresh authority. |
| [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911), `ea472d8d67a8539dca7de02096634bb770a36b0f` | Open | CodeSage explicitly describes Python-reference-only coverage. Do not add it to native coverage without importing, compiling and qualifying its contribution. |
| [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797), `4b89e0d2d496a85f04922b2e019a4aea15326bb9` | Open draft | Release-to-main aggregate; this implementation targets its release branch rather than replacing that PR. |

## Selected work and evidence

The first tranche optimizes repeated work and establishes trustworthy
measurement. Native extension execution is a separate compatibility tranche.
Neither a catalog entry nor a successful Python matcher test proves that a
production Rust hook executes a rule.

| Tranche | Implemented direction | Evidence and qualification limit |
| --- | --- | --- |
| Benchmark integrity | Isolated semantic oracle, actual registered launchers, paired qualification, independent daemon resources, offered-rate accounting and frozen delivery cases | `scripts/qualify_guard_native.py` and `native_slo_*`; final installed runs pending |
| Rust core | Typed lifecycle/results, one request identity, strict discard parsing, immutable compiled policy and reduced output copying | Per-crate, runtime, edge and adversarial tests; kernel timings are diagnostics |
| Package evaluation | Verified indexes, shared structured parse and exact input snapshot, atomic evidence batch | [Package report](../rsp-package-performance.md); five 1,000-by-1,000 pairs observed 98.22% lower median CPU, without release percentile qualification |
| Offline scans | Bounded Git object streams, immutable blob finding reuse and shared plugin reads | [Scanner report](../rust-performance-scanner-review.md); complete result parity on synthetic source CLI comparisons, with platform/native qualification outstanding |
| MCP | Immutable full-catalog digest and request-local classification reuse | Actual stdio session harness; timing profile is noisy and does not justify a native proxy rewrite |
| Evidence/policy | Compact foreground facts, bounded SQL/journal batching and exact policy-domain invalidation | [Background report](../rust-performance-background.md); source fault/mutation tests and paired diagnostics |
| Runtime identity/posture | Acknowledged observe binding avoids a redundant config read; verified live-process reuse is under implementation | Full hashing remains required without equivalent live-process proof; final installed transitions pending |
| Native extensions | Deterministic executable IR, explicit control authority and native matcher/receipt integration | Under implementation; final coverage and actual installed activation pending |

A RegexSet prototype regressed the sample-heavy scanner diagnostic and was not
adopted. Native package, rich offline detector, new launcher, additional native
connection/ingress, MCP kernel, inventory, spool and compiler ports remain behind
their respective measured benefit gates. Algorithm improvements are the new
comparison baseline. No task is closed merely by asserting Rust would be faster.

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

The frozen targets remain those in the PRD: warm installed c1 p95 <= 50 ms and
p99 <= 100 ms; c16 p99 <= 200 ms without errors; native client p95 <= 20 ms;
cold native p95 <= 150 ms; existing readiness bound 400 ms. A selected hot tranche
needs at least 30% p95 or CPU benefit with no more than 5% regression in the other
primary metric. Optional ingress needs at least 25% private-memory or 30% c16 p99
benefit. Current RSS-growth gates remain intact. Use at least five alternating
independent runs, 10,000 priority warm decisions, 1,000 other-route decisions,
100 priority cold starts, 100 recoveries and 30 resource observations as specified
per scope in the PRD. Do not pool routes to conceal a miss.

Local process/socket restrictions prevent this workspace from establishing
resident/daemon installed acceptance. Local source tests, one-shot timings and
status component profiles are useful evidence with those boundaries. They are
not substitutes for the installed GitHub Actions matrix.

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
