# Sixth package component checkpoint

[Package run 35257232889, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35257232889)
measured candidate `9d3907a2e6ed1ec201281901cb878836a7dad32d`, tree
`833ea191211db2a0613db8520d072f5edf485380`, against frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. **The workflow failed:** phase
attribution passed; format and cardinality retained baseline failures. Every
candidate observation completed. This is the first retained package cohort
using the current `complete-v3` parser identity. The frozen `complete-v1`
baseline and historical `complete-v2` cohorts keep their separate identities.

The [2ebb package decision](package-native-selection-decision.md) remains the
release's keep-Python/no-native-selection decision. This cohort changes no task
status and supplies no new Rust comparison, installed qualification or tail gate.

## Terminal outcomes

The [job/artifact facts](evidence/package-ci-9d3907/run-jobs-artifacts.json) and
[exact public file manifest](evidence/package-ci-9d3907/manifest.json) bind these
observations. Each job's finite-corpus correctness step passed **132 tests**;
this does not describe Main CI or the complete release test suite.

| Job | Result | Retained observations |
| --- | --- | --- |
| [Format, 105323757176](https://github.com/hashgraph-online/hol-guard/actions/runs/35257232889/job/105323757176) | Failure | 40 offers: 20 candidate and 18 baseline completions; two baseline Composer `package_count` failures |
| [Diagnostic, 105323757509](https://github.com/hashgraph-online/hol-guard/actions/runs/35257232889/job/105323757509) | Failure | Cardinality: 72 offers, 36 candidate and 24 baseline completions, 12 censored baseline workers. Separate unresolved pair and all five protect pairs completed |
| [Phase attribution, 105323757499](https://github.com/hashgraph-online/hol-guard/actions/runs/35257232889/job/105323757499) | Success | Two candidate validations, six separate candidate profiles and the two-arm explicit-`*` registry witness: all ten workers completed |

The [diagnostic report](evidence/package-ci-9d3907/diagnostic-component.json)
retains every offered cell. Nine evaluator baseline cells were censored:
absent/exact/deny at D/B = 1,000/10,000, 10,000/1,000 and 10,000/10,000.
The three None-version unversioned bundle-kernel cells at those sizes were
also censored. Those kernel cells do not stand in for a full evaluator route.
No censored latency or causal explanation is invented. The 15-second diagnostic,
20-second format and 30-second phase limits bound the **whole worker**, including
setup and postvalidation; they do not redefine production deadlines.

## Separate five-pair Python result

The actual npm protect dry-run route at D=B=1,000 completed five independent,
alternating pairs. All five fixture, semantic and evidence comparisons passed.

| Metric | Baseline median, ms | Candidate median, ms | Median paired reduction |
| --- | ---: | ---: | ---: |
| Wall time | 8,765.805 | 320.749 | 96.3405% |
| Process CPU | 7,750.150 | 312.036 | 95.9717% |

The interval includes local evaluation, serialization and evidence persistence;
imports, fixture setup, signed-bundle admission and postvalidation stay outside.
These are descriptive source-route results, not p95 estimates, complete
process-tree accounting, installed tails or native benefit. Per-arm medians and
the median paired reduction are different statistics. Cohorts are not pooled,
and differences between CI runs do not establish a causal performance change.

## Phase and registry checks

The [phase report](evidence/package-ci-9d3907/phase-component.json) contains three
instrumented protect D=B=1,000 trials and three evaluator D=B=10,000 trials.
All six pass disjoint origin accounting and the signed process-minus-profile
residual check. Each matches its separate validation's five declared
fixture/semantic/entry/evidence/protect commitments and performs one lockfile
parse, one immutable bundle-index construction and one evidence batch.
Signed-bundle admission is positively witnessed before the route; zero
in-route signature-verification calls do not remove that admission cost.

Guard-Python function origin accounts for median **42.3513% protect** and
**54.2777% evaluator** exclusive calling-thread CPU. Pydantic Python and core
record zero calls in all six trials. These instrumented function-origin shares
are not exact language attribution or attainable Rust savings. Inclusive spans
overlap; the original decision's 37.31%/51.75% shares remain tied to 2ebb.

Both explicit npm `*` arms make 100 admitted GETs through synthetic transport
bytes while executing the real retry dispatch, JSON decoder, semver resolver,
evaluator, protect projection and evidence persistence. Their commitments
match. The discriminating oracle selects lower-risk 2.0.0 instead of higher-risk
1.0.0; substituting None-version highest-risk matching cannot pass. Exact URL,
method, headers, body absence and one-second initial/retry budgets remain
checked. This supplies neither external HTTPS timing nor bare-`latest`
resolution coverage; the literal shortcut remains unchanged.

## Why the frozen Composer failures remain

The [format report](evidence/package-ci-9d3907/format-component.json) retains
`evaluator.composer.exact.d100.b100` and
`protect_dry_run.composer.exact.d100.b100` as failed, noncomparable baseline
observations. Their lockfiles contain valid qualified `bench/bench-dep-*`
package names. This is a frozen baseline identity-admission defect, not an
unsupported Composer JSON format or an incorrectly named fixture.

The frozen baseline's
[Composer parser](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/package_manifest_diff.py#L590)
reads both `packages` and `packages-dev` and retains qualified names. Its
[transitive evaluator](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py#L2594)
passes those names through a generic
[dependency-name helper](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py#L4233)
that rejects ordinary slash-qualified names unless they have an npm shape.
Consequently the baseline omits the Composer transitive targets before lookup.

Replacing qualified names with bare or npm names would invalidate Composer
identity; turning all transitive packages into explicit requests would change
the workload and violate the oracle's direct/transitive distinction. There is
no honest common-input correction preserving this cell's real work. A future
direct-only supplement must have a separate identity. The frozen baseline,
exact count gate and both historical failures remain intact; corrected
candidate coverage is not a parity-equivalent speedup.

## Retention and limits

Three public ZIPs, totaling **24,113 bytes**, were checked against GitHub's exact
size and SHA-256 metadata and bounded for member names, traversal, symlinks,
duplicates and extracted size. The manifest retains 16 finite public, receipt
and metadata files, including all three exact component JSON files. It contains
no raw payload, private function identity, ciphertext, private path or key.

All nine staging groups report complete with zero missing required records.
Producer encryption receipts report **103 format + 194 diagnostic + 34 phase =
331 files**, including staging manifests; all public and encrypted uploads
succeeded. These producer receipts and ciphertext artifact identities are
retained. **No sixth-cohort ciphertext download, decryption or recovery
verification is claimed.**

All reports leave installed qualification, tail qualification, native benefit
and activation false. These jobs establish no new candidate source defect.
The twelve censored baseline cells and two Composer failures remain explicit
limits; reopening a native package boundary still requires the original
optimized-Python 30%/5% comparison gate.
