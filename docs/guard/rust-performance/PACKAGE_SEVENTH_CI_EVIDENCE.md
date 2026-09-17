# Seventh package and MCP component checkpoint

[Run 35264203583, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35264203583)
measured candidate `79cb6921ff722a597b545350485864dcd9310bdc`, tree
`f158652293b1e10931122db6ccf48e33f5dd3c38`, against frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. **The workflow failed:** phase
attribution passed; format and cardinality retained baseline failures. Every
candidate observation completed. Candidate `complete-v3` and baseline
`complete-v1` are explicit source identities; historical `complete-v2` results
are neither rewritten nor pooled with this cohort.

The [fourth-cohort package decision](package-native-selection-decision.md)
remains the release's keep-Python/no-native-selection decision. This report
changes no task status and establishes no new Rust, installed or tail result.

## Terminal results

The [terminal metadata](evidence/package-ci-79cb/run-jobs-artifacts.json) and
[20-file manifest](evidence/package-ci-79cb/manifest.json) bind these observations.
Each job passed its **132-test** finite-corpus correctness step; those counts
do not describe Main CI or the full release test suite.

| Job | Result | Exact retained scope |
| --- | --- | --- |
| [Format, 105347152966](https://github.com/hashgraph-online/hol-guard/actions/runs/35264203583/job/105347152966) | Failure | 40 offers: 20 candidate and 18 baseline completions; two frozen Composer `package_count` failures |
| [Diagnostic, 105347152649](https://github.com/hashgraph-online/hol-guard/actions/runs/35264203583/job/105347152649) | Failure | 72 cardinality offers: 36 candidate and 24 baseline completions; twelve censored baseline workers. Separate unresolved pair and all five protect pairs complete |
| [Phase attribution, 105347153114](https://github.com/hashgraph-online/hol-guard/actions/runs/35264203583/job/105347153114) | Success | Two candidate validations, six candidate profiles and two explicit-`*` registry validation arms: all ten workers complete |

The [diagnostic report](evidence/package-ci-79cb/diagnostic-component.json)
retains nine censored baseline evaluator cells: absent/exact/deny at
D/B = 1,000/10,000, 10,000/1,000 and 10,000/10,000. The three None-version
unversioned bundle-kernel cells at those sizes are also censored. Kernel cells
do not substitute for full evaluator coverage. No route latency is invented
for a censored worker. Diagnostic/format/phase limits of 15/20/30 seconds cover
the **whole worker**, including setup and postvalidation; they do not redefine
production deadlines.

The [format report](evidence/package-ci-79cb/format-component.json) preserves
`evaluator.composer.exact.d100.b100` and
`protect_dry_run.composer.exact.d100.b100` as failed, noncomparable baseline
observations. The [source diagnosis](PACKAGE_SIXTH_CI_EVIDENCE.md#why-the-frozen-composer-failures-remain)
still applies: frozen parsing retains valid `vendor/package` names, but later
transitive identity admission drops them. Bare/npm-shaped names or converting
transitives to direct requests would change the workload. Neither the frozen
baseline nor its count gate is modified; corrected candidate coverage is not
a parity-equivalent speedup.

## Five independent protect pairs

The actual npm protect dry-run route at D=B=1,000 completes five alternating,
independent pairs, each with matching fixture, semantic and evidence results.

| Metric | Baseline median, ms | Candidate median, ms | Median paired reduction |
| --- | ---: | ---: | ---: |
| Wall time | 8,904.153534 | 326.290654 | 96.3355230483% |
| Process CPU | 7,808.830 | 318.823 | 95.9201319796% |

The interval includes local evaluation, serialization and evidence persistence;
imports, setup, signed-bundle admission and postvalidation stay outside. These
are descriptive source-route results, not p95 estimates, complete process-tree
accounting, installed tails or native benefit. Per-arm medians and the median
paired reduction are distinct statistics. Differences from previous CI cohorts
do not establish a causal performance change.

## Attribution and registry validation

The [phase report](evidence/package-ci-79cb/phase-component.json) contains three
instrumented protect D=B=1,000 trials and three evaluator D=B=10,000 trials.
All six match the separate validation's five declared fixture, semantic, entry,
evidence and protect commitments. Disjoint origin totals, selected/unattributed
partition and signed process-minus-profile residual checks pass. Each route
performs one lockfile parse, one immutable bundle-index construction and one
evidence batch. Signed-bundle admission is positively witnessed before the
route; zero in-route signature calls do not remove that admission cost.

Guard-Python function origin accounts for median **42.3529253% protect** and
**54.2615553% evaluator** exclusive calling-thread CPU. Both Pydantic categories
record zero calls. These instrumented function-origin shares are not exact
language attribution or attainable Rust savings; inclusive spans overlap.
The original decision's 37.31%/51.75% figures retain their fourth-cohort scope.

Each explicit npm `*` arm makes 100 admitted GETs using frozen transport bytes
and the real retry dispatch, JSON decoder, semver resolver, evaluator, protect
projection and evidence persistence. The validation-only comparison passes.
Exact URL, method, headers, absent body and one-second initial/retry budgets
remain checked. The oracle chooses lower-risk 2.0.0 rather than higher-risk
1.0.0, so None-version highest-risk substitution fails. External HTTPS timing
and bare-`latest` resolution are not claimed; the literal shortcut is unchanged.

## Separate MCP completion

[MCP run 35264203282, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35264203282)
and [job 105347148690](https://github.com/hashgraph-online/hol-guard/actions/runs/35264203282/job/105347148690)
succeed at the same seventh candidate source. The job passes its separate
126-test controller/oracle check. The [exact public report](evidence/package-ci-79cb/mcp-component.json)
and [terminal metadata](evidence/package-ci-79cb/mcp-run-jobs-artifacts.json)
retain 30 workers, 10,080 outcomes, zero failures, 48 groups, 240 run/trace
summaries and 364 diagnostic phase rows. All eight comparisons contain the
five independent plain-mode block pairs. This completion record introduces
no new native selection decision and does not pool earlier MCP cohorts.

All 80 warm resource windows complete, with 139–361 valid snapshots and zero
missing samples. Their bounded begin/end protocol preserves process identity
and 99 completed warm calls per window. The ten separate lifecycle rows remain
incomplete: they retain 13 missing samples and 39 descriptor denials across
all ten rows. Successful warm windows do not repair lifecycle missingness.
The report remains a Linux source-stdio component result; installed/cross-platform
qualification and tail qualification remain false.

MCP's independently verified public ZIP is 92,827 bytes. It retains 181 raw
record commitments and a producer receipt for 182 encrypted files. Its public
and encrypted uploads pass; this report claims no ciphertext download or
recovery. The source report separately identifies each arm's production
subtree and dependency-lock digest; these are not the full source tree above.

## Retention and limits

The three package public ZIPs total **24,148 bytes**; the MCP public ZIP brings
the four-ZIP total to **116,975 bytes**. Their exact sizes and SHA-256
digests match GitHub metadata; extraction checks member count, duplicates,
traversal, symlinks and per-file/total size. The manifest retains their exact
component JSON, ten producer encryption receipts, four download receipts and
finite terminal metadata for both workflows. It contains no raw payload, private function identity,
ciphertext, private path or key.

All nine package private staging groups report complete with zero missing records.
Producer receipts report **103 format + 194 diagnostic + 34 phase = 331
encrypted files**, including staging manifests. All public and encrypted
uploads succeed. **No seventh ciphertext download, decryption or recovery
verification is claimed.**

The reports establish no installed qualification, tail qualification, native benefit
or activation. These jobs establish no new candidate source defect.
The censored baseline cells and Composer noncomparability remain limits.
Any reopened native package boundary must still satisfy the original
optimized-Python 30%/5% comparison gate.
