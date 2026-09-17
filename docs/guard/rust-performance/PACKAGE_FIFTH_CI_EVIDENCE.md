# Fifth package component checkpoint

[Package run 35247986524, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986524)
measured candidate `96a69725eab018674174dabc6f205a4087d6ff4b`, tree
`7da3dcf25df5dc75b61f773c40a3a4dd96bbf2fa`, against frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. **The workflow failed:** phase
attribution passed, while format and cardinality retained baseline failures.
Every candidate observation completed. These results belong to this source;
they do not qualify later repairs or an installed/native package path.

The [2ebb package decision](package-native-selection-decision.md) remains the
release's keep-Python/no-native-selection decision. This fifth cohort is not
pooled with it, changes no task status, and supplies no new Rust comparison.

## Terminal outcomes

The [retained job/artifact facts](evidence/package-ci-96a697/run-jobs-artifacts.json)
and [exact public file manifest](evidence/package-ci-96a697/manifest.json) bind the
following observations.

| Job | Result | Retained observations |
| --- | --- | --- |
| [Format preflight, 105292961000](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986524/job/105292961000) | Failure | 40 offers: 20 candidate and 18 baseline completions; two baseline Composer `package_count` failures, one evaluator and one protect route |
| [Diagnostic, 105292960791](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986524/job/105292960791) | Failure | Cardinality: 72 offers, 36 candidate and 23 baseline completions, 13 censored baseline workers. Separate unresolved pair and all five protect pairs completed |
| [Phase attribution, 105292960970](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986524/job/105292960970) | Success | Two candidate validations, six separate candidate profiles and the two-arm explicit-`*` registry witness: all ten workers completed |

The finite-corpus/failure-handling correctness step passed in all three jobs;
the format job log records 127 tests passed. This is the package workflow's
source-test boundary, not a Main CI coverage or whole-release result.

The [format report](evidence/package-ci-96a697/format-component.json) retains
both Composer failures as noncomparable. Correcting candidate package coverage
is not a parity-equivalent speedup. The
[diagnostic report](evidence/package-ci-96a697/diagnostic-component.json) retains
13 censored baseline cells, including `evaluator.npm.deny.d1000.b1000`; the
fourth cohort had 12. No cause or censored route latency is inferred. All cells
retain the original independently scaled D/B sizes and match modes. Unversioned
highest-risk cells still exercise the real None-version bundle kernel, not a
fabricated full evaluator route.

The 15-second diagnostic, 20-second format and 30-second phase limits are
**whole-worker containment**, including setup and postvalidation. They do not
redefine production deadlines. Failed jobs and incomplete comparisons remain
failed/incomplete after evidence uploads succeed.

## Separate five-pair Python result

The exact npm protect dry-run route at D=B=1,000 completed five independent
alternating pairs, one observation per arm per run. Fixture, semantic and
evidence comparisons passed for all five pairs.

| Metric | Baseline median, ms | Candidate median, ms | Median paired reduction |
| --- | ---: | ---: | ---: |
| Wall time | 11,735.251 | 274.568 | 97.6966% |
| Process CPU | 5,930.041 | 245.011 | 95.8707% |

The interval includes local evaluation, serialization and evidence persistence;
imports, fixture setup, signed-bundle admission and postvalidation stay outside.
These are descriptive source-route medians, not p95 estimates, installed tails,
complete process-tree qualification or native benefit. Per-arm medians and the
median of paired reductions are different statistics. Do not use differences
between CI cohorts to infer a causal change or profiler overhead.

## Phase and registry checks

The [phase report](evidence/package-ci-96a697/phase-component.json) contains three
instrumented protect D=B=1,000 trials and three evaluator D=B=10,000 trials.
All six pass the strict phase-v2 schema, disjoint origin accounting and signed
process-minus-profile residual checks. Every trial matches the separate
validation's five declared fixture/semantic/entry/evidence/protect commitments.
Each performs one lockfile parse, one immutable index construction and one
evidence batch. Signed-bundle admission was positively witnessed before each
route; zero in-route verification calls do not remove that admission cost.

Guard-Python function origin accounts for median **41.9683% protect** and
**53.6792% evaluator** exclusive calling-thread CPU in this cohort. Pydantic
Python and Pydantic-core again record zero calls. These are instrumented
function-origin shares, not exact language attribution or attainable native
savings. Inclusive spans overlap. The earlier decision's 37.31%/51.75% shares
retain their original cohort identity.

Both explicit npm `*` arms make 100 admitted GETs through synthetic transport
bytes while running the real retry dispatch, JSON decoder, semver resolver,
evaluator, protect projection and evidence persistence. Their semantic/evidence
commitments match. The unchanged oracle selects lower-risk 2.0.0 instead of
higher-risk 1.0.0, so None-version highest-risk substitution cannot pass. URL,
method, headers, body absence and one-second initial/retry budgets remain
checked. This supplies neither external HTTPS timing nor bare-`latest`
resolution coverage; that literal shortcut is unchanged.

## Retention and practical limits

Three public ZIPs were downloaded, matched against GitHub's exact byte counts
and SHA-256 digests, and extracted only after finite member-name, traversal,
symlink and size checks. The manifest retains 16 public/receipt/metadata files,
including all three exact component JSON files. It contains no raw payload,
private function identity, ciphertext, private filesystem path or key.

All nine staging groups report complete with zero missing required records.
The producer encryption receipts report 103 format files, 193 diagnostic files
and 34 phase files, including their staging manifests. All public and encrypted
uploads succeeded. Those receipts and GitHub ciphertext artifact identities
are retained; **no fifth-cohort ciphertext download, decryption or recovery
verification is claimed**.

Every report explicitly leaves installed qualification, tail qualification,
native benefit and activation false. No new candidate source defect is
established by these package jobs. The original package parity, censored-baseline
and installed acceptance limits remain, and any reopened native boundary must
still satisfy the original optimized-Python 30%/5% gate.
