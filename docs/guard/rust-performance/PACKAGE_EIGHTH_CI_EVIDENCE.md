# Eighth package and MCP component checkpoint

[Package run 35270079970, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079970)
measured candidate `a933921372ddb3772eff8a9d86771fe15da063b1`, tree
`3db430b618fe63cc1b85b8037e5de700cc3378c9`, against frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. **The workflow failed:** phase
attribution passed; the format and cardinality jobs retained baseline failures.
Every candidate observation completed. The candidate parser is `complete-v3`
and the frozen baseline parser is `complete-v1`; earlier `complete-v2` cohorts
are preserved separately.

The [fourth-cohort package decision](package-native-selection-decision.md)
remains the release's keep-Python/no-native-selection decision. This checkpoint
does not replace that decision, pool prior measurements, change task statuses,
or establish an optimized-Python-versus-Rust comparison.

## Terminal results

The [terminal metadata](evidence/package-ci-a933/run-jobs-artifacts.json) and
[20-file manifest](evidence/package-ci-a933/manifest.json) bind this report.
All three package jobs passed their finite-corpus correctness step; their
measurement and finalizer outcomes remain separate.

| Job | Conclusion | Retained scope |
| --- | --- | --- |
| [Format, 105366902254](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079970/job/105366902254) | Failure | 40 offers: 20 candidate and 18 baseline completions; two frozen Composer `package_count` failures |
| [Diagnostic, 105366902628](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079970/job/105366902628) | Failure | 72 cardinality offers: 36 candidate and 24 baseline completions; twelve censored baseline workers. The separate unresolved pair and all five protect pairs complete |
| [Phase attribution, 105366902630](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079970/job/105366902630) | Success | Two candidate validations, six candidate profiles and two explicit-`*` registry validation arms: all ten workers complete |

The [diagnostic report](evidence/package-ci-a933/diagnostic-component.json)
retains nine censored baseline evaluator cells: absent/exact/deny at
D/B = 1,000/10,000, 10,000/1,000 and 10,000/10,000. Three None-version
unversioned bundle-kernel cells at those sizes are also censored. Those kernel
cells do not establish full evaluator coverage. No completed route latency is
invented for a censored worker. The diagnostic/format/phase limits of
15/20/30 seconds bound the **whole worker**, including setup and
postvalidation; they do not redefine production deadlines.

The [format report](evidence/package-ci-a933/format-component.json) retains
`evaluator.composer.exact.d100.b100` and
`protect_dry_run.composer.exact.d100.b100` as failed, noncomparable baseline
observations. The [frozen-source diagnosis](PACKAGE_SIXTH_CI_EVIDENCE.md#why-the-frozen-composer-failures-remain)
still applies: parsing retains valid `vendor/package` names, but the baseline's
later transitive identity admission drops them. Bare names or direct requests
would change the actual work. The baseline and exact package-count gate remain
unchanged; candidate coverage of these dependencies is not counted as a
parity-equivalent speedup.

## Five independent protect pairs

The actual npm protect dry-run route at D=B=1,000 completes five alternating,
independent pairs with matching fixture, semantic and evidence commitments.

| Metric | Baseline median, ms | Candidate median, ms | Median paired reduction |
| --- | ---: | ---: | ---: |
| Wall time | 8,864.682061 | 326.475958 | 96.3336902129% |
| Process CPU | 7,774.195 | 316.916 | 95.9413386466% |

The interval includes local evaluation, serialization and evidence persistence.
Imports, setup, signed-bundle admission and postvalidation remain outside.
These are descriptive source-route observations, not p95 estimates, complete
process-tree accounting, installed tails or native benefit. Arm medians and
median paired reductions are distinct statistics. Changes between CI cohorts
do not establish a causal performance change.

## Attribution and registry validation

The [phase report](evidence/package-ci-a933/phase-component.json) retains three
instrumented protect D=B=1,000 trials and three evaluator D=B=10,000 trials.
Each matches its separate validation's fixture, semantic, entry, evidence and
protect commitments. The disjoint origin totals, selected/unattributed
partition and signed process-minus-profile residual reconcile in all six
profiles. Each performs one lockfile parse, one immutable bundle-index
construction and one evidence batch. Signed-bundle admission is positively
witnessed before the route; zero in-route signature calls do not remove that
admission cost.

Guard-Python function origin accounts for median **41.9452820% protect** and
**53.7612411% evaluator** exclusive calling-thread CPU. Both Pydantic categories
record zero calls. These instrumented origin shares are not exact language
attribution or attainable Rust savings, and inclusive spans overlap. The
decision's original 37.31%/51.75% figures retain their fourth-cohort scope.

Both explicit npm `*` arms complete 100 admitted GETs using frozen transport
bytes with the real retry dispatch, JSON decoder, semver resolver, evaluator,
protect projection and evidence persistence. Their validation-only comparison
passes. Exact URL, method, headers, absent body and one-second initial/retry
budgets remain checked. The oracle selects lower-risk 2.0.0 rather than
higher-risk 1.0.0, so a None-version highest-risk substitution fails. This does
not measure external HTTPS latency or change the bare-`latest` literal shortcut.

## Separate MCP completion

[MCP run 35270080057, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35270080057)
and [job 105366902676](https://github.com/hashgraph-online/hol-guard/actions/runs/35270080057/job/105366902676)
succeed at the same eighth candidate source. The controller/oracle check passes
126 tests. The [exact public report](evidence/package-ci-a933/mcp-component.json)
and [terminal metadata](evidence/package-ci-a933/mcp-run-jobs-artifacts.json)
retain 30 workers, 10,080 outcomes, zero failures, 48 groups, 240 run/trace
summaries and 364 diagnostic phase rows. All eight comparisons contain the
five independent plain-mode block pairs. This records completion without
replacing the earlier MCP native-selection decision or pooling cohorts.

All 80 warm resource windows complete with 149–352 valid snapshots and zero
missing samples. The begin/end protocol verifies process identity and preserves
99 completed warm calls per window. The ten separate lifecycle rows remain
incomplete: 14 missing samples and 38 descriptor denials across all ten rows.
Successful warm windows do not repair lifecycle missingness. The report remains
a Linux source-stdio component result; installed/cross-platform and tail
qualification remain false.

The MCP public ZIP is 92,962 bytes. It retains 181 raw-record commitments and
a producer receipt for 182 encrypted files. Its public and encrypted uploads
succeed; no ciphertext download or recovery is claimed. The report separately
binds each arm's production `src` subtree and dependency-lock digest, which are
distinct from the full candidate tree above.

## Retention and limits

The three package public ZIPs total **24,167 bytes**; including MCP, the four
verified ZIPs total **117,129 bytes**. Existing downloads were independently
rechecked against fresh GitHub artifact metadata for exact byte length and
SHA-256. Admission rejects duplicate members, traversal, symlinks and encrypted
members, and checks a 1 MiB ZIP bound, at most ten members, a 1 MiB member bound
and 2 MiB total uncompressed bound. The finite manifest retains their exact
public JSON, ten producer encryption receipts, four verification receipts and
terminal metadata. It contains no private observations, raw function identities,
ciphertext, private paths or keys.

All nine package staging groups report complete with zero missing records.
Producer receipts report **103 format + 194 diagnostic + 34 phase = 331
encrypted files**, including staging manifests. All public and encrypted
uploads succeed. **No eighth ciphertext download, decryption or recovery
verification is claimed.** Producer receipts are distinct from locally verified
public ZIPs and from recovery proof.

No installed qualification, tail qualification, native benefit or activation
is established. The baseline censoring and Composer noncomparability remain
limits. Any reopened package Rust boundary must still satisfy the original
optimized-Python 30%/5% comparison gate.
