# Package phase evidence at d0e37011

The first completed package phase-attribution job identifies larger costs around
bundle reconstruction, result projection and evidence handling than around the
single lockfile parse. It does **not** yet establish a Rust candidate capable of
improving the optimized Python route by the PRD's 30% threshold. The finite phase
names cover only about 14–18% of exclusive calling-thread CPU; the remaining
82–86% needs a bounded breakdown before selecting a native boundary.

These are actual GitHub runner observations from
[run 35233473461](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473461),
candidate `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f` against frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. They do not describe a later
integration source. The source-component boundary, unchanged workload and
instrumentation contract are in [the collector design](package-phase-attribution.md).

## Retained evidence and outcomes

The [hash manifest](evidence/package-ci-d0e/manifest.json) records all four
verified artifact ZIP identities and 15 retained public files. Downloaded ZIPs
were checked against GitHub's byte counts and SHA-256, and extraction admitted
only expected bounded members. No raw observations, encrypted archives or
private key are committed here.

| Job | Actual outcome | Bounded observations |
| --- | --- | --- |
| [Phase attribution, 105243299210](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473461/job/105243299210) | Success | Two uninstrumented validation workers, six attribution workers, two registry-resolution workers; all ten completed |
| [Cardinality and hot route, 105243298721](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473461/job/105243298721) | Failure / public incomplete | 72 cardinality offers: 60 completed and 12 censored baseline attempts; both unresolved validation attempts and all ten hot-route attempts completed |
| [Format preflight, 105243299044](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473461/job/105243299044) | Failure / public incomplete | 40 offers: 20 candidate and 18 baseline completions; two baseline Composer `package_count` failures |

The format failures are retained correctness differences, not speedups. The
cardinality censored attempts have no invented route latency. The existing
15-second diagnostic and 20-second format limits cover the whole worker,
including setup and validation; they are not new production deadlines. The phase
job uses a separate 30-second whole-worker limit. Its full report is retained as
[phase-component.json](evidence/package-ci-d0e/phase-component.json).

The three phase ciphertext groups were authenticated and recovered locally with
the existing owner-private recovery key: 9 validation files, 17 attribution
files and 8 registry files, including three staging manifests. All 34 recovered
files were mode `0600` under mode `0700` directories. The original limits stayed
256 files, 32 MiB per file and 128 MiB total. Their three fixed recovery receipts
are retained in the manifest. The public staging report has zero missing records
and 31 staged records; the additional three files are staging manifests. Format
and diagnostic archive receipts are retained, but their ciphertext was not
recovered in this review.

## Observed operation counts

The six instrumented workers used the original npm exact fixtures: three real
`protect_dry_run` calls with D=B=1,000 and three real evaluator calls with
D=B=10,000. Every instrumented semantic, evidence, entry, fixture and protect
commitment agreed with its separate uninstrumented validation observation.

| Operation per route invocation | Protect, D=B=1,000 | Evaluator, D=B=10,000 |
| --- | ---: | ---: |
| Lockfile parse / structure validation | 1 / 1 | 1 / 1 |
| Evidence batch | 1 | 1 |
| Immutable bundle index construction | 1 | 1 |
| Indexed match / offline decision | 1,001 / 1,001 | 10,001 / 10,001 |
| Transitive lookup | 1,000 | 10,000 |
| Package identity canonicalization | 7,009 | 70,009 |
| Package model construction / evidence row construction | 1,000 / 1,000 | 10,000 / 10,000 |
| In-route signed-payload canonicalization / bundle verification / RSA calls | 0 / 0 / 0 | 0 / 0 / 0 |

Each worker actually verified the signed bundle before entering the original
route interval and recorded that admission. The zero cryptographic counts apply
to that pre-admitted route; they do not erase verification from the complete
operation. Snapshot helper counts are retained as method invocations, not
physical file-read counts. The operation evidence supports the intended
single-parse, single-batch and indexed-lookup behavior.

## Calling-thread CPU attribution

Values below are medians of three instrumented invocations in milliseconds.
These are diagnostic observations; they are not ordinary route timings or tail
estimates. Inclusive rows include their callees and overlap. **Do not sum the
rows.** The exclusive selected-function total is a separate, disjoint accounting
measure, not the sum of inclusive spans.

| Inclusive phase | Protect, D=B=1,000 | Evaluator, D=B=10,000 |
| --- | ---: | ---: |
| Lockfile parse | 66.623 | 664.882 |
| Bundle load, including model construction | 259.980 | 2,673.812 |
| Immutable bundle index construction | 68.717 | 691.365 |
| Indexed matches | 64.008 | 720.480 |
| Package identity canonicalization | 177.433 | 1,777.576 |
| Package model construction | 148.821 | 1,498.634 |
| Transitive result construction | 197.501 | 2,068.578 |
| Evaluation finalization | 135.525 | 1,356.656 |
| Evidence projection | 228.746 | 2,317.681 |
| Evidence transaction | 223.311 | 2,264.183 |
| SQLite calls, including Python callbacks | 251.696 | 2,301.938 |

| Exclusive accounting and diagnostic totals | Protect, D=B=1,000 | Evaluator, D=B=10,000 |
| --- | ---: | ---: |
| All profiled exclusive calling-thread CPU | 1,433.439 | 10,253.108 |
| Selected functions' exclusive CPU | 203.263 | 1,803.555 |
| Unnamed profiled exclusive CPU | 1,231.543 | 8,449.553 |
| Diagnostic process CPU | 1,433.496 | 10,253.249 |
| Diagnostic wall time | 1,450.974 | 10,277.189 |

Each cell is independently summarized, so the displayed medians need not add
exactly. The parser's inclusive median divided by the total exclusive median is
about 4.65% and 6.48%. Bundle load is about 18.14% and 26.08%; evidence projection
is about 15.96% and 22.60%. These describe the instrumented profile, not a formal
upper bound on native savings. Profiling can disproportionately perturb code
with many function calls.

The unnamed exclusive CPU is still measured **on the calling thread**. It must
not be mislabeled other-thread work. The separate signed process-minus-profile
residual is only 0.052–0.057 ms for protect and 0.125–0.141 ms for the evaluator;
that residual can reflect other threads or instrumentation. The collector
retains only its finite phase projection in both public and encrypted journals.
It does not retain full cProfile statistics that could classify the unnamed CPU
after this run. A later diagnostic projection must preserve this limitation in
the historical report.

## Separate registry-resolution correctness witness

Both frozen baseline and candidate completed the same real local protect case
with 100 explicit npm `*` requests and 1,000 signed bundle records. Only the
registry transport was synthetic. Each made exactly 100 expected GETs with the
fixed headers, no request body and unchanged one-second initial/retry budgets;
real retry dispatch, JSON decoding, semver resolution, evaluation, protect
projection and evidence persistence ran. Both arms produced 100 packages and
100 evidence rows, with identical fixture, semantic, evidence and protect
commitments. The public report binds request and response byte identities.

The oracle requires requested `*` to resolve to version 2.0.0, risk 100 and the
ordinary bundle-match reason even though version 1.0.0 has risk 999 and a malware
reason. This distinguishes concrete-version resolution from the separate
None-version highest-risk kernel. It does not replace that kernel's cardinality
coverage, measure real HTTPS/network latency, or establish full-route
None-version semantics. Bare `latest` still follows the unchanged literal
shortcut before registry resolution in both sources; no bare-request behavior
was changed or credited as covered.

## Separate uninstrumented comparison and decision

The [diagnostic report](evidence/package-ci-d0e/diagnostic-component.json) retains
five independent alternating pairs of the original exact npm protect route at
D=B=1,000. Baseline medians were 5,828.384 ms wall and 4,571.890 ms CPU; optimized
Python medians were 215.214 ms wall and 195.921 ms CPU. The median of the five
paired reductions was **96.2766% wall and 95.7711% CPU**. These are paired
source-route diagnostics, with no installed, tail or native-benefit qualification.
The candidate's single exact D=B=10,000 evaluator observation was 1,246.269 ms
wall and 935.470 ms CPU. It is one observation, not a p95. Those uninstrumented
workers ran in a different job from the attribution workers; dividing the two
jobs' numbers would not establish causal profiler overhead.

RSP-050 now has actual independently scaled D/B observations for all four match
modes at 100/1,000/10,000, with all 36 candidate cells completed. Twelve baseline
cells remain explicitly censored; the unversioned cells exercise the documented
bundle kernel rather than a fictitious full local None-version route. This is
useful cardinality evidence, with that route limitation retained. The new
explicit-`*` pair closes a separate concrete-resolution correctness gap.

RSP-054 has a real current-versus-optimized-Python comparison, but this phase
report does not finish its port/no-port decision against the 30% native benefit
threshold. A parser-only rewrite is not selected by the present evidence.
Bundle/model reconstruction, identity and evidence/serialization are candidate
areas for the next bounded breakdown. Before selecting a coarse native pilot,
classify the large unnamed exclusive share without changing the interval or
workload, then measure the selected pilot against optimized Python at the real
route boundary. No native package implementation or activation is authorized by
these observations, and no permanent no-port conclusion is drawn.
