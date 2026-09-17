# Package core completion: text projections and current-source matrix

Follow-up: the [actual native selection and bundle correction](rsp-package-native-selection.md)
records the completed first-format pilot, the direct repeated deny-regression
control, and the bounded no-go decision. The measurements and pending-selection
statements below remain historical records for the frozen source identified here.

Source implementation: `06e97a984`, `040c18f85`, and `e79c4bf02`, based on `fb8d57a8efc3`. Intended integration: `release/3.2`. No native package crate, trust-authority change, or package-manager execution is introduced.

## RSP-052: one traversal of each supported text input

The production parser now obtains validation, dependency entries, pnpm root-importer/direct versions, and Yarn selector/version groups from one traversal of captured content. JSON/JSONC/TOML continue to pass their single decoded document to extraction. Parsed projections are immutable and remain attached to the evaluation-scoped input snapshot. Production direct-version resolution consumes those projections instead of scanning text again.

Yarn dependency maps preserve the last declaration for a package name. Target resolution preserves the first matching selector declaration, including when a target admits multiple selector spellings and aliases. Root/default pnpm importers and legacy top-level dependency sections retain their distinct direct-dependency behavior. Nested workspace importers do not replace root selections. Snapshot dependencies, peer suffixes, scoped names, aliases and prereleases retain the previous supported projection. Bundler `specs` blocks retain their existing section and indentation rules.

This remains the existing supported text grammar. It does not claim general YAML parsing or broaden supported Yarn/pnpm versions. The existing NUL/tab/header/bracket validation, byte bounds, complete-or-fail behavior and parser deadline remain. The new stored direct-version and selector projections each obey the existing 100,000-entry ceiling; hitting that ceiling publishes no partial projection. Yarn header names use ordered dictionary deduplication, with deadline and selector-admission checks inside each header. Versionless headers count toward admission and cannot bypass the bound or spend quadratic time in name deduplication. Structured formats retain node/depth limits. Parsed data remains `complete-v1`, and completeness is checked before evaluation-cache reuse.

The older standalone manifest diff parsers and direct-selector helpers remain useful independent compatibility oracles. They are not called by the production parsed-text target path. The new reuse tests make legacy target helpers raise if invoked and verify that a real signed-bundle evaluator still resolves and blocks the direct dependency after exactly one text traversal.

## RSP-050 and RSP-054: measured boundaries and comparison contract

The new matrix runner varies dependency and bundle cardinality independently across 100, 1,000 and 10,000, covering absent, exact, unversioned and emergency-deny matching. Twenty-seven cells call the full local production evaluator; nine unversioned cells call the existing cached-bundle API because the production lockfile route resolves exact versions. The later [real artifact witness](rsp-package-unversioned-route.md) confirms that the full evaluator never passes a None version to that API and preserves RSP-050's literal full-route gap as open. Every full-route fixture contains a known-blocked direct anchor, with independently varied transitive match cases. The absent cases therefore retain one evidence row; exact/deny cases exercise dependency-sized result and evidence batches. These synthetic blocking fixtures do not establish latency for every package decision class.

The local evaluator interval includes workspace reads, complete parsing, cached signed-bundle model construction, matching, policy/result composition, evaluation-cache writes and SQLite evidence persistence. Fixture signing, initialization, cache invalidation, result assertions, output hashing and optional profiling are outside primary timing. Network attempts fail the harness. CLI launch, installed shim transport, human approval, package-manager launch and final execution revalidation are not measured.

The original result-subset digest is retained, but a comparison now additionally requires equality of every public evaluation field and every persisted evidence column. No field is normalized or dropped. All samples for each arm must be deterministic; two arms with the same set of inconsistent outputs fail comparison. Unversioned batches compare complete decision dataclasses and perform no evidence persistence. A censored whole-process timeout has no invented evaluator latency.

Both timed arms use the same sample count and begin with fresh synthetic stores in independent processes. With one timed sample per arm, both include the first evaluator call and initial evidence insertion; neither median mixes first insertion with later replacement. Arm order flips within each match mode across successive cardinality cells. Each baseline/candidate pair holds the common advisory lock. The lock is released after each independent cell and a checkpoint is written. The lock coordinates participating benchmarks but does not exclude unrelated host contention. Instrumented profiles use one additional warmed sample in the candidate process, excluded from the primary wall/CPU arrays. They include replacement of previously written evidence and must not be treated as first-call timing. Cumulative profile fractions overlap and cannot be added indiscriminately.

The frozen `e79c4bf02` harness also constructed and retained one fixture bundle model before timing in every mode. Only the unversioned API uses that model; full local routes load a separate model from the store inside timing. Consequently the historical matrix and first four deny repeats describe a first evaluation with an extra fixture model already resident. That setup can affect allocation and garbage-collection state, and it provides no memory qualification. The revised harness constructs the fixture model only for unversioned batches. Its separate deny controls are labeled with the changed harness digest and are not substituted for historical observations.

The matrix uses generated npm package-lock fixtures. Its timings characterize the combined optimized Python state, including earlier immutable indexing, structured parse reuse, evaluation snapshots and evidence batching. It does not isolate the timing benefit of the new Yarn/pnpm/Bundler projections. Those text changes have differential, completeness and one-traversal source tests.

Collector commit `4a0bb2341` adds bounded default collection, atomic checkpoints, continuation after failed/censored cells, equal-count and ordered-prefix resume checks, and source/harness provenance checks. Each new successful arm must match the pinned source identity, and both identities are checked again before final success. Collection segments record whether an additional profile was requested. Future failed arms retain the last observed collection phase. Historical error records retain their original fields; unavailable phase information is not retroactively invented. The raw unversioned records' older universal evidence-scope string is interpreted as complete cached-bundle decisions only: their persisted-evidence arrays contain null because that API does not persist evidence.

## Verification

- 296 existing package/parser/input-snapshot/JavaScript/tier-2/Python intent tests passed with external networking prohibited.
- 70 focused tests passed after bounded-header review fixes. The 17-test runner integrity suite passed and covers equal-count admission, per-mode order, incompatible resume checkpoints, retention of failed observations, and phase attribution for failed collection.
- After the exhaustive branch type fix, 110 focused parser and benchmark tests passed.
- Scoped type checking: zero errors. Existing strict-style warnings remain and are not presented as a warning-free project-wide pass.
- Ruff and whitespace validation passed for changed files.
- Independent review reproduced the header bound fix and accepted full-result/evidence hash coverage, equal timed counts, and per-mode order.

The first four continuation matrix cells are superseded: they used one baseline sample against three candidate samples, and a four-mode loop accidentally correlated order with mode. Those observations are retained separately as failed methodology evidence and excluded from the final timing comparison. No claim relies on their favorable ratios.

Independent installed artifact qualification, release tail percentiles and multi-platform results remain separate gates. The preceding counts are source validation; they do not establish installed package-protect qualification.

## Expanded source observations and retained failures

The [complete matrix](performance/rsp-package-continuation-matrix.json) contains all **36 independently scaled cells**. **31 comparisons match complete outputs: 23 full local evaluator routes and 8 separate cached-bundle API batches.** All 35 completed candidate arms and 31 completed baseline arms match the frozen clean source identities, which were independently checked again after collection. The other five pairs remain non-comparable. Four baseline arms hit a 120-second whole-process collection limit; candidate cell 30 and baseline cell 36 reported harness errors. Censors and errors have no assigned evaluator CPU/latency or parity result.

The environment was CPython 3.12.14 on Linux x64, an Intel Xeon Platinum 8370C host exposing 9 logical CPUs and 23,109,894,144 bytes of RAM. Power mode was not exposed. Raw observations retain host load. Shared-host allocation, storage and scheduling variability is substantial; no observation is an installed artifact result or a reliable tail percentile.

The table reports **audited Python → optimized Python evaluator-process CPU in milliseconds**, one timed observation per arm. `censored` is a whole-process collection outcome, never a substitute CPU value. Unversioned columns exclude model construction and persistence and must not be interpreted as full-route latency. Exact and unversioned fixtures cycle package identities across the independently sized bundle; deny fixtures repeat the same denied identity at distinct lockfile paths. Dependency cardinality is lockfile-entry cardinality, not a guarantee of that many unique canonical names.

| Dependency records | Bundle records | Absent | Exact | Unversioned API | Emergency deny |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 100 | 139.39 → 59.93 | 458.70 → 53.31 | 73.89 → 0.93 | 704.32 → 56.00 |
| 100 | 1,000 | 1,051.88 → 88.03 | 873.16 → 51.50 | 671.89 → 8.23 | 2,216.55 → 125.33 |
| 100 | 10,000 | 5,036.72 → 296.92 | 8,423.76 → 368.29 | 6,680.01 → 1.11 | 756.06 → 1,336.63 |
| 1,000 | 100 | 719.88 → 87.05 | 5,352.22 → 126.13 | 683.94 → 7.16 | 5,180.02 → 199.01 |
| 1,000 | 1,000 | 5,896.15 → 63.43 | 10,252.76 → 187.84 | 7,347.66 → 8.34 | 4,261.97 → 389.71 |
| 1,000 | 10,000 | 60,653.48 → 1,105.81 | 80,197.63 → 676.32 | 42,563.87 → 16.82 | 5,237.31 → 636.96 |
| 10,000 | 100 | 11,217.52 → 256.42 | 81,462.97 → 1,373.89 | 6,097.14 → 149.47 | 50,656.95 → 2,049.19 |
| 10,000 | 1,000 | 62,423.37 → 250.96 | censored → error | 84,469.00 → 188.15 | 91,972.50 → 1,270.43 |
| 10,000 | 10,000 | censored → 720.94 | censored → 3,425.82 | censored → 206.12 | error → 2,734.38 |

The original 100 × 10,000 deny pair regressed CPU from 756.06ms to 1,336.63ms (**76.79%**) and wall time from 756.25ms to 1,365.29ms (**80.54%**). Four separately retained [fresh-process repeats](performance/rsp-package-continuation-deny-repeats.json) had mixed signs: CPU improvements of 81.38%,48.17%,48.14%, and a 36.50% regression. Their median CPU was 871.07ms versus 451.64ms, but those four observations do not establish a stable advantage.

Removing the unused preconstructed full-route fixture produced the separately labeled [corrected-setup controls](performance/rsp-package-continuation-deny-corrected-setup.json). All four complete result/evidence comparisons match. Three pairs regressed CPU by 62.93%,61.35%, and34.90%; the fourth improved 13.15%. The ratio of per-arm median CPU shows a **16.17% regression**. This strengthens the case for a targeted bundle-load correction; the material regression remains unresolved by this baseline report and is not dismissed as an outlier. The measured redundant canonicalization pass is the next Python change to investigate. No control replaces the unfavorable original observation.

Both stored harness-error digests exactly match a reconstructed standard traceback ending `AssertionError: Unexpected route output: ask, 1 packages`. Candidate cell 30 could have failed in the primary or additional instrumented evaluation; the old collector did not retain phase. Baseline cell 36 had only its primary evaluation. Neither digest identifies the underlying parse or policy reason. A separate [candidate-only cell 30 reproduction](performance/rsp-package-continuation-case30-reproduction.json) passed both primary and additional-profile assertions with 10,001 blocked package results/evidence rows, at 1,638.34ms primary CPU. That reproduction does not establish parity with a completed baseline or erase the failed sample.

The [collection history](performance/rsp-package-continuation-history.json) preserves the interrupted first attempt at cell 19 and the 18 balanced cells retained across collector handoff. The [four unequal-count observations](performance/rsp-package-continuation-superseded.json) remain excluded as failed methodology. The [historical resume source](performance/rsp-package-continuation-resume-source.txt) records the actual bounded continuation implementation. Temporary disk exhaustion occurred while the final pair/controls were pending: a safety copy failed with ENOSPC, a validated 35-cell checkpoint was retained outside the overlay, and cleanup restored space before the intact final checkpoint was copied. This is another reason to treat this shared-host dataset as diagnostic; it does not establish the cause of either evaluator error.

The [machine-readable summary](performance/rsp-package-continuation-summary.json) records source checks, status counts, error-digest attribution, control outcomes and artifact digests. Source validation passed 17 runner-integrity tests and the revised full-route/unversioned harness smoke. No Rust comparison is included here.

### Reproduction

Use frozen source worktrees at the listed commits and the same locked Python environment. The current collector can run all 36 cells with a bounded cutoff and can resume a compatible checkpoint without discarding failures:

```bash
python scripts/bench_guard_package_matrix.py \
  --baseline-root /path/to/audited-python \
  --candidate-root /path/to/optimized-python \
  --measurement-lock /path/to/performance-measurement.lock \
  --baseline-samples 1 --candidate-samples 1 --timeout 120 --profile \
  --output /path/to/package-matrix.json
```

Add `--resume` only for a matching harness/source/count/order checkpoint. The current harness intentionally removes the unused preconstructed model from full modes, so it will produce new observations under the corrected setup. Historical raw matrix/repeat records identify their original harness digest and the frozen `e79c4bf02` implementation. Do not silently combine results from the two harness versions.

## Native pilot selection from the expanded baseline

**Retain optimized Python in production and select a bounded first-format native parser pilot for a separate measured comparison.** The large-input profiles below prevent closing the native decision from the earlier small-fixture profile. This report completes the expanded Python baseline, not RSP-054 native selection or installed activation. No Rust package implementation is measured in these artifacts, so there is no claim that a native candidate failed the threshold.

The combined Python prerequisites remove the old repeated-scan and per-record-transaction costs. The remaining cost depends strongly on workload. The following shares come from additional instrumented, warmed samples; the denominator is the evaluator's cumulative elapsed time. They are not process-CPU shares or installed tail measurements.

| Dependency records × bundle records, mode | Parser | Indexed match | Cached model loading | Evidence persistence |
| --- | ---: | ---: | ---: | ---: |
| 100 × 1,000, exact | 1.6% | 1.0% | 46.2% | 16.6% |
| 1,000 × 1,000, exact | 3.9% | 4.1% | 12.5% | 40.7% |
| 10,000 × 100, absent | 40.1% | 18.3% | 0.8% | 0.4% |
| 10,000 × 1,000, absent | 24.8% | 19.7% | 9.1% | 0.5% |
| 100 × 10,000, deny | 0.2% | 0.2% | 84.5% | 1.8% |

At the observed instrumented fractions, even a hypothetical zero-cost parser alone could remove only 3.9% of the 1,000 × 1,000 exact sample. That conditional bound does not extend to the 10,000-record absent samples. The selected next pilot will send one captured package-lock.json input through a coarse versioned Rust validation/projection boundary, with explicit Python fallback outside its declared scope. The 10,000 × 100 absent full route is the first test of whether parser savings survive native launch, serialization and result reconstruction; 10,000 × 1,000 absent is a second control. Python retains bundle verification, trust/freshness, cache, policy and evidence storage. A combined parser/matching boundary or larger model-construction boundary requires its own evidence if the first pilot does not justify it. Profiler overhead and state differences prevent translating these fractions into a promised CPU or p95 benefit. The earlier single small-fixture profile cannot establish a universal no-port result or prove that every product target is met.

An emergency-deny shortcut cannot avoid model/index construction in the measured full route: the non-denied direct anchor needs exact package severity before policy evaluation, and transitive results use the index too. Moving emergency-deny checks ahead of those steps would require proving policy/result equivalence. A lazy index would still be constructed by this route. Identity canonicalization is also repeated between package deduplication and index construction; combining those passes is a possible Python optimization, but must preserve direct-constructor duplicate behavior, parsed-payload ordering, and malformed-input rejection. No speculative cache or trust-authority change was introduced to explain a variable timing observation.

| Decision field | Evidence and limit |
| --- | --- |
| Workload | Independently scaled source local routes and the separately labeled unversioned cached-bundle API; generated blocking fixtures |
| Reference and candidate | Audited starting Python `2e672d2d950c6ec471005ddba46e49bba16dc23b`; optimized Python `e79c4bf02bb2cc0b108480313a62c1ce0e9032ba` |
| Correctness | Complete public result and persisted evidence hashes for comparable full routes; complete decision hashes without persistence for unversioned batches; failed/censored comparisons remain unqualified |
| Timing | Raw evaluator-process CPU and local wall observations; no reliable p95/p99 or process-tree qualification |
| Memory | No comparative RSS/private-memory qualification. Existing byte/entry/node/depth bounds remain; immutable bundle indexes consume additional memory proportional to bundle records |
| Operational scope | Existing Python package route and store; no new native binary, loader, ABI or platform distribution burden introduced |
| Platform evidence | Linux x64 source environment, CPython 3.12.14; no installed four-platform package qualification |
| Native status | No native package format is delivered or activated. RSP-055 through RSP-060 remain conditional implementation/qualification work; the selected first-format pilot has not been measured by this baseline report |

A future selected native boundary must beat the optimized Python baseline by at least 30% in full local evaluation p95 or CPU, including serialization and startup amortization, while the other primary metric regresses no more than 5%. It must preserve complete results, authority, malformed-input behavior, supported-format fallback and final execution revalidation, and then qualify its actual installed consumer on the declared platforms. The current source evidence does not satisfy those activation gates.
