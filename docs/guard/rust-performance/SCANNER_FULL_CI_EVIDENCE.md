# Full scanner CLI experiment: a9339213

The full source CLI experiment completed all **840 planned observations** across **35 independent fixture/run shards**. Only the two `working_provider_large` cache cohorts passed the unchanged benefit rule; all twelve other cohorts failed it. **Keep optimized Python as the default.** The measured large-file result supports a narrow candidate for further port selection, not blanket native activation or an inferred size threshold.

This freezes [run 35270748894](https://github.com/hashgraph-online/hol-guard/actions/runs/35270748894), attempt 1, at source `a933921372ddb3772eff8a9d86771fe15da063b1`, tree `3db430b618fe63cc1b85b8037e5de700cc3378c9`. Its merge `e54cf7732f61a6a7e609250a4e17344b5e92039d` has the same tree. This was a separately requested full-label event: all 37 jobs passed (plan, 35 shards, aggregate). It is separate from the original 41 synchronize workflows and from [smoke run 35270079985](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079985). The smoke run's 24 observations are not pooled into this report.

## Boundary, workload, and measurement

The [benchmark-only pilot](https://github.com/hashgraph-online/hol-guard/blob/a933921372ddb3772eff8a9d86771fe15da063b1/scripts/secret_scan_native_pilot.py) substitutes bounded ASCII regular-expression candidate extraction in a fresh Python CLI process. Python retains classification, suppression, entropy checks, positions, completeness and finding limits, ordering, public HMAC construction, and fallback. The experiment includes startup, Python/Rust serialization, JSON stdout, process shutdown, and the reaped CLI/Git/native descendant CPU boundary. Cache preparation and fixture creation occur outside each timed CLI call. Both arms use this same source and locked environment; this is not a comparison against the frozen 2e672d2 release baseline. These are source CLI measurements on Linux x86-64, Python 3.12.14; no macOS, Windows, installed-wheel, or default-production activation is qualified here. See the pinned [collector](https://github.com/hashgraph-online/hol-guard/blob/a933921372ddb3772eff8a9d86771fe15da063b1/scripts/scanner_pilot_process.py), [workload definitions](https://github.com/hashgraph-online/hol-guard/blob/a933921372ddb3772eff8a9d86771fe15da063b1/scripts/secret_scan_benchmark_fixtures.py), and [comparison implementation](https://github.com/hashgraph-online/hol-guard/blob/a933921372ddb3772eff8a9d86771fe15da063b1/scripts/scanner_pilot_public.py).

Each of seven workloads has five independent runs. Every run offers six alternating optimized-Python/native pairs in each of two states, `prewarmed` and `evicted`: 7 × 5 × 6 × 2 × 2 = 840 CLI observations. Thus each workload/cache cohort has 30 observations per arm, grouped into five independent runs. All 840 completed; none failed or remained unoffered. All 420 native-arm observations reported native work and zero Python fallback files. Native work counts are preserved per shard; they represent actual extraction calls and must not be substituted for logical Git-file occurrences (repeated blobs can reuse results).

The dense workload is exactly four 256 KiB files with 170 findings per file, 680 findings total. The timed collector explicitly uses `--max-findings 10000` so this case can complete; the default 500-finding truncation contract is checked separately by preflight. Staged cases include deliberate unstaged changes; history uses six commits plus working files. The unchanged preflight validates rule/context expectations, public HMAC behavior, full finding counts, files/bytes, completeness, bounds, and CLI exits. These are producer-verified checks, with their commitments retained below.

The original selection rule is a reduction of at least 30% in full-command wall time or CPU, with no more than 5% regression in the other metric. The implementation uses the larger of the pooled point ratio and the **unrounded** upper 95% interval for each metric, then applies `(wall <= 0.70 and cpu <= 1.05) or (cpu <= 0.70 and wall <= 1.05)`. Each run contributes its six-sample nearest-rank p95 wall time or mean CPU; the interval resamples the five paired run ratios 2,000 times with seed 0. This review independently recomputed all 28 metric comparisons and all 14 gates from the retained observations, exactly matching the producer aggregate. A workflow success proves complete evidence collection; it does not turn a failed benefit gate into a pass.

## All fourteen comparisons

Ratios are native / optimized Python; lower is better. Brackets show the producer's rounded 95% interval. Gate calculations retain unrounded bounds and pooled ratios in [the exact aggregate](evidence/scanner-full-a9339213/scanner-aggregate.json) and [independent audit](evidence/scanner-full-a9339213/independent-audit.json).

| Workload | Cache state | p95 wall ratio [95% interval] | Mean CPU ratio [95% interval] | Original gate |
| --- | --- | --- | --- | --- |
| Working: 17 × 512 B, providers | prewarmed | 1.104176 [1.083907, 1.148515] | 1.107950 [1.099458, 1.120179] | FAIL |
| Working: 17 × 512 B, providers | evicted | 1.111847 [1.086511, 1.135154] | 1.108895 [1.086445, 1.117857] | FAIL |
| Working: 510 × 512 B, providers | prewarmed | 1.081009 [1.057604, 1.105322] | 1.064203 [1.042199, 1.068736] | FAIL |
| Working: 510 × 512 B, providers | evicted | 0.797154 [0.529641, 1.302142] | 1.042821 [1.040069, 1.055637] | FAIL |
| Working: 4 × 256 KiB, dense findings | prewarmed | 0.467884 [0.440494, 0.480920] | 0.461275 [0.445936, 0.476608] | PASS |
| Working: 4 × 256 KiB, dense findings | evicted | 0.379151 [0.301231, 0.471390] | 0.458187 [0.444888, 0.476023] | PASS |
| Staged: 34 × 512 B, unstaged divergence | prewarmed | 1.101536 [0.979765, 1.216099] | 1.097964 [1.080102, 1.116743] | FAIL |
| Staged: 34 × 512 B, unstaged divergence | evicted | 1.099890 [1.050987, 1.107483] | 1.099834 [1.097135, 1.113429] | FAIL |
| Staged: 170 × 2 KiB, repeated catalog | prewarmed | 1.095028 [1.070785, 1.191182] | 1.087204 [1.078433, 1.120355] | FAIL |
| Staged: 170 × 2 KiB, repeated catalog | evicted | 1.087777 [0.994706, 1.105552] | 1.082776 [1.081541, 1.090920] | FAIL |
| History: 34 × 2 KiB, repeated catalog | prewarmed | 1.036593 [1.031286, 1.055512] | 1.034952 [1.029557, 1.036930] | FAIL |
| History: 34 × 2 KiB, repeated catalog | evicted | 1.057916 [1.032248, 1.478883] | 1.033225 [1.030717, 1.046120] | FAIL |
| Working: 1,000 × 256 B, safe unique files | prewarmed | 1.130025 [1.107934, 1.162811] | 1.122144 [1.092601, 1.149202] | FAIL |
| Working: 1,000 × 256 B, safe unique files | evicted | 1.123335 [1.099624, 2.256550] | 1.127237 [1.114122, 1.149734] | FAIL |

The many-small-provider evicted case illustrates why point estimates alone are insufficient: its median wall ratio is 0.797154, while its upper wall interval is 1.302142 and its CPU upper interval is 1.055637. It fails the original rule. None of the twelve failed cohorts is omitted or reclassified.

For absolute scale, the next table shows medians across the five per-run p95 wall summaries and five per-run mean CPU summaries, in milliseconds. They are descriptive summaries, not the paired ratio estimator and not 30-sample tail qualification.

| Workload | Cache state | Python p95 wall ms | Native p95 wall ms | Python mean CPU ms | Native mean CPU ms |
| --- | --- | ---: | ---: | ---: | ---: |
| working_provider_small | prewarmed | 189.236 | 213.704 | 185.782 | 208.109 |
| working_provider_small | evicted | 190.441 | 213.521 | 186.554 | 208.541 |
| working_provider_many | prewarmed | 400.785 | 436.564 | 396.835 | 424.112 |
| working_provider_many | evicted | 1028.536 | 681.214 | 419.517 | 442.858 |
| working_provider_large | prewarmed | 713.271 | 325.914 | 704.212 | 319.681 |
| working_provider_large | evicted | 857.416 | 326.266 | 707.567 | 321.645 |
| staged_provider_diverged | prewarmed | 209.795 | 231.293 | 207.406 | 227.725 |
| staged_provider_diverged | evicted | 218.687 | 240.004 | 208.383 | 230.255 |
| staged_provider_repeated | prewarmed | 228.958 | 251.937 | 225.702 | 245.384 |
| staged_provider_repeated | evicted | 233.102 | 253.563 | 225.631 | 246.123 |
| history_provider_repeated | prewarmed | 343.762 | 354.517 | 339.914 | 349.961 |
| history_provider_repeated | evicted | 388.668 | 411.178 | 342.095 | 352.725 |
| working_many_unique | prewarmed | 529.391 | 605.571 | 524.007 | 588.012 |
| working_many_unique | evicted | 859.071 | 1001.460 | 558.985 | 628.300 |

## Equivalence, identity, and evidence custody

Within **each** matched shard, all 24 observations have identical complete-result and stdout SHA-256 commitments across both arms and both cache states. The public projection reports preflight success, unchanged source/fixture identity after collection, and no worker or identity failure. This review checked those public commitments and exact conservation independently; it did not decrypt private raw finding payloads or independently re-run their finding-level oracle.

All 35 shards share the same source, scanner, harness, locked-dependency, native-binary, interpreter, and interpreter-setup identities. Host metadata remains attached to each run. The native binary is `e65c59e3c6d524819114b6b443f18624b090f86442835eaa44dffee52e6dbcd9`; the owned Python executable is `bef88f140b625959f8af25c7b75cce2cd5d4b29cc2f2b079befd7f68eda4dba0`. Exact hashes and per-run workload commitments are preserved in the audit.

Independent fixture hashes are deliberately retained rather than collapsed: each workload has five distinct full fixture commitments, and history has four distinct result/stdout commitments across five runs. The [fixture commitment](https://github.com/hashgraph-online/hol-guard/blob/a933921372ddb3772eff8a9d86771fe15da063b1/scripts/scanner_pilot_protocol.py) includes Git metadata, and [history results](https://github.com/hashgraph-online/hol-guard/blob/a933921372ddb3772eff8a9d86771fe15da063b1/src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py) retain commit identity. Fixture construction does not freeze Git commit timestamps or index stat metadata. Consequently this report claims exact equivalence of matched arms within a shard, not byte-identical repository metadata or history JSON across independent runs. No cross-run hash mismatch was silently normalized; the public evidence does not identify the particular differing private members.

The [manifest](evidence/scanner-full-a9339213/manifest.json) retains all 35 public shard ZIP identities, their 105 exact JSON members, all 37 job outcomes, the original aggregate, the independent audit, and the 35 encrypted-artifact API identities. Each public ZIP was downloaded within explicit size/member bounds and independently matched against the Actions API SHA-256 and size: **97,265 ZIP bytes / 508,896 member bytes**. Each `retention.json` links the original summary and encryption receipt; those hashes were checked. The separate aggregate ZIP is 2,289 bytes, SHA-256 `13e13d9c1b149298ebedf792716115871be430eff2473508b3af2d75174b0317`, also independently downloaded and verified.

The 35 producer encryption receipts report **3,935 private files / 571,280,353 encrypted bytes**. Those are producer commitments, not a claim that the encrypted ZIPs or plaintext were independently verified here. No ciphertext was downloaded or decrypted for this audit. No raw command, source payload, finding candidate, private path, or credential is added to this public evidence.

## Source-bound selection decision and task recommendation

The decision is **no-go for a blanket regex substitution across the measured scanner workloads; keep default Python**. A narrow large, finding-dense working-file port remains a justified candidate because both of its cache cohorts meet the original wall/CPU rule. These seven discrete workloads establish no crossover point or safe production routing threshold. Selecting or activating such a path still requires its own explicit scope, preserved fallback and full-command benefit under the original rule; this note neither implements a selector nor extrapolates these speedups to other sizes, Unicode input, installed platforms, or archive scanning. No additional Rust boundary is selected by a failing cohort.

For the unchanged [144-task TODO](TODO.md), recommend literal **RSP-066 DONE**: this comparison measures optimized Python against the intended native boundary including startup and serialization, publishes the no-go for blanket substitution, and defers the portions without demonstrated full-command benefit. Recommend literal **RSP-072 DONE**: this note publishes full CLI wall/CPU comparisons, complete matched finding-equivalence evidence, the measured Linux platform, and the Python scopes deliberately retained. These are recommendations only; this evidence commit changes no task status, definition, dependency, or gate. RSP-067/068/069 implementation and installed activation requirements, broader performance qualification, and the separate archive obligations are not completed by these measurements. Dependencies remain exactly as written; literal evidence completion does not qualify dependent installed or release tasks.
