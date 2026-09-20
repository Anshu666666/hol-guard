# RSP-119 retained component benchmark assessment

The preserved DONE label has accessible, substantive evidence for its own component-benchmark clause. The original integrated commit `81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6` retains a 549,254-byte result with 638 catalog/control/command combinations, separate cold and warm distributions, explicit candidate/control cardinalities and false-review counts. This assessment re-reads and reconciles those original bytes. It does not run a new benchmark, resume a campaign, or relabel historical timings as measurements of current400.

The original acceptance requires: “Separate cold compile/load from warm evaluation; vary catalog/candidates/controls within valid combined limits and include false-review counts.” Its original dependencies remain RSP-118 and RSP-010. The initial TODO says OPEN; the later preserved execution ledger records DONE and explicitly describes completion of the benchmark acceptance rather than installed RSP-118/120 or release qualification. These different historical snapshots are retained, not overwritten.

## Exact recovered evidence

| Evidence | Git identity |
| --- | --- |
| Integrated historical source | `81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6` |
| Integrated tree | `3c1d250c23bee22e23e5525880bdd3f65a63a59d` |
| Original result, `docs/guard/evidence/native-command-catalog-matrix.v1.json` | `6405314ce5aeb164db98f805e867fb4094ebf985` |
| Original explanation, `docs/guard/native-command-matrix-performance.md` | `a6a65741807b6ecbe5b581bdce7187b5bdb419f8` |
| Recorded measurement source | `d9802fac2142bda7cd69906cb202748d24558abc` |
| Recorded native benchmark executable SHA-256 | `92f41f87c26cc608e44e53290bece20e9cbdfe63ea4fd8a5a7abda8dc12d8ca2` |
| Recorded reference manifest SHA-256 | `cd44468e18e6c88d6b723031beffb97f83b505e866adfdd8583d5fab9a40c1f7` |

The recorded host was Linux x86_64, CPython3.12.14 and Rust1.88.0, on 2026-09-17. The report records the compiler/native commands, executable and stdout hashes, exit0 for both processes, process resources and the shared-host reservation limitation. It identifies its scope as component-only and explicitly sets installed SLO qualification false.

## Independent reconciliation

The result contains 673 measurement records: 3 catalog admissions, 29 control admissions, 638 warm combinations and 3 outcome summaries. Each catalog records ten source compilations and ten native admissions; each control state records100 admissions; each warm combination records100 native evaluations and100 Python observations. All638 rows record declarative parity. Unique catalog/state/command keys and all declared sample/cardinality fields were checked without invoking either implementation.

| Extensions / rules / nodes | States / warm combinations | Declarative candidate range | Maximum controls / binding bytes | Benign ordinary restrictions |
| --- | --- | --- | --- | --- |
| 7 / 89 / 211 | 9 / 198 | 0–22 | 200 / 21,194 | 30 of39 |
| 48 / 200 / 1,092 | 10 / 220 | 5–29 | 506 / 52,979 | 30 of39 |
| 86 / 291 / 2,242 | 10 / 220 | 9–51 | 780 / 80,538 | 30 of39 |

All29 control binding sizes fit the original256KiB combined ceiling with16KiB explicitly reserved for surrounding snapshot fields. Control cardinalities remain within the two512-control layers. The native source actually validates each binding and compiles it against its exact admitted catalog; the input builder closes real registry dependencies. These are combined-valid inputs, not independent maximum claims.

All eight outcome totals were recomputed from each retained warm row and match the original summaries. Stronger-than-isolated-Python counts are160/168/158; weaker counts9/10/10. Benign restrictions across all control states are92/102/102. Each catalog has30 review/block outcomes among39 benign ordinary-control cases, with zero newly restricted intrinsic allows in those ordinary states. That last zero is not a zero false-review claim. The original explanation retains Docker/Kubernetes owned-uncertainty blocks and the distinct authority scopes causing other action differences.

Cold compilation/admission and warm evaluation are separate distributions. Python warm observations and native complete generic-pretool evaluation perform different work; no ratio is a justified speedup. Ten-sample cold p95 is the maximum of ten samples, not a statistically qualified startup percentile. Individual maxima are retained in distributions; the original file does not contain each raw timing sample.

## Current source continuity and limits

The exact Python benchmark, catalog/control input builder, trusted program compiler and native matrix test are byte-identical between integrated81ef and current400. Their four before/after hashes are in `source-continuity.json`. Broader production runtime source and the packaged artifact have changed since81ef; all97 changed paths under the selected broader comparison are listed. Current program identity and current installed Ollama proof are separately documented by the RSP120 assessment. This is not proof that the historical638 timing/outcome rows execute unchanged on current400.

The recorded local measurement source d9802fac is not currently accessible through GitHub’s commit endpoint (original422 response retained), while the integrated81ef source, original explanation and full structured result are accessible and hash-verifiable. The result records hashes for the native binary, reference manifest and stdout, but those byte bodies and the individual timing vectors are not embedded in this report. This assessment does not claim a reconstructed native binary or reverified original process stdout. No additional acceptance requirement is invented from those reproducibility limits, and no fresh current-source timing is inferred.

## Recommendation

Record the original RSP119 component-benchmark own scope as supported by this retained638-row evidence, with exact historical source/date and reproducibility limits. Keep its original RSP118/RSP010 dependency edges and their independent acceptance state intact. RSP118’s broader installed lifecycle remains unresolved; this benchmark does not claim to complete it. RSP120’s direct prerequisite can be assessed against this component scope without implying transitive lifecycle, full release or measured end-to-end performance completion. No new benchmark is proposed or executed by this assessment.
