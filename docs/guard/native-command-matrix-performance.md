# Native command catalog and control component matrix

This diagnostic executes 638 catalog/control/command combinations through the
trusted compiler, native program admission, control admission, and native generic
PreToolUse evaluator. Every combination preserves the complete independent Python
declarative observations. The report retains differences in final action instead
of treating observation parity as whole-runtime equivalence.

The evidence is [native-command-catalog-matrix.v1.json](evidence/native-command-catalog-matrix.v1.json).
It records source commit `d9802fac2142bda7cd69906cb202748d24558abc`, exact benchmark
binary hashes, compiler-produced program identities, input manifest hash, process
resources, sample counts, and every outcome/distribution. This is local component
evidence, not an installed release SLO or a claimed Python-to-Rust speedup.

## Inputs and execution

The catalogs contain 7, 48, and all 86 reviewed built-in extensions. The compiler
constructs each subset from actual extension definitions, closes extension and
permission dependencies, validates the registry, and computes fresh catalog,
trust, node, and program digests. All subsets retain the 42 compatibility rule
identities required by native admission. No synthetic matcher implementation,
untrusted contribution code, or forged digest enters the measurement.

There are 22 command strings per control state: 13 benign, six destructive, and
three ambiguous. They cover exact native allows, safe Git/GitHub operations,
Ollama opt-in and help, SQL, AWS, Docker/Kubernetes, Unicode operands, a compound
command, an unknown Git alias, and GraphQL. No command is executed. The small
catalog has nine control states because its maximum valid cardinality coincides
with one requested size; the larger catalogs have ten each.

Controls cover defaults, local external opt-in, managed-only enablement, 32 and
128 targets where available, every owned target, both complete layers, disable
dominance, external deactivation, and disabled Git/GitHub/Ollama permissions.
The full catalog has 390 distinct owned targets and exercises 780 controls across
two layers. Its largest binding is 80,538 bytes; the test reserves another 16 KiB
for surrounding snapshot fields and enforces the combined 256 KiB ceiling.
Bindings are validated and compiled against their exact admitted program.
Authenticated publication and per-request mutation leases are outside this
component measurement and remain separately tested production requirements.

Each catalog has ten cold source compilations and ten fresh native in-memory
admissions. Each control state has 100 control admissions, and each command has
100 warm native evaluations and 100 Python observation samples. Expected
observations and final native results are checked outside every timed interval.
The reference profile is CPython 3.12 / Unicode 15; cross-version equivalence is
not inferred from these vectors.

Python timing covers registry observations plus external activation filtering on
an existing canonical model. Native warm timing covers the generic pretool
evaluator, command parsing, compatibility and declarative observations, control
application, and compact evidence binding. Those scopes differ. Neither arm
includes installed launcher startup, HTTP/native transport, the policy store,
approval reuse, or receipt persistence, so no ratio between these columns is
presented as a release performance improvement.

## Reserved local run, 2026-09-17

Linux x86_64, CPython 3.12.14, Rust 1.88 release profile. Other team agents paused
tests and builds for the serial run. The shared host remained outside our
scheduling control; all tails are retained. Ten-sample cold p95 is the maximum
sample and does not establish a statistically qualified startup percentile.

| Extensions / rules / nodes | Python source compile p50 / p95 (ms) | Native admission p50 / p95 (ms) | Native declarative candidates | Maximum controls |
| --- | ---: | ---: | ---: | ---: |
| 7 / 89 / 211 | 41.10 / 112.16 | 8.62 / 11.14 | 0–22 | 200 |
| 48 / 200 / 1,092 | 460.19 / 898.08 | 56.09 / 222.94 | 5–29 | 506 |
| 86 / 291 / 2,242 | 649.90 / 2,210.73 | 84.13 / 114.30 | 9–51 | 780 |

The native raw candidate index also contains 42 compatibility identities, making
its total ranges 42–64, 47–71, and 51–93. The evidence reports declarative and
total counts separately. Compatibility interpretation runs once per canonical
command; these index counts are not a count of IPC calls or Python invocations.

| Full-catalog controls | Binding bytes | Control admission p50 / p95 (µs) |
| --- | ---: | ---: |
| 0 | 456 | 158.36 / 468.81 |
| 32 | 3,239 | 351.20 / 607.35 |
| 128 | 12,407 | 680.81 / 1,707.68 |
| 390 | 40,301 | 1,899.40 / 3,494.05 |
| 780, both layers enabled | 80,148 | 3,218.35 / 5,937.38 |
| 780, managed disable dominance | 80,538 | 3,402.93 / 6,373.80 |

Across the full catalog's 220 combinations, warm native p50 ranges from 25.48 to
520.70 µs. The largest per-case p95 is 1,793.67 µs. The largest individual sample
is 99.17 ms and remains in the raw report. For enabled `ollama push fixture-model`,
one local opt-in control gives p50/p95 81.56/279.22 µs; both full layers give
51.52/118.00 µs. The non-monotonic samples demonstrate why this shared-host run
does not establish a causal control-count speedup. Control compilation belongs
at admission and is excluded from warm decisions.

The compiler/reference process used 40.25 seconds wall / 37.19 seconds user CPU
and 61,200 KiB maximum RSS. The native process used 12.70 seconds wall / 11.01
seconds user CPU and 40,576 KiB maximum RSS. These totals include different
verification and reporting work and must not be compared as a throughput ratio.
The earlier 100-sample admission experiment remains separate evidence; its
different tail does not disappear from the record or become a new SLO threshold.

## Benign restrictions and semantic limits

For each catalog, 30 of 39 benign rows under defaults, local opt-in, or managed-only
enablement are reviewed or blocked. The denominator is 13 benign inputs in three
ordinary control states. All 30 already had an intrinsic native review floor;
there are zero cases where extensions newly turn an intrinsic allow into review
or block under these three states. That narrower zero is not a zero false-review
claim.

Two benign forms, `docker ps` and `kubectl get pods`, become owned-uncertainty
blocks where the intrinsic evaluator requested review. These six additional
hard blocks per catalog are an explicit compatibility limitation requiring
further semantic work. Existing generic review remains for other benign forms,
including SQL reads and help commands. `pwd`, `printf café`, and `git status`
remain native allows under ordinary controls.

| Catalog | Rows | Native action stronger than isolated Python reference | Native action weaker | Benign restrictions across all control states |
| --- | ---: | ---: | ---: | ---: |
| 7 extensions | 198 | 160 | 9 | 92 |
| 48 extensions | 220 | 168 | 10 | 102 |
| 86 extensions | 220 | 158 | 10 | 102 |

The Python final-action reference is `evaluate_command` without the external
compatibility classifier or filesystem proofs. Every weaker row is `pwd`: that
isolated Python component requests review without its read-proof context, while
the established native exact-safe classifier allows it. Stronger rows include
preserved generic review, explicit native compatibility uncertainty, intrinsic
destructive floors, and controls. All 638 complete declarative observation sets
match; final-action counts remain visible because those components have richer,
different authority contexts. Explicitly disabled control states are retained in
the all-state counts and are excluded from the ordinary-control false-review
denominator.

## Reproduction

Run from the repository root in the locked CPython 3.12 development environment,
with an exclusive team measurement reservation and previously built release tests:

```sh
PYTHONPATH=src python -m scripts.bench_native_command_matrix \
  --output /tmp/native-command-matrix --compile-samples 10 --warm-samples 100
HOL_GUARD_COMMAND_MATRIX_DIR=/tmp/native-command-matrix \
  cargo test --locked --manifest-path rust/Cargo.toml --release -p guard-command \
  native_command_catalog_control_matrix -- --ignored --nocapture --test-threads=1
```

Program files and reference observations are reproducible fixture outputs. Native
alternate-program admission is reachable only from the ignored in-crate test;
production still loads its single packaged, attested program. RSP-119 now has a
valid catalog/control/candidate component matrix and explicit restriction counts.
Installed route qualification, the optimized-Python end-to-end comparison, and
artifact update/rollback acceptance remain separate gates.
