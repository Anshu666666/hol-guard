# Package implementation decision at 2ebb01ff

Retain the optimized Python package route for this checkpoint. A package Rust
implementation is **not selected or activated** by these measurements. The
current-versus-optimized-Python comparison is complete for the selected exact npm
protect source route, and the residual breakdown identifies repeated identity, validation and
result construction work. It does not demonstrate a native implementation that
beats optimized Python by the PRD's 30% end-to-end local p95 or CPU threshold.
This is a source-bound no-selection decision, not a claim that Rust could never
provide that improvement or that an unbuilt pilot failed a comparison.

The measured candidate is `2ebb01ff356101aea8d658ce639fe2c87188bd0d`; the frozen
baseline is `2e672d2d950c6ec471005ddba46e49bba16dc23b`. The observations come from
[package run 35240794034](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794034).
They do not qualify a later integration source, installed launcher, native
package path, all-platform behavior or latency tail. Earlier
[d0e phase evidence](PACKAGE_PHASE_CI_EVIDENCE.md) remains a separate cohort.

## Actual outcomes and retained evidence

The [manifest](evidence/package-ci-2ebb/manifest.json) binds four downloaded ZIPs
and 15 retained public files by exact byte length and SHA-256. ZIP size, digest,
bounded member selection and traversal checks preceded extraction. Three phase
ciphertext groups were authenticated and recovered with the existing private
key: 9 validation files, 17 attribution files and 8 registry files. These 34
files include three staging manifests. All recovered files were `0600` under
`0700` directories, with unchanged 256-file, 32 MiB-per-file and 128 MiB-total
limits. Only fixed recovery receipts are committed; private function records,
payloads, ciphertext and keys are absent from this directory. Diagnostic and
format ciphertext recovery is not claimed.

| Job | Actual conclusion | Retained scope |
| --- | --- | --- |
| [Phase attribution, 105268398749](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794034/job/105268398749) | Success | Two candidate validation workers, six separate candidate profiles, two baseline/candidate registry-resolution workers; all ten completed |
| [Diagnostic, 105268398252](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794034/job/105268398252) | Failure | Cardinality: 36 candidate and 24 baseline completions, 12 censored baseline attempts; unresolved pair and all five hot-route pairs completed |
| [Format preflight, 105268398576](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794034/job/105268398576) | Failure | All 20 candidate cases and 18 baseline cases completed; two baseline Composer `package_count` failures |

The failed jobs remain failed. Censored workers have no invented route timing;
the Composer coverage correction is not a parity-equivalent speedup. Every
public staging group is complete with zero missing required records. The
15-second diagnostic, 20-second format and 30-second phase limits contain the
whole worker, including setup and validation; they are not production deadlines.

## Uninstrumented Python comparison

The [diagnostic report](evidence/package-ci-2ebb/diagnostic-component.json)
contains five independent alternating baseline/candidate pairs of the original
exact npm protect dry-run route at D=B=1,000. The median baseline wall/CPU times
were **8,785.843 / 7,739.458 ms**; optimized Python medians were
**327.344 / 319.842 ms**. The median paired reductions were **96.2752% wall and
95.8662% CPU**. These are source-route diagnostics, with serialization and
evidence persistence inside the route, not p95 estimates or Rust benefits.
They do not establish that the adopted package or installed latency targets
have been met.

The independently scaled cardinality matrix covers D/B of 100, 1,000 and 10,000
in absent, exact, emergency-deny and unversioned modes. All 36 candidate cells
completed; 12 baseline cells exceeded whole-worker containment. The single
candidate exact D=B=10,000 evaluator observation was 1,412.288 ms wall and
1,390.448 ms CPU. Unversioned cells exercise the real None-version bundle kernel,
not a fabricated full local evaluator path. These limits remain part of
RSP-050's evidence and must accompany any completion claim.

## What the residual profile actually measures

The [phase report](evidence/package-ci-2ebb/phase-component.json) uses the same
two original npm exact workloads: protect at D=B=1,000 and evaluator at
D=B=10,000, with three independent instrumented invocations each. All six
fixture, semantic, entry, evidence and protect commitments match their separate
uninstrumented validation observations. Each route performs one lockfile parse,
one immutable bundle index construction and one evidence batch. Canonical
package identity is constructed 7,009 / 70,009 times, respectively.

The phase-v2 origin partition assigns every cProfile entry's exclusive
calling-thread CPU once to one of 16 closed categories. It does not turn
function origin into an exact language or machine-code attribution: a Python
caller can own opaque native work, and a C entry can invoke callbacks. Unknown
entries remain `other_python` or `other_c`. Inclusive phase spans overlap and
must not be summed. The profile timer and finite projection are specified in
[the collector contract](package-phase-attribution.md).

Each cell below is the median of three invocations. Percentages are medians of
the per-invocation shares, independently rounded. They describe instrumented
exclusive calling-thread CPU, not ordinary route CPU, savings estimates or
formal upper bounds.

| Function origin | Protect CPU, ms | Protect share | Evaluator CPU, ms | Evaluator share |
| --- | ---: | ---: | ---: | ---: |
| Guard Python | 303.578 | 37.309% | 2,853.080 | 51.752% |
| String/byte C methods | 71.032 | 8.747% | 642.995 | 11.663% |
| Hash C methods | 84.244 | 10.353% | 71.025 | 1.294% |
| Hash Python wrappers | 2.856 | 0.353% | 29.054 | 0.527% |
| JSON Python entries | 43.519 | 5.365% | 352.126 | 6.438% |
| SQLite C entries | 55.100 | 6.796% | 230.840 | 4.220% |
| Regex C entries | 0.744 | 0.091% | 0.188 | 0.003% |
| Regex Python entries | 12.593 | 1.557% | 0.838 | 0.015% |
| Other standard-library Python | 42.697 | 5.263% | 27.503 | 0.500% |
| Other third-party Python | 0.426 | 0.053% | 0.031 | 0.001% |
| Other Python | 52.449 | 6.428% | 449.016 | 8.145% |
| Other C | 143.989 | 17.604% | 848.169 | 15.385% |
| Pydantic Python / Pydantic-core / JSON C / SQLite Python | 0 | 0% | 0 | 0% |

Both Pydantic categories recorded **zero calls**, so this residual cannot be
explained as already-native Pydantic validation. Existing hash, byte-processing
and SQLite primitives do execute in native libraries; moving their Python
wrappers to Rust does not eliminate the underlying work.

| Diagnostic accounting | Protect, ms | Evaluator, ms |
| --- | ---: | ---: |
| All profiled exclusive calling-thread CPU | 813.705 | 5,500.730 |
| Previously named functions' exclusive CPU | 122.942 | 1,011.139 |
| Previously unnamed exclusive CPU, now partitioned above | 690.763 | 4,489.591 |
| Process CPU over the instrumented route | 813.766 | 5,500.876 |
| Instrumented route wall time | 885.769 | 5,996.112 |

The separate signed process-minus-profile residual retains other-thread or
instrumentation differences. It is not assigned to a specific phase. Medians
need not add exactly, and the diagnostic and uninstrumented workers ran in
different jobs. Dividing their numbers would not measure causal profiler
overhead. Repeated tiny Python calls are especially sensitive to profiling cost.

The bounded encrypted residual record retains the top 50 unselected functions
per invocation, with hashes, counts and omitted-function counts. It is not full
cProfile retention: evaluator trials omit 557/557/563 eligible records; protect
trials omit 1,380/1,380/1,389. Source-verified Guard helper names show the concrete
remaining work without publishing private records:

| Existing source function | Protect calls | Evaluator calls | Exclusive median CPU, protect / evaluator ms |
| --- | ---: | ---: | ---: |
| `supply_chain_package_eval._optional_string` | 21,090 | 210,090 | 31.261 / 323.280 |
| `supply_chain_bundle_base._require_string` | 11,025 | 110,025 | 23.281 / 245.353 |
| `supply_chain_package_identity.normalize_ecosystem` | 18,027 | 180,027 | 23.835 / 245.032 |
| `supply_chain_package_eval._result_package_identity` | 3,000 | 30,000 | 14.584 / 149.896 |
| `supply_chain_package_identity.normalize_package_component` | 7,009 | 70,009 | 13.139 / 136.705 |

These counts are exact per invocation for all three trials. The source repeats
normalization while constructing canonical identities, projecting results and
forming evidence identities. They identify a possible reuse boundary within one
immutable evaluation; they do not authorize skipping validation, retaining trust
across mutable inputs, or changing canonicalization.

The parser's inclusive medians are 33.362 / 341.156 ms, versus total profiled
exclusive medians of 813.705 / 5,500.730 ms. Bundle load inclusive medians are
129.462 / 1,414.827 ms; evidence projection is 120.366 / 1,250.724 ms. These
overlapping spans support looking beyond a parser-only port. They are not
additive native savings. Signed bundle admission genuinely occurs before the
unchanged route interval; zero in-route signature/canonical-payload calls apply
only to this pre-admitted route.

## Separate real-resolution witness

Both baseline and candidate passed the 100-request explicit npm `*` fixture,
making exactly 100 admitted GETs through frozen transport bytes while using the
real retry dispatch, JSON decoder, semver resolver, evaluator, protect projection
and evidence persistence. Exact URL, method, headers, body absence and unchanged
one-second initial/retry budgets are checked. Each resolves to 2.0.0 with risk
100, despite 1.0.0 carrying risk 999, so substituting None-version highest-risk
matching fails the oracle. The pair's semantic and evidence commitments agree.

This measures neither external HTTPS latency nor bare-name resolution. Bare
`latest` retains its existing literal shortcut in both sources. The explicit
`*` witness does not replace the None-version kernel's distinct coverage.

## Decision and reopening gate

RSP-054's Python comparison supports keeping the implemented algorithmic gains:
indexed bundle matching, one parse per exact-content evaluation and batched
evidence storage. No parser-only or individual normalization-function Rust port
is selected. Such a boundary would retain repeated model/result traversal and
introduce integration costs that this evidence has not measured.

A future pilot should be one coarse immutable model/identity/result-projection
operation, after first checking whether the repeated work can be removed within
optimized Python. It must preserve canonical duplicates, ecosystem rules,
unversioned highest risk, stale emergency denies, exact-content parser identity,
incomplete results and evidence authorization/redaction/deduplication. SQLite
transaction ownership and mutable trust stay at their existing boundaries.

Selection requires an actual optimized-Python/native comparison of the same
real local route, including serialization, startup amortization and equivalent
correctness evidence. The gate remains at least 30% improvement in local p95 or
process-tree CPU with no more than 5% regression in the other metric, plus the
PRD's resource and platform conditions. No such comparison exists in this
checkpoint. The measured decision is to retain Python now and leave native
implementation and activation unselected, with this explicit reopening gate.

A separate Main CI shard at the same source rejected a negative profiling total
in its in-process correctness test. That failure is retained as a collector-test
issue; the phase job above actually completed all six fresh-worker profiles.
This document does not relabel Main CI as successful or infer an unseen negative
field/value from the short traceback.

The subsequent test correction executes the actual fresh-worker CLI instead of
profiling inside the shared pytest process. It preserves the signed fixture,
oracle, single-parse and private-journal assertions; deterministic negative-total
tests still require rejection. Fixed field and bounded numeric diagnostics
improve a future failure report without clamping values or changing the timer.
The 100 focused local tests passed under coverage after that correction. That is
source-test evidence, not a rerun of the failed Main CI job or a new measurement.
