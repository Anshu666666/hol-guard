# Package native selection and bundle correction

Retain optimized Python in production. A real bounded Rust package-lock parser was
built and invoked by the full source evaluator, including its process and JSON
boundary costs. Its primary parser-heavy workload regressed CPU by 11.03% and wall
time by 16.31%, and no fully comparable selected native workload demonstrated the
30% CPU benefit gate. This is a no-go for this prototype and declared scope, not a
claim about unmeasured formats, shapes or native signed-bundle kernels.

The immutable Python bundle correction is retained. It removes one redundant
canonical-identity pass for unique parsed bundle payloads while keeping duplicate,
signed order, emergency deny and trust behavior. The directly repeated original
deny regression workload improved CPU and wall in all five new pairs. Earlier
regressions and failures remain in the [continuation report](rsp-package-continuation.md).

## What actually ran

Both native arms used clean source `f0aba7317fa9f25f570543d8575ac91b236d99c3`.
The explicit example artifact was
`3a7243b9e0b07a67b98367719432face7f11a52aa8b9264eb77cc174bd122e2d`. Its
[protocol and invocation scope](rsp-package-native-protocol.md) are finite: integer
v3 package-lock input, Linux source route, 256 KiB–8 MiB, native depth at most 64,
with the original Python fallback and product limits preserved. No Cargo manifest,
lockfile, installed entrypoint or production default was changed for the pilot.

Five blocks alternated AB/BA within every workload. Each arm used a fresh interpreter
and store, one timed full `evaluate_package_request_artifact` call, no warmup and no
additional profile sample. Fixture creation/signing, setup, output hashing and
cleanup were outside the evaluation timer. The shared measurement lock covered each
pair and its child processes. Timings include reading/parsing, cached signed-bundle
model load, matching, policy composition, cache/evidence work, child startup,
request/response encoding and copies, and immutable Python result construction.
CPU includes the parent and every child reaped during evaluation. On the 20 native
calls, measured child CPU ranged from 20.24 to 451.29 ms
(median 33.82 ms); none of that cost was excluded.

All 30 requested pairs are retained: 29 have equal hashes for
every public result field and every persisted evidence column, without
normalization. All 20 selected candidate calls completed natively. All 10 small-input
controls recorded zero native invocations and explicit Python size fallback.
Source, harness and artifact identities remained stable through final validation.

## Full-route observations

Numbers below are the percentage improvement calculated from the median of each
arm's five fresh-process observations; negative means a regression. They are
shared-host diagnostic observations, not p95 estimates or installed qualification.
No aggregate gate is assigned to a workload with a failed pair.

| Dependency × bundle workload | Candidate route | Equal pairs | CPU improvement | Wall improvement |
| --- | --- | --- | --- | --- |
| 10,000 × 100 absent | Native | 5/5 | -11.03% | -16.31% |
| 10,000 × 1,000 absent | Native | 4/5 | not comparable | not comparable |
| 10,000 × 1,000 exact | Native | 5/5 | +25.20% | +22.76% |
| 10,000 × 10,000 deny | Native | 5/5 | +7.82% | +7.94% |
| 100 × 1,000 exact | Python fallback control | 5/5 | -12.86% | -27.19% |
| 100 × 10,000 deny | Python fallback control | 5/5 | -136.95% | -126.11% |

Repeat 2 of 10,000 × 1,000 absent produced a baseline harness error. The exact retained
stderr hash (`cb8f83d7052ac21856a962399e31c05ee63daf07fefff1f45a9610590fec857c`) matches the reconstructed
`Unexpected route output: ask, 1 packages` traceback in the machine summary. That
baseline gets no latency or parity pass. Its candidate completed natively; the
underlying original parse/policy cause was not retained and remains unresolved.

Individual observations varied widely, including very large swings in the small
deny control that never invoked Rust. This establishes a limitation on causal
attribution; it does not justify deleting slower samples or blaming all differences
on the native kernel. The complete raw arrays and failures remain reviewable. No
memory/RSS, reliable tail, installed artifact, four-platform or rollout claim is made.
Operational cost is one extra process per selected captured lockfile and two JSON
boundaries, measured inside evaluation; Python retains all signature, keyring,
freshness, rollback, authority, cache, policy and persistence responsibilities.

## Narrow bundle correction

The correction is `5f63b3000`, with the compatibility witness in `8cad2b16f`.
Against the previous optimized Python source `e79c4bf02`, all 15 paired controls had
exact complete-result and evidence parity:

| Dependency × bundle workload | CPU improvement | Wall improvement |
| --- | --- | --- |
| 100 × 10,000 deny | +8.29% | +15.88% |
| 100 × 1,000 exact | +34.30% | +33.97% |
| 10,000 × 1,000 absent | +33.11% | +29.66% |

The separate direct comparison against original source `2e672d2d` repeated the
100 × 10,000 deny workload five times with equal fresh state and alternating order.
All five pair signs improved; the ratio of medians improved CPU by 44.52% and wall
by 42.12%. That is direct evidence for the correction on the material regression
case, without erasing the earlier record.
The finite case-selection wrapper is retained with its hash in every checkpoint.

Unique parsed bundles now canonicalize once in immutable index construction.
Exact duplicate payloads preserve the deduplicated public sequence and compact
index positions; direct dataclass construction keeps its existing duplicate
behavior. If a payload contains both conflicting package identities and an invalid
advisory, the first detailed malformed-error text can change. The error family is
unchanged, and the new witness compares every public evaluator result and persisted
evidence field across the old and new validation priorities; all are equal.

Validation: 4 release Rust example tests; release example Clippy with warnings denied;
64 native projection/fallback tests; 17 existing matrix-integrity tests; 3 paired
summary tests; 110 existing bundle/evaluator tests and 4 focused correction tests.
Ruff, formatting and whitespace checks pass. Scoped bundle typechecking has zero
errors before and after; warnings decrease from 34 to 33 by removal of one private
helper import. Counts describe their individual suites and are not added across
overlapping reruns.

## Proposed original acceptance disposition

| Row | Proposed disposition | Exact scope |
| --- | --- | --- |
| RSP-050 | Open for literal full-route unversioned matching | All 36 independent original dependency/bundle/match cells were attempted and retained: 27 full evaluator routes and 9 separate unversioned cached-bundle API diagnostics. The production evaluator never passes a None version to that API; the [real artifact witness](rsp-package-unversioned-route.md) records the exact current behavior. Failed/censored arms have no invented timing or parity, and the API cells do not satisfy full-route acceptance. |
| RSP-054 | Complete bounded selection | Current-versus-optimized Python evidence plus an actual first-format native source-route comparison supports retaining optimized Python for this prototype's failed gate. |
| RSP-055 | Deferred pending a new go decision | The production package evaluation request/result schemas with verified bundle/policy identities are not delivered by the narrower experimental parser envelope. |
| RSP-056 | Defer production port | A compiled and measured v3 parser example exists; the proposed production guard-package-core was not added after a failed benefit gate. |
| RSP-057 | Deferred pending a new go decision | Native indexed signed-bundle evaluation remains unbuilt. This parser result does not establish a no-go for every possible bundle kernel. |
| RSP-058 | Defer production integration | The actual full source evaluator was exercised through explicit benchmark injection; installed protect/audit native activation is not claimed. |
| RSP-059 | Defer native format expansion | Finite v3 differential/malformed coverage and unchanged fallback tests for the other nine formats are delivered; broad native-format and installed lifecycle parity are not. |
| RSP-060 | Defer activation | Native scope is published, no installed/platform benefit qualification occurred, and Python remains the production default. |

These are bounded selection dispositions under the original conditional go/no-go
plan. They do not mark unbuilt production acceptance criteria as implemented or
claim that unmeasured work is unnecessary. The original matrix's unversioned API
scope and incomplete pairs must remain visible in the execution ledger. The later
functional route witness corrects the earlier proposed measurement-complete label
for RSP-050; it does not change the measured native selection or correction results.

## Retained evidence

- [Machine-readable selection, failure witness and validation](performance/rsp-package-native-selection.json)
- [All 30 native/control pairs](performance/rsp-package-native-paired-matrix.json)
- [All 15 optimized-Python correction pairs](performance/rsp-package-bundle-correction-pairs.json)
- [Five direct original-baseline deny pairs](performance/rsp-package-deny-postfix-original-pairs.json)
- [Exact targeted-control driver](performance/rsp-package-deny-postfix-runner.txt)
- [Initial actual full-route native witness](performance/rsp-package-native-full-route-smoke.json)
- [Bundle typecheck before](performance/rsp-package-bundle-before-fix-typecheck.json) and [after](performance/rsp-package-bundle-fix-typecheck.json)
