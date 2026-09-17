# Package source diagnostic, version 2

This harness prepares fresh evidence for RSP-050 and RSP-054 after the
`complete-v2` parser change. It does not reuse the earlier package timings,
qualify an installed wheel, implement a native parser, or authorize native
activation. The source baseline is exactly
`2e672d2d950c6ec471005ddba46e49bba16dc23b`; the candidate must be a supplied full
commit with clean measured source. Both children use the same candidate-locked
CPython environment. Source-tree execution is stated in every result.

## Finite workloads and boundaries

`scripts/package_benchmark_corpus.py` defines 567 independently generated cases:

| Scope | Cases | Meaning |
| --- | ---: | --- |
| Ten formats, three independent dependency sizes, three bundle sizes, absent/exact/emergency modes, evaluator/protect routes | 540 | Exact complete input and emitted evidence coverage |
| Genuine versionless install requests, nine cardinality cells, evaluator/protect routes | 18 | Real unresolved production route; isolated fixture has no cloud credentials |
| Unversioned cached-bundle lookup, nine cardinality cells | 9 | Explicitly separate kernel; never labeled complete package execution |

The formats are npm, pnpm, Yarn, Bun JSONC, Cargo, Composer, Bundler, Poetry,
uv, and Pipenv. Dependency and bundle sizes vary independently over 100,
1,000 and 10,000. Dependency identities are distinct; an exact bundle contains
one direct anchor plus `B-1` dependency records, so matched transitive count is
`min(D, B-1)`. Absent cases still contain the blocking direct anchor. Emergency
cases require the explicit deny reason for the first transitive dependency.
Unversioned kernel fixtures contain different-risk versions and require the
highest-risk result; absent identities remain monitor results.

The evaluator boundary includes actual command parsing, artifact construction,
captured input parsing, signed-bundle load/verification, policy composition,
and evidence persistence. The protect boundary calls the actual
`build_package_protect_payload(..., dry_run=True)` path and verifies no command
executed and the terminal exit/verdict. A fresh GuardStore and workspace are
created for each arm/sample and the evaluation cache is explicitly cleared
before measurement. Setup, fixture signing and post-result oracle inspection
are outside the measured interval. The fixture supplies only a synthetic
workspace ID; it uses real generated RSA signatures and real store operations.
Unexpected socket connection attempts invalidate the observation.

The genuine unresolved fixture reaches `premium_cloud`, `cloud-error`, and
`cloud_auth_error`, with every requested version still unresolved and every
package blocked. This is an observed credential-failure path, not an invented
local lookup benchmark. Large unresolved requests can legitimately exceed the
harness resource/time budget; those failures remain incomplete.

## Pairing, oracle and retained evidence

Each pair shares the exact fixture bytes and signed response. The runner binds
source commit plus all tracked Python source/config/lockfile hashes, harness
hash, installed dependency inventory hash, Python executable hash, and machine
metadata. Imports must originate under the selected source root. Source identity
is checked again after each worker and at controller completion. Independent
pairs alternate arm order. `-I` isolates Python environment overrides; no
deterministic hash-seed claim is made.

The frozen oracle verifies expected package names/counts, resolved versions,
ecosystem, direct/transitive status, reason codes, completeness, protect exit,
evidence row count, exact package correspondence, request/action identity,
workspace fingerprint correspondence, and evidence ID conservation. It compares
the entire result/evidence projection, retaining unknown fields. The only
normalizations remove per-attempt identity fields (`package_intent_hash`,
workspace/repository fingerprints and evidence/action/request IDs) and
`lockfileParseElapsedMs`; identity relationships are checked within
each attempt. Parser versions, diagnostics, decisions, policy, reasons and all
other fields remain visible. Tuple/list serialization differences use canonical
JSON equality. Canonical digests are streamed rather than materializing an
additional serialization of large evidence arrays.

An offered journal is written before each child starts. Workers append setup,
measurement-started, measurement-finished and terminal records. The controller
always records contained child failures/timeouts and continues the paired arm;
containment failure stops the run. Fresh output directories prevent stale paired
results. Failed source checks and controller exceptions create `incomplete.json`;
failed or contract-different pairs never produce speed ratios. Public results
accept only a finite worker schema and numeric/hash fields. Child stdout/stderr
and arbitrary exception strings are not republished.

Private evidence contains exact synthetic fixtures and bounded outcome
projections: full-result/evidence digests, counts, and at most sixteen package
samples. It excludes raw command text from outcome samples. Files use exclusive
creation, Linux owner-private directory/file admission, no-follow opens, and
regular-file/single-link checks. These paths are for the existing encrypted
qualification archive, not a raw upload. Completed/contained attempt workspaces
are removed; their timing and outcome records remain. The default runner is
Linux-only and makes no Windows ACL or cross-platform execution claim.

The worker CLI has explicit fixture-process ceilings of 4 GiB address space and
64 MiB per file. These are harness resource limits, not changes to Guard's
8 MiB/input, 100,000-entry, 250,000-node, depth-128 or parser deadline contracts.
Whole-worker timeouts include imports, setup, measurement and postvalidation;
they do not imply a measured evaluator latency. `validation` emits no timings.
`attribution` counts relevant parse/read/evidence calls using a separate profiled
invocation and never yields a speed ratio. `timing` records wall time and CPU for
the worker plus waited children. This CPU scope does not claim descendant-tree
sampling or installed daemon CPU coverage.

## Bounded default CI

`.github/workflows/package-performance-rebaseline.yml` defines two independent
Linux jobs with pinned baseline/candidate checkouts and one candidate
`uv sync --frozen --extra dev --python 3.12` environment per job. Each uses a
runner-local lock; neither acquires or bypasses the occupied shared local
measurement lock. The controller uses that same interpreter. Every scope gets
a fresh output directory. A contained scope failure remains nonzero while the
other scopes in that job continue. The workflow runs on relevant pull-request
changes and manual dispatch; this implementation record does not claim CI has run.

| Job/scope | Preset | Runs × samples | Measurement | Processes | Whole-worker limit |
| --- | --- | --- | --- | ---: | ---: |
| Format preflight (25 minute job) | `format-preflight` | 1 × 1 | validation | 40 | 20 s |
| Cardinality diagnostic (30 minute job) | `cardinality` | 1 × 1 | timing | 72 | 15 s |
| Same diagnostic job, real unresolved witness | `unresolved` | 1 × 1 | validation | 2 | 15 s |
| Same diagnostic job, selected hot route | `hot-route` | 5 × 1 | timing | 10 | 15 s |

The preflight bounds worker execution to 13 minutes 20 seconds; the diagnostic
job bounds it to 21 minutes, leaving setup/archive time inside the job budget.
These ceilings do not guarantee completion on a loaded machine. Always-run
finalization retains failed/incomplete status and available journals while the
runner remains available. A hard runner termination can prevent finalization
and upload; such a job is
incomplete, never qualified from an earlier public file. Do not convert timeout
rows into observed latency or run only successful rows
through a benefit calculation. The full 567-case selection and its 63 disjoint
nine-cell shards are opt-in correctness/exploration tools, not default PR timing.

The always-run `package_rebaseline_ci.py` finalizer independently checks exact
source arms, finite preset cases, attempt identities, timeout scope and strict
completed-worker output before recomputing comparisons. It publishes only known
case IDs, numeric observations, hashes and finite failure codes. Raw environment
metadata, commands, fixtures, stdout and stderr are not public fields. A corrupt
or missing aggregate cannot be rescued by a stale success file. Missing required
fixture/offered-journal files make archive staging incomplete, even if an
aggregate claims success. A validated completed non-kernel attempt also requires
its private semantic projection. Failed, censored and kernel attempts may
legitimately lack that projection.

Private staging copies only the finite expected fixture, journal, semantic and
aggregate paths using owner-private, no-follow file admission. It retains partial
journals byte for byte. Cardinality evidence is split by dependency size to stay
inside the existing 256-file, 32 MiB/file and 128 MiB/archive limits; format,
unresolved and hot-route evidence have separate groups. Each archive includes a
private filename mapping. The existing public-recipient encryption helper creates
one `.hge` per group, using recipient
`d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb`.
Only fixed public status/receipt filenames and fixed encrypted filenames are
uploaded. The old Composer coverage defect keeps format preflight incomplete;
the candidate attempt and the other completed format pairs remain in evidence.

Example invocation (replace paths and SHA with pinned checkout values):

```sh
candidate/.venv/bin/python candidate/scripts/package_benchmark_matrix.py \
  --baseline-root baseline --candidate-root candidate --candidate-sha FULL_SHA \
  --output qualification-evidence/package-cardinality \
  --preset cardinality --runs 1 --samples 1 --max-attempts 72 \
  --measurement timing --timeout-seconds 15
```

Five hot-route pairs yield descriptive median/range reductions only. No p95,
tail confidence interval, installed qualification or native benefit is inferred.
The native admission requirement remains at least 30% full-local p95 or CPU
improvement over optimized Python, with no more than 5% regression in the other
metric. A native candidate is not present in this comparison. RSP-054 therefore
remains a measured selection task after these fresh diagnostic results, and
RSP-055–059 must not be marked native-complete from this harness.

## Known intentional differences

Complete-v2 enforces explicit text node/depth admission and preserves typed
incomplete results within one evaluation. Original complete-v1 may admit a
different input or retry it. Those outcomes are contract differences, not
performance samples with equivalent work.

Composer fixtures use genuine `vendor/package` names. The frozen baseline's
transitive path helper skips those names despite a complete parser result. The
oracle reports that as a coverage failure. A corrected candidate that looks up
all Composer dependencies performs additional required work and remains
noncomparable to the baseline's zero-lookup path. This harness does not rename
Composer packages to conceal that gap.

## Implementation validation

The initial harness validation has 62 passing disconnected tests covering the
frozen formats/modes, actual evaluator/protect calls, private file handling,
wrong-arm/partial/timeout/output-limit/containment failures, source changes,
strict worker projections and no favorable-subset summaries. Six scripts passed
BasedPyright with zero errors and 240 strict warnings; Ruff/format checks passed.
One real frozen-baseline/candidate npm 100-by-100 pair completed in validation
mode with matching full semantic, evidence and entry digests. Its
[bounded validation record](evidence/rsp-package-matrix-v2-validation.json)
contains no timing samples. An earlier format preflight was interrupted by
workspace disk exhaustion; it is explicitly unqualified and its private offered/
worker journals were retained. No complete format-wide CI run is claimed here.

The CI follow-up passed 75 combined disconnected harness/finalizer tests. After
adding encrypted truncated-journal and missing-semantic regressions, all 15
finalizer tests passed.
That roundtrip uses a generated fixture recipient with the existing archive
implementation; it does not replace the configured qualification recipient. The
new finalizer passed BasedPyright with zero errors and 67 strict warnings, Ruff
and formatting checks. Workflow YAML parsed with the two declared matrix jobs,
and the finalizer CLI loaded under `python -I -S`. Independent Actions execution,
not these correctness checks, must supply the fresh paired observations.

Independent source-only review checked pinned source selection, paired identities,
public projection, archive bounds/completeness and fixed encrypted uploads. Its
missing-semantic-record finding was corrected and regression-tested. The reviewer
reported no remaining concrete finding in that scope; this was not an independent
test run or a performance measurement.
