# Streaming MCP preparation F: incomplete first comparison

Keep optimized Python B as the product default and RSP-100 OPEN. The first
preregistered B/F comparison stopped at cell 20 of 64 when the baseline worker
exited during its first near-limit dense-integer call in the second block. The
attempt retains 19 completed cells, the failed cell and all 44 never-attempted
cells. It was not retried, resumed, reordered or replaced. No diagnostic profile
ran, no five-block performance summary is inferred from the partial cohort,
and F is not activated.

F remains a concrete, private implementation of sequential exact binding
comparison with the separately corrected final-write selector. Its source
validation is distinct from the stopped route measurement. The complete
historical E comparison and its source remain byte-for-byte unchanged; this
attempt neither pools E observations nor replaces its finite safety limits.

## Implementation and source validation

The [F boundary](mcp-streaming-preparation-pilot-boundary.md) records the strict
finite plain-JSON owner, serialize-only CPython protocol-4 binding, unchanged
authority checks, exact saved-claim rebuilding and actual immutable wire-byte
authorization. Initial request/artifact/command bindings are retained. Freshness
checks compare emitted bytes sequentially against those references without
accumulating a second complete binding. They still finish serialization after a
mismatch, reject custom values, and enforce the existing serialized limit.
Large strings can still allocate a full Pickler output chunk; owned containers,
retained bindings, final wire decoding and JSON encoding also remain allocated.

F selects the admitted final frame by object ownership before full byte
authorization. This corrects frozen E's mutable-method selector gap. Two actual
child-pipe regressions failed against the initial F selector before correction;
the final F gate passed 44 tests in 11.39 seconds. Those tests include the
96-case authority/browser comparison within that count, actual child/no-child
mutation cases, changed encoded wire after owner restoration, original approval
deadlines, unrelated child replies and nested B calls with context restoration.
The [retained source evidence](rust-performance/evidence/mcp-stream-binding-feasibility/manifest.json)
contains the collection failure, earlier overlapping 39-test pass, two failed
method cases and final 44-test receipt. These are not new campaign test counts.

The explicit F worker and collector were prepared in commit
5a5ad6d3873d83ac6411bf9204f704c449580c41. Their separate
[fixed plan](rust-performance/mcp-streaming-preparation-plan.md) preserves E's
workload, ordering, quantiles, timeouts, resource scopes and phase rules. Its
16-test source/accounting validation used stubbed workers and passed in
0.92 seconds; it is not a measured route. Product code does not install the
adapter. Package, unsupported and busy/nested admission continue through B.

## Frozen launch and exact outcome

Both arms used the same complete 5a5ad6 runtime/harness export on tmpfs. The
independent public oracle used the complete d811b08f081d72c348b95f0cf9e45349fb1787e6
export with the four frozen B module hashes. Before launch, all 4,635 runtime
files (61,603,323 bytes) and 4,100 oracle files (51,565,876 bytes) matched Git blob
bytes, SHA-256 values and executable modes. CPython 3.12.14 and all 69 installed
distribution identities were recorded; 12,745 RECORD-hashed files totaling
343,809,854 bytes verified, and every installed version appeared in the frozen
lockfile. Unhashed RECORD entries are explicitly outside that verification.

The collector passed the separate 3,008-case oracle with zero mismatches for
ordered risk categories, approval hashes and full policy decisions. As in the
frozen helper, this loads the historical B module with shared unchanged
authorities; it is not an installed or cross-platform test. The first timed
cell began at 2026-09-17 18:54:40.610097 UTC. Cell 20 failed at
18:59:13.026099 UTC, 272.416 seconds later. The nineteen completed cells occupied
240.598 seconds in their individual shared-lock intervals; the failed cell's
interval was 24.403 seconds. No outer campaign lock excluded other coordinated
work between cells.

| Accounting | B | F | Total |
| --- | ---: | ---: | ---: |
| Completed cells | 9 | 10 | 19 |
| Failed cells | 1 | 0 | 1 |
| Never-attempted cells | 22 | 22 | 44 |
| Verified accepted responses/forwards in completed cells | 198 | 202 | 400 |
| Progress notifications in completed cells | 198 | 202 | 400 |
| Attempted tool calls, including the failed first call | 199 | 202 | 401 |

F recorded 202 admissions, category derivations, completed preparations and
bound forwards. Completed cells reported no selected failures, fallback,
cancellation, invalidation or error. This applies to those completed fixture
cells; it does not qualify the failed baseline request. Its receipt records one
attempted call, no observed response, one collector error, worker exit 1 and
zero child forwards observed by the collector. **That last value does not prove
no forwarding:** the frozen collector substitutes an empty ledger when the
child-forward file is absent, unreadable or malformed and does not retain an
availability flag. Actual forwarding of the failed request is unresolved.

The original 1,108-request schedule partitions into 400 completed requests,
one failed attempted request, three unattempted calls inside the failed cell
and 704 calls in the 44 never-attempted cells. The largest completed external
client line was 4,193,908 bytes, below the unchanged 4,194,304-byte frame limit.
The final completed F dense cell remains unpaired and retains all four of its
successful forwards; it is not dropped from totals.

The collector's comparison loop runs only after all 64 cells, so it emitted
zero pair comparisons. A separate post-failure reconstruction verifies nine
complete paired correctness records, including exact response-trace digests,
IDs/order, decision counts, notifications, catalog generations and framing
witnesses. That check does not create complete-campaign credit or compare
every private approval field in every timed request.

## All observed paired results, without a partial-cohort gate

Positive percentage change means F was slower. These are the nine actual
within-block pairs, with no five-block median, confidence interval or selection
decision. Ordinary cells contain 30 warm calls after one cold call; large cells
contain three warm calls, so their nearest-rank p95 is simply the observed
maximum. Process-tree CPU includes the proxy and synthetic child from catalog
delivery through the final response, including cold plus warm calls. It
excludes benchmark-client CPU and cleanup. No costs or waits are subtracted.

| Block / order | Input | Client p95 B / F, ms | p95 change | Tree CPU/call B / F, ms | CPU change |
| --- | --- | ---: | ---: | ---: | ---: |
| 0 / B then F | 1 KiB ASCII | 105.27 / 66.53 | -36.80% | 50.65 / 47.74 | -5.73% |
| 0 / B then F | 16 KiB ASCII | 60.34 / 132.15 | +118.99% | 40.32 / 44.84 | +11.20% |
| 0 / B then F | 128 KiB ASCII | 347.23 / 284.14 | -18.17% | 108.06 / 153.23 | +41.79% |
| 0 / B then F | Near-limit Unicode | 7,285.28 / 2,543.46 | -65.09% | 4,025.00 / 1,860.00 | -53.79% |
| 0 / B then F | Near-limit dense integers | 8,212.27 / 11,542.28 | +40.55% | 7,092.50 / 8,265.00 | +16.53% |
| 1 / F then B | 1 KiB ASCII | 57.09 / 49.25 | -13.73% | 40.65 / 35.48 | -12.70% |
| 1 / F then B | 16 KiB ASCII | 363.26 / 42.72 | -88.24% | 72.58 / 32.90 | -54.67% |
| 1 / F then B | 128 KiB ASCII | 72.31 / 226.14 | +212.75% | 49.03 / 69.68 | +42.11% |
| 1 / F then B | Near-limit Unicode | 1,097.46 / 777.70 | -29.14% | 992.50 / 697.50 | -29.72% |

The unpaired F dense cell had a 15,979.67 ms warm maximum and
12,115.00 ms tree CPU/call. Its B counterpart produced no completed latency,
CPU or memory result. Neither the favorable Unicode pairs nor adverse ordinary
and dense pairs are omitted. Their variation and the incomplete schedule
preclude the declared 30% benefit / 5% other-metric gate from this attempt.

| Block / input | Whole-worker peak RSS B / F, MiB | Sampled tree USS B / F, MiB |
| --- | ---: | ---: |
| 0 / Near-limit Unicode | 132.07 / 154.19 | 147.34 / 149.55 |
| 1 / Near-limit Unicode | 131.73 / 153.73 | 147.05 / 149.32 |
| 0 / Near-limit dense integers | 436.74 / 462.93 | 223.67 / 239.49 |
| 1 / Near-limit dense integers | unavailable / 459.37 | unavailable / 244.33 |

The completed large pairs still observed higher F worker peaks: about 22 MiB
for Unicode and 26.19 MiB for dense integers. These are route observations of
the final adapter, not the earlier prototype's isolated traced allocation.
They do not prove a universal allocation bound or identify the cause of the
later EOF. Tree RSS/USS is sampled after catalog and responses and can miss
transient peaks. OS RUSAGE_SELF peak covers the worker's whole lifetime,
including imports, and excludes child peaks. No profile cell ran, so no final-F
phase-cost attribution is supplied by this attempt.

## Failure diagnosis and evidence limits

After the failure, every tracked runtime/oracle byte and executable mode
verified unchanged. The 625 runtime and one oracle untracked entries were
ordinary generated Python caches and are individually inventoried. The Python
dependency manifests are exactly identical before and after. The fixture
directory was empty after the frozen TemporaryDirectory cleanup. About
945 MB of tmpfs capacity remained at the completed after-verification check.
Those checks exclude source drift and a changed recorded Python installation;
they do not exclude transient process resource failures.

The preflight host observation recorded Linux x86_64, nine visible CPUs, an
eight-CPU cgroup quota, a 20 GiB cgroup memory limit and 21.29 GB current cgroup
usage. Current memory includes more than the worker and tmpfs capacity is a
different quantity. A later diagnostic snapshot has cumulative OOM counters,
but this attempt has no corresponding pre-run counter snapshot, so those
events cannot be attributed to cell 20. The worker's observed exit was 1,
not an observed signal-9 exit. Neither fact identifies a unique cause.

The reviewed worker used stderr=DEVNULL. Its selected failure receipt retains
`worker_failure: null`, which cannot distinguish a missing worker output file
from an explicitly null field. Cleanup removed intermediate worker and child
files after retaining the selected fields. Consequently the exact internal
exception/child-exit cause, failed-worker peak memory and failed-ledger
availability are unavailable. The retained evidence establishes EOF and exit 1;
it does not justify labeling the failure an OOM, timeout, F defect or confirmed
no-forward result. Any diagnostic harness improvement and fresh experiment
would need a separately reviewed plan, keeping this attempt intact.

## Provenance and decision

The [raw attempt](../../release-metadata/mcp-streaming-preparation-run1-comparison.json)
is 78,970 bytes, SHA-256
`ffb06c3889fc1895a04a0bb7dd4d3df4b25cc1d950c8f636bbe13c2458085865`.
The [derived accounting](../../release-metadata/mcp-streaming-preparation-run1-decision.json)
retains the never-attempted schedule, nine reconstructed pairs, unpaired F cell,
request partition and empty profile/primary-gate summaries. The
[evidence manifest](rust-performance/evidence/mcp-streaming-run1/manifest.json)
indexes the original preflight, complete before/after export and dependency
proofs, launch/end metadata, stderr, diagnostics and analysis source.

Independent review verified schedule/count/pair accounting, all recorded
before/after manifest values and hashes, generated-cache inventories, identical
dependency manifests and frozen harness hashes. It did not duplicate the full
physical export/dependency reread, run workers or supply a GitHub CODEOWNER
approval. The owner performed those full physical checks under the shared lock.

The [reconstruction supplement](rust-performance/reproducibility-streaming-preparation/README.md)
rebuilds both complete source/contract/project scopes, the four directly pinned
harness files, the unchanged E worker imported by the oracle helper, and the
fixed JSON plan from public commit 9db62e8844c2ba2627f55b6b00e58cb5b175185d.
Temporary-index verification and Ruff checks pass without executing a worker.
The initial verifier's two lint findings and pre-correction proof are retained
separately; their correction did not alter the measured source or raw attempt.
Independent review also added the imported E worker to the reconstruction;
the first narrower patch/proof remain retained, and all five Python files now
match the measured export. The frozen four-file plan itself is unchanged.

B still performs its retained separate category derivations; package rewriting,
broader shape/admission coverage, installed platforms, concurrency, soak and
release memory budgets remain outside F qualification. RSP-100 therefore
remains OPEN. This stopped experiment adds honest source, failure and partial
route evidence without changing the original acceptance requirements.
