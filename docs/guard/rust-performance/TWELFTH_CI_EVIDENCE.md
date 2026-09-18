# Twelfth CI cohort: completed results and limits

All **42 original first-attempt workflows are terminal: 37 successful and five
failed**. The cohort measures PR head `7eeb28f3ec3a2fdf320e52ad9f01430546226b42`,
tree `e3265c7a4d23284dbae09e99b96442036726f71b`. The distinct PR merge
`4ca765c0c6ff06a5b6afb27545ed4ac8aec8ea79` has the same tree, with ordered parents
release base `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and that publication.
The baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package 3.0.1.

The [manifest](evidence/ci-7eeb28f3/manifest.json) retains the complete workflow
census and SHA-256 commitments for the bounded review reports. GitHub metadata,
verified public ZIPs, producer commitments and authenticated private samples
are different evidence levels. No private archive in this cohort was decrypted
in the resumed workspace. The preceding eleven cohorts remain unchanged and
are not pooled with this one.

## Main validation and required gate

[Main run 35291896083](https://github.com/hashgraph-online/hol-guard/actions/runs/35291896083)
finishes **114 jobs: 110 successful, one failed and three skipped**. All **96
pytest shards pass**, including the shard containing the revised authenticated
symlink-path fixture. Quality and dependent test aggregation pass. The ordinary
Sonar analysis succeeds and its quality gate fails. This updates the earlier
eleventh-cohort 95-of-96-shard status; the prior failed invocation remains in
[eleventh evidence](ELEVENTH_CI_EVIDENCE.md).

Independent reads of the actual job steps also verify locked Rust formatting,
Clippy and crate tests, rule/command differential, adversarial and authority
integration, approval ownership, deterministic mutation and exact-source rule
binding. See [validation jobs](evidence/ci-7eeb28f3/prior-validation-jobs.json)
and [Main jobs](evidence/ci-7eeb28f3/main-jobs.json). The optional skipped Main
mutation job is not the separate successful Rust mutation-parity workflow.
The successful source checks do not complete required CI, final review or release
qualification. No custom Sonar lookup, finding disposition or gate change was
performed.

## Native wheel and installed Claude

| Scope | Completed result | Remaining failure or limit |
| --- | --- | --- |
| [Native wheel](https://github.com/hashgraph-online/hol-guard/actions/runs/35291896005) | Linux, ARM Mac and Windows pass all 14 existing smoke gates. | Intel Mac fails recovery sample zero; no final SLO report. Smoke gates differ from the original PRD gates. |
| Windows c64 | 36 native responses plus 28 explicit overloads; zero errors or unclassified replies. | Windows still records two evidence-writer failures despite eventually processing all 21 accepted default-auto records. |
| Linux soak | 100,000 logical requests/responses, zero errors; 18,183 successful health checks; stable PID and start/ready/stopped events. | This uses the existing fixture, 250,000 preseeded receipts and per-logical-operation transport retry policy. It is not the full mixed installed qualification. |
| [Installed Claude](https://github.com/hashgraph-online/hol-guard/actions/runs/35291896043) | 19 jobs pass; all 20 contract suites pass before measurement. | Windows run four rejects an optimized-Python PostToolUse response of `{}`. |

Intel's recovery preparation is an allowed native-resident response at 102.620 ms.
The original stop returns true, then the recovery response is an allowed
`native_fail_safe` with reason `native_post_tool_unavailable`, at **1,059.558 ms**.
The strict native-route assertion fails. Its retained `already-stopped` artifact
can come from later fixture cleanup and does not identify the stop before this
request. The unavailable response and elapsed time do not identify a cause.

Windows Claude fails benign sample 14 with `priority_launcher_event_mismatch`.
The process exits zero and returns the two-byte `{}` object, with no observed
outer timeout, containment failure, output overflow or stderr. Validation occurs
before the after-route read; its historical empty map is unobserved, not zero.
The cohort retains **1,760 planned requests, 1,739 attempts, 1,738 completed
validations, one failure and 21 unoffered requests**. All 160 preflights complete.
There are 1,579 timed process observations, including the failed sample, whose
private elapsed value was not recovered. Incomplete journals do not become a
successful four-series aggregate.

Linux soak RSS grows from 618,254,336 to 640,376,832 bytes (**3.5782%**); p95 is
544.760 ms and maximum 636.050 ms. Peak threads/descriptors are 71/193. These
scope-specific measurements do not establish ordinary launcher latency or full
process-tree CPU. Windows wheel warm p95 is 218.670 ms and c16 p99 653.063 ms;
passing its existing 1,000 ms smoke threshold does not satisfy the original
50/100/200 ms priority gates.

The [wheel/Claude receipt](evidence/ci-7eeb28f3/native-wheel-claude.json) verifies
21 ZIPs, 8,245,624 bytes and 45 members: all 20 Claude public reports agree with
their log projections, and the failed Intel wheel bundle's public records are
bound to their API digest. The bundled wheel was not independently installed,
executed or signing-verified. No new native launcher selection follows.

## Indexed qualification, resources and settings

[Qualification run 35291896291](https://github.com/hashgraph-online/hol-guard/actions/runs/35291896291)
finishes **27 jobs: 13 successful, 12 failed and two skipped**. All four wheel
builds pass. Linux baseline/candidate, both Mac candidates and Windows baseline
complete their indexed reports: **680 committed numeric values, 1,930 normalized
corpus validations and 310 registered-launcher validations**. Corpus validations
are separate preflights, not additional latency samples. The failed arms have no
committed numeric series; their partial work is unavailable without recovery.

Both Mac indexed baselines hit an inner daemon-construction deadline in
`HTTPServer.server_bind` → `getfqdn`; their outer worker timeout/containment flags
are false. Windows candidate fails native launcher route accounting. No precise
underlying cause follows from that public failure. Windows baseline includes
platform-denial source cases, which do not establish reviewed-content coverage.

All five completed arms conserve their 64 closed-loop replies with zero errors,
split between native responses and explicit overload. **All five offered-rate
tests fail.** Of 1,280 offers per arm, Linux baseline/candidate admit 319/183,
ARM candidate 380, Intel candidate 161 and Windows baseline 574. Completed/failed
counts are respectively 319/0, 183/0, 172/208, 157/4 and 545/29; the remaining
961/1,097/900/1,119/706 offers are generator drops. These denominators remain
visible.

Linux steady resource captures have 12 samples per arm; Mac candidates have
eight and 23, with general process-tree CPU unavailable. Windows baseline has
39 steady samples and 63 capacity samples with complete minimum gates, but its
candidate report is missing. No complete qualified platform comparison follows.
Every platform offered one smoke pair, below the required five independent pairs.

Settings complete 60 native cases: Linux two, ARM 22, Intel 14 and Windows 22.
Linux fails enabled readiness at **400.134 ms**; Intel rollback returns the
requested acknowledged revision after **405.906 ms**. Both fail the original
400 ms gate. ARM and Windows pass, and all four Builder checks pass. Isolated
publisher stack frames do not establish the cause of either overrun.

The eight nonpriority jobs finish four successful/four failed. Six complete arms
provide **12 timed values and 12 separate preflights**. Both Mac baselines report
`worker_failed`; this review did not decrypt their diagnostics and does not assign
the indexed `getfqdn` cause to those distinct failures. Across the four Mac
runners, 36/36 reverse probes enter and time out while 12/12 numeric controls
complete. PTR registration/self-test success and zero OS query traffic still do
not identify a native blocking frame.

The [qualification receipt](evidence/ci-7eeb28f3/qualification.json) verifies
24 ZIPs, 9,855,383 bytes and 86 members, including 78 public JSON members and
eight encrypted members. Numeric counts are public producer commitments
cross-checked against public summaries, not authenticated raw samples or
recomputed distributions. Qualification remains false.

## Package decision

[Package run 35291895999](https://github.com/hashgraph-online/hol-guard/actions/runs/35291895999)
passes 132 correctness tests in each of its three jobs. Formats retain 20
candidate and 18 baseline completions plus two failed frozen Composer cases.
Cardinality retains 36 candidate and 24 baseline completions plus 12 censored
baseline workers: nine evaluator and three None-version bundle-kernel cells.
The separate unresolved pair and all ten phase workers complete. These repeat
the prior baseline limitations; they do not identify a new candidate defect.

Five complete npm protect pairs have descriptive wall medians
**8,617.049837 → 316.029607 ms** and process-CPU medians
**7,716.270 → 308.876 ms**. Median paired reductions are **96.3409140%** and
**96.0070552%**. These are optimized-Python versus frozen-Python measurements,
not Rust gains. All six profiles reconcile their accounting and validation
commitments; exclusive Python origin shares are not attainable native savings.

The [package report](evidence/ci-7eeb28f3/package.json) and
[custody receipt](evidence/ci-7eeb28f3/package-custody.json) verify three public
ZIPs, 24,164 bytes and 12 members. Producer receipts report 331 encrypted files;
none was decrypted. Keep the existing Python package decision and RSP-050's
full-evaluator/unversioned limitations. MCP and scanner retain their prior
source-scoped decisions; their successful workflow status is not a new
independently reviewed native benefit claim.

## Later implementation

[Foreground evidence and failure observations](foreground-evidence-and-failure-observability.md)
describes the later scripts-only changes: actual receipt/writer attribution,
one bounded Mac native-stack observation, a failed-launcher after-route snapshot,
and the original recovery-request witness. The future archive recipient was
rotated after separately saving and round-trip-testing a new key. None of these
changes was measured by this twelfth cohort. They preserve the frozen baseline,
original failures, requests, deadlines and qualification gates. Their source
validation and remaining acceptance appear in [RELEASE_REVIEW](RELEASE_REVIEW.md).
