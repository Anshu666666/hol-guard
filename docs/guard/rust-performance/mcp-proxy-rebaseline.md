# MCP proxy component rebaseline

This evidence addresses the local stdio portion of RSP-098 and RSP-103. It
compares the frozen reviewed Python source at `2e672d2d950c6ec471005ddba46e49bba16dc23b`
with the exact candidate Git revision checked out by the component workflow.
The source revision, production-tree hash and trace identities are recorded in
every completed aggregate; the controller rejects an unexpected candidate SHA.
It does not select a Rust kernel, qualify a complete proxy rewrite, or establish
an installed CLI, remote HTTP, external-network, or real human-response SLO.

The entry point is `scripts/bench_mcp_rebaseline.py`; the existing
`bench_guard_mcp_session.py` pilot remains unchanged. The new worker invokes
`CodexMcpGuardProxy.run_session` against a real local child and anonymous stdio
pipes. It retains the actual policy, receipt, inventory, identity, catalog,
forwarding and child-cleanup paths. No policy decision, store operation, barrier,
timeout, frame limit, queue limit or child response is replaced by a fast stub.
The child is deliberately synthetic and performs no deletion. Only the additional
loopback trace performs a network request, to its own numeric loopback-only TCP
service; no external destination or DNS lookup is allowed.
As in the earlier session pilot, client requests enter as dictionaries. The
outer `serve` client-line parser and final client-output serialization are outside
this boundary; measured serialization is on the actual internal/child route.
Session totals include fixture observation/oracle bookkeeping between measured
request calls. Neither limit is hidden by calling this installed end-to-end data.

## Experimental contract

Five independent processes per revision and measurement mode execute the same
eight traces. Baseline/candidate order alternates between blocks. Plain and
diagnostic modes retain 13 calls (one first, 12 warm). Resource mode has a
separate fixed 100-call workload (one first, 99 warm), identical across both
revisions. Both trace inventories and their exact request hashes are in the
manifest; the first seven plain/diagnostic request sequences are unchanged. Each trace receives a new store, workspace and child. Every
process imports the selected production source afresh. Both revisions use the
same pinned interpreter and dependency environment; this controls dependency
drift and is not a comparison of two independently packaged installations.
The source revisions also contain other release changes. This is a complete
route rebaseline, not a causal ablation of catalog caching alone; phase counters
and source boundaries are needed to interpret a difference.

| Trace | Catalog | Call payload | Additional fixture behavior |
| --- | ---: | ---: | --- |
| `catalog10` | 10 tools | 128 ASCII bytes | Ordinary default-policy forwarding |
| `catalog100` | 100 tools | 128 ASCII bytes | Ordinary default-policy forwarding |
| `catalog1000` | 1,000 tools | 128 ASCII bytes | Ordinary default-policy forwarding |
| `payload16k` | 100 tools | 16,384 ASCII bytes | Larger local classification/serialization input |
| `catalog_refresh` | 100 tools | 128 ASCII bytes | Complete new catalog generation midway through the calls |
| `child_delay10ms` | 100 tools | 128 ASCII bytes | Child sleeps for 10 ms before producing its proof |
| `inline_approval10ms` | 10 tools | 128 ASCII bytes plus unique target | Synthetic user callback approves after 10 ms |
| `loopback_tcp10ms` | 100 tools | 128 ASCII bytes | Real bounded TCP round trip to child-owned loopback service with a separately measured synthetic 10 ms service delay |

The unmodified default configuration produces `policy-warn` / `warn` for the
benign traces. That is the exact expected route. The risky synthetic tool must
reach the actual inline approval path and produce `inline-approved` / `allow`.
Every tool result proves the digest and ID of the request observed by the child.
The exact canonical input traces match across revisions; production JSON wire
formatting may differ. The child reports the actual UTF-8 line byte count.
The child never executes the risky operation described by its name. Catalog
responses must match every advertised field and the expected generation.
Unexpected responses, policy actions, callbacks, missing requests and child
failures invalidate the run; they remain in the private evidence.

Three modes have separate purposes:

* `plain` records the actual request wall/process CPU boundary with no phase
  wrappers or resource sampler. Oracle validation happens after the timer.
* `resources` uses the same unwrapped production route, observed externally by
  a 10 ms process-tree sampler. It records total RSS and available private memory,
  threads, descriptors and CPU with missing metrics explicitly represented.
  Phase journals do not inflate this memory result. A separate sampler retains
  startup/churn observations, including missing reads; it is never used as proof
  of warm completeness.
* `diagnostic` wraps selected production helpers and records nested elapsed and
  current-thread CPU. These observations explain work; they are excluded from
  the ordinary timing and memory comparisons.

Both plain and resource workers also report their own process CPU/high-water RSS
and waited-child CPU/high-water RSS from `getrusage`. The two RSS high-water marks
are not added together: their peaks need not coincide. The external sum covers
the simultaneously observed worker and descendants. Sampling can miss a brief
peak, and summing RSS counts shared pages more than once. Private memory, when
available, and sample coverage are reported separately.

Warm observation begins only after the first real tools/call response passes
its oracle. The worker sends an exact sequenced frame over two private inherited
anonymous pipes and waits for the controller to start a fresh external sampler.
After the fixed last call, the worker waits for sampler stop, join and final
snapshot before returning to the production session teardown. The observer pins
the worker and its one child by PID and creation time at both barriers. No extra
sleep or adaptive work is added to reach a sample minimum. Each warm window
requires at least 30 successful samples for every required Linux metric, zero
missing reads or required-metric errors, unchanged membership/identity, and all
99 warm outcomes. A failed/aborted window reports unknown completed attempts
and no CPU-per-attempt denominator; per-request journals retain actual outcomes.
Permission denial or an insufficient fixed window remains incomplete. Passing
barrier ACKs do not themselves certify resource completeness.

Each trace/mode/run retains a bounded numerical summary. Paired plain comparisons
use `native_slo_qualification.paired_ratio_interval`: 2,000 deterministic bootstrap
resamples of the five independent paired run ratios. Metrics are per-run warm
wall median/p95, mean parent-process CPU, first call, construction and session
wall time. The estimator reports candidate/baseline median ratio and 95% interval.
The 60 warm requests are not 60 independent replicates. With only 12 warm
requests per block, a p95 ratio interval is descriptive and does not qualify a
product tail. A failed experiment or incomplete pair emits no interval. The
public finalizer recomputes intervals from the admitted independent summaries;
it cannot publish a fabricated interval, unmatched block or unknown metric.

## Phase ownership and limits

| Observation | Production boundary | Interpretation |
| --- | --- | --- |
| Import/startup | Import of the selected Guard modules; proxy construction; `_start_process` | Module import, store setup, launch identity, process creation and pump startup have separate observations |
| Catalog | `_capture_tools_catalog`, `_tool_catalog_fingerprint` | Includes actual immutable-catalog publication and cached or uncached full-catalog identity |
| Classification | `tool_call_risk_categories`, `tool_call_risk_signals`, optional category-to-signal helper | Counts actual invocations; functions absent in the baseline are not invented |
| Policy | `evaluate_tool_call`, `resolve_policy_decision_lookup_with_memory_pattern` | Composite policy evaluation and its nested store lookup; not isolated SQL/VFS timings |
| Identity and evidence | `build_tool_call_hash`, `allow_tool_call`, actual inventory/receipt/event store methods | Separates selected identity and persistence boundaries while preserving commit semantics |
| Barrier | `_drain_child_messages` with its actual positive quiet interval | The unchanged final 5 ms quiet drain is retained and counted for every forwarded call |
| Wait | `_next_child_output_frame` | Required child-response wait, positive quiet-frame wait and zero-time polls are distinguished |
| Serialization/hash | Module-local JSON wrappers, actual framing encoder, selected SHA-256 callsites | Includes observed byte/work counts; uninstrumented JSON/hash users elsewhere are not asserted to be zero |

The elapsed wait includes its Python call/queue overhead. It is not a direct OS
blocked-time counter. Child service timing comes from the synthetic child and
starts after JSON parsing and ends before output encoding. It does not isolate
kernel transport latency. Whole-child CPU also includes that parsing and encoding.
The approval timer measures the synthetic callback, not actual human latency.
The loopback trace sends exactly a 64-character request commitment plus newline
over an actual TCP connection to `127.0.0.1`; the child checks the exact response
commitment. The bounded response is at most 512 bytes and sockets have one-second
timeouts. Child-client round-trip wall/thread CPU and service wall/thread CPU
are retained separately. The service runs in its own child-owned thread and
sleeps for 10 ms as declared synthetic work. Round-trip wall includes that service
and connection/serialization work; it must not be called pure kernel/network
latency or silently subtracted from headline Guard wall time. Parent Guard CPU
is separate. This is not remote-HTTP MCP, Internet latency or a hosted service.

Inclusive phase timings overlap. Exclusive timings subtract only instrumented
same-thread children and still contain remaining work and instrumentation costs.
They must not be presented as exact attribution of every instruction or syscall.
Per-request process CPU includes the proxy's reader threads; diagnostic
current-thread CPU does not. SQL transaction, fsync and VFS internals are not
separately measured by this harness.

## Evidence integrity and validation

The private evidence directory is created with mode `0700`; files use exclusive
creation and mode `0600`. Each worker has a 180-second execution timeout,
16 MiB result limit, 100,000 diagnostic-row limit, and two 64 KiB retained
stdout/stderr buffers. A separate 2 MiB private JSONL journal records trace and
request starts before execution, then actual delivered outcomes and timings.
A killed worker therefore leaves its attempted-work prefix. Exceeding any
observation limit fails the report.
Worker groups are terminated on timeout or observer startup failure. These are
diagnostic supervisory bounds and do not alter production proxy budgets.
Pipe control frames are at most 1 KiB with a five-second ACK deadline. Observer,
worker quarantine and output-capture cleanup have separate finite bounds; 180
seconds is not a claim about total controller wall time including cleanup.
Observer-owned duplicated pipe descriptors close only when its thread stops;
failed cleanup stops further worker offers and stays an incomplete experiment.

The manifest records production Git commit/tree identities, both source lockfile
hashes, the shared interpreter digest/dependency versions, every harness file,
the child source and exact canonical trace identities. Begin records precede
each attempted worker. Raw observations and failures are retained; the public
aggregate includes file byte counts and digests. Phase-row/counter consistency,
expected and observed attempt denominators, alternating order, request order,
catalog generation, delivered decisions, callback counts and
the actual final quiet barrier all have explicit checks.

Focused tests cover corrupted child proof, policy drift, dropped/duplicated runs,
missing attempts, stale catalogs, missing approvals, incomplete phase journals,
missing child memory, restoration of production bindings, bounded private output,
observer-failure cleanup, and preservation of failed-attempt denominators.

## Isolated runner and retention

The Linux-only `MCP Python component rebaseline` workflow runs this complete
component matrix for relevant pull requests or an explicit workflow dispatch.
It is independent of the four-platform installed-native qualification job.
It pins the candidate to the pull-request head or dispatch SHA, checks out the
baseline separately, and installs only the candidate's frozen dependency lock.
All workers use that interpreter while selecting one verified production source.
The v2 matrix has 30 independent worker attempts, 240 child sessions and 10,080
tool call attempts (8,000 resource-mode and 2,080 plain/diagnostic). No smoke run or old pilot can satisfy this matrix.

The workflow first runs focused correctness tests, then measures under a fresh
runner-local lock. The shared local measurement lock was unavailable during
preparation; no accepted local timing matrix was run, and its lock was not
replaced or bypassed. The local preparation runs establish only fixture behavior.

Always-run finalization publishes a maximum 2 MiB public aggregate, or an explicit
incomplete report with no invented measurements. A failed matrix step cannot
publish a passing result. Public uploads contain only that component report and
an archive receipt. Plaintext stdout, stderr, request journals, phase rows and
begin records remain in the private directory and are never upload paths.

The publisher reconstructs nested metrics from a strict schema: numeric values
must be finite, counters cannot be booleans, labels come from the frozen trace
and phase inventory, and unknown fields are rejected. A passing report requires
all 30 worker identities, 10,080 tool outcomes, 48 aggregate comparison groups,
240 independent run/trace summaries, eight paired plain comparisons and 80
complete warm resource windows. Each plain/diagnostic group has five first and
60 warm outcomes; each resource group has five first and 495 warm outcomes.
Phase counts and the complete 181-file raw inventory must also agree. Failed reports retain their actual observed counts and missing
metrics; validation failure produces an explicit incomplete report. Free-form
platform, interpreter, and dependency descriptions stay in the encrypted
manifest, whose canonical SHA-256 is public alongside the typed source and
artifact identities. Controller exceptions that occur before a worker result
exists retain a bounded exception class in the private observation; exception
messages are never included in that record or the public report.

The existing `native_slo_evidence_archive.py` encryptor seals all private files
with the checked-in public recipient. The job does not obtain a private key or
repository secret. The existing authenticated archive limits remain 256 files,
32 MiB per file and 128 MiB total; exceeding them yields a failed archive receipt,
never a truncated successful archive. Encrypted observations and public evidence
are retained for 30 days with run ID/attempt artifact names. A runner terminated
before always-run finalization can still lose unuploaded files; an absent archive
receipt is missing evidence, not a successful retained run. This workflow makes
no installed CLI, cross-platform or native SLO claim.

## Results and remaining acceptance

This v2 contract was developed from source `a01e210146c3154a71fb6090cf7cd4a4648055c3`,
which includes the reviewed MCP prefilters. The measured candidate remains the
exact later frozen workflow head, never this design cutoff by implication. The
prior v1 run `35220287536` at `107606388ad55f924a4e2924b4ff84e5fa08e6ff`
retains its own seven-trace scope, absent intervals and incomplete lifecycle
resource reads. It is not reused as measurement of the new prefilters or v2
warm/resource/network contract.

The measured aggregate and interpretation are added only after the isolated
five-block matrix completes and its source/trace/oracle checks pass. Earlier noisy session pilots and preparation runs
are not substituted for this matrix. Source-bound stdio evidence can establish
where local cost remains; actual Windows transport, installed CLI overhead,
remote HTTP behavior and external network/human latency remain separate qualification
work. RSP-104/105/107/108 remain conditional on a selected coarse native kernel
and a measured comparison against this optimized Python route.
