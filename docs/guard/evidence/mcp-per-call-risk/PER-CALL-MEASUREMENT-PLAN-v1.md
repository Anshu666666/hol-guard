# New repaired-B versus per-invocation candidate measurement plan

Status: proposed for root review; no timing cohort has run. This is a new bounded diagnostic cohort, not a continuation, retry, expansion or pool of E/F. Independent correctness review cleared candidate `f186a64a812bc8c5d4f2537293e6ef58076a2531`: its unchanged five-case security/hook gate passes, its separate workspace trace passes, and the owner's final 47 focused and 209 broader adapter cases pass. All original failures and intermediate sources remain retained. RSP-100 is OPEN.

## Exact source and scope

The baseline is repaired current production B at `4edad2ca1dc075c69cbec7c3b59d1a59fc4d3505`, including callback authority repair `7e735d29`, ownership mapping `6f930c56`, generated Desktop fixture `3ce15cf9` and the launcher repair. It is not any historical unsafe B, E or F source. The selected candidate source is exactly `f186a64a812bc8c5d4f2537293e6ef58076a2531`, incorporating `07bd5e08` and `20817a98`; production Python files are unchanged by these three candidate-only commits.

After this plan is reviewed, create an isolated measurement checkout on the baseline, apply only the three candidate script/test commits, and add a new self-contained plain-stdio driver/worker/child fixture. Both B and candidate workers use that same final checkout and all identical production files; only the explicit candidate adapter installation differs. Verify the seven repaired production files match the independently reviewed source, record the complete Git tree and all loaded source paths/hashes, and freeze a new harness/source commit plus protocol JSON digest before the first timed cell. The plan alone does not provide that not-yet-created harness pin. Any production source mismatch or automatic candidate compatibility fallback in an ordinary selected cell blocks the cohort before timing.

No E/F module, worker, profile or campaign entrypoint is imported or executed by the new measurement harness. The small historical test helper used by finite source tests is not used by this harness. RSP-106 and all frozen records remain untouched. No production selector or writer is replaced. The adapter substitutes only the evaluator in the candidate worker; the repaired request owner, package flow, authority checks, notifications and final fixed 5 ms barrier remain active.

## Real route and charged costs

Run a new Python worker using the real `CodexMcpGuardProxy.serve` over OS stdin/stdout pipes and a new deterministic local Python MCP child. The driver is an actual closed-loop MCP client: initialize, initialized notification, complete tools/list, then tools/call requests. The child returns a SHA-256 digest of the exact received request frame, the same deterministic result for both variants, and one bounded progress notification per tool call. It does not dump payloads to disk or echo a multi-megabyte result. The driver verifies exact IDs, result class, frame digests, notification delivery and count, and forwards/counts for every attempted request. It records a digest of each frozen synthetic input and frame size, not exported command text or arbitrary user material.

Each worker is fresh. Its source imports, candidate import and constructor (including pinned-source reads and compile-without-execute verification), interpreter/child startup, framing/encoding/parsing, all request/authority/catalog binding work, policy/store activity, final deliberate waits, child work and orderly teardown are included in complete-session wall/CPU measurements. There is no preconstructed candidate, precompiled verified metadata supplied by the driver, shared process pool, reused profile, removed check or optimized registration mechanism. The existing script's setup cost remains part of the candidate under test.

Primary request wall latency is measured by the external driver from immediately before request serialization/write through receipt and parsing of the corresponding response, with progress notifications drained normally. Fixed 5 ms waits stay included. Complete-session process-tree CPU/request includes worker and waited child user+system CPU from spawn through exit, divided by all attempted tool calls including warmups; it includes setup, compilation and teardown. Cross-check the worker's self+children resource receipt against the parent's wait resource receipt. If complete child accounting cannot be demonstrated, CPU is unavailable and cannot support the CPU-benefit branch. Also report complete-session wall/request and first-call/cold setup separately. Never claim startup-inclusive p95 from the warm latency series.

The benchmark client/observer CPU and memory are reported separately. No category wrapper or replacement freshness callback runs during timing. The candidate's existing internal counters are emitted once at teardown and must match selected/completed request counts; baseline two-category behavior is established by the preceding finite source gate, not a timing wrapper that changes its cost.

## Frozen inputs and schedule

Concurrency is one, local plain stdio only. This environment supports that real route even though AF_UNIX creation has failed; this protocol does not claim installed native, offered-rate, concurrent or cross-platform qualification.

Freeze the following shape order. Sizes refer to the final `framing.encoded_line` UTF-8 byte length including framing overhead, not Unicode character count. Generate before timing and verify equal digests for both variants. Every request uses a fixed-width unique ID. Preserve ordinary nested JSON scalar controls, including boolean, integer, negative zero and null.

| Cell | Shape | Warmup calls/worker | Timed calls/worker |
| --- | --- | ---: | ---: |
| 1 | ASCII, 1 KiB frame | 20 | 200 |
| 2 | ASCII, 16 KiB frame | 20 | 200 |
| 3 | ASCII, 128 KiB frame | 20 | 200 |
| 4 | ASCII, 256 KiB frame | 20 | 200 |
| 5 | ASCII, 1 MiB frame | 2 | 20 |
| 6 | maximum supported ASCII frame | 1 | 3 |
| 7 | maximum supported multibyte Unicode frame | 1 | 3 |
| 8 | maximum supported dense integer-array frame | 1 | 3 |
| 9 | maximum supported nested-record frame | 1 | 3 |

The current source limit is 4 MiB per line. The fixture builder must target that supported limit exactly where the shape permits; any bounded shortfall for valid integer/record boundaries is declared and frozen before timing, never selected after a result. Padding belongs to the same predeclared request shape. An over-limit control belongs to the preceding untimed finite framing gate and must be rejected identically, not silently truncated for a timed run.

Each cell consists of five independent paired blocks, in order B/C, C/B, B/C, C/B, B/C. Each variant gets a fresh worker, child, scratch workspace and Guard database. Ten workers per cell, 90 at most for the complete proposed schedule. Acquire the shared validation lock for each paired block and release after both variants and their resource/process cleanup receipts finish. Do not run other owned heavy work concurrently. Host background load remains recorded, not retroactively filtered away.

A cell's performance decision is made only after its five paired blocks finish. A process, correctness or resource failure stops immediately, including in the middle of a block. A failed or inconclusive completed cell stops the schedule before the next cell. No skipped cell, replacement block, retry, resumed suffix, best subset or pooled historical run is allowed. The unvisited suffix is explicitly not run.

## Metrics, uncertainty and unchanged gates

Retain every per-request latency, attempted/completed/failed state, per-worker setup/CPU/resource value and per-block comparison. Use nearest-rank p95 (`sorted[ceil(.95*n)-1]`) and state sample counts. Report every block separately; the summary is the median of the five paired candidate/baseline ratios, never a ratio formed by pooling unlike shapes. Compute a paired-block bootstrap percentile interval with fixed seed 20260918 and 10,000 resamples and label it exploratory: five blocks are few, and ranges are not confidence intervals.

The original PRD selected-tranche gate is unchanged: at least 30% lower p95 OR at least 30% lower complete process-tree CPU/request, with no more than 5% regression in the other primary metric. Thus a benefit ratio must be <=0.70 and the other ratio <=1.05. Do not substitute 1.30x throughput for 30% lower latency. A favorable point estimate whose interval cannot establish the same bound is inconclusive for this attempt and stops further cells; no repeat is permitted under the same cohort identity. Report all block ratios so inconsistent regressions remain visible. Every attempted request must have the expected complete decision, response, notification and forward count; failure cannot improve the apparent denominator.

The resource observer samples the full worker+child process tree at fixed 20 ms intervals, records simultaneous aggregate RSS and private clean+dirty memory when available, and records per-process high-water statistics separately. Never sum unrelated per-process maxima and call that a simultaneous peak. Preserve the installed short-load observed RSS growth safeguard of 12% with a declared boundary from the last warmup to the final timed call; record baseline and candidate failures distinctly. The separate 50% long-soak safeguard remains unchanged and is not tested or qualified by this short protocol. Fewer than 30 resource observations makes resource inference incomplete. A fixed additional 512 MiB observed process-tree private-memory ceiling is a proposed diagnostic stop bound, not a replacement or relaxation of either existing growth gate; root should accept or revise it before protocol freeze, never after observations.

This cohort cannot qualify release tails. It has only 1,000 timed samples per variant for each small/medium cell, 100 for 1 MiB and 15 for each maximum-size cell, on one declared host at c1. The PRD still requires 10,000 timed warm decisions per priority route/platform across >=5 runs, 100 cold starts, 100 recoveries, >=30 steady-state resource samples, other concurrency levels and offered-rate load, plus declared release artifacts/platforms. Maximum-size p95 with three samples per worker is descriptive only. Even an entirely favorable diagnostic cohort leaves RSP-100 unqualified until the missing release scope is completed. A negative or inconclusive cell is an honest no-go for selecting this candidate; the repaired B default stays active.

## Failure retention and execution limits

Before each worker starts, append and flush its planned cell/block/variant, exact source and fixture digests, command argument digest, host metadata and starting cgroup memory-event counters. Stream separate bounded JSONL progress and raw stdout/stderr from launch through teardown. Record request start and completion individually; an interrupted request remains started/unknown or failed, never completed by aggregation. Preserve stderr, exit code, signal, watchdog action and the last progress position even if the worker cannot produce a final receipt. Preserve before/after memory.events when readable: SIGKILL alone is not proof of OOM, while an attributable oom_kill increase is recorded as such. Capture parent exceptions in a final driver-status file without overwriting the raw prefix.

Keep production operation deadlines, quiet waits and frame bounds unchanged. A separate per-worker supervisor ceiling of 180 seconds and total cohort ceiling of 30 minutes prevent indefinite diagnostic work; hitting either stops the whole cohort and retains the exact incomplete schedule. Emit progress often enough for the supervising agent to report at least every minute. After a stop, terminate only the owned process group, reap descendants and record cleanup; do not reopen an ambiguous writer or retry a request. No concurrency fanout is allowed in this protocol.

Record CPU model/core count, memory/cgroup limits, OS/kernel, Python/build, package/source digests, affinity/governor/power data where observable, filesystem and background load. Missing host metadata is stated. All paths, scripts, protocol and raw receipts remain frozen and privately reproducible; exported summaries contain bounded synthetic aggregate evidence.

## Review sequence before any timed cell

1. Root reviews this concrete plan and the final independent correctness result. No campaign starts now.
2. Implement the new standalone harness and fixed protocol file on the isolated repaired-B checkout; preserve this plan unchanged if a reviewed revision is required.
3. Run only finite harness correctness/accounting controls: actual B and candidate stdio framing/notification parity, one deliberate worker failure with stderr/progress retention, a timeout/cleanup control, source-mismatch refusal and CPU-tree accounting. These are not timing/benefit trials; their outcomes cannot tune workload counts or thresholds.
4. Freeze the complete harness/production/candidate source commit, input/protocol digests and unique cohort ID. Send those concrete pins and finite controls to root for final review.
5. Only after root's explicit go, execute the one finite scheduled cohort and retain its complete visited prefix. No profiles run as part of the gate; any later profile is a separate explicitly identified task and cannot rescue a failed gate.
