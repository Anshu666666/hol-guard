# Fifth finalization CI checkpoint

This report records candidate `96a69725eab018674174dabc6f205a4087d6ff4b`,
tree `7da3dcf25df5dc75b61f773c40a3a4dd96bbf2fa`, on
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970).
The release base remains `4b89e0d2d496a85f04922b2e019a4aea15326bb9`.
GitHub's merge `c9a4b508ec5e9f5e6526990f9a3fad8c8b97646d` has that base and
candidate as parents and the same tree. Explicit candidate checkouts and PR
merge checkouts remain distinct build identities despite equal trees.

The terminal API snapshot at 17:14:35 UTC on 2026-09-17 contains **41 workflow
instances: 33 successful, eight failed, none active or skipped**. The
[public manifest](evidence/fifth-ci-96a697/manifest.json)
records each run and attempt, with selected complete job inventories. Job-level
skips are separate from workflow conclusions. The
[fourth checkpoint](FOURTH_CI_EVIDENCE.md) remains a separate immutable cohort;
later fixes do not turn this checkpoint's failures into successes.

**Installed performance qualification and release remain incomplete. No new
production Rust boundary or launcher is selected by these results.**

## Required source and platform checks

| Scope | Actual result and practical limit |
| --- | --- |
| [Main CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986641) | 19 jobs: nine successful, three failed and seven skipped. Quality/protected inventory and test planning failed during collection; the aggregate CI job failed its dependency gate. The 96 pytest shards did not run. |
| [Security](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986521) | All four jobs passed: Semgrep, Gitleaks, privileged workflow policy and Trivy release scan. |
| [Decision-critical I/O ownership](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986568) and [Rust authority ownership](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986675) | Both failed the same permanent-manifest coverage check before downstream ownership checks could run. |
| [Windows resident](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986619) | Both Windows-resident and Unix-regression jobs passed. |
| [Daemon edge](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986582) | Five jobs passed; the optional soak was skipped. |
| [MCP component](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986728) | The workflow passed. This checkpoint records completion and does not pool new component results with the earlier selection cohort. |

Main's source cause was a pilot test module leaving `scripts` on the global
import path, which shadowed the `ci` namespace during broad collection. The
later correction restores the temporary path in `finally`. Its separate local
checks collected 84 affected tests, collected the full 22,181-test inventory,
passed 24 protected-inventory tests, and passed 20 pilot tests with 11 actual
binary cases skipped. These are source-repair checks, not a passing fifth Main
run. The duration-manifest and Sonar jobs were skipped; no fifth-run 96-shard
duration or Sonar result is claimed.

The ownership error named
`rust/crates/guard-offline-regex-pilot/Cargo.toml`; the crate's `src/main.rs`
was also unmapped. The later dedicated benchmark-only owner retains the
existing `rust/**` protection and all gate code. Nineteen ownership tests
passed, the full authority gate checked 2,061 changed paths against the exact
release base, and the I/O gate passed with 435 reachable functions and 3,861
inventory operations. Independent source review found no additional inventory
gap. Both original workflow failures remain failures until a new source runs.

## Native wheel observations

[Native-wheel run 35247986691](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986691)
finished with Linux successful and both macOS jobs and Windows failed.

| Target / job | Observed result |
| --- | --- |
| Linux / `105292962551` | Installed SLO and soak steps passed; the platform job completed successfully. |
| macOS ARM / `105292962641` | Before wheel build: 54 source tests passed, one skipped and two failed. The ignored-child CPU assertion failed; an absent-process test also encountered an existing PID with denied access. |
| macOS Intel / `105292962768` | Before wheel build: 55 source tests passed, one skipped and the ignored-child CPU assertion failed. |
| Windows / `105292962863` | The installed smoke report failed six gates: 1 MiB latency, c16 concurrency, c64 boundedness, recovery, resident share and safe-corpus coverage. Source-reference review and RSS gates passed. |

Linux passed all 14 installed smoke gates. Its c16 and c64 waves retained all
16 and 64 native-resident responses, respectively, with no unclassified
responses, explicit overloads or observed raw-bridge `None` returns. The
separate registered Claude PostToolUse sample contains only two observations,
with p95 **354.188 ms**. The report still declares
`qualification_complete=false`.

Linux's separate soak completed **100,000 requests and responses**, retained
**250,000 receipts**, and recorded zero errors. All **18,484 health checks**
completed without failed or transient health checks. It retained one daemon
with a stable PID, maxima of 71 threads and 200 file descriptors, and reported
RSS of **615,903,232 → 636,903,424 bytes**, growth **3.4097%**. Hook latency p95
was **551.880 ms**, maximum **687.350 ms**, within the unchanged **4,500 ms**
soak limit. Both soak pass flags are true. These source-specific smoke and soak
results do not satisfy the separate full qualification plan or qualify another
platform. The manifest records their finite facts and the Linux artifact's
GitHub identity; that ZIP was not independently downloaded for this checkpoint.

Windows received all 16 c16 responses with zero transport errors, but only
14 were native-resident allows; two were unclassified. At c64 it received all
64 responses with zero transport errors: 30 native-resident allows, 30 explicit
overloads with engine-bypass accounting, and four unclassified responses.
Both waves failed route conservation. The report's legacy aggregate
`overloaded` values of two and 34 are not proof of that many explicit overloads;
the explicit observed counts are zero and 30. The native-overload counter delta
was zero. The c16 p99 was **3,584.140 ms** against the unchanged **1,000 ms**
gate; recovery p95 was **1,549.546 ms**.

The capacity witness retained zero original raw-bridge `None` returns in both
waves. That narrow observation neither establishes native authority for the
unclassified responses nor identifies their cause. The Windows report contains
146 daemon-ingress observations and a separate two-case registered Claude
PostToolUse launcher sample. These are distinct populations. Its runtime build
identity is the PR merge, `c9a4b508…`; equal source trees do not substitute a
different binary identity. No counter, pool-sizing or scheduler cause is
inferred from these counts.

The [Darwin accounting evidence](darwin-resource-accounting.md) retains the
actual child clocks and raw counters: ARM **51,244,000 ns** versus
**102,642,416.6667 ns**, and Intel **189,394,000 ns** versus **379,164,912 ns**.
Own-clock conversion and nested `wait4` conservation passed. The later source
correction preserves the observed doubled ignored-child accounting and marks
general Darwin tree CPU unavailable; it does not divide counters or infer
complete CPU from endpoint samples. Sixty source tests passed locally with
three actual Darwin witnesses skipped. Neither that correction nor the fixed
absent-process fixture is a passing macOS rerun.

## Immutable qualification

[Qualification run 35247986949](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986949)
finished with **27 jobs: nine successful, 16 failed and two skipped**. All four
immutable artifact builds passed. Candidate scenarios passed on Linux, macOS
ARM and Windows: each retained 22 native cases with native, Builder and overall
pass flags at the exact candidate build. Intel's scenario failed. All four
indexed primary pair jobs and their four aggregators failed. The first nonpriority group had one
successful pair job and three failures, while all four nonpriority aggregators
failed. Artifact transitions and the second nonpriority group were skipped.

The Linux indexed baseline completed 386 normalized cases, 62 registered cases
and 136 numeric observations across 38 series. Its candidate then failed
`omp.PostToolUse.block.1m` with a retained `native_hook_edge_invalid_response`
diagnostic: an error object with public reason `other`, **9 ms** elapsed and
**2,985 ms** remaining. This is not deadline exhaustion or a passing baseline
qualification. Both Mac indexed baselines blocked during daemon construction
in `socket.getfqdn`. Their independently attempted candidates failed
`cursor.afterShellExecution.benign.max` on ARM and
`pi.PostToolUse.benign.1k` on Intel, with the same finite invalid-response
classification. These diagnostics do not expose or establish the rejected
lower-layer reason.

The Windows indexed baseline completed its implemented block: 136 numeric
observations across 38 series, 386 corpus cases and 62 registered cases. Its
corpus still reports `complete=false`: 55 frozen source-reference cases were
validated unsupported denials, not content reviews. Its candidate failed
`codex.PostToolUse.benign.1k` with the same invalid-response/error-object
classification, **47 ms** elapsed and **2,937 ms** remaining. Its encrypted
evidence archive was retained. Completion of either indexed baseline does not
produce a complete baseline/candidate pair or installed qualification.

Intel's candidate scenario completed ten native cases before disabled-control
ACK readiness took **523.888 ms**, exceeding the unchanged **400 ms** barrier.
Builder passed there; receiving a later ACK does not make the barrier pass.

The [first nonpriority smoke report](nonpriority-smoke-ci-96a697.md) retains the
separate Cursor first-group outcomes. Linux completed two timed observations
and two semantic preflights per arm. Both Windows workers likewise retained
four valid native cases and two timed observations with zero errors, but their
missing RAM identity failed the unchanged strict admission gate. The original
outer process return code was not retained, so an additional process failure
cannot be excluded. Both Mac candidates completed their two timed observations,
while frozen baselines failed at the resolver boundary. Authenticated recovery
verified 25 private records across those three failed archives; only finite
public projections are published in the linked report.

All eight ordinary/nonpriority aggregators failed. The logs of all four ordinary
aggregators and the Linux nonpriority aggregator (`105296268452`) directly
demonstrate a concrete singleton artifact layout defect: the pinned download
action flattens a sole matched artifact despite `merge-multiple: false`.
The later download-layout correction preserves exact manifest admission and
passed 24 source tests. The other three nonpriority aggregators use the same
workflow structure, but their failed logs were not individually diagnosed here.
The separate benchmark-only Windows RAM correction
uses a positive bounded `psutil` value and retains rejection of missing data;
84 focused source tests passed. The Mac resolver probes did not establish a
successful environment correction: libc reverse lookups exceeded their
five-second observation limits, and the experimental resolver received no
queries. Intel's cleanup probe still observed its resolver registration. No
baseline bytes, original failure, fixture deadline or tail criterion is changed.

## Opt-in Claude launcher experiment

[Claude experiment run 35247986580](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986580)
finished with **nine successful and 11 failed jobs**. Complete pairs were
ARM 4/5, Intel 3/5, Linux 2/5 and Windows 0/5. No platform completed its five
independent pairs. Every job completed its encryption and retention gates;
those successes do not change failed comparisons into passes.

The retained finite progress records contain 1,760 planned observations,
1,090 attempted, 1,079 completed, 11 attempted failures and 670 not attempted.
These counts include preflight. Only the nine complete reports publish latency
series: 720 timed observations, 20 per arm/event/job. The comparator is the
optimized Python launcher in the same installed wheel, not frozen baseline
`2e672d2…`.

Five Windows jobs failed the initial native-pilot benign PreToolUse preflight
with an availability response and unknown route. Six POSIX jobs failed an
optimized-Python benign PostToolUse check with an unexpected reason. Exact
source-generated response hashes match the respective discovery fallback and
`native_post_tool_unavailable` shapes. Those matches do not recover rejected
stdout or establish the underlying key, peer, ACL, transport or native failure
stage. All fixtures were restored; qualification and production-selection flags
remain false.

## Scanner and package experiments

[Scanner run 35247986730](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986730)
had three jobs: plan passed, collection and aggregation failed. Four Rust tests
and 69 Python tests using the actual binary passed before collection. The
24 planned worker observations remained unoffered after collection failed
before source identity was retained. All three public/encrypted uploads
succeeded, but there are no measured pairs and no scanner Rust selection. The
[scanner checkpoint](scanner-smoke-ci-96a697.md) distinguishes the demonstrated
executable-reader source defect from the original artifact's unknown specific
identity subcheck. Its later source and retention corrections require a new
experiment; they provide no fifth-cohort timing evidence.

[Package run 35247986524](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986524)
failed with one successful phase job and two failed component jobs. Cardinality
retained 36 candidate completions, 23 baseline completions and 13 censored
baseline workers; formats retained 20 candidate completions, 18 baseline
completions and two baseline Composer failures. All ten phase/validation
workers completed. The separate five-pair Python protect route completed, but
does not erase those coverage and comparison limits.

The [fifth package report](PACKAGE_FIFTH_CI_EVIDENCE.md) and its
[public evidence manifest](evidence/package-ci-96a697/manifest.json) retain the
exact component results, 16 file commitments and retention limits. No
fifth-cohort package ciphertext recovery is claimed. The earlier
[keep-Python decision](package-native-selection-decision.md) remains unchanged;
this cohort supplies no Rust comparison or new native selection.

## Evidence boundary

The compact manifest preserves source/merge identities, all 41 workflow
instances and bounded job conclusions. It contains no raw hook payloads,
command text, private filesystem paths, secrets or decrypted observations.
Successful workflows named for publishing describe their pull-request job
conclusions and do not prove a release was published. All failures, skips,
unoffered observations and incomplete comparisons remain part of this
checkpoint. No task status or acceptance criterion is changed by this report.
