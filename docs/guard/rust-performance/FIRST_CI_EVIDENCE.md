# First finalization CI: measured evidence and remaining decisions

Observed 2026-09-17 at 13:01 UTC. [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970)
head `107606388ad55f924a4e2924b4ff84e5fa08e6ff`, tree
`a9998b9aee230bcdf42d8164011c334481817373`, completed **39 workflows: 33 successful
and six failed**. These are source-specific results. The release is not qualified.
The [evidence manifest](evidence/first-ci-107606/manifest.json) binds retained public
reports to exact downloaded ZIP hashes, artifact members and content hashes.

The package/MCP and paired performance builds compare frozen source
`2e672d2d950c6ec471005ddba46e49bba16dc23b` with `107606388...`. The separate native-wheel
workflow identifies PR merge build `a806a38f84c083171a980c084032725efcf43a58`.
Do not attribute that installed artifact identity to a later source revision.

## Package evaluation: retain the optimized Python baseline

The real local `protect --dry-run` function with npm, 1,000 dependencies and
1,000 exact bundle entries completed five alternating independent pairs. All
ten observations retained 1,000 entries, packages and evidence rows, with matching
fixture, entry, semantic, evidence and signed-response commitments. The measured
interval includes the production local protect function; worker import, fixture
construction and postvalidation are outside it.

| Measure | Frozen Python median | Optimized Python median | Median paired reduction |
| --- | ---: | ---: | ---: |
| Local wall time | 6885.272 ms | 259.996 ms | 96.2239% |
| Local process CPU | 5923.255 ms | 242.241 ms | 95.9041% |

These are five paired medians, not installed CLI startup measurements, qualified
p95 estimates or a native comparison. The remaining approximately 242 ms CPU is
a profiling target. Any package Rust pilot must beat this optimized Python
route by the original PRD threshold while preserving the other metric.

The independent cardinality diagnostic retained all 72 offered observations:
36 candidate cells completed; 24 baseline cells completed and 12 were censored.
All four match modes at dependency/bundle pairs (1,000,10,000), (10,000,1,000)
and (10,000,10,000) hit the baseline worker's 15-second bound. That bound includes
setup and postvalidation, so it is not a 15-second evaluator lower bound and
cannot supply a speedup ratio. The unversioned diagnostic is explicitly a
bundle-kernel scope; its complete protect-route parity remains separate.

The format preflight completed all 20 candidate cases. The baseline completed
18 and failed two Composer package-count checks. Those two cases are
noncomparable. This is why the [package workflow](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287514)
remains failed despite completed candidate work. The unresolved fixture also
preserves both explicit credential-unavailable outcomes. RSP-050 and RSP-054
remain OPEN; no native package activation or permanent no-port decision follows.

## MCP: local improvements are measured; further attribution remains

The [MCP workflow](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287536)
completed 30 workers and 2,730 tool calls with zero failed call outcomes. It used
five independent runs per revision and mode, seven identical synthetic traces,
and the actual source stdio proxy session. The plain groups each contain 60 warm
calls plus five first calls. These descriptive nearest-rank summaries have no
paired confidence intervals in the v1 report; the 60 calls are not 60 independent
runs. This source predates the subsequently integrated classification prefilters.

| Trace | Warm p50, baseline → candidate (ms) | Warm p95, baseline → candidate (ms) |
| --- | ---: | ---: |
| `catalog10` | 32.547 → 32.114 | 34.953 → 33.325 |
| `catalog100` | 34.857 → 32.353 | 35.866 → 33.677 |
| `catalog1000` | 57.583 → 32.253 | 83.897 → 33.421 |
| `catalog_refresh` | 35.043 → 32.199 | 35.556 → 33.493 |
| `payload16k` | 48.227 → 41.160 | 49.616 → 41.989 |
| `child_delay10ms` | 45.140 → 42.305 | 46.045 → 43.902 |
| `inline_approval10ms` | 68.288 → 67.629 | 71.640 → 69.912 |

The 1,000-tool catalog's mean parent CPU fell from 51.886 to 24.455 ms per call.
A separate instrumented diagnostic attributes catalog fingerprint CPU of
1,370.10 → 79.50 ms across 130 fingerprint invocations spanning 65 tool calls. Nested diagnostic phases are not additive
headline timings. The final quiet barrier remains approximately 5.10 ms per
call with little CPU. Delayed-child and simulated approval service remain
separate waits; external network latency was not exercised.

Startup-inclusive resource observations recorded 337–367 valid snapshots in
each resource worker, but all failed resource completeness because final reads
encountered exited PIDs; eight also retained descriptor access failures.
Measured median sampled tree peaks were 109.60 → 112.84 MiB RSS and
88.05 → 91.18 MiB private memory. These are incomplete, sampled lower bounds,
not a qualified memory regression conclusion. RSP-098 and RSP-103 remain OPEN.
The corrected collector needs five paired run-level intervals, a separately
attributed loopback-network trace and complete warm resource windows before
selecting a native MCP kernel.

## Installed correctness and platform outcomes

All four dormant Claude launcher source-feature jobs passed in
[workflow 35220287381](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287381).
The feature remains off. This establishes source-feature correctness at those
four targets, not installed activation or a native performance benefit.

The [native-wheel workflow](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287375)
passed Linux and macOS ARM. Linux completed 100,000 requests, 250,000 receipts,
17,888 health checks, zero request/health errors and stable PID. Its sampled RSS
growth was 3.9683%; response p95 was 528.06 ms. This is the existing soak scope
with its own latency bound, not the PRD's 50 ms installed-priority target.
The ordinary registered Claude PostToolUse smoke had only two observations:
Linux max/p95 344.126 ms and macOS ARM 282.838 ms. Both correctly retain
`qualification_complete=false`; neither supplies a qualified tail comparison.

macOS Intel failed recovery sample 1 after verified resident containment.
Windows failed because the old RSS reader returned unavailable. These failures
need exact corrected installed reruns. Local measurement repairs are documented
separately and do not change these historical outcomes.

All four paired performance jobs failed in smoke mode. Windows retained one
completed baseline block, but its side scenarios still contain failures and
its coverage is incomplete. Every candidate stopped at the expiry fixture's
publication-authentication assertion. Linux's baseline stopped at Codex
interpreter permission validation. Both Mac baselines timed out constructing
`HTTPServer` through `socket.getfqdn`.

The Mac resolver reports now show that each reverse-name and legacy lookup
entered the call and exceeded five seconds, while numeric lookup completed in
47–66 ms. Resolver setup/cleanup completed but all OS-query counters stayed zero.
The reports do not establish resolver registration or selection. Retain the
baseline failure; do not mutate its wheel, resolver implementation or deadline.

Installed Ollama completed all 22 native cases and Builder checks on both Macs.
Windows completed ten native cases, then failed disable-phase readiness at
406 ms against the unchanged 400 ms limit. Its publisher stack reached repeated
Windows DLL/file-binding setup. This localizes observed work, without proving
that one sampled frame caused the miss. Settings rollback still does not prove
changed artifact/program rollback, enrollment or native approval consumption.

## Privacy, reproducibility and release status

Authorized decryption of package format-preflight ciphertext artifact
`10496204564` recovered **103 files**, including 40 JSONL journals. Manifest/file
hashes and 0700 directory/0600 file permissions were verified. The plaintext and
recovery key are excluded from the retained public evidence. This recovery
claim applies only to that archive; diagnostic package and MCP ciphertext
recovery are still outstanding.

The remaining failures also include the main Python CI's fixture/version tests,
macOS secure-path test fixtures and the secret scanner's public-hash finding.
Their local corrections require a new source-bound CI run. Main quality,
scheduler-sensitive, differential, approval and adversarial workflows passed at
this checkpoint, but those passes cannot turn the six failed workflows green.

Keep the original [PRD](PRD.md), all 144 [TODO](TODO.md) acceptance conditions and
thresholds. Use these measured optimized-Python baselines for new Rust pilots.
Do not activate the dormant launcher, native package/scanner/MCP kernels or
native ingress without their required correctness, installed measurement,
platform, update/rollback and independent-review evidence.
