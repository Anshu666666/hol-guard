# Installed baseline launcher ranking: retained Windows scope

The retained installed baseline provides a concrete, host-specific ordering for
four canonical Claude Code and Codex command-hook routes. **It does not identify
Claude as uniformly most expensive.** The observed ordering changes with the
event and concurrency. This note supports RSP-073 with actual installed command
measurements and an explicit inventory of the other supported surfaces, without
turning daemon HTTP calls into launcher observations or combining platforms.

The evidence is baseline block zero from
[workflow 35220287310, artifact 10497662006](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287310/artifacts/10497662006),
member `aggregate/00-baseline.json`. The workflow used collector source
`107606388ad55f924a4e2924b4ff84e5fa08e6ff`; the installed baseline under test is
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. Its Windows target is
`x86_64-pc-windows-msvc`, package version 3.0.1, Python 3.12.10 and Rust 1.88.0.
The report identifies one Windows Server 2025 x64 runner, four effective CPUs,
and AMD64 Family 25 Model 1. Power mode and RAM are unrecorded. All rankings below
stay inside that one runner and block.

| Identity | SHA-256 |
| --- | --- |
| Downloaded public ZIP, 17,324 bytes | `c5818f6c498371508a2ba3b80cc28f3bdafe7bb7e77d263a27cc77a5e9c2fd0d` |
| Exact baseline JSON member, 66,947 bytes | `8720640ea8e17bdb3edb442685f98ff22a6de9c603a912febb2e60b0adb34e4c` |
| Qualification artifact commitment | `4031a873cc6da687ae5fd91f3b6145e068f53d68c8fbd1ba0ed659c448d6df36` |
| Installed package commitment | `86cfcba44f6b5769e429d2d071e7952c3530d4d0d39f93336a798004c3c94d1b` |
| Installed package RECORD commitment | `390d2e880bcec87dba518c6f0f38e8921d7324206adc24d62531fadd780803c6` |
| Installed native runtime | `49535b65c62f7ea32d829aeaf7816441ba45a9d291c681ec9e59553147d72abf` |

The artifact was downloaded again for this review, with exact size and ZIP hash
verification, bounded member reads and traversal checks. Its baseline member
matches the previously retained first-checkpoint copy. No new timing was run.

The frozen
[priority-launcher collector](https://github.com/hashgraph-online/hol-guard/blob/107606388ad55f924a4e2924b4ff84e5fa08e6ff/scripts/native_slo_priority_launchers.py)
calls the shipped installers, independently reads actual registered argv and
environment, starts that command, sends stdin, captures stdout and waits for
exit. It validates delivered fields and exit status, checks registrations before
and after the series, and requires native-resident route-count conservation.
No direct HTTP request substitutes for a registered process.

Every timed invocation uses the benign case. PreToolUse submits the same small
synthetic `pwd` command to both harnesses; the command itself is not executed.
PostToolUse submits the same 1 KiB benign text output. Benign and block cases are
validated separately before timing each route. The daemon has an explicit,
acknowledged allow policy and a prepared resident. Each route contributes two
serial observations, two fresh-launcher observations and one simultaneous burst
of 16 invocations: **80 timed invocations across four routes**. Process startup
is included in every series. The separately labeled fresh-launcher series does
not establish cold resident/bootstrap or cold OS-cache behavior.

The table gives observed wall-time p50 values. Compare the two harnesses within
the same event and series; Pre and Post use different workloads.

| Event and matched case | Harness | Serial, n=2 (ms) | Fresh launcher, n=2 (ms) | c16 burst, n=16 (ms) |
| --- | --- | ---: | ---: | ---: |
| PreToolUse, small benign command | Claude Code | 505.797 | 577.661 | 3,023.653 |
| PreToolUse, small benign command | Codex | 516.494 | 516.778 | 2,843.115 |
| PostToolUse, 1 KiB benign output | Claude Code | 524.846 | 496.793 | 3,233.690 |
| PostToolUse, 1 KiB benign output | Codex | 523.527 | 530.651 | 4,065.828 |

For the matched PostToolUse c16 workload, Codex's observed median is 832.138 ms
(25.7%) higher than Claude's. For serial PostToolUse the observed medians differ
by only 1.319 ms, with Claude higher. For PreToolUse, Codex is higher in the
serial series, while Claude is higher in the fresh-launcher and c16 series.
This justifies including Codex PostToolUse under concurrency in subsequent
launcher investigations; selecting Claude alone cannot be justified by claiming
it is the slowest measured harness in all cases.

These are descriptive rankings from one fixed-order block: Claude Pre, Claude
Post, Codex Pre, then Codex Post. There are no independent repeated blocks for
these comparisons, no uncertainty claim separating the close serial results,
and no installed usage-frequency data for weighting a product-wide ranking.
The report's p95/p99 fields are retained in the source artifact but are not used
here as qualified tails. A tail sample minimum is not a prerequisite for
recording this bounded observed ordering; it remains a separate qualification
requirement. The interval covers startup, transport, daemon work and delivered
output/exit together. Subtracting unrelated daemon quantiles would not isolate
launcher-only overhead. Per-launch process-tree CPU is not supplied by these
series.

The current installed-route inventory at source `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`
must retain distinct execution forms. It covers the sixteen adapters in the
[registry](https://github.com/hashgraph-online/hol-guard/blob/d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f/src/codex_plugin_scanner/guard/adapters/__init__.py);
it does not imply that every current surface existed in or was timed by the
frozen baseline:

| Supported surface | Actual installed form and delivery scope | Comparable baseline timing in this note |
| --- | --- | --- |
| Claude Code canonical Pre/Post | Registered command argv; pre permission and post output contracts | Canonical Pre/Post series above, grouped by event and load; other event groups are unranked |
| Codex canonical Pre/Post | Registered isolated Python bridge argv and environment; harness-specific stdout and continuation contracts | Same matched Pre/Post workloads and host as Claude; approval continuation is outside timed benign cases |
| Cursor | Six installed aliases in `hooks.json`, including shell/MCP/read/write pre hooks and two observation-only post aliases | None retained as a comparable latency series |
| Copilot | Global/project registrations, pre/post aliases and platform-selected CLI commands; post is observation-only | None; the separate baseline semantic corpus failed at `copilot.preToolUse.benign.small` |
| Kimi | Installed TOML pre/post command hooks | None |
| Grok | Installed catch-all pre command hook; post unavailable | None |
| ZCode | Installed pre CLI matcher registrations; post normalization is not an installed hook | None; Windows marker/shell execution remains unsupported by the registration probe |
| Cline | Persisted filesystem hook slots and worker files; pre cancellation, observation-only post | None |
| Pi / OMP | Generated extension/plugin callbacks, including `tool_result` and source-reference handling | No command-launcher series; importing a generated callback probe is not complete host activation |
| Hermes | Installed `hooks.pre_tool_call` configuration plus exact shell-allowlist pairing | None; preflight/configuration inspection is not installed process timing |
| OpenCode | Global plugin with `tool.execute.before` | None; not a Python command-hook latency observation |
| OpenClaw | Managed overlay/pretool bundle requiring host activation | None; managed JSON readback is not installed host execution |
| Gemini / Antigravity | Reviewed installer path uses the inherited Guard launch/preflight shim plus inventory | None; this installer path is not evidence of a per-tool command-hook timing boundary |
| Paseo | Installs shared hooks for supported native providers and a launch shim; provider-native execution owns enforcement | None; provider hooks are not an independent Paseo permission-notification enforcement route |

The [registration and delivery inventory](registered-surfaces-smoke.md) records
the exact aliases, readback rules, observation-only behavior and unavailable
surfaces. The
[capability registry](https://github.com/hashgraph-online/hol-guard/blob/d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f/src/codex_plugin_scanner/guard/protection_capabilities.py)
with the [base installer](https://github.com/hashgraph-online/hol-guard/blob/d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f/src/codex_plugin_scanner/guard/adapters/base.py)
and [Paseo adapter](https://github.com/hashgraph-online/hol-guard/blob/d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f/src/codex_plugin_scanner/guard/adapters/paseo.py)
preserve the limited, preflight and provider boundaries. None of the missing timings above
is assigned zero cost. The Windows
block separately measures 21 daemon-ingress routes; those HTTP-boundary numbers
are not relabeled as launchers or mixed into the table. Its nonpriority
registered-surface scenario failed, so that scenario supplies no complete
cross-harness latency ranking. The entire qualification block retains
`qualification_complete=false` and missing source-reference coverage.

The other first-checkpoint platforms cannot fill this baseline table:

| Platform / artifact | Retained baseline outcome | Consequence for ranking |
| --- | --- | --- |
| Linux x64, [10497305428](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287310/artifacts/10497305428) | `CodexHookIntegrityError`; no completed baseline timing aggregate | No baseline route ordering recovered from this artifact |
| macOS ARM, [10497165409](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287310/artifacts/10497165409) | `daemon_fixture_deadline_at_construct_daemon` before timing | No baseline launcher series |
| macOS Intel, [10497501044](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287310/artifacts/10497501044) | Same constructor deadline before timing | No baseline launcher series |

All three public ZIPs were also re-downloaded and verified for this review.
Their ZIP SHA-256 values, in table order, are
`496a748383d1581ed0d13695a1e410e813c6b57db16bb4a495df3bccce2cd9aa`,
`83bb834a058c2189ccdf1fdd37d9badc162ec05340e236a8ef5c951c82344e05`, and
`0adc63320f31a8a11a24af70f3966905161a2cf39c3fb9eac7f9160d90e1d5ea`.
These failures are retained rather than converted into slow, successful or
zero-duration observations.

The first checkpoint's separate Linux and macOS ARM native-wheel smokes include
two Claude PostToolUse observations each, but their installed build is
`a806a38f84c083171a980c084032725efcf43a58`, not frozen baseline `2e672d2...`.
The [first CI report](FIRST_CI_EVIDENCE.md) preserves their exact identities.
They have no same-host Codex peer measurement and cannot be pooled with the
Windows baseline or used to complete missing baseline cells. Later `24ba`
installed qualification created no jobs because its workflow was invalid;
source corrections do not create observations retrospectively.

RSP-073 can cite this note for the observed installed baseline ordering and the
explicit measured/unmeasured route inventory. The evidence is sufficient to
record that bounded ranking without imposing a new tail prerequisite. It does
not support a frequency-weighted ranking of every harness, a stable cross-host
ordering, or a claim that the existing Claude pilot targets the highest-cost
route. Any broader prioritization must add comparable installed observations
for its selected surfaces while preserving these missing and failed cases.
The native launcher benefit, alias parity, rollout, platform and update/rollback
gates remain separate; no port or default activation is authorized here.
