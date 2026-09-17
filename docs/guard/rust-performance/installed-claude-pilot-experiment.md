# Opt-in installed Claude launcher experiment

This experiment supports the investigation in RSP-073–082. It changes no task
status, acceptance criterion, dependency, production registration, default
Cargo feature, ordinary wheel build, or headline qualification workload.

At candidate `107606388ad55f924a4e2924b4ff84e5fa08e6ff`, the dormant source
workflow `35220287381` passed on all four targets. The retained registered Python
Claude PostToolUse smoke was approximately 344 ms on Linux and 283 ms on macOS
ARM, with only two samples each. Those measurements justify a controlled
experiment. They do not establish a tail distribution, a Rust benefit, or a
complete ranking by actual harness use.

## Exact comparison

The explicitly selected `native-claude-launcher-experiment.yml` builds a separate
release wheel with the explicit `native-claude-launcher-pilot` Cargo feature.
It installs that wheel into a locked Python 3.12 environment outside the source
checkout. Regular release builds remain unchanged. The experiment has five
independent jobs per target: Linux x64, macOS x64/ARM64, and Windows x64.
It can be dispatched manually or enabled on a same-repository pull request by
the `native-claude-launcher-experiment` label. Unlabeled requests and forks do
not run it. The PR path uses its exact head SHA for checkout, runtime build,
measurement, and archive context. Path filters restrict the eligible PR diff;
later pushes to an eligible labeled request may enqueue another run. A unique
run/attempt concurrency group with cancellation disabled preserves earlier
offered runs after later pushes, including documentation updates.

Each job compares the current optimized Python registration with the native
pilot **inside the same installed wheel**, using the same native runtime bytes,
private interpreter, dependencies, policy, prepared daemon, synthetic context,
and hook input. This is an incremental launcher comparison; it does not replace
the frozen `2e672d2` baseline in the main qualification pipeline.

The installed worker runs under `python -I`, verifies all imported Guard modules
come from the installed distribution, compares installed package bytes with the
wheel, and checks the bundled runtime's full identity and advertised pilot
capability. It records wheel/package/runtime/interpreter hashes, build/target/
rule identity, the installed dependency-version inventory digest, and a digest
of the experiment's script sources. It repeats identity verification after
collection. The dependency digest identifies versions; it is not a claim that
every dependency's installed byte inventory was independently attested.

The worker creates a disposable daemon fixture with the protected empty local
authority and explicit normal policy. The existing readiness check retains its
400 ms ceiling. It installs Claude through the real adapter, reads the generated
structured command/args, and checks idempotent installation. For the pilot arm,
only the two canonical PreToolUse/PostToolUse handlers in that private settings
file are replaced with the explicit prepared native vector. Matchers, timeout,
other event groups, and unrelated settings remain unchanged. Each invocation
reads back the actual selected settings, and the original installed bytes are
restored on completion or failure. No source-checkout executable, environment
binary override, PATH-selected runtime, download, or one-shot semantic evaluator
can stand in for the installed launcher.

Every sample starts a fresh registered process and includes its startup, stdin,
authenticated daemon transport, stdout, containment, and exit. Healthy measured
responses must have empty stderr, the exact frozen allow/block semantics, and
exactly one native-resident route observation. The two arms must return equal
complete JSON objects for the same synthetic input. Before timing benign cases,
both arms must pass benign and malicious witnesses for both events. Native
availability, integrity, size-limit, unsupported-response-profile, and unknown
delivery shapes remain failed observations with bounded diagnostic labels.

Arm order reverses between pairs and independent runs. The daemon and resident
remain prepared; these are fresh-launcher samples, not cold-resident samples.
Configuration selection and artifact validation occur outside the timer. This
is not phase attribution or a process-tree CPU/memory comparison.

Private numeric journals offer every planned series before sampling and record
the elapsed time of failed process calls before assertions. A separate outcome
journal persists the full planned denominator before preflight, then an offered
record and a terminal record per attempted invocation, including arm/event/case,
sample index, input and registration/argv identities, captured-stream hashes and
lengths, process flags, full-response digest, and route observations. Each pair
records exact response equality before any mismatch assertion. These records
are flushed and synced individually. A hard interruption leaves an unmatched
offer; it cannot become a completed observation. Captured-stream hashes identify
the contained runner's UTF-8 reencoded text, not the original OS byte stream.
On interruption, unobserved counts remain incomplete. The public aggregate retains progress,
failure stage, bounded process flags, delivered classification, registration/
argv digests, and summary statistics; it never includes argv, local paths, hook
bodies, stdout, or stderr. The always-run retention step encrypts the explicit
flat `private_samples` files with the established public recipient key. Uploads
select only the bounded public summary/receipt and ciphertext.
The final always-run gate requires successful encryption, both uploaded artifact
IDs, and the expected recipient, file count, ciphertext size, and SHA-256 in the
receipt. Encryption/upload failure cannot produce an evidence-complete green
job. Earlier failures still publish whatever bounded diagnostics and encrypted
prefix exist; a missing archive is never replaced with a fabricated success.

The dispatch default is 20 samples per arm/event in each job. A run with 2,000
per job supplies 10,000 per arm/event across five independent jobs, provided
every job completes successfully. The reports do not pool platforms/events or
automatically qualify the result. Raw samples are retained for a later paired
analysis with the declared estimator and confidence intervals. No selection
decision follows from this helper or its exit status.
Each series exposes its sampled 50 ms p95 and 100 ms p99 target checks using
unrounded nearest-rank values. A completed semantic experiment can still miss
either latency target; `contracts_passed` does not certify performance.

The source regression suite covers registration preservation/restoration,
tampering, failed process capture, availability rejection, counterbalanced
pairs, durable planned/offered counts, hard interruption, full-response mismatch,
receipt/ciphertext checks, and the opt-in workflow/retention gates. Together with
the existing preparation, source-pilot, and numeric-journal tests, 60 tests passed
locally. The five new Python source modules report zero type errors; Ruff and
format checks pass. These checks do not execute an installed pilot wheel or
establish platform latency, and no task is closed by this experiment's source.

## Remaining acceptance work

| Task | Remaining original acceptance boundary |
| --- | --- |
| RSP-073 | Complete the supported-route inventory and installed baseline ranking by actual harness use; the canonical Claude sample alone is insufficient. |
| RSP-074 | Validate the source design against installed package/identity and all argv/stdin/stdout/exit/environment contracts, including unsupported signed fields and lifecycle behavior. |
| RSP-075 | Qualify actual canonical pre/post response and continuation parity, Watch, malformed/oversize input, authenticated/unavailable outcomes, blocked stdio, and daemon startup/recovery. The dormant pilot still has explicit unsupported profiles. |
| RSP-076 | Add reviewed production ownership markers and generated-entry selection, detect existing installs, and prove exact idempotent reinstall/uninstall/repair. The current production ownership detector does not recognize native pilot entries. Fixture replacement is not that implementation. |
| RSP-077 | Prove no-environment selection through the final production registration and installed executable, including stale config, executable/manifest replacement, package upgrades, rollback, and absence of the feature. |
| RSP-078 | Port and qualify an alias-heavy harness such as Cursor/Copilot, including native event/response and permission/unavailable semantics. |
| RSP-079 | Qualify Pi/OMP reference identity, external-source permission, bounds, output equivalence, and native response schemas. |
| RSP-080 | Qualify review/pause/approve/revalidate/consume, expiration, restart, and ambiguous completion without duplicate execution across the required launchers. This experiment never executes the reviewed synthetic tool commands. |
| RSP-081 | Qualify installed wheels and frozen sidecars on all four targets, with signing, version/manifest/package binding and lifecycle ownership. Feature-enabled source tests are insufficient. |
| RSP-082 | Complete paired installed measurements against the optimized Python control, including c1 p95 ≤50 ms/p99 ≤100 ms, c16 p99 ≤200 ms with zero errors, 100 cold starts and 100 recoveries, final response/setup/queue time, and all platform misses. The full PRD also requires 30 steady resource samples. |

Production registration must remain unchanged until those applicable correctness
and measured-benefit gates are satisfied. This experiment cannot certify them:
every report fixes `qualification_complete=false` and `production_selected=false`.
