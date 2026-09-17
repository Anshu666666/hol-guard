# Installed canary and rollback plan — RSP-143

Preparation is complete; RSP-143 acceptance remains open. The next candidate wheel,
installed recovery transcript and final-head CI/review have not been qualified.
The accompanying [machine manifest](canary-rollback-manifest.json) therefore keeps
`qualified: false`, `activation: false`, `tested_rollback: false`, and every
candidate identity pending. This plan defines internal validation in isolated
test homes. It records no customer deployment, named operators or scheduled rollout.

## Bound versions and artifacts

The audited baseline is `2e672d2d950c6ec471005ddba46e49bba16dc23b`, package version
`3.0.1`. It remains the original production comparison and a specific legacy
downgrade rejection case. It is not the compatible rollback destination.

The prior native wheel also has package version `3.0.1`. Its embedded build is
`a224cc2e01e1eb8d74182fa32d78f46e9b417348`, Git tree
`f292bc95eb53af29162fcc8ea7e46a4b213803b7`. That tree was independently verified
against PR head `ae33987d0c8675c36a77375e03419aee920825f6` and local commit
`8aa2b63ee33bdebbb170678f500b0405bb3bea58`. The build commit's parents are release
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and that PR head. The wheel's embedded
build identity remains `a224cc2`; these related identities must not be substituted
for it. The [prior selector](../../../scripts/ci/installed_transition_prior.py)
pins the following artifacts from workflow run
[35217841356](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841356).

| Platform / native target | Existing qualification runner | Prior artifact ID | Prior wheel |
| --- | --- | --- | --- |
| Linux x64 / `x86_64-unknown-linux-musl` | `ubuntu-latest` | 10495348403 | `hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl` |
| macOS x64 / `x86_64-apple-darwin` | `macos-15-intel` | 10496030613 | `hol_guard-3.0.1-py3-none-macosx_13_0_x86_64.whl` |
| macOS arm64 / `aarch64-apple-darwin` | `macos-15` | 10496485020 | `hol_guard-3.0.1-py3-none-macosx_11_0_arm64.whl` |
| Windows x64 / `x86_64-pc-windows-msvc` | `windows-latest` | 10495748426 | `hol_guard-3.0.1-py3-none-win_amd64.whl` |

All four full wheel and archive hashes are in the machine manifest. Archive hashes
describe the retained original download; extracted wheel verification alone does
not verify a newly downloaded ZIP's bytes. Each use must verify the exact wheel
bytes, target, embedded build and installed native capabilities. Missing artifacts
or ambiguous paths stop that cohort; a rebuild cannot replace a pinned prior wheel.

Populate the candidate's full source/build/tree SHA, canonical package version,
CI run/artifact IDs, wheel names/hashes, target tags, native program and rule
digests, dependency-lock digest, signing/frozen manifest identity and installed
RECORD proof from the next exact-head build. Recheck these identities after
installation and every transition. A new build or signing step invalidates evidence
for the superseded bytes. Runner labels alone are not hardware qualification:
record actual CPU, cores, RAM, power mode, OS, compiler/interpreter, flags and load.

## Internal cohorts and prerequisites

On **each of the four platforms**, create separate private fixture homes for
`claude-code/PreToolUse`, `claude-code/PostToolUse`, `codex/PreToolUse` and
`codex/PostToolUse`. These are the four real priority registrations read by
[native_slo_priority_launchers.py](../../../scripts/native_slo_priority_launchers.py).
Capture the installed executable/argv, registration hash, configured environment,
stdin corpus hash, stdout contract and exit status; keep private invocation data
in restricted evidence. Use the normal no-override auto route and independently
validate native route counters, policy result and durable receipts.

The remaining installed-registration validation cohorts come directly from
[native_slo_registered_surfaces.py](../../../scripts/native_slo_registered_surfaces.py):

| Harness | Events | Platform qualification requirement |
| --- | --- | --- |
| Cursor | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `beforeWriteFile`, `afterShellExecution`, `afterMCPExecution` | All four targets |
| Copilot | `preToolUse`, `postToolUse` | All four targets |
| Kimi | `PreToolUse`, `PostToolUse` | All four targets |
| Grok | `PreToolUse` | All four targets |
| ZCode | `PreToolUse` | Three Unix targets; Windows registration currently reports `zcode_windows_shell_comment_unqualified` and remains inactive/unqualified |
| Cline | `PreToolUse`, `PostToolUse` | All four targets |

The existing nonpriority collector is a small-input semantic smoke. Full host
application selection, large/source-reference input, Watch, approval continuation,
load and recovery require separate installed evidence before those scopes can be
selected. An unavailable route remains visible in the manifest. Do not turn an
HTTP corpus response or reconstructed argv into proof that a host ran its installed
registration. Other harnesses are outside these declared registration cohorts;
the candidate capability manifest must enumerate their selected or unqualified scope.

Before opening any cohort, require exact-head required CI and independent review,
the RSP-139 transition witnesses, artifact provenance, correct default-auto route,
complete frozen oracle/result and receipt parity, authority freshness/replay tests,
privacy checks and the applicable performance/resource gates. The missing candidate,
live-transition and final-review fields currently prevent advancement. Complete
source tests and earlier wheel smoke are retained evidence for their stated scopes.

Reuse [installed_canary_proof.py](../../../scripts/installed_canary_proof.py) to
create one `hol-guard.installed-canary-subject.v1` per actual wheel and verify its
download; each subject's distribution directory must contain exactly its one
selected wheel. Then run [run_installed_canary.py](../../../scripts/run_installed_canary.py)
from the isolated installed environment with an external Python cache prefix.
It verifies the local immutable wheel origin, payload/RECORD contents, imports
outside the checkout, the frozen 51,000-case installed Python evaluator corpus,
dashboard smoke and the OpenCode no-post-execution-proof control. The registered
native cohorts and their performance evidence are additional requirements.
The existing publish canary has three OS labels; it does not establish both macOS
architectures. The four-target native qualification matrix remains required.

These existing commands are concrete templates after the pending identities are filled:

```bash
python scripts/installed_canary_proof.py write-subject \
  --dist-dir "$RSP_CANDIDATE_DIST" --version "$RSP_CANDIDATE_VERSION" \
  --source-sha "$RSP_CANDIDATE_SHA" --output "$RSP_CANARY_SUBJECT"
python scripts/installed_canary_proof.py verify-download \
  --subject "$RSP_CANARY_SUBJECT" --version "$RSP_CANDIDATE_VERSION" \
  --source-sha "$RSP_CANDIDATE_SHA" --download-dir "$RSP_VERIFIED_DOWNLOAD"
"$RSP_INSTALLED_PYTHON" -X "pycache_prefix=$RSP_EXTERNAL_PYCACHE" \
  -m scripts.run_installed_canary --subject "$RSP_CANARY_SUBJECT" \
  --version "$RSP_CANDIDATE_VERSION" --source-sha "$RSP_CANDIDATE_SHA" \
  --repo-root "$RSP_HARNESS_CHECKOUT" --output "$RSP_CANARY_EVIDENCE"
```

Use the existing [native qualification workflow](../../../.github/workflows/native-performance-qualification.yml)
in `qualification` mode for the four platform builds and paired collector, with
the pinned original baseline and `--prior-artifact-root`. A smoke-mode run leaves
tail qualification false. A distribution canary with a different package version
needs explicit version-transition evidence; the same-version fixture below does
not establish that downgrade.

## Frozen measurement and stop conditions

Apply the original [PRD §§5–6](PRD.md) and the recorded estimator without changing
thresholds after observing results. Use same-host alternating baseline/candidate
order, retain errors/denials/retries and distinct admission outcomes, and keep
normalized daemon ingress separate from actual launcher timing.
Apply sample minima to each platform and comparison arm, with the stated
per-route or per-launcher minima retained separately.

| Requirement | Frozen minimum or gate |
| --- | --- |
| Priority warm decisions | 10,000 per route/platform/arm across at least five independent runs |
| Remaining installed warm routes | At least 1,000 samples per selected route/platform/arm |
| Cold / recovery / resources | 100 cold starts per priority launcher; 100 recoveries; 30 steady-state resource samples |
| Estimation | Deterministic nearest-rank percentiles; report confidence intervals and sample counts per route, platform and arm |
| Inputs / load | 1 KiB, 16 KiB, 256 KiB, 1 MiB and declared maximum supported bytes; concurrency 1/4/16/64 and arrival-rate load |
| Ordinary installed launcher, 1–16 KiB | c1 p95 ≤50 ms and p99 ≤100 ms; c16 p99 ≤200 ms with zero request errors and correct decisions |
| Native client / cold hook / readiness | Warm c1 p95 ≤20 ms; cold hook p95 ≤150 ms; adapter-first-request readiness ≤400 ms, with full daemon startup reported separately |
| Existing relative release gates | Warm ≤20 ms **or** ≥1.15× reference speedup; cold ≤150 ms **and** ≥5× reference speedup; the reference must actually evaluate the intended semantic route |
| Selected new hot path | At least 30% lower full local p95 or process-tree CPU, with ≤5% regression in the other primary metric |
| Optional ingress selection | At least 25% lower steady-state process-tree private memory or 30% lower c16 p99, with preserved correctness and containment |
| Resources / overload | Short-load observed RSS growth ≤12%; separate long-soak growth ≤50%; measure the complete daemon/helper/resident tree; c64 overload must remain bounded |

The existing 1,000 ms normalized adapter budget is a production ceiling, not the
50/100 ms launcher target. Sparse smoke, a fast availability continuation or a
source-only prototype cannot satisfy these distributions. Long mixed-load evidence
must include real evidence ingest, policy changes, inventory, startup/restart and
saturation. Missing reliable measurements keep the corresponding gate unqualified.

Stop the affected cohort immediately on semantic/receipt mismatch, replay or stale
stricter authority, leaked private evidence, identity/signing failure, unsupported
capability, wrong installed argv/route/stdout/exit, failed containment, unbounded
queues/resources, missing samples or a failed applicable metric. Preserve the
failure record and all attempts. Expected policy denials remain valid semantic
observations; unexpected availability or omitted errors cannot improve a score.

## Stopped rollback, restoration and remaining live work

Run [verify_installed_artifact_transitions.py](../../../scripts/ci/verify_installed_artifact_transitions.py)
with both wheel identities and the distinct pinned prior candidate, following
[installed-artifact-transition-contract.md](installed-artifact-transition-contract.md).
The current fixture starts the actual registered Claude `PostToolUse` launcher.
It requires two native decisions per positive phase and exact receipt, registration
and monotonic authority preservation. It does not establish rollback for every
other harness without their post-restoration registration checks.

1. In one fresh private home, test **candidate → pinned prior native wheel → candidate**.
   Require matching package version `3.0.1`, proven compatible native capabilities,
   all three positive phases and retirement between each installed artifact.
2. In another private home, test **clean original baseline → candidate upgrade →
   candidate reinstall → original-baseline downgrade attempt → candidate restore**.
   The original downgrade must reject its recognized unsupported policy reader,
   preserve bound policy bytes, all six prior receipts and registration, stop the
   publisher and verify the exact legacy runtime's authenticated idempotent
   `resident-stop` containment. Preserve that phase's `passed: false`.
3. Accept the separate stopped-transition contract only after all seven positive
   phases, the verified negative and explicit candidate restoration succeed in
   order with unchanged artifacts and dependency lock. The original sequence's
   all-positive result remains false. A reinstall cannot substitute for a distinct
   prior artifact or the missing negative containment proof.
4. Before any real restoration, stop new admission to the affected fixture, record
   outstanding outcomes, retire the exact owned generation and verify process/pipe
   shutdown. Restore the verified compatible package and installed registration,
   then verify the restored native identity, acknowledged policy and fresh requests
   through every selected harness. Never silently replay ambiguous tool execution
   or approval consumption, lower persistent floors, remove authority bindings,
   delete retained receipts or reopen hidden Python semantic fallback.
5. Keep live mixed generations, in-progress update/approval/tool requests, package
   version downgrade, native program downgrade, enrollment and signing/frozen-byte
   changes explicitly pending. Each needs its own four-platform transcript,
   protected authority/receipt continuity, stale-write rejection and first-request
   verification. If compatible restoration cannot be proved, retain the stopped
   cohort and its state instead of forcing the original baseline to start.
6. After durable restricted evidence and bounded aggregate reports are verified,
   remove only owned disposable fixture homes, caches and child processes. Retain
   the exact candidate/prior wheels, identities, manifests and rollback transcripts.
   During shared local collection, builds, installs, tests and cleanup use the
   existing performance lock and occur outside another cohort's measurement block.

The retained [ae33987 evidence manifest](evidence/takeover-ae33987/manifest.json)
and four historical transition reports remain failed/incomplete evidence predating
the stricter stopped-transition contract. No tested candidate rollback is recorded
here. Fill the manifest with new immutable evidence, obtain the exact-head required
review and keep publication/merge/activation within the implementation session's
authorization before changing the activation state.
