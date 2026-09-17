# Ninth native-wheel checkpoint

[Native-wheel run 35275855174, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855174)
is terminal **failure**. Its head is
`d33f64d5fb86a3f2baa6848382ce763e2ed9fc59`; the four installed runtimes identify
tested pull-request merge `009c7253ce2e132bffaea837b23b0a36b9bc16c2`. Both commits
have tree `0a40e2ebd6515094b5ce6b92c21a5fde3d056f40`. Package and runtime version
fields remain `3.0.1`; neither these fields nor the distinct merge identity is
rewritten to a release label or the workflow head.

The [terminal metadata](evidence/native-wheel-ci-d33/terminal-metadata.json),
[decoded-log provenance](evidence/native-wheel-ci-d33/log-record-provenance.json)
and [manifest](evidence/native-wheel-ci-d33/manifest.json) retain complete public
JSON values emitted in the job logs. Artifact API sizes and hashes remain
metadata. No wheel, binary or artifact ZIP download, archive-member byte
verification, private recovery or new performance measurement is claimed.

## Platform outcomes

| Job | Conclusion | Actual scope |
| --- | --- | --- |
| [Linux x64, 105386194815](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855174/job/105386194815) | Success | Installed identity/default-auto/generated OMP probes, all emitted adapter smoke gates and 100,000-call soak pass |
| [macOS ARM, 105386195205](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855174/job/105386195205) | Success | Installed identity/default-auto/generated OMP probes and all emitted adapter smoke gates pass |
| [macOS Intel, 105386195008](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855174/job/105386195008) | Failure | Installed probes complete; only the resident-recovery smoke gate fails |
| [Windows x64, 105386195052](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855174/job/105386195052) | Success | Installed identity, independent Win32 lock, default-auto corpus and all emitted adapter smoke gates pass |

All four artifact upload steps succeed. The [eighth wheel checkpoint](NATIVE_WHEEL_EIGHTH_CI_EVIDENCE.md)
keeps its original Windows conservation failure and two Intel latency-gate
failures. This ninth cohort neither replaces those observations nor isolates a
cause for the change. The separate Main Windows bootstrap outcome is outside
this wheel report.

## Identity, delivery and receipt scope

Each platform retains a 17-entry installed-status and real stdio-child identity
sequence: 16 `passed` results and a successful replacement marker. Runtime,
manifest and Python-module hashes remain in each identity report. This is the
probe's status/child scope, not a measurement of cold or warm evaluated hooks.
Cross-release upgrade/rollback and signing remain explicitly `not_exercised`.

All four default-auto reports retain 21 resident decisions, zero Python semantic,
one-shot or fail-safe decisions and 21 accepted/processed receipts with zero
drops or durable pending receipts. Both Macs report zero writer failures;
Linux and Windows each retain the two failures described below. These are normalized daemon-ingress routes, not 21
installed launcher registrations. Each uses an isolated generated-key command
authority verified `protected`; user enrollment is not exercised.

The [Linux](evidence/native-wheel-ci-d33/linux-x64-default-auto.json) and
[Windows](evidence/native-wheel-ci-d33/windows-x64-default-auto.json) default-auto
reports each retain 21 accepted and 21 processed receipts, zero drops and zero
durable pending receipts, **with a receipt-writer failure counter of two**. The existing
completeness predicate checks the accepted/processed/dropped/pending fields;
it does not require a zero historical failure counter. This report does not
infer the failed writer operations' cause. The exact current predicate is in
the [pinned receipt helper](https://github.com/hashgraph-online/hol-guard/blob/d33f64d5fb86a3f2baa6848382ce763e2ed9fc59/scripts/native_probe_receipts.py).

The new bounded delivery observer emits only if aggregate validation fails.
Windows conservation passes in this invocation, so there is no failure-only
delivery record to explain the eighth cohort's missing route. Generated route
rows and aggregate conservation do not become independently authenticated
per-request native-route attribution.

The separate generated-extension probes on Linux and both Macs identify
**OMP**, despite their shared Pi/OMP probe filename. Each validates four real
output cases and seven malformed-result/observation vectors through the actual
installed extension/daemon/resident route. This does not establish every Pi/OMP
surface. Windows' four control-lock cases exercise a Python lease against an
independent Win32 child; its separately named default-auto interoperability
probe now also completes on this cohort.

## Adapter smoke outcomes

Each complete platform SLO report retains **146 observations**: 42 warm values
over 21 routes and 13 harnesses, eight values at each of 250 KiB, 1 MiB and
5 MiB, and c16/c64 waves. Cold-native, readiness and recovery each have two
separate observations. The registered Claude PostToolUse launcher also has two
timed invocations, after benign/redacted validation with stdout and exit checks.
All reports are labeled `smoke` and retain `qualification_complete=false`.

| Metric, ms | Linux x64 | macOS ARM | macOS Intel | Windows x64 | Emitted smoke gate |
| --- | ---: | ---: | ---: | ---: | --- |
| Warm all-harness p95, n=42 | 37.169 | 58.543 | 152.570 | 207.684 | ≤1,000 |
| c16 p99, n=16 | 499.538 | 265.225 | 896.869 | 921.216 | ≤1,000, zero errors and route conservation |
| Resident recovery p95, n=2 | 152.705 | 219.562 | 1,152.981 | 296.736 | ≤1,000 |
| Cold native one-shot p95, n=2 | 5.881 | 7.507 | 28.727 | 18.872 | ≤150 |
| Readiness p95, n=2 | 0.044 | 0.042 | 0.090 | 0.040 | ≤400 |
| Registered Claude PostToolUse p95, n=2 | 272.821 | 273.585 | 803.415 | 581.744 | Reported separately; no emitted gate |

Intel fails exactly `recovery_latency`; its other 13 emitted gates pass.
Linux, ARM and Windows pass all 14 emitted gates. No signing, hashing, scheduler, disk or network cause follows
from the aggregate timings. The unchanged 1,000 ms smoke adapter/recovery gates
do not replace ordinary-priority 50 ms c1 / 200 ms c16 release targets or their
independent-run and tail-sample requirements. The separately reported launcher
series has no emitted pass/fail latency gate in this probe.

All four c16 waves retain 16 resident responses with zero errors. At c64,
Linux retains 64 resident responses and no overloads; ARM retains 58 resident
responses plus six explicit overloads; Intel retains 35 plus 29; Windows
retains 38 plus 26. Each accounts for all 64 responses with zero errors or fail-safe
results. The attribution is isolated whole-wave counter conservation;
per-request native-route proof remains false. The c64 boundedness gate has no
latency ceiling. Empty original-`None` witness records supply no additional
bridge or per-request routing proof.

## Linux soak

The [Linux soak JSON](evidence/native-wheel-ci-d33/linux-x64-soak.json) retains
**100,000 requested and 100,000 completed logical stress calls**, zero request
errors, 19,126 health checks and zero health/transient-health failures. Its
p95 is **617.21 ms** and maximum **1,698.46 ms**, below the unchanged
4,500 ms maximum-hook limit. One daemon PID remains stable.

RSS rises from **614,260,736 to 810,242,048 bytes**, with reported
growth **31.9052%**, below the soak's 50% ceiling. Peak threads are
71/128 and descriptors 203/512. Both `passed` and `soak_passed` are true.
The actual lifecycle list contains only **`start_requested`, `ready`**; it
contains no `stopped` marker. The emitted passing gate is retained, but this
record does not prove an explicit stopped lifecycle event. The earlier eighth
record's stopped marker is not copied into this cohort.

The fixture preloads and verifies **250,000 receipt rows**. These are not newly
emitted hook receipts. Warmup precedes the measured batches; the workflow uses
`--settle-seconds 0`. The helper permits up to three transport attempts per
logical call and checks bounded JSON-object responses. Its logical-call count
does not establish exact wire attempts or validate every request's native
decision/receipt identity. The unchanged stress helper, receipt predicate and
smoke thresholds were source-compared with the eighth checkpoint; no gate was
relaxed for this report.

## Retention and limits

Seventeen complete JSON values are reconstructed by removing decoded-log
timestamp prefixes and normalizing line endings/trailing newlines. Parsed values
are checked against their exact retained log spans. The manifest binds these
records, public GitHub terminal metadata and extraction provenance. Full decoded
logs remain private; no raw hook payload, private path, key or binary is added
to this evidence.

Successful uploads do not repair failed gates. This checkpoint changes no
original task definition, dependency, status, source behavior, threshold,
selection decision or release gate. It does not establish full installed,
cross-platform tail, upgrade/rollback or signing qualification.
