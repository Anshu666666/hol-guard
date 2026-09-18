# Eleventh native-wheel checkpoint

[Run 35287995035, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995035)
is terminal **failure** and has workflow head `23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d`. The installed
runtimes identify tested pull-request merge
`fb6112dd964df5b88e90e43e04229a4d6914f7e6`; both commits have tree
`e3fa69336ff37d8e91add1ecd0a5a89b5cca35d9`. Package and runtime versions remain
`3.0.1`. These identities are distinct from the preceding implementation
checkpoint `224cca37a57ea4e068c0c586d2354c15abd887f0`, tree
`7c4322a4c243c900bedf1365aa2194d888023f7b`.

The [terminal metadata](evidence/native-wheel-ci-23bef0/terminal-metadata.json),
[decoded-log provenance](evidence/native-wheel-ci-23bef0/log-record-provenance.json)
and [manifest](evidence/native-wheel-ci-23bef0/manifest.json) bind finite public
JSON reconstructed from decoded GitHub logs. Artifact API sizes and digests
remain metadata: no ZIP, wheel, binary or ciphertext download, artifact-member
byte verification or private recovery is claimed.

## Platform outcomes

| Job | Conclusion | Actual scope |
| --- | --- | --- |
| [Linux x64, 105424488945](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995035/job/105424488945) | Success | Installed identity/default-auto/generated OMP probes, all 14 adapter smoke gates and 100,000-call soak pass |
| [macOS ARM, 105424488814](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995035/job/105424488814) | Success | Resource correctness, installed identity/default-auto/generated OMP probes and all 14 adapter smoke gates pass |
| [macOS Intel, 105424488917](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995035/job/105424488917) | Success | Resource correctness, installed identity/default-auto/generated OMP probes and all 14 adapter smoke gates pass |
| [Windows x64, 105424488685](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995035/job/105424488685) | Failure | Installed identity, independent Win32 lock and default-auto corpus complete; only c64 boundedness fails |

Both Mac resource correctness invocations pass **117 tests with one skip**.
This is new actual-platform evidence for the structured privacy assertion;
the [tenth ARM assertion collision](NATIVE_WHEEL_TENTH_CI_EVIDENCE.md#arm-test-failure)
remains a failed historical invocation. Windows resource correctness passes
47 tests with 25 skips. These test results do not waive any smoke gate.

## Delivery, receipts and smoke boundaries

Each installed identity report contains 17 entries: 16 passing status/real-child
checks and one successful replacement marker. Cross-release upgrade/rollback
and signing remain `not_exercised`; these are not evaluated-hook cold/warm
measurements.

Default-auto reports each retain 21 resident decisions with no Python-semantic,
one-shot or fail-safe decisions. This is normalized daemon ingress over 21
routes, not 21 installed registrations. The isolated generated-key command
authority is verified `protected`; user enrollment is not exercised.

Windows records **21 accepted and 21 processed receipts, no drops or pending
receipts, and one writer failure**. Both Macs record zero writer failures.
Linux also records zero writer failures. The unchanged completeness predicate checks
accepted/processed/dropped/pending counts; it does not require a zero historical
failure counter. No cause is inferred for that operation.

Each SLO report retains **146 observations**: 42 warm values over 21 daemon
routes and 13 harnesses, eight values at each of 250 KiB, 1 MiB and 5 MiB,
and c16/c64 waves. Cold-native, readiness and recovery each have two separate
values. The registered Claude PostToolUse launcher has two timed process
invocations after benign/redacted checks, with actual argv/stdout/exit
validation. All reports are `smoke`, with `qualification_complete=false`.

| Metric, ms | Linux x64 | macOS ARM | macOS Intel | Windows x64 | Emitted smoke gate |
| --- | ---: | ---: | ---: | ---: | --- |
| Warm all-harness p95, n=42 | 34.242 | 47.508 | 101.480 | 289.979 | ≤1,000 |
| c16 p99, n=16 | 461.598 | 335.298 | 615.965 | 665.333 | ≤1,000, zero errors and route conservation |
| Resident recovery p95, n=2 | 293.194 | 291.836 | 364.485 | 781.544 | ≤1,000 |
| Cold native one-shot p95, n=2 | 7.226 | 7.577 | 18.874 | 13.197 | ≤150 |
| Readiness p95, n=2 | 0.047 | 0.030 | 0.104 | 0.041 | ≤400 |
| Registered Claude PostToolUse p95, n=2 | 344.103 | 240.408 | 568.035 | 415.677 | Separate series; no emitted gate |

Linux and both Macs pass all 14 emitted gates. Windows passes c16, including all 16
resident replies and zero errors; **only `concurrency_64_bounded` fails**.
Its c64 wave receives all 64 replies with zero request errors, but classifies
only **37 resident + 23 explicit overload + four unclassified** responses.
The retained failures are `unclassified_delivered_response` and
`route_counter_conservation_failed`. The coarse `overloaded` count is 27;
it must not replace the stricter count of 23 explicit overloads. The overall
route counters total 142 against 146 observations, so the four replies cannot
be silently filled into a native or overload category.

ARM c64 retains 50 resident replies plus 14 explicit overloads; Intel retains
49 plus 15, with no unclassified replies or request errors. Linux retains all 64 replies as resident with no overloads, unclassified replies or errors.
The c64 boundedness gate has no latency ceiling. `native_overloads=0` is
separate from explicit overload responses. Whole-wave counter conservation
is not per-request route proof.

The Windows original-`None` witnesses contain zero records in both waves,
with no observer error or overflow. They do not identify the four unclassified
responses or prove a bridge stage. Timing values likewise do not establish a
signing, disk, scheduling or transport cause. The 1,000 ms warm/c16/recovery
smoke thresholds do not replace ordinary-priority release targets of 50 ms
c1 / 200 ms c16 or their independent-run and tail-sample requirements.

The generated extension probes on the completed POSIX platforms identify OMP,
despite their shared Pi/OMP filename: four real output cases and seven
malformed-result/observation vectors use the installed extension, daemon and
resident. Windows' four lock cases use a Python lease and an independent Win32
child. Neither probe establishes every launcher surface.

## Linux soak

The [Linux soak report](evidence/native-wheel-ci-23bef0/linux-x64-soak.json)
retains **100,000 requested and 100,000 completed logical calls**, zero request
errors, **17,706 health checks** and zero health or transient-health failures.
Its p95 is **518.09 ms** and maximum **585.38 ms**, below the unchanged
4,500 ms maximum-hook limit. One daemon PID remains stable.

RSS rises from **619,708,416 to 636,317,696 bytes**, with reported growth
**2.6802%**, below the 50% soak ceiling. Peak threads are **71/128** and
file descriptors **195/512**. Both `passed` and `soak_passed` are true.
The lifecycle contains `start_requested`, `ready` and `stopped`. The RSS
baseline is captured after warmup and worker-capacity stabilization, before
the measured batches; it is not a clean-process or pre-start baseline. The
50% growth ceiling is the soak predicate, not proof of the separate release
resource and tail criteria.

The fixture preloads and verifies 250,000 receipt rows; these are not newly
emitted hook receipts. Warmup precedes measured batches and the workflow uses
`--settle-seconds 0`. The stress helper permits up to three transport attempts
per logical call and validates bounded JSON-object responses. Logical call
counts therefore do not establish exact wire attempts or authenticate every
request's native decision/receipt.

## Retention and limits

Seventeen complete public JSON values are reconstructed by
removing timestamp prefixes and normalizing line endings/trailing newlines.
Their parsed values are checked against retained log spans. The manifest also
binds terminal metadata and extraction provenance. Full decoded logs remain
private; no hook payload, private path, key or binary is included.

This cohort preserves earlier failures rather than repairing or pooling them.
It changes no task status, dependency, threshold or native-selection decision,
and does not establish full installed, cross-platform tail, upgrade/rollback
or signing qualification.
