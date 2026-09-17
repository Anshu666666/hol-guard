# Tenth native-wheel checkpoint

[Run 35283194143, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194143)
is terminal **failure** and has workflow head `095074cda6a751ffaf12b070ecc46a3091f12471`. The installed
runtimes identify tested pull-request merge
`9e85de6f42910785e7ba4b53198ddcc05672607c`; both commits have tree
`04d79da9c1cf212cce263c202bfdd5b4350007e3`. Package and runtime versions remain
`3.0.1`. The distinct workflow, merge and version identities are preserved.

The [terminal metadata](evidence/native-wheel-ci-095074/terminal-metadata.json),
[decoded-log provenance](evidence/native-wheel-ci-095074/log-record-provenance.json)
and [manifest](evidence/native-wheel-ci-095074/manifest.json) bind the finite
public JSON values reconstructed from decoded GitHub job logs. Artifact API
sizes and hashes are metadata; no artifact ZIP, wheel, binary or ciphertext was
downloaded, and no artifact-member byte verification or private recovery is
claimed.

## Platform outcomes

| Job | Conclusion | Actual scope |
| --- | --- | --- |
| [Linux x64, 105409585685](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194143/job/105409585685) | Success | Installed identity/default-auto/generated OMP probes, all emitted adapter smoke gates and 100,000-call soak pass |
| [macOS Intel, 105409585595](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194143/job/105409585595) | Success | Installed identity/default-auto/generated OMP probes and all 14 emitted adapter smoke gates pass |
| [Windows x64, 105409585522](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194143/job/105409585522) | Failure | Installed identity, independent Win32 lock and default-auto corpus complete; only the c16 concurrency smoke gate fails |
| [macOS ARM, 105409585771](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194143/job/105409585771) | Failure | Pre-build resource test fails; native build, installation and adapter SLO steps are skipped |

The [ninth wheel checkpoint](NATIVE_WHEEL_NINTH_CI_EVIDENCE.md) retains its
original Intel recovery failure and Windows success. This cohort neither
replaces those results nor establishes a cause for their changes.

## ARM test failure

The [bounded failure record](evidence/native-wheel-ci-095074/macos-arm64-prebuild-failure.json)
retains **111 passed, one failed and one skipped** resource correctness tests.
The failing test is
`test_any_missing_or_invalid_sample_withholds_complete_darwin_cpu[regression]`.
Its assertion searched the entire rendered report for fixture PID digits
`321`; the legitimate elapsed value `338.413213` contains those digits. The
report still has `cpu_seconds=null`, `cpu_ms_per_attempt=null`, incomplete
descendant CPU and 33 unavailable CPU samples. This is an assertion collision,
not evidence of complete CPU accounting or a runtime identity disclosure.

The subsequent test-only corrections `df75cd1ac3` and `872635da7d` replace the
substring search with closed field/value-shape checks and exercise that exact
numeric collision across all five fault cases. All 60 module tests pass
locally. They change no collector, threshold or production behavior and do not
requalify this failed attempt. The ARM upload step reports no matching files;
there is no tenth ARM installed result or artifact to substitute.

## Delivery, receipts and smoke boundaries

Each completed installed identity report retains 17 entries: 16 passing
status/real-stdio-child checks and one successful replacement marker. These
are not evaluated-hook cold/warm measurements; cross-release upgrade/rollback
and signing remain `not_exercised`.

The completed default-auto reports each retain 21 resident decisions and no
Python semantic, one-shot or fail-safe decisions. They cover normalized daemon
ingress, not 21 installed registrations. The isolated generated-key command
authority is verified `protected`; user enrollment is not exercised.

The [Windows receipt report](evidence/native-wheel-ci-095074/windows-x64-default-auto.json)
retains 21 accepted and 21 processed receipts, zero drops and zero durable
pending receipts, **with three writer failures**. Intel records zero writer
failures. Linux also records zero writer failures. The unchanged
[completeness predicate](https://github.com/hashgraph-online/hol-guard/blob/095074cda6a751ffaf12b070ecc46a3091f12471/scripts/native_probe_receipts.py)
checks accepted/processed/dropped/pending counts; it does not require a zero
historical failure counter. No cause is inferred for those operations.
The failure-only delivery observer emits no record when route conservation
passes. Aggregate conservation does not become per-request native-route proof.

Each completed SLO report retains **146 observations**: 42 warm values over
21 daemon routes and 13 harnesses, eight values at each of 250 KiB, 1 MiB and
5 MiB, and c16/c64 waves. Cold-native, readiness and recovery each have two
separate values. A registered Claude PostToolUse launcher has two timed process
invocations after benign/redacted checks, with actual argv/stdout/exit
validation. These series are labeled `smoke`, with
`qualification_complete=false`.

| Metric, ms | Linux x64 | macOS Intel | Windows x64 | Emitted smoke gate |
| --- | ---: | ---: | ---: | --- |
| Warm all-harness p95, n=42 | 36.818 | 142.635 | 639.777 | ≤1,000 |
| c16 p99, n=16 | 601.399 | 698.637 | 1,282.125 | ≤1,000, zero errors and route conservation |
| Resident recovery p95, n=2 | 193.910 | 436.733 | 946.883 | ≤1,000 |
| Cold native one-shot p95, n=2 | 7.425 | 35.449 | 15.793 | ≤150 |
| Readiness p95, n=2 | 0.049 | 0.230 | 0.039 | ≤400 |
| Registered Claude PostToolUse p95, n=2 | 344.392 | 791.833 | 516.592 | Separate series; no emitted gate |

Windows fails exactly `concurrency`; its other 13 emitted gates pass. Its c16
wave accounts for all 16 resident responses with zero errors, but p99 exceeds
the unchanged 1,000 ms smoke threshold. Intel passes all 14 gates. Linux also passes all 14 gates.
No signing, hashing, scheduling, disk or network cause follows from these
timings. The smoke thresholds do not replace ordinary-priority release targets
of 50 ms c1 / 200 ms c16 or their independent-run and tail-sample requirements.

At c64, Intel retains 39 resident responses plus 25 explicit overloads; Windows
retains 42 plus 22. Linux retains 63 resident responses plus one explicit overload. Each completed wave accounts for all 64
responses with zero errors or fail-safe results. `native_overloads=0` remains
distinct from explicit overload responses. The c64 boundedness gate has no
latency ceiling; attribution is whole-wave counter conservation, not
per-request proof. Empty original-`None` witness records add no bridge proof.

The generated-extension probes on the completed POSIX platforms identify OMP,
despite their shared Pi/OMP filename: four real output cases and seven
malformed-result/observation vectors use the installed extension/daemon/resident
route. Windows' four lock cases use a Python lease and an independent Win32
child. Neither probe establishes every launcher surface.

## Linux soak

The [Linux soak report](evidence/native-wheel-ci-095074/linux-x64-soak.json)
retains **100,000 requested and 100,000 completed logical calls**, zero request
errors, **17,367 health checks** and zero health or transient-health failures.
Its p95 is **503.43 ms** and maximum **581.21 ms**, below the unchanged
4,500 ms maximum-hook limit. One daemon PID remains stable.

RSS rises from **615,759,872 to 638,566,400 bytes**, with reported growth
**3.7038%**, below the 50% soak ceiling. Peak threads are **71/128** and
file descriptors **199/512**. Both `passed` and `soak_passed` are true. This
cohort's lifecycle contains `start_requested`, `ready` and `stopped`; the
ninth cohort's missing stopped marker is not retroactively repaired.

The fixture preloads and verifies 250,000 receipt rows; these are not newly
emitted hook receipts. Warmup precedes measured batches and the workflow uses
`--settle-seconds 0`. The stress helper permits up to three transport attempts
per logical call and validates bounded JSON-object responses. Logical call
counts therefore do not establish exact wire attempts or authenticate each
request's native decision/receipt. The stress helpers, receipt predicate and
smoke thresholds are byte-identical to the ninth checkpoint.

## Retention and limits

Thirteen complete public JSON values are reconstructed by removing
timestamp prefixes and normalizing line endings/trailing newlines. Their parsed
values are checked against the retained log spans. The manifest also binds
public terminal metadata, extraction provenance and the finite ARM failure
record. Full decoded logs remain private; no hook payload, private path, key or
binary is included.

Successful uploads and test-only repairs do not repair failed gates. This
checkpoint changes no task status, dependency, original threshold or selection
decision. It does not establish full installed, cross-platform tail,
upgrade/rollback or signing qualification.
