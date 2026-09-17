# Eighth native-wheel checkpoint

[Native-wheel run 35270079893, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079893)
is terminal **failure**: Linux and macOS ARM pass; Windows and macOS Intel fail
at different boundaries. The workflow head is
`a933921372ddb3772eff8a9d86771fe15da063b1`. The four built runtimes identify the
tested pull-request merge `e54cf7732f61a6a7e609250a4e17344b5e92039d`; both
commits have tree `3db430b618fe63cc1b85b8037e5de700cc3378c9`. Runtime and package
version fields are `3.0.1`. The merge identity is retained separately from the
head identity, not rewritten to it.

The [terminal metadata](evidence/native-wheel-ci-a933/terminal-metadata.json),
[record provenance](evidence/native-wheel-ci-a933/log-record-provenance.json)
and [manifest](evidence/native-wheel-ci-a933/manifest.json) retain the exact
bounded reports printed in decoded GitHub job logs. No wheel binaries or
artifact ZIPs were downloaded. Artifact metadata is retained as metadata;
artifact-member byte verification and signing qualification are not claimed.

## Platform outcomes

| Job | Conclusion | Last substantive outcome |
| --- | --- | --- |
| [Linux x64, 105366901084](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079893/job/105366901084) | Success | Installed identity/default-auto/generated OMP probes, adapter SLO smoke and 100,000-call daemon soak pass |
| [macOS ARM, 105366900945](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079893/job/105366900945) | Success | Installed identity/default-auto/generated OMP probes and adapter SLO smoke pass |
| [macOS Intel, 105366901065](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079893/job/105366901065) | Failure | Installed probes complete; c16 latency and resident-recovery gates fail |
| [Windows x64, 105366900977](https://github.com/hashgraph-online/hol-guard/actions/runs/35270079893/job/105366900977) | Failure | Identity and independent Win32 lock probe complete; default-auto aggregate route conservation fails before SLO invocation |

All four artifact upload steps succeed. Upload success does not supply a
missing probe result or change a failed platform conclusion.

## Installed identity and delivery scope

Each platform prints the full 17-entry
[installed status and real stdio-child identity sequence](evidence/native-wheel-ci-a933/linux-x64-identity.json):
16 `passed` results and one successful replacement marker. The corresponding
[ARM](evidence/native-wheel-ci-a933/macos-arm64-identity.json),
[Intel](evidence/native-wheel-ci-a933/macos-x64-identity.json) and
[Windows](evidence/native-wheel-ci-a933/windows-x64-identity.json) reports retain
their runtime, manifest and Python-module hashes. Cross-release upgrade/rollback
and signing are explicitly `not_exercised`.

Linux's three status calls with a live client hash zero executable bytes;
without a client they hash 36,726,432 bytes, and fresh/restarted child checks
hash 24,484,288 bytes. macOS and Windows retain full status hashing. These are
the identity probe's specific status/stdio-child observations, not counts from
an evaluated hook or a universal warm-path guarantee.

Linux and both Macs each retain a successful default-auto report with 21
normalized daemon-ingress routes, 21 resident decisions, zero Python semantic
decisions/fail-safe decisions and 21 accepted/processed receipts with zero
drops, failures or pending receipts. This uses an isolated generated-key
authority verified `protected`; user enrollment is not exercised. These 21
routes are not 21 installed launcher registrations.

The separate generated-extension reports on those three platforms name
**OMP**, despite the shared probe's Pi/OMP filename. Each verifies four real
output cases through the installed daemon/resident and seven malformed-result
or observation-mode vectors. This is that OMP extension scope, not a claim
that every Pi/OMP surface was activated. The Windows
[control-lock report](evidence/native-wheel-ci-a933/windows-x64-control-lock.json)
retains four Python-lease versus independent Win32-child cases; its declared
Rust-publisher interoperability check is the separate default-auto probe,
which fails in this run.

## Adapter SLO smoke

The exact [Linux](evidence/native-wheel-ci-a933/linux-x64-slo.json),
[ARM](evidence/native-wheel-ci-a933/macos-arm64-slo.json) and
[Intel](evidence/native-wheel-ci-a933/macos-x64-slo.json) reports each retain
146 observations: 42 warm observations over 21 routes/13 harnesses, eight
observations for each of 250 KiB, 1 MiB and 5 MiB, plus c16 and c64 waves.
Separate cold-native, readiness and recovery series have two observations each;
the registered Claude PostToolUse launcher series also has two timed invocations
with stdout and exit validation. All reports label this **smoke** and retain
`qualification_complete=false`.

| Metric, ms | Linux x64 | macOS ARM | macOS Intel | Emitted smoke gate |
| --- | ---: | ---: | ---: | --- |
| Warm all-harness p95, n=42 | 30.326 | 67.696 | 160.735 | ≤1,000 |
| c16 p99, n=16 | 420.323 | 335.187 | **1,430.876** | ≤1,000; zero errors and route conservation |
| Resident recovery p95, n=2 | 217.714 | 416.404 | **1,913.911** | ≤1,000 |
| Cold native one-shot p95, n=2 | 5.149 | 12.163 | 40.289 | ≤150 |
| Readiness p95, n=2 | 0.040 | 0.218 | 0.393 | ≤400 |
| Registered Claude PostToolUse p95, n=2 | 262.877 | 350.659 | 1,083.822 | Separately reported; not an emitted pass/fail gate |

Intel fails exactly `concurrency` and `recovery_latency`; its remaining emitted
gates pass. No cause such as signing, hashing, disk, scheduler contention or
network delay is established by these aggregate timings. This smoke's
1,000 ms adapter gates do not replace the release's adopted ordinary-priority
50 ms c1 / 200 ms c16 targets or its full independent-run/tail requirements.

All three c16 waves account for 16 resident responses and zero errors. At c64,
Linux retains 58 resident responses plus six explicit overloads; ARM retains
47 plus 17; Intel retains 36 plus 28. Each accounts for all 64 responses with
zero errors/fail-safe results. This is isolated whole-wave counter conservation;
per-request native attribution remains false. The c64 smoke gate has no latency
ceiling, so its passing boundedness result is not a c64 tail-latency pass.
The empty original-`None` observer records do not establish additional bridge
or per-request routing evidence.

## Windows failure boundary

The [bounded failure record](evidence/native-wheel-ci-a933/windows-default-auto-failure.json)
retains the actual assertion and aggregate counters: 19 `native_resident` plus
one `native_fail_safe` equals 20, where 21 were expected. The decoded traceback
reaches `_installed_hook_corpus` line 382, after delivery checks and the exact
21-route-count assertion, at `sum(observed_routes.values()) == expected`.
Thus completion of the 21 delivery checks is a source-control-flow inference,
not an independently retained per-request native-route trace. The missing
aggregate route and the specific fail-safe request cannot be identified from
this report.

The source writes `native-default-auto.json` only after this function succeeds.
The PowerShell step exits on its failure before invoking the SLO script. There
is no completed Windows default-auto receipt or Windows SLO report from this
invocation. Zero latency fields in the failure's generic metric snapshot are
not measurements and are not filled into a Windows latency table. No narrower
failure cause is inferred.

## Linux installed-daemon soak

The [soak record](evidence/native-wheel-ci-a933/linux-x64-soak.json) passes the
existing contract with **100,000 requested/completed logical stress calls**,
zero errors, 19,961 health checks, zero health or transient health failures,
one stable daemon PID and the expected start/ready/stopped lifecycle. It
reports p95 **472.61 ms** and maximum **556.14 ms**, below the unchanged
4,500 ms maximum-hook limit.

The fixture preloads and verifies **250,000 receipt rows**; this is not a claim
that these hooks emitted 250,000 new receipts. RSS baseline is 614,137,856 bytes,
peak 635,490,304 bytes and reported growth **3.4768%**, below the soak's 50%
ceiling. Peak threads are 71/128 allowed and file descriptors 198/512 allowed.
Warmup precedes these measured batches; the command uses `--settle-seconds 0`.
The stress helper permits up to three transport attempts per logical call, so
the report's 100,000 logical calls do not establish exactly 100,000 wire
attempts. It checks bounded JSON-object responses, not each request's native
decision/receipt identity. This successful Linux lifecycle/resource soak does
not repair Windows/Intel results or establish all-platform qualification.

## Provenance and limits

Fifteen complete JSON values are reconstructed from the retained job-log line
ranges by removing timestamp prefixes and normalizing trailing newlines.
Their parsed values are checked against those ranges. The manifest hashes
these records, the closed Windows failure projection, terminal metadata and
the source/log provenance. Full decoded logs remain private; no raw hook
payloads, private paths, credentials or binaries are added to this evidence.

The artifact API advertises four successful uploads with exact sizes and
digests, retained in terminal metadata. Those archives were not downloaded
or independently hashed here. This note claims decoded-log evidence rather
than artifact-member verification. It changes no source, benchmark threshold,
task status, native selection or release gate, and performs no new measurement.
