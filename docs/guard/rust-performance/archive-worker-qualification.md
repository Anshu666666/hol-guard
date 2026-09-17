# RSP-070: isolated archive worker qualification

Date: 2026-09-17. Decision: **retain the isolated Python archive worker; do not select an archive parser port or qualify a native worker for rollout from these results.** Interpreter/bootstrap cost dominates the small archives, and repeated integrity reads account for much of the large-archive inspection. A parser-only migration does not have an evidenced 30% end-to-end improvement. The 500-member case merits continued profiling, but its median member-processing share is still below 30% even before native boundary costs.

The functional containment and binding witnesses pass. **The recorded performance run did not pass its exact-result gate:** two of 510 measured inspections timed out instead of returning the expected fixture result. Both failed closed. The harness exits 1 and retains these samples. This is a completed profiling decision, not a claim of successful native parity, a release performance gate, or a production native archive implementation.

## Source and measurement boundary

The real caller is `supply_chain_package_eval._scan_external_tarball`, which downloads an authorized external source through the restricted downloader and then calls `inspect_archive_offline`. A clean inspection still leads to the existing approval flow. Any blocked or incomplete inspection becomes a package block and the retained blob is cleaned up. Launch uses `_bound_external_archive_launch_command` / `_verified_external_archive_replacements` to recheck the local file and substitute its path for the remote source.

The timing boundary starts immediately before the unchanged `inspect_archive_offline` call and ends after its typed result returns. Every sample starts a fresh `-I -S -B` child with the production minimal environment, platform sandbox wrapper, capability guard and resource limits. Parent imports, download latency, network access, approval waiting and package-manager execution are outside this offline-worker measurement. Filesystem cache is warm. No archive is extracted or executed.

The raw evidence is [archive-worker-measurement.json](archive-worker-measurement.json). It records Linux x86_64, Python 3.12.14, nine reported CPUs, c1, 30 samples per fixture, nearest-rank p95 and ten separate diagnostic profiles per clean fixture. It pins the source at `f7bb7fd767842512b7df7c2d99bf24ceb0f5c836`, archive-source SHA-256 `38e540def8038dc689a5ec6dcc9f8984827f26754798db9eb4afccf9ceafd7d9`, and harness SHA-256 `3637fb521ead05b0db95ee99cd17efec85f3578c7773c258c4071d5bbc568b84`. Subsequent qualification commits add tests and this report without changing the measured archive or harness code.

The sweep held the shared performance lock. The host still exhibited substantial run-to-run wall and CPU variation. These data do not establish a dedicated-hardware SLO or identify the cause of that variation.

## Uninstrumented operation results

All values below include fresh child startup, bounded inspection, exit and parent result validation. Timed failures remain in the percentiles; they are not discarded as outliers.

| Clean fixture | Archive bytes | Wall median (ms) | Wall p95 (ms) | Process-tree CPU median (ms) | Expected result |
| --- | ---: | ---: | ---: | ---: | ---: |
| One package manifest | 151 | 108.28 | 854.49 | 92.75 | 30 / 30 |
| 100 members | 14,221 | 117.16 | 598.74 | 98.15 | 30 / 30 |
| 500 members | 70,831 | 179.39 | 513.74 | 147.89 | 30 / 30 |
| 1 MiB gzip payload | 1,049,205 | 137.42 | 383.34 | 100.56 | 30 / 30 |
| 5 MiB gzip payload | 5,244,816 | 167.76 | 1,010.07 | 140.99 | 29 / 30 |
| 5 MiB tar payload | 5,253,120 | 162.04 | 1,288.25 | 138.67 | 30 / 30 |

The full corpus has 17 fixtures and 510 measured calls. Of those calls, 508 returned the exact expected status and code. One 5 MiB gzip scan returned `incomplete / external_archive_inspection_timeout` at 2,665.56 ms, and one traversal fixture returned the same timeout result at 2,682.14 ms. The latter remained non-clean. A separate 5 MiB gzip warmup also timed out; warmups are recorded separately and excluded from percentiles.

All 330 hostile/bounded-failure fixture calls remained non-clean. These include traversal, install scripts, invalid UTF-8 manifests, 501 members, excessive path depth, member size, expanded stream size, compression ratio, nested archive count, an expired worker deadline and truncated gzip. No incomplete inspection counted as clean or as an expected successful fixture result. All 60 separately instrumented diagnostic children completed with the verified clean digest and exit 0.

## Phase attribution

`scripts/archive_worker_profile.py` wraps the actual child functions without replacing parsing, removing checks or changing deadlines. It reports child bootstrap/import time, path/descriptor digest reads, full expanded-stream preflight, tar member decoding and manifest policy. The remaining inspection time includes member policy, manifest reads, file opens and bookkeeping. Tar member decoding can include decompression and seeks, so it is not purely Python arithmetic.

Diagnostic instrumentation adds overhead. These medians explain cost ownership; they are not substituted for the uninstrumented latency samples. Independently computed medians need not sum exactly.

| Fixture | Child bootstrap/import (ms) | Full inspection (ms) | Digest reads (ms) | Expansion preflight (ms) | Tar member decode (ms) | Other inspection (ms) | Median member-work share of diagnostic wall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| One manifest | 66.12 | 0.95 | 0.10 | 0.25 | 0.19 | 0.37 | 0.53% |
| 100 members | 90.60 | 10.05 | 0.25 | 0.55 | 5.96 | 3.20 | 5.19% |
| 500 members | 182.57 | 79.33 | 0.83 | 3.09 | 33.57 | 42.20 | 24.85% |
| 1 MiB gzip | 88.81 | 8.65 | 5.34 | 1.52 | 1.33 | 0.39 | 1.14% |
| 5 MiB gzip | 67.56 | 36.29 | 23.07 | 5.24 | 5.75 | 0.46 | 4.25% |
| 5 MiB tar | 67.66 | 21.60 | 19.82 | 0.73 | 0.32 | 0.75 | 0.85% |

Member-work share includes tar member decoding, manifest policy and the residual inspection work, divided by that diagnostic sample's full wall time. It is deliberately a generous estimate of removable parser work. In the 500-member case it ranges up to 35.99% in individual profiles, so that upper-end workload cannot be dismissed. However, a parser-only port leaves the larger startup/import component in place and cannot remove the three digest passes or preflight without changing the security contract. SHA-256 and gzip already execute their core algorithms in native libraries.

A completely separate Rust executable could also reduce interpreter startup, but no such implementation or benefit is measured here. It would require a new containment, resource, decoder and typed-result qualification rather than moving hostile parsing into the resident hook. Under PRD §§6 and 10, the next acceptance gate remains at least 30% lower full-operation p95 or CPU against optimized Python, with no more than 5% regression in the other primary metric and identical completion/security behavior. No native adoption gate is waived by this report.

## Preserved boundaries and executable witnesses

| Boundary | Existing limit or behavior | Qualification evidence |
| --- | --- | --- |
| Isolation | Fresh isolated Python child; minimal environment | Real child tests ignore ambient `PYTHONPATH` and synthetic credential environment values |
| Capabilities | Audit guard denies socket/process creation and file opens for writing | Actual child probes exercise socket, subprocess, shell, high-level write and descriptor write denial |
| Resource limits | 2 s worker deadline; 0.5 s parent termination grace; 512 MiB address space; bounded CPU and file descriptors | Actual POSIX limit probe; expired worker deadline; parent timeout kills and reaps a deliberately stalled child |
| Immutable blob | Regular, single-link, non-writable file; descriptor device/inode match; expected digest | Real parent rejects writable/shared blobs; deterministic worker tests reject equal-byte inode replacement and same-inode content mutation |
| Read identity | Initial path hash, initial descriptor hash and final descriptor hash | Real diagnostic verifies three digest passes; launch rechecks digest/size and stat/descriptor identity |
| Expansion | 6 MiB compressed input, 32 MiB expanded stream, 8 MiB member, 200x ratio | Corpus exercises member, stream and ratio violations without extraction |
| Structural bounds | 500 members, eight nested-archive suffixes, 64 path components, 256 KiB manifest | Corpus exercises count/nesting/depth; existing manifest and malformed-input regressions remain covered |
| Result protocol | Child exit 0 can mean clean, blocked or incomplete; malformed invocation exits 2; crash/oversized/invalid output fails closed | Actual successful-block and invalid-argument child probes; malformed-output and expected-digest witnesses |
| Approval and launch | Clean inspection still requires approval; failed inspection never authorizes launch | Actual inspector-to-package evaluation fixtures preserve ask/block/cleanup; actual inspection-to-launch fixtures reject changed, linked or writable blobs |

The inode-race tests call the worker directly to synchronize mutations deterministically. Isolation/capability tests and normal/hostile timing fixtures use real separate children. The Linux audit-hook probes do not claim OS-level containment against a compromised interpreter. macOS and Windows execution were not measured in this environment.

## Validation and failure history

The focused command covers the new qualification file and six existing archive/download/approval/launch suites, 147 tests in the final collected source. All 32 new tests pass. In the latest full run, 146 passed and one existing restricted-download deadline assertion failed: it returned the correct `external_archive_download_timeout`, but elapsed wall time was 181 ms against a 150 ms assertion. The unchanged failing test then passed in a targeted retry (`1 passed in 0.66s`). An earlier run had 141 passes and one different existing lifecycle-script case that returned fail-closed incomplete instead of blocked; that case passed on the later run. Thus every final test case has a passing witness, while neither multi-file run is mislabeled as wholly green. No deadline or assertion was relaxed. Ruff and `git diff --check` pass.

An initial measurement attempt verified the ordinary corpus outcomes but stopped during a 5 MiB diagnostic child timeout before saving its timing data. Those unsaved timings are not used here. The harness now checkpoints completed baseline iterations before diagnostics, records diagnostic errors without omitting them, and exits nonzero on either an unexpected operation result or a diagnostic failure. Independent regression cases verify both failure paths.

Reproduce from the repository root, serializing against other timed work:

```sh
python scripts/bench_guard_archive_worker.py \
  --samples 30 --profile-samples 10 \
  --output docs/guard/rust-performance/archive-worker-measurement.json

python -m pytest \
  tests/test_guard_archive_worker_qualification.py \
  tests/test_guard_offline_archive_inspection.py \
  tests/test_guard_restricted_archive_download.py \
  tests/test_guard_external_archive_launch_binding.py \
  tests/test_guard_external_archive_approval_boundary.py \
  tests/test_guard_external_archive_approval_evidence.py \
  tests/test_guard_external_archive_private_binding.py -q

python -m ruff check scripts/archive_worker_profile.py \
  scripts/bench_guard_archive_worker.py \
  tests/test_guard_archive_worker_qualification.py
```

No production archive parser, isolation policy, resource limit, approval behavior or launch binding changed in this qualification tranche.
