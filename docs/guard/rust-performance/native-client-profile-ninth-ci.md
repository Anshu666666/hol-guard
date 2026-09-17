# Ninth CI: persistent helper to resident measurements

The first selected four-platform client diagnostic completed successfully in [run 35275926017, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35275926017). It measured the existing persistent helper opening one resident connection for each of 160 completed hook requests. Discovery, connection, authentication, request-write and response-read spans are available for every request on all four declared platforms. This completes the client-side transport measurement, but RSP-085 remains OPEN because the same requests lack an isolated resident evaluator span. It does not select a connection redesign or qualify release performance.

The measured source is `d33f64d5fb86a3f2baa6848382ce763e2ed9fc59`, tree `0a40e2ebd6515094b5ce6b92c21a5fde3d056f40`. PR merge `009c7253ce2e132bffaea837b23b0a36b9bc16c2` has that same tree. The explicitly labeled workflow checked out the source head, built a separate `diagnostic-native-client` wheel and measured its installed runtime. Its runtime/package/wheel/rule/lock/helper identities are preserved in the four original public summaries and the [custody manifest](evidence/ninth-client-profile-d33/manifest.json). These are diagnostic artifacts; the normal release runtime was not measured by this experiment.

## Outcomes and provenance

| Target | Job | Completed hook requests | Persistent helpers | Matched hook socket opens | Result |
| --- | --- | ---: | ---: | ---: | --- |
| Linux x86_64 musl | [105386424976](https://github.com/hashgraph-online/hol-guard/actions/runs/35275926017/job/105386424976) | 40/40 | 1 | 40 | Complete diagnostic |
| macOS ARM | [105386425093](https://github.com/hashgraph-online/hol-guard/actions/runs/35275926017/job/105386425093) | 40/40 | 1 | 40 | Complete diagnostic |
| macOS Intel | [105386424752](https://github.com/hashgraph-online/hol-guard/actions/runs/35275926017/job/105386424752) | 40/40 | 1 | 40 | Complete diagnostic |
| Windows x86_64 MSVC | [105386425020](https://github.com/hashgraph-online/hol-guard/actions/runs/35275926017/job/105386425020) | 40/40 | 1 | 40 | Complete diagnostic |

Each job passed 77 Python source-contract tests and five compiled Rust feature tests, built and installed its target wheel, completed collection, encrypted the private records, uploaded both artifacts and passed the retention gate. These are the same test cases repeated on four platforms, not 328 distinct tests. Each collection used 20 benign and 20 synthetic credential-fixture Claude PostToolUse requests through the installed hook edge. Every completed record reports the validated `native_resident` route. No offer failed or remained uncompleted. The worker exited zero without timeout, capture overflow or containment failure; cleanup reported `already-stopped`.

Each private journal retains 80 offered/terminal rows and 42 native frame records. Exactly 40 unique `(helper, sequence, request digest)` identities correspond to completed hook observations. The two other native frames are retained and excluded from hook statistics. All matched records have complete socket accounting, one successful connect/authentication/write/read call, a non-null total span and no counter overflow. Runtime-identity calls occur twice per hook. Peer-validation calls occur twice per hook on POSIX and three times on Windows; these include nested spans and must not be summed with connection time.

All eight downloaded ZIPs were checked against their GitHub artifact size and SHA-256. All four ciphertexts authenticated successfully, including the exact run, attempt, source and distribution target in the encrypted manifest. The five recovered files per platform matched every authenticated size/hash and had private directory/file modes. An independent pass matched every offered/completed pair to its native frame, recomputed the phase summaries, and checked the retained worker capture against the private and public summaries. The custody manifest records artifact IDs, ZIP/member hashes, authenticated manifest hashes, private-file commitments and these verification outcomes. Raw journals, captures and recovery keys are not committed.

The POSIX collector/helper/lock hashes equal their source Git blob bytes. The Windows hashes instead equal the exact LF-to-CRLF expansion of those blobs; its observed hashes are retained unchanged alongside the Git hashes and explicit byte correspondence. This is a source-provenance distinction, not an assertion of identical cross-platform checkout bytes. The archived source-head and installed runtime identities remain separately bound.

The coordinator also independently re-read all four recovered sets, checked their request correlations and recomputed every published phase aggregate. Its [review receipt](evidence/ninth-client-profile-d33/root-independent-review.json) preserves the input-file hashes and explicitly excludes a second decryption, redownload or semantic replay. The frame/request digest and validated edge-response digest remain distinct domains; matching one does not substitute for the other.

## Measured spans

The table gives per-request p50 / p95 elapsed milliseconds, rounded to three decimal places. Each cell uses 20 observations. The [Linux](evidence/ninth-client-profile-d33/linux.json), [macOS ARM](evidence/ninth-client-profile-d33/macos-arm.json), [macOS Intel](evidence/ninth-client-profile-d33/macos-intel.json) and [Windows](evidence/ninth-client-profile-d33/windows.json) summaries retain counts, p99, maxima and exact recorded identities. These small diagnostic distributions are not qualified production tails.

| Platform / case | Discovery | Connect | Authentication | Peer validation | Request write | Response read |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux / benign | 0.097 / 0.124 | 0.052 / 0.065 | 3.764 / 4.735 | 0.087 / 0.103 | 0.019 / 0.053 | 0.498 / 0.602 |
| Linux / credential fixture | 0.089 / 0.106 | 0.031 / 0.040 | 4.228 / 5.063 | 0.051 / 0.060 | 0.007 / 0.010 | 0.263 / 0.475 |
| macOS ARM / benign | 0.105 / 0.129 | 0.047 / 0.088 | 11.626 / 18.302 | 0.082 / 0.124 | 0.018 / 0.023 | 0.296 / 0.426 |
| macOS ARM / credential fixture | 0.111 / 0.136 | 0.049 / 0.058 | 12.342 / 19.739 | 0.085 / 0.094 | 0.018 / 0.026 | 0.304 / 0.444 |
| macOS Intel / benign | 0.416 / 0.586 | 0.168 / 0.287 | 18.687 / 34.045 | 0.301 / 0.472 | 0.051 / 0.055 | 0.965 / 4.364 |
| macOS Intel / credential fixture | 0.459 / 4.429 | 0.173 / 2.992 | 4.570 / 25.206 | 0.337 / 3.138 | 0.052 / 0.096 | 1.025 / 3.713 |
| Windows / benign | 1.290 / 1.449 | 3.452 / 3.708 | 1.832 / 3.607 | 5.495 / 5.900 | 0.027 / 0.038 | 1.518 / 3.818 |
| Windows / credential fixture | 1.308 / 1.701 | 3.451 / 3.584 | 2.518 / 3.824 | 5.447 / 5.783 | 0.026 / 0.039 | 1.456 / 1.761 |

The [diagnostic contract](native-client-profile-diagnostic.md) defines each span. Authentication includes the existing nonce and server-proof exchange; these observations do not distinguish cryptographic work from scheduling or transport waiting. Response-read includes resident queue, evaluation and transport waiting, so it is not isolated evaluation time. Runtime-identity spans retain the existing cache behavior. All spans are inclusive (`inclusive_do_not_sum`). Neither subtraction nor the relative size of these spans establishes the gain available from a persistent session.

The instrumented runtime adds clocks and record serialization; the scripts add a stderr reader, request correlation and durable journals. This collection measures direct installed hook-edge calls, not launcher startup or daemon HTTP ingress. It does not measure CPU/RSS, failed-connect socket allocation, a cold resident, ordinary release latency, a connection-reuse alternative or a native-server comparison. All four summaries retain `headline_timing_eligible=false`, `evaluation_isolated=false`, `resource_comparison_measured=false`, `normal_release_runtime_measured=false`, `production_selected=false` and `qualification_complete=false`.

## Literal task assessment

RSP-085 is titled “Profile discovery/connect/auth versus evaluation” and requires: “Measure platform-specific per-request work through the existing persistent helper and resident; count current socket opens.” The four installed target runs satisfy the client-side phase and socket-count portions. However, `response_read` combines queue, evaluation and transport, and `evaluation_isolated=false` is an actual missing measurement. The previously recorded native parse/evaluation component diagnostics are not correlated evaluator spans for these installed requests. They therefore cannot supply the missing evaluation share by combination or subtraction.

The recommendation is to retain **RSP-085 OPEN** for that specific same-request resident attribution gap. A bounded follow-up needs an independently emitted resident evaluator span, correlated to the same authenticated request bytes, while preserving semantic responses, authority and deadlines. These successful client observations remain valid evidence and do not become failures merely because the task has a residual requirement. No task title, acceptance text, dependency, threshold or registration is changed here.

RSP-086 still requires comparison of the supported alternatives with full process-tree cost before a measured decision. RSP-087 remains conditional on that selection and its protocol requirements. This evidence makes neither decision. There is no demonstrated collector failure requiring a runtime correction from this run, and no default production activation follows from it.
