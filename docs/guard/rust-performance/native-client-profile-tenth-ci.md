# Tenth installed client and resident attribution

The four first-attempt jobs in [run 35283193998](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193998) complete the declared client/resident diagnostic on Linux, macOS ARM, macOS Intel and Windows. Each offers and completes 40 hooks, with zero failed or unoffered cases. Every completed hook has one unique client record and one independently emitted resident evaluator record for the same authenticated request digest. The eight artifact ZIPs are independently verified; all four encrypted five-file archives authenticate and recover; all request correlations, helper/relay EOF evidence and published span aggregates recompute from the recovered journals.

This supplies the same-request resident measurement missing from the [ninth client-only evidence](native-client-profile-ninth-ci.md). Independent review confirms completion of RSP-085 at its literal diagnostic measurement scope. It does not select a persistent connection, qualify release latency or resources, activate a production feature, or satisfy the separate RSP-086/087 decisions. Ninth observations and their original assessment remain unchanged.

## Exact source and execution

The selected source is `095074cda6a751ffaf12b070ecc46a3091f12471`, tree `04d79da9c1cf212cce263c202bfdd5b4350007e3`. The equal-tree PR merge is `9e85de6f42910785e7ba4b53198ddcc05672607c`; this workflow explicitly checks out the PR source head, and every collected runtime identity binds that source SHA. Run 35283193998, attempt 1, belongs to the original tenth 42-workflow cohort. The label was already selected; this is not a supplemental ninth-style label event.

The wheel is explicitly built with the default-off `diagnostic-native-client` feature and admits both diagnostic capabilities. Ordinary production artifact selection and registration are unchanged. Each platform runs the installed persistent helper and resident through the existing direct `review_raw_hook_native` path: 20 benign and 20 credential-fixture Claude PostToolUse requests. The existing 400 ms policy-readiness and five-second hook deadlines remain. This route measures neither registered launcher startup nor daemon HTTP ingress.

| Platform | Exact job | Python tests | Runtime profile tests | Windows companion tests | Offered / completed / failed |
| --- | --- | ---: | ---: | ---: | ---: |
| Linux x86_64 musl | [105409584601](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193998/job/105409584601) | 125 | 9 | Not selected | 40 / 40 / 0 |
| macOS ARM | [105409584349](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193998/job/105409584349) | 125 | 9 | Not selected | 40 / 40 / 0 |
| macOS Intel | [105409584573](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193998/job/105409584573) | 125 | 9 | Not selected | 40 / 40 / 0 |
| Windows x86_64 MSVC | [105409584484](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193998/job/105409584484) | 125 | 9 | 2 | 40 / 40 / 0 |

All four actual feature builds, collection, encryption, artifact uploads and final retention gates pass. The nine runtime tests are the selected client/resident/relay tests, not the full runtime suite. Windows additionally executes the real captured-pipe and explicit-handle-list tests. Its separate zero-test filtered doctest result is not counted as an additional test. No failed first attempt is replaced or omitted.

## Custody and complete correlation

The [manifest](evidence/tenth-client-profile-095/manifest.json) binds job IDs, artifact IDs, ZIP and member sizes/hashes, authenticated archive context, recovered private-file commitments and source-byte correspondence. All eight downloaded ZIP sizes and SHA256 values match GitHub metadata. The public recipient/size/hash receipts match the retained ciphertext. RSA-OAEP/AES-GCM authentication and the bounded recovery parser verify the exact source, target, run and attempt and every recovered file. Recovery verifies owner-private 0700 directories and 0600 files. Keys, raw journals and captures are not committed.

Each target has the same independently verified inventory:

| Evidence | Count / result |
| --- | --- |
| Planned, offered, completed hooks | 40 each; zero failed/unoffered |
| Unique selected authenticated request digests | 40 |
| Selected client frames / resident frames | 40 / 40; exactly one of each per hook |
| Successful matched hook socket opens | 40; one per hook |
| All observed client frames / resident frames | 42 / 43 |
| Helpers / helper reader starts / clean EOFs | 1 / 1 / 1 |
| Resident process/generation groups | 1 |
| Relay EOF terminals | 2; resident hop retains 43 records, supervisor hop 44 including its child's EOF terminal |
| Private native journal rows | 89: 42 client + 43 resident + two relay terminals + reader-start and reader-EOF records |
| Cleanup and outer containment | `already-stopped`; return code 0; no timeout, containment failure or capture overflow |

The final journals retain the originally selected helper/frame identities and resident PID/generation/sequence for every hook. The offline check rejects duplicate/reused selected digests, missing sequence entries, unmatched selected identities, missing helpers/readers/EOFs and incorrect relay chains or counts. It verifies the whole final inventory, rather than only the first successful live lookup. The two extra client frames and three extra resident frames are auxiliary activity, not additional hook successes. The installed collector validates native authority, route and the frozen semantic outcome; the custody review verifies the retained correlation and arithmetic and does not claim a new semantic execution or independent recovery of raw request/response bytes from their hashes.

The private worker capture matches the private and public summaries. Its scope remains decoded UTF-8 re-encoded capture, as declared by the collector. All six collector/helper/lock source bindings match exact Git blob bytes on POSIX. Windows bindings match the exact LF-to-CRLF expansion of those blobs; the observed and Git SHA256 values remain separate in the manifest. Wheel/runtime/package digests are retained as the identities checked by the installed collector; this review does not claim a separate wheel download or rebuilt executable.

The coordinator's separate standard-library [review receipt](evidence/tenth-client-profile-095/root-review.json) binds the exact manifest SHA256. It independently rehashes all 20 retained private files, verifies 0700/0600 modes, rechecks all 160 selected joins, four helper EOFs and eight relay terminals, and independently recomputes every phase/evaluator/dispatch aggregate. Its scope explicitly excludes a second download, decryption, semantic execution or performance qualification.

## Same-request spans

The [source contract](native-client-profile-diagnostic.md) defines all boundaries. Resident `edge_evaluation` times one original `evaluate_envelope_with_store_started` call, including envelope validation, snapshot acquisition, control fencing, evaluation and receipt/edge encoding. Resident `dispatch_encode` independently surrounds `evaluate_resident_bytes_started`; it excludes queueing, authentication, frame-digest verification, response transport writes and diagnostic serialization. Outer rejected/panic error-response mapping occurs after that span. These are monotonic elapsed spans, not pure matcher CPU or exclusive resource shares.

The table reports per-request p50 / p95 milliseconds, with 20 observations per cell. The [Linux](evidence/tenth-client-profile-095/linux.json), [ARM](evidence/tenth-client-profile-095/macos-arm.json), [Intel](evidence/tenth-client-profile-095/macos-intel.json) and [Windows](evidence/tenth-client-profile-095/windows.json) summaries retain all phases, p99, maxima and exact artifact identities. Every aggregate matches an independent standard-library recomputation from the authenticated journals.

| Platform / case | Discovery | Connect | Authentication | Response read | Resident edge evaluator | Resident dispatch/encode |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux / benign | 0.122 / 0.211 | 0.071 / 0.102 | 2.573 / 4.672 | 0.633 / 0.952 | 0.537 / 0.829 | 0.569 / 0.874 |
| Linux / credential fixture | 0.122 / 0.159 | 0.070 / 0.107 | 2.967 / 3.154 | 0.283 / 0.705 | 0.195 / 0.613 | 0.230 / 0.653 |
| macOS ARM / benign | 0.118 / 0.143 | 0.051 / 0.069 | 23.347 / 38.214 | 0.339 / 0.600 | 0.245 / 0.461 | 0.276 / 0.498 |
| macOS ARM / credential fixture | 0.108 / 0.113 | 0.047 / 0.053 | 12.327 / 30.175 | 0.302 / 0.440 | 0.214 / 0.350 | 0.242 / 0.379 |
| macOS Intel / benign | 0.234 / 0.395 | 0.087 / 0.109 | 9.671 / 33.951 | 0.603 / 1.758 | 0.395 / 1.044 | 0.454 / 1.103 |
| macOS Intel / credential fixture | 0.228 / 0.320 | 0.089 / 0.140 | 15.853 / 33.143 | 0.667 / 1.250 | 0.433 / 1.009 | 0.489 / 1.079 |
| Windows / benign | 1.674 / 2.654 | 4.595 / 4.831 | 0.583 / 2.556 | 1.871 / 2.174 | 1.739 / 2.068 | 1.793 / 2.122 |
| Windows / credential fixture | 1.712 / 2.458 | 4.583 / 5.981 | 0.329 / 2.782 | 1.939 / 2.991 | 1.821 / 2.759 | 1.874 / 2.823 |

Authentication includes nonce/proof exchange and scheduling/transport waiting. Its measured size does not isolate cryptographic cost or establish a connection-reuse benefit. `response_read` still includes queue/evaluation/transport; it is never relabeled as evaluator time. All spans remain `inclusive_do_not_sum`: no addition or subtraction is used to derive the independently measured resident duration or a proposed speedup. These small, instrumented distributions are not qualified production tails, and ninth/tenth timings are not a paired performance comparison.

All four reports set `evaluation_isolated=true` and `resident_capture_complete=true` at the exact edge-evaluator boundary above. They retain `headline_timing_eligible=false`, `resource_comparison_measured=false`, `normal_release_runtime_measured=false`, `production_selected=false` and `qualification_complete=false`. They do not measure CPU/RSS, full process-tree cost, failed-connect kernel socket allocation, cold-resident work, ordinary release latency or a connection-reuse alternative.

## Literal task assessment

RSP-085 is titled “Profile discovery/connect/auth versus evaluation” and requires: “Measure platform-specific per-request work through the existing persistent helper and resident; count current socket opens.” The four installed targets now supply the declared client phases, actual socket counts and separately emitted same-request resident evaluator spans with complete retained correlation. The specific gap preserved in ninth evidence is therefore measured, rather than inferred from response-read time or another component benchmark.

The independently reviewed recommendation is **RSP-085 DONE at its diagnostic measurement criterion**. Original dependencies RSP-035, RSP-048 and RSP-010 remain unchanged; this result does not complete any residual criterion of those tasks. RSP-086 still requires comparing alternatives with full process-tree cost. RSP-087 remains conditional on that selection and its protocol specification. No original acceptance text, dependency, threshold, release decision or registration is changed by this note.
