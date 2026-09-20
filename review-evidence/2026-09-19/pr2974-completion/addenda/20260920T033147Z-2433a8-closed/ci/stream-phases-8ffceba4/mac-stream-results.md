The Intel diagnostic reproduced the capacity 16 failure and identified the failing operation: the actual `SO_SNDTIMEO` setter in `DeadlineStream::flush` returned `EINVAL` (22) after successful connection and authentication. The three failing requests preserved the leaf `native_client_frame_write_failed` before the existing public mapping to `native_resident_live_request_failed`. Each native frame joins uniquely to the actual Python call through its process index and exact payload and response SHA256 values.

This evidence comes from [run 35486381398](https://github.com/hashgraph-online/hol-guard/actions/runs/35486381398), driver `4341af38b1e1230424613ebc48e9c01bc4e82dae` / tree `34777b2efc6920b347f653c7bd966981ae69b098`. Its installed diagnostic wheels were built from source `8ffceba4f6440caf98fb86f29f7a27c1248502cd` / tree `054606497f49b0721aea9332ed4baad9713d441f`, with parent `2433a8ce570f34f5ad3dbf23f3d7367267aad461`. Both checkouts were clean and matched that source/tree before and after execution. The separate `diagnostic-phases` feature and explicit `resident-client-stream-diagnostic` command observed the original per-frame operation. The original SLO workload order, payloads, requests, retries, and deadlines were retained.

| Actual hosted result | ARM | Intel |
| --- | ---: | ---: |
| Job | 106013421031 | 106013421327 |
| Python driver controls passed | 28 | 28 |
| Native diagnostic controls passed | 8 | 8 |
| Native client controls passed | 22 | 22 |
| Python calls / joined native frames | 184 / 184 | 139 / 139 |
| Owned persistent clients | 18 | 10 |
| Native operation failures | 0 | 3 |
| Missing, extra, invalid, dropped, or recording failures | 0 | 0 |
| Diagnostic observation complete | true | true |
| Original SLO outcome | All 14 gates passed | Capacity16 conservation failed |

All observed persistent clients were reaped and their stderr readers reached EOF. This is the capture's owned-client cleanup boundary; it does not establish complete system-wide descendant or resident containment.

The Intel original workload again delivered 16 allowed responses and zero overload or outer transport errors. The isolated batch counters recorded 13 native resident routes and 3 native fail-safe routes, with 3 missing native edges/receipts. The unchanged conservation gate correctly failed. The capture does not join individual delivered hook semantics to each native frame, so a fail-safe route must not be relabeled as a delivered denial.

| Failed native frame | Payload bytes | Original native budget | Native operation elapsed | Failed operation |
| --- | ---: | ---: | ---: | --- |
| Process 6 / frame 0 | 806 | 2666ms | 20.629ms | Flush timeout configuration: EINVAL 22 |
| Process 6 / frame 1 | 805 | 2487ms | 38.709ms | Flush timeout configuration: EINVAL 22 |
| Process 7 / frame 0 | 811 | 2602ms | 17.143ms | Flush timeout configuration: EINVAL 22 |

These fixed diagnostic values show that the observed failures preceded expiry of their original budgets. They do not support the earlier authentication-queue hypothesis: all three authentication phases completed successfully. Diagnostic timings remain ineligible for headline performance qualification. The earlier uninstrumented capacity failure retains its original collapsed error and has no retrospectively proven leaf; this fresh reproduction supplies direct evidence for the flush setter mechanism.

The diagnostic does not directly record `POLLHUP` on the failed sockets. The separately published external commit `79c555fc2` contains a narrowly conditional repair: only macOS `UnixStream`, only an actual setter `EINVAL`, and only an independently observed zero-wait hangup on the same owned descriptor may proceed to the stream's actual no-op flush. Poll errors, invalid descriptors, other errors, and a live peer preserve the failure. The original absolute deadline is checked before and after; no request bytes are resent, no socket mode is changed, and framing, binding, authentication, and fatal-response rules remain intact.

The new real Mac regression in that external repair checks a fully written request followed by peer close with a buffered bound response, expired-deadline behavior, and unchanged blocking mode. Existing negative controls cover a live peer and the wrong errno. Independent source review found no blocking semantic defect. Those new repair controls are not part of this 8ff diagnostic source; separate exact 79c default-wheel CI evidence must establish their actual execution and the repaired installed behavior. The external repair review is retained at `external79c-native-review/review.json`, SHA256 `90b6af357b3ecdd4886981cd3dd31d3c3ee113512507bf3c239e5efc7171b0f0`.

The ARM run is a complete diagnostic non-reproduction. Its capacity 16 wave had 16 native resident routes and no errors; capacity 64 had 32 resident routes and 32 explicit overload bypasses. That pass does not clear the historical Intel failure, and neither platform supplies full qualification.

| Verified identity | ARM | Intel |
| --- | --- | --- |
| Artifact ID | 10597620629 | 10597691389 |
| ZIP SHA256 | `64e03b3e5a8b4d4763f62a6824162a5212978b939c174b600d907ca3af6f9982` | `c1d7dd176c68d4f16923918740206b7adb9e67667c1ab953467f5266d193c637` |
| Wheel SHA256 | `31ca22010a166bf9922f079be623778b3f45e9153e4d09b052bc50b1b6dc7425` | `ccdb867d80bc8a75681e39886595c57e289a95aa28b76a0a89c68c07287f712b` |
| Runtime SHA256 | `0071837aa6dabfccbfd792336c0e0036877931f7bca5daac40e265d1c0d31ddd` | `4ba3e398e9d655c529fbc266d7b841434238ce2fb4949cd5a44a020a582a3f7d` |
| Raw diagnostic SHA256 | `09de7ba1ae89d305083d3916081fd127251fc263cbed8ab4a55b32bbd18f8fda` | `17b3d44326c5f853a93e6c35184d77066cdc9d46310598dacb74489f8dcfb2ff` |

Both ZIP digests were verified against GitHub metadata before extraction. The wheel-contained runtime hashes and byte lengths match the respective installed runtime identities. The raw ZIPs, raw diagnostic JSON, exact source bindings, and complete job logs are retained. This packet is additive; all prior failed startup, capacity, paired-comparison, and containment records remain unchanged. Windows uses a separate original workload and is audited separately.
