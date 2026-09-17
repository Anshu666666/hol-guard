# Mac source-review bridge diagnostics at d0e370

The native-wheel [run 35233473553](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473553)
tested PR head `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f` through merge
`c855bae3e83579587d229c83b597dc1cbc1d4bb6`, against release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9`. Both Mac jobs passed their
installed identity, default-auto and generated OMP output probes before
failing the full-source SLO witness. Neither artifact contains an installed
SLO report. [The finite evidence record](evidence/source-witness-d0e370.json)
retains the exact diagnostics, runtime and wheel hashes, archive identities,
decoded-log commitments and public checkpoint commitments.

| Runner / job | Failed source case | Original raw-edge call | Budget remaining at entry |
| --- | --- | --- | --- |
| Mac ARM / `105243298934` | OMP / 5,242,880 bytes | 30 ms, no admitted edge | 2,938 ms |
| Mac Intel / `105243299185` | Kimi / 256,000 bytes | 108 ms, no admitted edge | 2,927 ms |

Each witness saw exactly one raw-edge call. Both the before and after client
failure contexts were `not_recorded`; authority, decision, action and reason
were absent, and there was no reviewed-content digest. This evidence does not
establish deadline exhaustion, a 5 MB-specific defect, or a source-read policy
failure. Both artifacts independently retain a successful authenticated
resident-stop diagnostic after the failure, including verified owner/marker
locks, generation, endpoint and serving shutdown. Successful cleanup does not
explain or qualify the preceding request.

The same merge's [daemon-edge run 35233473122](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473122)
completed successfully for contracts, low-descriptor and all three platform
jobs; its optional soak was skipped. The Mac job's actual workspace/native
checks and both Python edge/lifecycle suites passed. These are different
workloads from the installed source matrix. Qualification run `35233473603`
attempt 1 was cancelled during build; that attempt supplies no measurement evidence.

Source tracing narrows the missing observation. Every `None` exit in the
actual native client and its stream sets a finite client failure code. The
raw bridge can also refuse a runtime/capability, missing or invalid-generation
snapshot, or unencodable envelope before entering that client. After the
client returns bytes, malformed JSON, a typed Rust error object, an invalid
edge shape or a receipt mismatch all produce a refused edge. Those bridge
paths do not themselves set the client failure context. No one of these
causes is established by the retained Mac diagnostics.

`scripts/native_slo_bridge_witness.py` closes that observation gap inside the
existing source fixture. It wraps the bridge's actual imported status,
encoding, client, decoder, receipt and failure-recorder call boundaries. Each
wrapper invokes its original exactly once, with the same arguments, return
value and exception. Only calls on the actual captured HTTP handler thread
contribute. Wrappers are restored on normal and exceptional exit. Counts are
capped at two; status and error labels are finite; receipt/decoder results are
booleans. Unknown reasons become `other`. Paths, request/response bytes,
arbitrary error text, source digests and policy material are not copied into
these diagnostics. Snapshot metadata describes presence and a positive
integer generation only; it is not an authentication assertion.

Diagnostic projection failures are contained separately from the original
call. They set a finite `observer_error` flag, a count capped at two, and
`observer_state=partial`; they cannot replace a returned result. Original
exceptions still propagate unchanged. A nonblocking fixture-only ownership
guard prevents concurrent contexts from installing or restoring overlapping
module wrappers. An overlapping context reports `overlap_unavailable` and
runs its request immediately. Thread and context identities exclude both
other-thread calls and same-thread nested calls from the active observer.
The ownership guard does not wait, serialize requests or acquire a production
lock. Its wrappers and ownership are released on exceptional exits as well.

The observer does not perform another runtime check, serialize or parse a
second request/response, validate a second receipt, retry, reset client state,
or change deadlines and admission decisions. It reports `not_observed` when a
stage did not return an observed value, rather than inferring success. The
raw-call elapsed timer excludes wrapper installation/restoration but includes
its callbacks; these diagnostics do not isolate inner phase performance. The
existing request timer also includes the fixture callbacks. No performance
threshold, native-route requirement or exact source-digest assertion changes.

Focused source validation passes 54 tests, including the real production
bridge decoder and receipt checks, pre-client refusal, malformed JSON, typed
Rust errors, edge-shape/receipt mismatch, other-thread exclusion, bounded
privacy projection, malformed diagnostic status projection, nested/concurrent
observer exclusion, and exact restoration after exceptions. This establishes
the diagnostic contract only. A new installed Mac run must supply the missing
stage evidence before selecting a production correction or claiming success.
