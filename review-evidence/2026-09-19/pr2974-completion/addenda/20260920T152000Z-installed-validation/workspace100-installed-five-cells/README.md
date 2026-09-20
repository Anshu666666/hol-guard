# Original five-scenario workspace100 result

Run 35518521594 / job 106098451260 executed the original `--counts 100` lifecycle CLI exactly once. The separate strict five-cell admission failed. Thirty reader/archive controls, source checks and before/after installed identities passed. The original CLI returned 1, and its complete-fifteen-cell and implemented-checks flags remain false.

The source checkout was the tests-only successor `f8f190a286159b46bf14a624a62ba52b5d2371a3`, tree `341d2c02c79b0c510544df5297600d5a3a47f211`. The admitted default Linux wheel was built at `be612a3e562a2041b3732a33c158eeae4f1dad40`, tree `19977465d6e419f1276d75fb6bd1b3477f5c9720`, for product `ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d`. All packaged Python bytes matched the checkout with the sole explicit Hatch legacy exclusion. The original normal job was cancelled during its soak; that incomplete soak receives no success credit here.

| Scenario | Original outcome | Retained boundary |
| --- | --- | --- |
| lost_metadata_hint | Failed | Actual overlay mutation and dropped metadata hints occurred; authenticated/current `await_ack` deadline failed. Earlier validated transport ACK and ready-barrier observations were retained. |
| key_rotation | Failed | Actual key removal, fault-request continuation and supported recovery occurred; authenticated/current `await_ack` deadline failed. Earlier validated transport ACK and ready-barrier observations were retained. |
| first_admission_fault | Failed | Initial setup `await_ack` failed before replacement, fault injection or acceptance. No publication observer was installed yet. |
| expiry_fault | Passed | Original acceptance-to-ACK return 190.295685 ms; strict workspace99 request/receipt join, current authority, writer drain and publisher containment passed. |
| service_restart | Passed | Original acceptance-to-ACK return 367.173894 ms; real same-process service replacement, strict workspace99 request/receipt join, later full-startup authority fence, writer drain and publisher containment passed. |

The two passing cells do not establish causality or a performance improvement from a particular change. Both original clocks and the 400 ms threshold remain intact. Publication rows timestamp an observation after an original operation/state read, not an exact internal commit. Publication and lifecycle caller clocks have different origins and are not directly subtracted. Earlier ACK/ready observations do not prove that the later authenticated/current predicate passed; the failed individual predicate is not recorded. The final false barrier observation can also reflect original failure cleanup and cannot identify the earlier withdrawal instant by itself.

A failed cell's `installed_runtime_matches=false` is its default uncompleted comparison, not evidence of a different installed binary; the full actual before/after runtime and package checks match. No recovered request was offered in any failed cell. The absence of their recovered receipts is not SQLite loss. Full cross-platform, fifteen-cell and performance qualification remain incomplete.

The archive was independently rehashed against GitHub metadata before bounded safe extraction. All 38 original members are inventoried; the wheel is retained locally and referenced by digest in this small-file Git packet. All 53 original log frames reconstruct 31 exact framed files, including the projection index; every artifact-backed projection matches the original archive member. `verify_result.py` only reads retained bytes and reapplies the original lifecycle evidence serializer. It executes no workload or native runtime.
