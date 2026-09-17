# Persisted configuration-reader validation

These receipts retain the original main-checkout validation of explicit configuration-reader propagation. The final owned source is commit `12b647b674d8975036ccb71fd963bbfbd534862b`; the earlier worker/posture/attention transport is `891d91b06c43e6bc11d69faf7f382bd48fdda617`. Main and foundation have different native continuation architectures. These logs validate main only.

| Invocation | Retained result | Interpretation |
| --- | --- | --- |
| [Earlier worker propagation](worker-propagation.txt) | 105 passed, 76.68 s | Includes the ten earlier reader cases and adjacent worker/attention tests. |
| [Persisted test development](persisted-development.txt.gz) | 10 passed, 2 failed, 6.56 s | Two new assertions incorrectly expected an expired deadline to remain in an offer and omitted a retained final liveness check. Assertions were corrected. |
| [Adjacent persisted suite](persisted-adjacent.txt.gz) | 215 passed, 1 failed, 1 skipped, 553.62 s | All twelve new cases passed. One existing isolated app-server helper failed under its original two-second budget. |
| [Isolated diagnostic](isolated-diagnostic.txt) | 1 passed, 2.69 s | The same failing case passed without any source or timeout change. |
| [Approval queue](approval-queue.txt.gz) | 17 passed, 3 failed, 77 deselected, 35.24 s | Three daemon startup fixtures did not yet accept the newly explicit reader keyword. |
| [Queue fixture regate](approval-queue-regate.txt) | 3 passed, 18.34 s | Only those three cases were rerun after the shared fixture accepted the optional keyword. |

These counts overlap and must not be summed into a disjoint gate. The original app-server assertion records `continuationStatus=failed` rather than `resumed`; it does not retain a precise internal cause. Its temporary database had already been removed by later pytest retention when inspected. The isolated pass neither erases that failure nor proves a particular failure mechanism.

The new persisted cases preserve rejected-reader notification and legacy-budget fallback behavior, configured legacy expiry through six public APIs, and the reader at each native completion checkpoint. Reader errors retain the existing fallback behavior; no deadline or policy rule was relaxed. Shared daemon startup fixtures were adapted to the new optional dependency. Ruff check, format check and diff check passed separately; no synthetic raw lint log is included.

The [manifest](manifest.json) records exact raw-log hashes, selections, results and final owned source-file hashes. Those file hashes do not claim to reconstruct the complete concurrently edited working tree, or the initial development test version. Each pytest command used the shared `flock --close -w 180` boundary with `PYTHONPATH=src` and the repository virtual environment. These are functional source-checkout receipts; they provide no performance, installed-platform, foundation or release qualification. A later combined-source gate must remain a separate receipt.

Three failure logs are stored as deterministic gzip because their original output contains trailing whitespace. The manifest records both compressed-file hashes and original-byte hashes. For example, `gzip -dc persisted-adjacent.txt.gz` restores the exact retained log; the failure text has not been trimmed or rewritten.
