# Original 634-control report reconciliation

The original terminal Linux [run 35494533524](https://github.com/hashgraph-online/hol-guard/actions/runs/35494533524), job 106035074778, now has an independent bounded reconciliation of **634 cases, 1,902 passed setup/call/teardown rows, and 634 matching JUnit cases**. Its 298 ordered selector entries are disjoint. The ten physical cohorts form eight logical groups; the original 593 cases and separately declared 41 additions remain distinct. There were no skipped or expected-failure outcomes.

The source is `4d10758e2cb44e5afa72a08aa631a02541dad534` / tree `fbc00caa3788eb422158a2263a578e83ac626183`. The separate driver is `b05127dd2cec4f02eb97d715138179c741e52ec0` / tree `d910c223f4628cef73694ca9a2d4dd70c6dc63b1`. The prior terminal log and reported aggregate are retained in commit `f1b033246d3d5fe623573e5bb3bafe588260fafd`; this packet adds data reconciliation, without rerunning those controls.

| Physical cohort | Cases | Phases | Selectors |
| --- | ---: | ---: | ---: |
| oauth_fingerprint_original | 13 | 39 | 6 |
| secret_promotion | 13 | 39 | 3 |
| incoming_python_additions | 112 | 336 | 69 |
| workspace-pure | 62 | 186 | 18 |
| workspace-forward | 16 | 48 | 10 |
| workspace-lifecycle | 10 | 30 | 10 |
| incoming_ed731_python | 253 | 759 | 102 |
| incoming_2433_python | 94 | 282 | 48 |
| incoming_017_python | 20 | 60 | 10 |
| incoming_8f15_python | 41 | 123 | 22 |

Read [AUDIT.json](AUDIT.json) and [reader-result-v2.json](reader-result-v2.json) for the boundaries. The [content index](content-extraction-v1.json) retains every original member name, size, encoding, and digest. All 216 names and 172 unique contents were verified from the original 1,797 log frames, exact gzip stream, and exact 80,685,332-byte raw packet. The original log remains the complete byte source for the full collection/run snapshots and contracts. This smaller selection includes the original phase JSONL and JUnit XML, aggregate and command records, and ten derived collection/provenance projections under `reconciliation/`. Embedded producer pathnames are retained unchanged; the selection manifest maps them to their published paths.

The reader checks each fresh collect/run contract for byte equality, each declared selector/count/order, every setup/call/teardown row, and each ordered JUnit identity/property list. Original property lists are empty; separate synthetic controls prove that the reader preserves duplicate properties and rejects changed order. It also matches all 4,751 recorded Git path/blob/mode rows against the independently fetched source tree and all 37 driver blob references. Inline provider bytes are rehashed, candidate provider Git blobs are recomputed, and referenced function definitions/signatures are reconstructed from those provider sources. Other source-file SHA-256 values are retained observations linked to the source census, not a claim that every repository file was downloaded independently.

[The first semantic attempt](reader-result-v1-failed.json) stopped on an AST serialization mismatch. Asnf runs Python 3.13.13; the original recorder was configured for Python 3.12.13. Python 3.13 added the `show_empty` option to [ast.dump](https://docs.python.org/3.13/library/ast.html#ast.dump). Explicit `show_empty=True` reproduces every recorded definition and signature exactly. The original failed reader, exact mismatch demonstration, corrected reader, and successful receipt are all retained. No original record was edited.

The 36 synthetic parser controls ran before extraction, including the old existing-directory receipt overwrite and corrected receipt preservation. The separate six semantic-reader controls checked duplicate/nonfinite JSON and phase/JUnit property ordering. These are parser controls, not additional product-test credit. All processing used a hard 95 MiB address-space cap, 64 KiB streaming chunks, an 8 MiB semantic-value limit, and a 32 MiB streamed-member limit. Peak RSS was 19.1 MB for parser controls, 25.4 MB for log extraction, 18.0 MB for member extraction, and 61.9 MB for successful semantic reconciliation.

The 25,193,469-byte formatter proposal member was byte-verified through streaming and remains semantically unparsed above the 8 MiB limit. No proposal was applied. These records substantiate the selected Linux Python control bodies, whose original fixture contracts include the Python rollback/differential providers. They do not establish installed native phase or performance qualification, complete descendant retirement, or task promotion. The later worker-retirement/poststart run is a separate population.
