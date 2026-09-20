# Workspace freshness diagnostics — final qualification pending

Published candidate [`ed7313dff240292a482c53410a2492f80ba8a220`](https://github.com/hashgraph-online/hol-guard/commit/ed7313dff240292a482c53410a2492f80ba8a220) has tree `cfb0c3707db387518e4051ba1b0efa236515f2ef`: 59 changed files, 647,531 content bytes relative to its parent. Publication and local file identities were verified. Prior 3780 failures require successor validation; this is not an accepted final candidate. A further proven correction may supersede this immutable source. [successor-publication.json](successor-publication.json) distinguishes the current readback from the preserved preparations; [source-publication.json](source-publication.json) retains the earlier 3780 publication.

The original lost-metadata regression missed the unchanged 400 ms deadline. Its failed result is retained by the implementation owner; the final addendum still needs its exact artifact/source pin. No deadline is increased and no original task is promoted by this diagnostic.

Running full reconciliation four times per second was rejected because its measured CPU cost grows with 1/10/100 registered workspaces. The published candidate uses a minimal content-only check in the other existing 250 ms publisher cycles, while complete control reconciliation remains at 1 s. Scoped source review and local controls are complete; hosted and original performance qualification remain pending.

Each file below contains 30 instrumented source-fixture samples at each workspace count and explicitly sets `native_or_platform_qualification=false`. They do not measure native decisions, installed end-to-end latency, mixed offered-load process-tree CPU or the original full platform/sample requirements. Before/after CPU figures below describe different operation scopes; their ratio is not an overall product speedup.

The measured fixtures use a 728-byte home configuration and 28-byte overlays. They do not establish cost for large allowed configurations. The lost-metadata regression is a deterministic scheduling control, not an installed-latency qualification.

| Workspaces | Earlier full reconciliation CPU median / p95 (ms per pass) | Candidate content-only CPU median / p95 (ms per pass) |
| --- | --- | --- |
| 1 | 29.686 / 33.530 | 0.328 / 0.426 |
| 10 | 33.446 / 43.799 | 2.437 / 9.654 |
| 100 | 73.168 / 94.952 | 22.343 / 47.551 |

At 100 workspaces, three additional content checks per second imply **6.7029% of one core** using the observed per-pass median, or **14.2653%** using the observed per-pass p95. These arithmetic duty-cycle estimates are not observed process-tree steady-state CPU percentiles. This material cost remains an unresolved performance tradeoff and does not satisfy the original benefit/nonregression acceptance. Retain the 100-workspace and adverse samples when evaluating the final selected behavior.

| Preserved report | Scope |
| --- | --- |
| [workspace-capture-cost-before.json](workspace-freshness/workspace-capture-cost-before.json) | Earlier full cached reconciliation baseline; source instrumentation only. |
| [workspace-capture-cost.json](workspace-freshness/workspace-capture-cost.json) | Separate later full cached reconciliation observation; retain its distinct population. |
| [workspace-capture-components-policy.json](workspace-freshness/workspace-capture-components-policy.json) | Policy-component diagnostic. |
| [workspace-capture-components-bytes.json](workspace-freshness/workspace-capture-components-bytes.json) | Byte-capture component diagnostic. |
| [workspace-capture-freshness-after.json](workspace-freshness/workspace-capture-freshness-after.json) | Candidate content-only freshness-check cost; this filename does not imply installed enforcement qualification. |

The files were copied byte-for-byte from the local retained measurements. Their identities and original metadata are recorded in `checkpoint.json` and the publication manifest. The candidate is now published, but these earlier instrumented measurement files retain their original source limitations; they are not retroactively relabeled as final installed observations. Preserve the original regression and all five populations when adding validation; do not replace unfavorable measurements or pool these diagnostics with prior workload qualification.
