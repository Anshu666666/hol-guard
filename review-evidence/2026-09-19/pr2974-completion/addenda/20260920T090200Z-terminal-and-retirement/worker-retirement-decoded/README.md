# Original worker-retirement validation: bounded independent readback

The original Linux job [35496733388 / 106040961917](https://github.com/hashgraph-online/hol-guard/actions/runs/35496733388/job/106040961917) completed the declared 1/10/100 poststart cells on source `2ac6b1bd84516c75fc169c7d1c849f9aad7b89bd`, tree `89c4343c8a528e2abdc0b755b3242f9ae52e6323`, through driver `869856a68204fe4662fbbc87414f492d8306ef7b`. This packet decodes and checks that original evidence. It runs no workload, compiler or original test again.

The exact published [original terminal log](https://raw.githubusercontent.com/hashgraph-online/hol-guard/e5dd87805911e0f95d25f1474398d62235eee2fb/review-evidence/2026-09-19/pr2974-completion/addenda/20260920T075800Z-worker-terminal/worker-terminal/original-terminal.log) supplies 2,130 gzip frames. Its log, compressed stream and 57,292,752-byte raw packet hashes match the frozen identities. The unchanged 95 MiB address-space bound and 8 MiB member/semantic bound admit 111 of 114 members. Three large installed inventory records remain unadmitted; [AUDIT.json](AUDIT.json) states that boundary explicitly.

The control reader matches 29 Python cases to 87 setup/call/teardown phases and 29 JUnit cases, then six producer-fixture cases to 18 phases and six JUnit cases. It verifies selector order, collection equality, ordered JUnit properties, complete function AST/provider identities, 296 source-input snapshots and the exact 4,751-entry Git source census. The four original Rust list/run populations contain 9 + 3 + 9 + 3 = 24 distinct tests. The separately invoked one-test producer emits six actual cases; it is not an additional unique Rust test. Three original WebFetch/Read/MCP consumers join the actual native output through their typed receipt, SQLite and approval results; they do not exercise the full HTTP worker.

All 707 retained ledger records reconstruct 93 packets with exact ordered parts, lengths and SHA-256 digests. Full terminal cell, service, phase and publisher-event objects match [the original diagnostic report](original/poststart-diagnostic.original.json). Each of the nine phases has one explicit request, matching complete native and SQL receipt objects, the actual published policy binding and the unchanged 400 ms acceptance-to-ACK check:

| Workspaces | Service instance | Phase | Accepted → ACK, ms | Delivered decision |
|---:|---:|---|---:|---|
| 1 | 0 | poststart_registration | 93.529 | allow |
| 1 | 0 | public_policy | 87.907 | deny |
| 1 | 1 | explicit_reregistration | 85.333 | deny |
| 10 | 0 | poststart_registration | 101.000 | allow |
| 10 | 0 | public_policy | 99.041 | deny |
| 10 | 1 | explicit_reregistration | 118.908 | deny |
| 100 | 0 | poststart_registration | 197.415 | allow |
| 100 | 0 | public_policy | 195.903 | deny |
| 100 | 1 | explicit_reregistration | 189.184 | deny |

These are individual instrumented observations. The receipt readback clock is not the transaction commit instant, and internal Rust decision time is unobserved. Initial startup compilation, Python-process restart, automatic workspace restoration, other fault lanes and full paired/platform sampling remain open.

All six service retirements preserve the two original native-stop observations, actual owned runner/thread state and two direct worker objects. All 12 retained direct worker processes were reaped with return code **-9**. This is evidence of observed reaping and owned-home containment; it is not graceful shutdown or a complete escaped-descendant census. Each of the three owned homes was removed after both service retirements.

The original hash-enforced wheel install remains bound to its recorded source/runtime/member identities and original 180-second installer budget. The binary archives and three oversized installed inventories are not independently admitted by this readback. Physical SQLite fsync/byte measurements remain unavailable. No task is promoted and `qualification_complete` remains false.

Reader-only failures are preserved in `semantic-installed-v1/result.json` and `semantic-installed-v2/result.json`: the first treated structured metadata as booleans; the second omitted the original producer line delimiter while comparing bytes. The final [v3 result](semantic-installed-v3/result.json) checks the actual structures and exact delimiter without changing any original input or limit. The prior failed 4d diagnostic and its `.poll()` fixture mismatch remain separate, with references in the audit.

The final reader source, projections, original report/ledger, native logs, installer references and byte manifest are retained here. Full inline collection/provider captures and the three oversized values remain preserved in the immutable original log, rather than silently claimed as fully selected data.
