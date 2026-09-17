# Sixth indexed qualification: bounded follow-up

This supplement records additional inspection of retained evidence from
[qualification run 35257233257, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35257233257),
ARM indexed job `105327055316`. It does not rewrite the frozen
[sixth report](SIXTH_CI_EVIDENCE.md) or [manifest](evidence/ci-9d3907/manifest.json).
Measured source remains `9d3907a2e6ed1ec201281901cb878836a7dad32d`, tree
`833ea191211db2a0613db8520d072f5edf485380`; tested merge
`64164db9cd11e3d05182a99dba100daa6011c83d` has that same tree.
No new execution, performance measurement, qualification or task closure follows.

## Artifact and recovery commitments

ARM artifact `10513830208` was independently downloaded and checked: ZIP
1,852,248 bytes, SHA-256
`12e77e86efaea5fa3abba6154ab204c925153542d87f5af952d5f2e7c82f0920`.
Its encrypted archive is 1,833,621 bytes, SHA-256
`fc7288aafc87706cca3024b26dd0c556473ebc5622ee13bf4267f8c1333dc550`.
Authenticated recovery produced 26 files. The public pair-manifest commitment is
`8c27630e3449aeb7d6892144933d505bf1d9e265ffe55e18fc76e609dab6a0f3`.
The member hashes below were independently recomputed from recovered bytes;
raw payloads, identifiers and output remain private.

The candidate final numeric file has 38 series and 136 observations and matches
its public commitment. This is a completed numeric arm, not complete qualification:
the frozen baseline failed construction, and the candidate's additional acceptance
checks retain the failures below. The ordinary 386 daemon and 62 priority
registered preflight cases remain completed; the separate registered-surface
corpus below is a different scope.

## Ordinary acceptance failures

| Scope | Retained facts | Limit on interpretation |
| --- | --- | --- |
| Registered approval continuation | Three attempts offered: two validated, then Codex PreToolUse failed at `browser_wait_completion`. The process exited 0 after 1,030.173 ms without timeout, containment failure or stream-limit overflow. Two recorded native evaluations remained `review`; the resident-route counter increased by two. The matched approval was durably resolved to allow with a binding, but continuation status remained `pending` and the atomic completion observer was empty. | `qualification_Codex_browser_continuation_unproven` remains an acceptance failure. A resolved row and exit 0 do not prove authorized continuation. The retained facts do not establish a polling race: binding, request-digest or liveness checks may have rejected completion earlier. |
| Fixed malformed-input contract | Two attempts offered: one completed, then the fixed `[]` Claude PreToolUse case exited 0 with `engine_bypassed` at the witness stage. | `priority_launcher_input_route_mismatch` remains a failure. The expected route was not observed; the underlying cause is absent. |
| Additional registered surfaces | Twenty-six attempts offered: 25 completed, then global Cline PreToolUse benign/small exited 0 with `engine_bypassed` at the route check. | The assertion failed. This is separate from the completed 62-case priority preflight. No native allow or precise bypass cause is inferred. |
| Mixed load and controls | All 600 planned offers were admitted and completed; transport failures, completion timeouts and generator/capacity rejections were zero. The result retained 363 allows and 237 denies. | Completion and delivered outcomes do not prove native receipt coverage or complete resources. The receipt-commit, every-hook binding, no-evidence-drops and resource-coverage checks failed. |

The mixed summary retains 604 reconciliation rows, 599 delivered-binding matches,
zero delivered mismatches and no unexpected rows. These different counters are
not interchangeable. General CPU was unavailable, resource coverage failed,
and the original overall `passed=false` remains intact despite passing completion,
control-action, evidence-drain, latency and RSS-growth checks.

## Raw UTF-8 diagnostic is a separate scope

The [source at the measured checkpoint](https://github.com/hashgraph-online/hol-guard/blob/9d3907a2e6ed1ec201281901cb878836a7dad32d/scripts/native_slo_launcher_utf8.py)
intentionally returns `passed=false`, `qualification_complete=false` and
`expected_delivery_profile=not_qualified`, even after complete collection.
That design must not be counted as an ordinary semantic acceptance failure.
It preserves the original sixteen text-input cases as a separate contract.

This actual diagnostic also stopped early: three offers produced two completed
observations, then the Codex PreToolUse attempt failed at registration with no
attempted exit or observed route. The fixed source exception at line 100 is
`registered_utf8_registration_override`; its public failure projection records
`unclassified_failure`. This establishes an interrupted diagnostic, not a
malformed-input delivery verdict, native decision or underlying cause for the
registration-override rejection. The ordinary `[]` failure above remains independently
recorded by its own acceptance suite.

## Boundaries retained

The frozen sixth census remains 35 successful and six failed workflows.
Linux's indexed c16 Codex Post batch 36 was terminally validated; its later
load-profile route failure remains a distinct observation with unknown wave,
concurrency and counter deltas. Intel's explicit command-control mutation errors
retain the original substantial remaining deadlines; the historical lease holder
was not observed. Neither observation explains the ARM failures above.

ARM and Windows candidate-scenario jobs succeeded; Linux and Intel failed.
This supplement does not establish their finer readiness phase names or causes.
Later source corrections require fresh execution, and none of these results
establishes a complete paired comparison, full platform parity or release acceptance.

## Recovered member commitments

These are hashes and bounded counts of existing authenticated members, not new
public exports of their contents. The append-only numeric journal is distinct
from the final numeric file and is not substituted for its commitment.

| Member | Bytes | SHA-256 |
| --- | ---: | --- |
| `00-candidate.json` | 4,013 | `4c16471cdd0660e172f7683d07c516f65d1434dc549fb5d9c2cbd5566c20850c` |
| `00-candidate-approval-summary.json` | 353 | `969dd5a67743d9cc6f7d3168ab83800dc8d02173ad7c54ae56074a0cd10a83a0` |
| `00-candidate-approval-cases.jsonl` | 6,106 | `d6cde7ae6fc2ca205b3efe95075bf987727a7df095d3fc20825c6af053862e22` |
| `00-candidate-input-summary.json` | 336 | `843fc1c65f99f3fbd6f873c4a5087b40ec1789fe5ddf5fd1c81fd7bbb7c863d2` |
| `00-candidate-input-cases.jsonl` | 1,110 | `79e4c454a29cc28c48f1457600effddc8208749fea7d14f1521c15e2db2331d7` |
| `00-candidate-registered-summary.json` | 359 | `f29e4bdc7e131deb55f07a3e10393411a937364e94ee0c13f3e20b567c9d6a1b` |
| `00-candidate-registered-cases.jsonl` | 14,170 | `2eb0c161d6b08911f1fb055a443515296334c9741b55c51fac11956b507f35c1` |
| `00-candidate-mixed-summary.json` | 10,695 | `f7903aea3465d2dfbac604a6b48b14bfaacd56cac988d659770689dfd4a44320` |
| `00-candidate-utf8-summary.json` | 342 | `cee0edd627a3cded6e8ecd7ac78fee54aa01487dc5ed35f73b29be1470f0e54a` |
| `00-candidate-utf8-cases.jsonl` | 1,544 | `f781782175d5c8a3ad67025fe517e3594eaed1830829cee7dd2f6dfa29a23e29` |
