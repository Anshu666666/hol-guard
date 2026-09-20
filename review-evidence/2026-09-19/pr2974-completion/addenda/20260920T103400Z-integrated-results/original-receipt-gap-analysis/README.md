# Original 8f receipt-join gap

The original installed Linux mixed workload completed 600 load hooks, but only 598 have a native receipt join. The missing attempts are **mixed-load-313** and **mixed-load-321**. All **603 observed native receipts**—598 load receipts and five control-probe receipts—were unique, writer-admitted and committed with valid bindings. The original receipt-integrity gates remain failed. These records show no SQLite persistence loss among the observed receipts.

| Attempt | Harness and event | Retained delivered result | Original ledger lines |
| --- | --- | --- | --- |
| mixed-load-313 | Claude PreToolUse, 1k | warn / allow; completed | offer 719, terminal 721 |
| mixed-load-321 | Claude PostToolUse, 1k | allow / allow; completed | offer 733, terminal 734 |

The generator and five actual control probes made 605 hook calls. The owned scheduler recorded 604 admissions and 604 completions, while the native witness observed 603 receipt-bearing normal returns and one normal return without a receipt. The exact provider returns either a validated receipt-bearing dictionary or None, so the latter supports one normal None return. This accounting supports one completed hook outside scheduler admission and one normal native None **in aggregate**. The retained data cannot assign either boundary to 313 versus 321. Scheduler completion is not native-success evidence.

The reason this cannot be resolved further is concrete in the source. MixedLoad._worker discards the original response reason code and native route. ReceiptWitness.observe increments an aggregate missing-receipt counter and drops the attempt; its wrapper records only normal raw-native returns, not earlier admission or exceptions. No actual native request identity, decision identity, policy binding or failure phase is retained for either missing attempt. Their delivered shapes do not distinguish policy readiness, client availability or another supported failure path.

Recovery is nearby in the recorded ledger: restart offer 718 precedes the 313 terminal 721; restart result 730 precedes the 321 offer 733 and terminal 734. This is serialized ledger-write order only. The witness and generator have different monotonic origins, and receipt rows are emitted later during reconciliation. The recovery's first matching decision, mixed-load-312, was offered at line 715 before the restart offer. Its recorded 22.36ms is therefore not proof of a request begun after containment or of evaluation by a replacement resident.

The next bounded diagnostic needs the existing owned handler context to retain policy-preparation, native-entry, normal-return/None/exception and receipt-submission outcomes for the same attempt. That work is coordinated with the separately accepted priority phase plan. No product cause, repair, timing replay or new native execution is claimed here; the existing missing-receipt gate is preserved.

This packet binds exact source 8f15b37b4a1bd054ef486148610e518b1be05cfc and original run 35491537211 / job 106027206739. The entire 22,575,317-byte ZIP was stream-hashed against its original artifact digest; only the 719,300-byte ledger and 52,261-byte summary were decompressed. Their exact bytes and retrieval/ownership receipts are in the attached original-recovery tree. The complete archive and binary bodies are excluded.

The data-only JavaScript reader rechecks original member hashes, all 1,981 row classifications, hook/receipt identities, delivered decisions, writer and scheduler populations, the 603-ID commitment digest, original failed gates and installed runtime identity. Eight synthetic reader-refusal controls passed; they execute no application or native code. See DATA-RESULT.json, ANALYSIS.json, SOURCE-BINDINGS.json and reader/ for reproducible checks. This is a new two-member recovery and analysis, not restoration of the unavailable historical observer packet.
