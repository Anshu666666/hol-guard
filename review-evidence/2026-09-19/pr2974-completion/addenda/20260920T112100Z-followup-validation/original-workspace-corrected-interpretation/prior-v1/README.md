# Original 8f workspace lifecycle review

This packet reconciles the original 15-cell installed Linux workspace lifecycle report and ledger from run 35491537211. Twelve cells passed their implemented checks; the three failures at 100 workspaces remain failures under the original 400 ms deadline. No application, native control, or workload was executed during this readback.

The recovered JSON/JSONL are attached under `original-recovery/` with the complete original ZIP identity and bounded extraction receipt. `reconstructed/` preserves each exact original cell body. `timelines/` gives derived coordinates using only a shared original clock or an explicit conservative lower bound. `DATA-RESULT.json` verifies all 131 ledger records, 116 parts, 15 summary projections, and 15 original publisher event digests without reserializing floating-point lexemes.

Read `ANALYSIS.json` for the distinct failures: timely ACK and barrier but late constructor in first-admission fault; a real +419.290400 ms barrier miss in service restart; and current authority withdrawal after a timely key-recovery barrier. The source-supported candidate causes remain unassigned. The evidence does not justify weakening a resident or command-authority fence.

All 18 source images are exact public 8f Git objects. The seven synthetic reader controls validate corruption refusal and preservation of original number lexemes; they are not runtime tests. The initial reader-control preparation error caused by an unavailable `structuredClone` helper is retained separately. The corrected control helper uses JSON copies of already parsed JSON; source and original evidence were unchanged.

With Node 18 or later, `node reader/run.cjs` reproduces the data reconciliation and controls from this packet. It writes the result to standard output and performs no HOL Guard imports or external calls.

A separate fixture-only three-cell diagnostic has been authorized for preparation and independent review. It has not been implemented or run in this packet. The original full-matrix and qualification flags remain false; no original 600-hook receipt-gap or 88-launch priority result is transferred into these cells.
