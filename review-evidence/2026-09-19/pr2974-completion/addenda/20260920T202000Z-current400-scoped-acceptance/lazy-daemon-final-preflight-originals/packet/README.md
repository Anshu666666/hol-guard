# Exact lazy-daemon preflight preservation

This packet preserves all 17 finalized files under root-checkpoint/daemon-lazy-preflight, the original preflight wrapper, the pure data reconciliation reader, staging record, two predecessor XML inputs, and three postcheckpoint publication records. Every original byte count, SHA-256 and Git blob identity is recorded. Three large originals use deterministic gzip plus ordered base64 chunks.

The original pytest process passed 393 cases with three existing Windows-only skips. The original outer wrapper exited 1 because it compared raw predecessor XML order with a different declared argv order. The unchanged original wrapper and failure description are retained. MATCHED-RESULT and FINAL-NODES are derived data-only reconciliation, not a rerun: all 396 ordered identities and outcomes match the actual declared pytest argv. Qualification independently reviewed that result.

The full type output retains zero errors and 30,183 warnings. Source before/after maps retain all 4,796 unchanged tracked files. No warning-clean, installed, latency benefit or whole resource qualification is inferred.

Run `python verify.py` for pure data verification or `python verify.py --reconstruct <new-directory>` for exact reconstruction. That copied verifier imports only the standard library and does not run any retained script or product code. Its legacy verification schema name remains unchanged because the reconstruction mechanics are identical. The original reconciliation reader is retained as data and was not executed for this preservation.

The three publication records describe the already completed a5fd evidence/PR-body checkpoint. They do not publish the lazy source candidate or the separately proposed encrypted Rust correction. No Git ref is changed by this packet.
