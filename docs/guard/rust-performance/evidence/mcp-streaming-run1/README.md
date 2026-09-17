# Retained F run1 evidence

This is the first, incomplete attempt under the fixed B/F plan: 19 completed
cells, one failed baseline cell and 44 never attempted. The
[report](../../../rust-performance-mcp-streaming-preparation.md) and
[manifest](manifest.json) explain the provenance and accounting. Raw collector
output is retained separately in release metadata; no completed F campaign,
profile, activation or partial-cohort gate is claimed.

The files retain the original complete export manifests before and after,
Python dependency identities, launch/end records, collector stderr,
post-failure diagnostics and the exact owner verification/analysis scripts.
Historical Python scripts use a `.py.txt` suffix here so they remain evidence,
not newly installed executables. Their bytes are unchanged from the attempt.
Their absolute paths describe the original workspace; they are not an
instruction to relaunch or overwrite that workspace. The reconstruction utility
and patches are in the [separate supplement](../../reproducibility-streaming-preparation/README.md).

The raw receipt verifies 400 completed-cell forwards and responses, including
the four successful calls in an unpaired F cell. It records zero child forwards
observed by the collector in the failed cell; absence of actual forwarding is
unproved because missing/unreadable/malformed ledgers also produce zero. The
worker-failure null similarly lacks a file-availability distinction. Worker
stderr was discarded under the frozen policy, and temporary files were removed
after the selected failure fields were captured. No pre-run OOM event counters
exist for this attempt. The report preserves these diagnostic limits.

The before/after export checks physically read every tracked file, verify Git
blob bytes, SHA-256 and executable mode, and separately inventory generated
caches. Before/after dependency checks verify every hashed installed RECORD
entry and compare the exact package/interpreter identity manifests. These checks
ran under the shared lock and passed after the failed campaign. They are
integrity verification, not additional benchmark cells or functional test counts.

An independent reviewer recomputed the exact schedule partition and nine paired
correctness records, checked before/after manifest consistency, all artifact
digests and frozen harness hashes, and preserved the orphan F cell and failed
ledger gap. That review did not duplicate the entire physical export/dependency
reread, execute workers or supply GitHub CODEOWNER approval. Initial reconstruction
lint findings and the earlier verifier/proof are also retained; the final
reconstruction source and static checks are separate and successful.
