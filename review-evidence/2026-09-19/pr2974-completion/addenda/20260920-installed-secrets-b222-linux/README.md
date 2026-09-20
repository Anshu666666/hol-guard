# Installed Secrets CLI: current-source Linux results

Source: `b222318cca2811ac7ae90c7364e2ec6d0a10651f`.
Tree: `ef0c0b8abb8144ed010b4c23c05a2dc70f20c354`.

## Completed

The unchanged installed Secrets probe passed **28 of 28 cases**, with no skips, from a new non-editable pure-wheel installation on Linux x86_64 / Python 3.12.14. The source/probe regression cohort separately passed **69 of 69 cases**, with no skips or failures. The product checkout remained clean.

The installed cases invoke the registered `hol-guard` and `hol-guard-secrets` launchers and check full public-result parity, rich synthetic credential detection and suppression, staged bytes versus unstaged changes, exits 0/2/3, default and explicit file/finding/byte/commit limits, history occurrence handling, hardlinks and symlinks, invalid encodings, and incomplete scans. Three explicitly labeled mutation cases load the installed entrypoint under controlled filesystem changes; they are not ordinary launcher invocations.

The probe checks eight installed module bodies against the supplied wheel and validates both launchers' distribution RECORD, entrypoint wrapper and interpreter binding before and after the run. `source-bindings.json` separately joins those providers, all four probe partitions, both source test files, the package manifest and frozen runtime lock to the exact clean Git source. No production or probe source was edited.

## Files and reproduction

`installed-secrets.json` and the stdout/stderr logs retain the original successful probe result. `source-controls.json` projects all 69 original JUnit cases and records the original XML digest; the hostname is omitted and parameterized test IDs are replaced by hashes so synthetic input values cannot appear in the public record. `build-and-run.json` records the exact artifact identity, environment, actual commands with local paths replaced by placeholders, and limitations. `build-requirements.txt` preserves the hash-locked build requirements while removing only local-path-bearing comments and blank lines. `MANIFEST.json` binds every included file.

The build used uv 0.12.17 and hatchling 1.30.1, within the repository's `hatchling<1.31` requirement, with a separate hash-locked build environment. Runtime dependencies were installed from the unchanged frozen project lock. This is a fresh local pure wheel, not a normal-CI native artifact or a signed release.

## Acceptance boundary

This adds current-source own-clause support for the retained-Python portions of RSP-069 and RSP-071. It does **not** close RSP-069's deferred RSP-068 dependency, the separate hostile-archive requirements, the other operating-system matrix, or native performance/release qualification. Original task objects and counts are unchanged: **80 DONE / 25 OPEN / 29 BLOCKED / 10 DEFERRED**.

A separate additional live pre-commit experiment was blocked before execution. It contributes zero cases and its unexecuted draft is excluded. Native Actions artifact downloads also remain unverified by this session. No privileged setup, alternate retrieval workaround, merge, formal approval, signing or release publishing was performed.

Public receipts contain fixed case labels, counts, identities and digests, not input credential values, raw CLI payloads or private fixture paths. The probe's two-MiB output check occurs after command completion; it is not an active child-output disk quota. The 0.99-second regression-test duration is not a product latency benchmark.
