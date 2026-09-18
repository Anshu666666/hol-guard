# Self-contained source capture

`manifest.json` is the original 13-record manifest, unchanged. Its paths are
relative to the repository root at diagnostic commit
`0372eafd4a95e1f415e4665c1f857773bcb3c332`. Six historical entries name source
or test files that may change in later commits.

`package-manifest.json` uses paths relative to this evidence directory and maps
every original record to retained bytes. The six source/test files are frozen
under `frozen-source/`; the seven original evidence files retain their original
paths and bytes within this package. The original manifest itself is also
indexed losslessly. No original digest or source record was rewritten.

Use the package manifest for durable verification. `verify_preservation.py`
reconstructs the original diagnostic comparison against a repository checkout
at that source capture; it is not an assertion that unrelated future changes
remain identical to the old source. This packaging adds no execution,
qualification credit, or change to the historical hosted outcomes.
