# Source69 archive publication receipts

These lossless copies preserve publication and validation of the earlier evidence
checkpoint `aeb04b6b06bd15ae2a2ecf00e8671c7501239278`, tree
`760c34da6cd3190ec66a6b54ae287a0e119a3aa0`, parent
`47b8af9b5e83d0404fedc1517032b9bcd107df35`. Its source and core records retain the
source69 archive context. This package adds receipts beside those records and
does not rewrite their fields or claim a newer implementation has qualified.

The exact prepared-commit Gitleaks 8.24.2 scan covered the complete range from
release base `4b89e0d2d496a85f04922b2e019a4aea15326bb9` through actual checkpoint
aeb04b6b. It found zero findings in 20.807 seconds including lock wait, using the
unchanged ignore file. The scan receipt, raw output, empty report, and exact ignore
bytes are retained. The branch publication response and readback are separate
from the prepublication scan, whose `branch_ref_moved` field correctly remains
false at its capture boundary.

The prepared publication receipt retains the initial oversized tree request
ReadTimeout, two subsequent 404 checks, and successful construction through
nineteen intermediate tree groups. The final tree exactly matched the local
prepared tree before publication. These are Git object publication outcomes;
they are not qualification executions or workflow reruns.

The original publication metadata and known-object provenance are preserved.
Large transport payload parts and binary upload bodies are omitted because they
are reproducible from the identified Git tree. Exact preparation and scan script
bytes are included for reproduction. No current PR status is inferred from this
historical archive receipt.

All manifest paths are relative to this directory. Gzip records preserve original
bytes without newline normalization; each row records both stored and decoded
lengths and SHA-256 digests. The core validation receipt remains a historical
validation of the source69 archive, separate from current implementation gates.
