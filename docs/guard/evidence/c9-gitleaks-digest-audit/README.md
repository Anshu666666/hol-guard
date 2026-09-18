# Historical Gitleaks digest audit at c9ed06b

The exact c9ed06bbcb7cef2ecbb93955fdad34be71710aa7 reproduction reports 96 unique findings. Every fingerprint matches an exact fingerprint removed by that cleanup commit; none lies outside the removed set. The audit retrieves each original historical JSON locally and reconstructs the scanner's redacted match from its exact diff line and columns. Only digests and provenance are retained here.

| Evidence | Findings | Verification |
| --- | ---: | --- |
| Module source digests | 75 | SHA256 independently recomputed from historical Git source; five Windows values use the explicitly recorded LF-to-CRLF byte transformation |
| Exact source digests | 6 | SHA256 independently recomputed from the named historical source files |
| Archived source patch | 1 | Original base and patch hashes verified, patch applied in an isolated scratch directory, reconstructed bytes match recorded SHA256 |
| Installed launcher digest fields | 14 | Original verified report provenance, exact retained probe source, matching launcher and wheel digest observations; historical installed launcher bytes unavailable for a fresh independent rehash |

The 14 launcher findings are recorded artifact digests, not newly recomputed launcher binaries. Seven are hosted observations; seven are local observations. The local encoding-bound report pins available probe source that hashes bounded installed bytes after RECORD hash/size checks, wrapper/interpreter validation, and an unchanged-byte reread. All seven local observations have equal launcher maps and wheel digest. Two validation metadata records also hash-bind their exact underlying reports. Three early local reports lack original binding metadata, and two records pin an older fdd81 probe whose historical source commit is unavailable locally. Later matching digest observations do not establish earlier execution identity or timing. The original Windows failure remains failed. No report receives new runtime qualification credit.

The hosted Gitleaks job reports 1264 commits and 96 findings but uploads no per-finding artifact. The individual audit uses the separate local reproduction with scanner v8.24.2, the exact base-to-c9 range, and exact c9 ignore bytes. This is source-bound reproduction evidence, not a claim that hosted logs contain the individual records. The scanner binary, workflow source, reproduction input, report bytes, per-finding original blobs, and matched values are SHA256-bound in audit.json.

This package makes no ignore or alert changes. Recognition is limited to these 96 exact historical fingerprints. It does not justify new patterns, unrelated exemptions, restoration of deleted raw evidence, or alteration of CodeQL findings.
