# Hosted evidence secret-scan review

The completed local scan from `4b89e0d2d496a85f04922b2e019a4aea15326bb9` through `d4e13547f0e25f66f32db14012b14c0fad0abf4f` produced 108 redacted `generic-api-key` matches with 67 unique fingerprints. All matches have a source-bound classification in the [derived review](gitleaks-hosted-evidence-review.json). This records the existing review; it does not claim that a later prepared GitHub commit has passed a scan.

| Matches | Classification and evidence |
| --- | --- |
| 84 | The same 42 public Sonar issue identifiers appear in the retained raw API response and issue review. Every value matches the public response. |
| 20 | Installed module SHA256 values recompute from the pinned source, including the Windows CRLF encoding. |
| 3 | Unix launcher SHA256 values match the retained reconstruction of the exact interpreter shebang and wrapper body. |
| 1 | The Windows launcher value comes from the pinned SHA256 producer and an immutable hosted receipt that verifies the installed RECORD and PE entrypoint/interpreter binding. |

The Windows launcher binary was not retained. The review therefore does not claim to have recomputed that complete binary's digest. The JSON preserves this distinction and the exact probe, source commit, artifact, receipt and reconstructed-byte bindings. It references the existing public issue evidence without copying the identifiers or full source-line matches.

Gitleaks version `8.24.2` was used. The original redacted report is 83,747 bytes with SHA256 `adef33df15ff2a650a5151aca6f0cec87132a043ffaac71671e9ba4e13d18d52`. The original detailed classification is 134,378 bytes with SHA256 `e260a412629cd51ceb8c15fd211d47d3a200d20750658da6baefbc45fd2f30a6`. The JSON retains the scanner binary and official archive hashes, the source tree, all six scanned document hashes, and the match counts.

No new ignore entries, broad allowlist or scanner rule changes are included. The actual prepared GitHub commit still requires its own full-range scan before publication, with any excluded fingerprint justified against that exact commit.
