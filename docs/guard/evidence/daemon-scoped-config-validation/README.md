# Daemon configuration scope integration

Source commit `591d5c81e6bb341c6c3271332f3a6615a01bc748` binds daemon configuration captures to the admitted canonical paths. The trusted configured home retains its construction-time canonical destination. Workspace configuration captures reject a different canonical parent before opening the leaf and apply the existing root policy to the held parent and its metadata. The capture still enforces the shared source size, regular-file, link, replacement and mutation checks. This is a canonical-path binding, not an inode identity carried across process launches.

The same capture dependency reaches publishers and native workers. Scoped readers reach posture and availability reads, package and CLI reloads, saved approval continuation, and remote approval callbacks. The daemon stores one bound reader object for command-worker reuse. An existing worker cannot silently accept a different reader. Rejected publisher captures withdraw the prior acknowledgement immediately. The original policy decisions, continuation deadlines and default standalone reader behavior are preserved.

The native I/O gate explicitly includes the injected capture and reader callbacks. Both ordinary and scoped readers use the existing byte-to-TOML parser through the new `_parse_toml` helper, allowing the conservative resolver to follow that call. No resolver exception was added.

## Retained checks

| Check | Recorded outcome |
| --- | --- |
| Integrated source capture, scope, publisher reconciliation, remote callback and command-queue cases | 137 passed, 1 platform-specific skip; pytest 12.69 s |
| Integrated server path cases | 12 passed, 1 platform-specific skip, 102 deselected; pytest 55.85 s |
| Ownership suites before parser extraction | 46 passed, 1 failed; pytest 65.36 s. The actual-source inventory could not resolve the re-exported `tomllib.loads` call. |
| That inventory after parser extraction | 1 passed; the other 46 cases were unchanged and were not repeated |
| Final configuration-path, capture, scope and reconciliation cases | 98 passed, 1 platform-specific skip; pytest 8.53 s |
| Native authority ownership and Python semantic call-graph gates | Both passed |
| Workflow token-permission cases | 82 passed; pytest 0.72 s |
| Full production typing before parser extraction | 1,255 files, 0 errors, 20,241 retained warnings; analyzer 147.878 s |
| Final two changed production files and two ownership-gate files | 4 files, 0 errors, 68 retained warnings; analyzer 1.905 s |
| Changed Python lint and formatting before the final parser extraction | 87 files passed; the four subsequently changed parser/gate files separately passed lint and formatting |

These counts overlap and must not be added into a distinct-test total. They do not represent installed-platform or performance qualification. The complete final-source production type check is not claimed: the full check preceded a two-file parser extraction, and the final changed files were then checked separately. `parser-extraction-proof.json` verifies the other 1,253 source files are unchanged and reverses the extraction to reproduce both original files exactly. Each integrated run also retains identical before/after inventories of all 1,255 production files.

Earlier attempts remain available. The first isolated scope suite passed 63 cases with one skip. An earlier server subset had 11 passes, one skip and one failure while the scoped CLI signatures were still being integrated; the integrated server result above is separate. A 180-second lock-wait timeout ran no ownership tests. One parser command named a nonexistent test file and collected no tests; the corrected command is retained separately. An initial lint invocation treated the archived Gitleaks verification program as a repository Python utility; its original bytes are now retained as `verify.py.txt`, and the subsequent 87-file check passes. None of these original outcomes was overwritten. The initial staged whitespace check is also retained: two original pytest failure logs were then compressed without changing their decoded bytes or the whitespace policy.

## Artifact integrity

`manifest.json` maps every original evidence filename to the retained file, its original length and SHA-256, and its stored length and SHA-256. Files larger than 128,000 bytes and the original failure logs containing trailing whitespace are deterministically gzip-compressed; decompression was checked against every original byte. Original manifests remain unchanged and continue to identify the uncompressed log names. The three driver programs are archival `.py.txt` sources containing their original temporary paths. `root-scope-commit-inputs.json` pins the twenty files committed in this integration.

The initial complete production type diagnostic retains nonfatal warnings without asserting equality to a prior baseline. The local source checks do not determine hosted CodeQL alert state, independent reviewer approval, required GitHub check status, or any of the original 144 acceptance statuses.
