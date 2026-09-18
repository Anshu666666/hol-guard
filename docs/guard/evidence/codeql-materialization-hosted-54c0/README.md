All six jobs in [repaired diagnostic run 35326220494, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35326220494) completed successfully on September 18, 2026, from 08:48:04 through 08:59:28 UTC. The dispatched workflow head was `54c0ce882f83edb341e148d5eae2817bdf0c6451`; the analyzed sources remained the immutable cdd and d8 snapshots. This completes the diagnostic reproduction and its source-materialization proof. It does not resolve GitHub security alerts or qualify the Rust migration.

Every artifact ZIP matches its GitHub API SHA-256 and byte count. Each original SARIF is preserved unchanged, matches its collector's hash and result count, parses as SARIF 2.1.0, has a successful invocation, has no external result-file references, and reports no warning/error notifications. The two zero-result JavaScript reports include hundreds of successfully extracted files. All provided witness paths and notifications are retained; their enumeration is not a claim to cover every possible runtime execution path.

| Source profile | Language | Job | Successfully extracted files | Raw findings |
| --- | --- | ---: | ---: | ---: |
| Foundation cdd | Actions | 105539777972 | 62 | 2 |
| Foundation cdd | JavaScript/TypeScript | 105539777900 | 657 | 0 |
| Foundation cdd | Python | 105539778047 | 2,605 | 23 |
| Implementation d8 | Actions | 105539778018 | 64 | 2 |
| Implementation d8 | JavaScript/TypeScript | 105539777894 | 681 | 0 |
| Implementation d8 | Python | 105539778053 | 2,876 | 27 |

The foundation source is commit `cdd14176ef0e0a258d4655c64210524d7047a257`, tree `efb4e859e19b5456f2bdfbac17b2de784adf36a7`, with all 3,902 tracked paths present. The implementation source is commit `d8bde000de992009be3b2ed009347d2b3707ef0d`, tree `1967a2127a325ae340d313bf73e80c60abb4d1f6`, with all 4,793 tracked paths present. Every job reports zero skip-worktree, assume-unchanged, and missing-path entries, disabled sparse checkout, clean pinned source, and the expected collector/workflow hashes. The collector remains outside the analyzed source directory.

All six logs report CodeQL 2.27.0, CLI build `b47b3e59262c95aff4eeb84ac72d09e25a9c37e9`, and the intended bundled query packs: Actions 0.6.35, JavaScript 2.4.5, and Python 1.8.10. Query selection, the existing `stable_digest.py` path exclusion, three-language matrix, disabled diff filtering, `upload: never`, and disabled database upload are unchanged. Rust paths were materialized, but Rust is not a language analyzed by this diagnostic matrix.

The 25 cdd and 29 d8 findings are raw full-source diagnostic results. They are not equivalent to the PR checks' counts of newly introduced alerts. No alert ID mapping or GitHub disposition was inferred from matching totals. The raw Python reports still include imported `stable_digest.py` paths despite the unchanged exclusion configuration. They also retain existing source-commented findings; this review neither adds suppressions nor filters them away.

All 54 findings were reviewed against their retained SARIF source/sink witnesses and 84 exact immutable source blobs. `source-review.json.gz` contains an assessment for each profile, language, result index, rule, and sink. `finding-summary.json.gz` supplies the source line and function chain for every provided witness. These assessments describe the actual control flow and data purpose; they do not modify security gate status.

| Finding group | cdd | d8 | Source-based assessment |
| --- | ---: | ---: | --- |
| `publish.yml` cache-poisoning sinks at 683 and 725 | 2 | 2 | Both paths claim `workflow_dispatch`, but the enclosing job requires `github.event_name == 'pull_request'`. The modeled dispatch path cannot enter the job. |
| Approval-gate state storage | 1 | 1 | Stored values are TOTP secret-store lookup identifiers. The generated TOTP secret is separately passed to `TotpSecretStore`. |
| Benchmark credential storage | 1 | 1 | The complete source is a literal synthetic benchmark fixture. |
| MDM JSON logging | 1 | 1 | The retained source is verified public installed-version metadata. |
| Approval workspace normalization | 1 | 1 | The sink canonicalizes a scope identity and does not read file contents. |
| Bounded config capture | 8 | 8 | Hook admission, captured canonical scope, fixed config names, expected-parent checks, held-parent authorization, and bounded regular-file reads constrain the retained paths. |
| Temporary-root canonicalization | 1 | 1 | Metadata resolution occurs inside lexical and canonical temporary-root validation; it is not a file-content read. |
| Owned temporary workspace stat | 1 | 1 | The stat result is used to verify directory type and ownership after trusted temporary-root checks. |
| Generic publisher reader | 0 | 3 | Config callers append only fixed Guard config basenames. Those basenames return through `capture_guard_config` before the flagged generic `lstat`, `stat`, or `open` branch. |
| Launch-context digest | 1 | 1 | The retained SHA-256 value identifies exact launch/approval context; it is not a password authentication verifier. |
| Authority record digest and HMAC | 2 | 2 | The sinks verify canonical record identity and a purpose-separated authentication MAC. |
| Authority key identifier | 0 | 1 | The input is a validated 32-byte random authority key; the digest identifies its generation. |
| Review-event payload binding | 1 | 1 | The retained source is OAuth-source metadata used in an event/installation binding. |
| Rollout bucket | 1 | 1 | The input is workspace/device identity reduced into a percentage cohort. |
| DPoP access-token binding | 1 | 1 | SHA-256 is required for the token's `ath` claim. |
| Stable content/metadata identity | 2 | 2 | The retained paths bind signed content or workspace metadata to stable digests. |
| Legacy secret fingerprint comparison | 1 | 1 | The SHA-256 compatibility branch remains. Current fingerprints use scrypt, and the preceding legacy format uses PBKDF2; no migration removal is claimed. |

For the eight config findings in each snapshot, the actual fail-safe caller passes `HookConfigReadScope.read_toml`. Its captured scope retains the admitted canonical workspace and authorizes the held directory before leaf access. Several SARIF witnesses also traverse the default `_read_toml` branch even though that caller passes an explicit reader. The alternative witnesses through the real scope reader retain its confinement checks. The config source limits filenames to `config.toml`, `.ai-plugin-scanner-guard.toml`, and `.hol-guard.toml`; verifies the expected canonical parent; holds the directory chain; rejects symlink/reparse and non-regular leaves; and checks identity around one bounded descriptor read. The retained witnesses do not establish an arbitrary config content read outside the admitted policy.

For the three d8 publisher findings, two independent source branches constrain the reported path. `_capture_config_policy_input` first uses the supplied scoped capture callback. If no callback is supplied, `_capture_policy_input` still returns through the bounded config reader for every fixed Guard config basename before reaching its generic reader. The retained tainted config path cannot select the flagged generic branch. This does not exempt the generic reader's other uses.

The DPoP assessment is supported by [RFC 9449, section 4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2), which requires `ath` to encode the SHA-256 digest of the access token's ASCII representation. A password KDF would change that protocol representation. Other identity-digest assessments are limited to their retained uses and do not claim that hashing arbitrary low-entropy content guarantees confidentiality.

`hosted-summary.json` records each exact job, source tree, materialization count, tool build, query pack, extraction count, ZIP digest, SARIF hash, and finding count. `raw/` preserves the six full decoded logs, terminal and earlier inventories, and all six original ZIPs. `members/` preserves all six original collector manifests and SARIF files with lossless compression. `source-blobs/` preserves the reviewed source bytes. `manifest.json` binds every file by SHA-256 and also binds decoded bytes for compressed records.

The failed earlier six-job run `35276260889` remains preserved in the separate `codeql-source-materialization/original-35276260889` evidence package, including its two misleading zero-result completion claims. The repaired run supersedes its source-materialization evidence without rewriting that history. No production code, query, threshold, security alert, approval, release target, or requirement status was changed during this collection and review.
