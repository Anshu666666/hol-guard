# Config path CodeQL source audit at 9428

Reviewed on 2026-09-18. This is a disposition rationale for the eleven
`py/path-injection` alerts listed below. The recommended classification is
**false positive for these specific source flows**. This document does not
change alert state, queries, workflow configuration, or runtime code.

## Exact source and alert identity

The live repository alert listing for `refs/pull/2954/merge`, filtered to open
CodeQL alerts, returned thirteen entries. Eleven are the Python path findings
below. The other two, 288 and 289, are inherited
`actions/cache-poisoning/poisonable-step` findings in `publish.yml` and are
outside this review. The Python alerts identify CodeQL 2.27.0 and analyzed
merge commit `667e6f385341e4c8db903973e3eb0088104d886d`.

Each of the following files was fetched from that exact merge commit through
GitHub and compared with the local checkout of PR #2954 head
`9428b660fa6a261307627660ff7b258327ed9bd4`. All five Git blob identities match.
Paths in this document are relative to `src/codex_plugin_scanner/guard/`.

| Source | Git blob in both commits |
| --- | --- |
| `config_source_io.py` | `ad02d372c9a47791556e82ab2ac8fcad3eeb9a42` |
| `daemon/config_read_scope.py` | `365cc591acf630e15fadaec583b77a1c6394da1d` |
| `config.py` | `792be3d454f0b74a756c3770f503ada4cec34df4` |
| `native_policy_snapshot_publisher_inputs.py` | `c5a9047538403a7718c1fd306172380bf5b9bb88` |
| `daemon/server.py` | `77287aca876d7650dd29101b0cb72d067122318d` |

Live PR #2951 head `a001b2691f481b7b5a66dd14d68e48d61c44cb78` also has
the same `config_source_io.py` and `daemon/config_read_scope.py` blobs. That
establishes shared source identity; it does not assert that every caller or
every analysis result on the two branches is identical.

## Current uploaded flow evidence

The [analysis API](https://api.github.com/repos/hashgraph-online/hol-guard/code-scanning/analyses/1800335213)
was read at `2026-09-18T15:09:25.540139+00:00` using the documented
`Accept: application/sarif+json` representation. GitHub returns a subset of
the uploaded analysis; this was neither a new scan nor the original complete
upload. The returned SARIF itself identifies CodeQL 2.27.0, repository
`hashgraph-online/hol-guard`, revision
`667e6f385341e4c8db903973e3eb0088104d886d`, and branch
`refs/pull/2954/merge`.

The response contains 27 results. Each of the eleven target alerts has four
returned paths, giving 44 inspected paths. Each target's SARIF alert number,
sink location, and analyzed revision match the independently fetched live
alert API entry. The other sixteen results are outside this audit. All 44
paths pass the admitted workspace return at `daemon/server.py:7586`, the
workspace argument to the explicitly scoped load at `daemon/server.py:5893`,
and the fixed-basename config loader at `config.py:1405`.

The complete path inspection distinguishes actual scoped capture from
inconsistent callback alternatives:

| Alerts | Returned paths per alert | Basis for review |
| --- | --- | --- |
| 357, 358, 359, 361, 367 | Two through the scoped reader; two through the unscoped default | The ten scoped paths require the held-parent, scope, fixed-name, and identity invariants below. They are not callback-selection errors. The default alternative is inconsistent with the explicitly supplied scoped reader. |
| 362, 363, 364 | Four through the unscoped default | The selected reader is explicitly scoped. The metadata operations are also capture consistency checks with the limitations below. |
| 368, 369, 370 | Four through an unrelated publisher callback | The actual fail-safe load supplies its scoped reader. Independently, the three config basenames return before these generic publisher sinks. |

In total, ten paths traverse the actual scoped reader and thirty-four choose
inconsistent reader alternatives, including twelve publisher paths. No
blanket callback-selection rationale is applied to the ten scoped paths.

The saved API subset is 1,127,113 bytes with SHA-256
`413fe4d9fa9f3fd5c62fb86676dd1b7a6b1fa8f09c7316a0ed48a41218f692c0`.
This identifies the compact UTF-8 JSON serialization of the response, not
the original HTTP bytes. The 4,288-byte compact identity/path proof has
SHA-256 `136fa01d672d94762bd781a479a547bf245c5b1e1e7e579cdf011e8a217c9946`.
The raw returned SARIF and expanded paths remain outside the repository.

## Historical diagnostic context

The retained diagnostic SARIF has SHA-256
`dcc29cb6ab2d1305af493aef08d57685ccb390ab2739cdf1b1eb089f5976db9d`, size
3,695,072 bytes, artifact ID 10553265979, and workflow run 35357541894.
Its manifest pins **historical source
`d8bde000de992009be3b2ed009347d2b3707ef0d`**, profile `implementation-d8`.
It used CodeQL 2.27.0 and did not upload security results. The collection
directory's reference to 9428 is not its analyzed-source identity. This is
historical diagnostic evidence, not the current uploaded SARIF.

The first four source blobs above are identical at d8 and 9428. The seven
relevant server methods also have identical Python ASTs, ignoring locations:
`_runtime_hook_fail_safe_response`, `_validated_fail_safe_hook_paths`,
`_validated_fail_safe_directory`, `_validated_hook_directory_string`,
`_validate_hook_directory_path`, `_is_owned_temporary_hook_workspace`, and
`_hook_safe_roots`. This supports reviewing the historical flow shape against
current source. Current alert identities and all 44 returned paths were
verified from the live APIs, independently of this diagnostic artifact.

Historical examples exposed the hook HTTP request's `workspace` query
parameter flowing through admission and `load_guard_config` into default or
publisher callback alternatives. Those examples do not establish every
current flow. The complete current inspection above distinguishes these
alternatives from paths through the actual scoped reader.

## Actual authority and capture boundary

1. `daemon/server.py` lines 649-652 construct a `HookConfigReadScope` from the
   configured Guard home and bind its `read_toml` method as
   `hook_config_reader`. The fail-safe load at lines 5891-5895 explicitly
   supplies that reader. It does not select the unscoped default reader.
2. The fail-safe workspace is admitted using an absolute, canonical path.
   `_validate_hook_directory_path` requires containment in the configured
   roots or the existing owned-temporary-workspace exception. Invalid input
   becomes no workspace; it is not passed through as an unvalidated path.
3. `HookConfigReadScope` supplies both `expected_parent` and its held-parent
   validator to `capture_guard_config`. The configured home alias is pinned
   to its construction-time canonical home. Other parents must still equal
   their admitted canonical path. Root/owner authorization uses held-parent
   metadata and runs before opening a config leaf.
4. Capture only accepts `config.toml`, `.ai-plugin-scanner-guard.toml`, and
   `.hol-guard.toml`. On POSIX, each parent is held by a no-follow directory
   descriptor; the leaf opens relative to that descriptor with `O_NOFOLLOW`.
   The reader rejects nonregular files, reparse attributes, multiple hard
   links, oversized inputs, changed identity, short reads, and changed parent
   bindings. Windows uses retained no-reparse directory and regular-file
   handles. This audit includes no fresh Windows execution.
5. A rejected input raises `GuardConfigSourceError`. Fail-safe posture lookup
   catches it as `ValueError` and does not enter observe mode on that basis.
   Publisher capture rejection withdraws its ACK before rethrowing.

Parent `stat` and resolution operations occur before all capture checks are
complete. They are consistency/admission operations, not reads of config
contents. This review does not claim that those metadata operations can never
follow a concurrently replaced alias. Its verified acceptance property is
that outside config bytes do not become an accepted policy through these
flows. A previously admitted pathname is not a universally safe capability.

## Per-alert rationale

Column intervals below are the live GitHub API values. Every row refers to
merge commit 667e6f385341e4c8db903973e3eb0088104d886d and proposes only the
specified alert's false-positive disposition.

| Alert | File, line, columns | Rationale and failure guard |
| --- | --- | --- |
| [357](https://github.com/hashgraph-online/hol-guard/security/code-scanning/357) | `config_source_io.py:65`, 30-43 | This POSIX helper receives a resolved absolute parent; its anchor is `/`. Opening that root directory handle does not select attacker-named config content. Descendants and the leaf remain subject to held-chain, expected-parent, and scope checks. |
| [358](https://github.com/hashgraph-online/hol-guard/security/code-scanning/358) | `config_source_io.py:134`, 13-22 | The relative leaf name is one of three fixed config basenames, validated at capture entry. The admitted parent is held, scope authorization precedes the leaf open, and `O_NOFOLLOW` plus identity checks reject replacement. |
| [359](https://github.com/hashgraph-online/hol-guard/security/code-scanning/359) | `config_source_io.py:187`, 49-60 | Parent metadata is sampled after hook admission. No config bytes are read here. A retargeted canonical parent fails `expected_parent`; held-parent identity and scope are checked before any leaf read. A metadata error rejects capture. |
| [361](https://github.com/hashgraph-online/hol-guard/security/code-scanning/361) | `config_source_io.py:194`, 32-38 | This is a consistency comparison of the resolved parent's metadata with the initial parent identity, after the expected canonical-parent comparison. Mismatch rejects capture before content access. |
| [362](https://github.com/hashgraph-online/hol-guard/security/code-scanning/362) | `config_source_io.py:215`, 76-87 | This final resolution check verifies that the original path still identifies the held canonical parent. It does not reopen config content. A changed binding rejects the captured result. |
| [363](https://github.com/hashgraph-online/hol-guard/security/code-scanning/363) | `config_source_io.py:204`, 20-26 | The pathname metadata arm is Windows-only and runs while the complete no-reparse parent chain is retained. Its identity must equal the initial parent identity; caller scope validation precedes leaf capture. Linux uses `fstat` instead. Source review does not substitute for the skipped Windows test. |
| [364](https://github.com/hashgraph-online/hol-guard/security/code-scanning/364) | `config_source_io.py:215`, 36-47 | This final parent metadata check rejects a parent-binding change before a capture is returned. Bytes are read from the already-held leaf descriptor, not from this metadata pathname. |
| [367](https://github.com/hashgraph-online/hol-guard/security/code-scanning/367) | `config_source_io.py:191`, 18-29 | Resolution determines the actual parent for comparison with the admitted canonical parent. A replacement alias cannot change the accepted scope: mismatch rejects before the leaf is opened. |
| [368](https://github.com/hashgraph-online/hol-guard/security/code-scanning/368) | `native_policy_snapshot_publisher_inputs.py:332`, 21-25 | The generic non-config branch's `lstat` is unreachable for the three fixed config basenames: lines 326-330 return through bounded capture first. The real daemon also supplies its scoped capture dependency. |
| [369](https://github.com/hashgraph-online/hol-guard/security/code-scanning/369) | `native_policy_snapshot_publisher_inputs.py:333`, 22-26 | Same fixed-name branch exclusion as 368. Config reads return before this generic state-file `stat`; the fallback was exercised with each allowed basename and no generic sink was reached. |
| [370](https://github.com/hashgraph-online/hol-guard/security/code-scanning/370) | `native_policy_snapshot_publisher_inputs.py:336`, 34-38 | Same fixed-name branch exclusion as 368. Config reads cannot reach this generic state-file `os.open`. This rationale does not classify all possible non-config uses of that helper as safe. |

## Executed verification

On the unchanged 9428 checkout, Python 3.12.14 executed:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pytest \
  tests/test_guard_config_source_io.py tests/test_daemon_config_read_scope.py -q
```

Result: **42 passed, 1 skipped in 0.48 seconds**. The skip is
`test_windows_directory_and_file_cannot_be_replaced_while_reading`, which
requires actual Windows handle-sharing behavior. Tests cover intentional
aliases, fixed names, symlink/hard-link rejection, FIFO rejection, bounded
reads, parent/leaf replacement, in-place mutation, held ownership, descriptor
cleanup, configured-home alias pinning, and publisher ACK withdrawal.

A separate reviewer executed 30 finite Linux cases against the same source.
Its JSON witness has SHA-256
`fdf41eaa5a525fb0790cf7137a3401e29795053adb71379761697ed761fc4684`.
The actual fail-safe handler method, using minimal server dependencies and
the real scope, dispatched all three config basenames to the scoped callback
while the unscoped default reader was trapped. Twenty-one filesystem attack
cases rejected their inputs, returned no config result, and read no outside
bytes. Three forced publisher-fallback cases reached none of the generic
leaf `lstat`, `stat`, or `open` operations. The remaining cases cover a valid
intentional alias and four admission rejections. These 30 cases are separate
from the pytest count and are not a live network-server or Windows test.

## Disposition boundaries

No runtime rewrite is warranted solely to make these paths disappear from
the analyzer. No generic sanitizer should mark all outputs of directory
admission or all inputs of `capture_guard_config` safe: standalone CLI
capture deliberately permits unscoped paths, and pathname replacement can
occur after admission. The relevant protection is the selected scoped
capture dependency and its held-handle checks.

This audit leaves unrelated findings, the Windows qualification failure,
independent approval, and merge/release requirements outside its conclusion.
An alert disposition must be applied to the exact listed IDs and recorded
separately. A successful CodeQL Actions workflow alone does not establish a
passing external CodeQL security check.
