# Benchmark source reconstruction at the published checkpoint

The published checkpoint is
[`abf319d5a345d761d88e26ba787026e98370c26f`](https://github.com/hashgraph-online/hol-guard/commit/abf319d5a345d761d88e26ba787026e98370c26f),
Git tree `62eb319323cc7c9de7513af6ef7f05009d411189`. Its flattened history does
not expose every local commit named in the benchmark reports. This directory
provides exact source reconstruction recipes against public commits. It does
not change the reports or their results.

[manifest.json](manifest.json) records 13 runtime/build-input snapshots, nine
exact harness sets, two already published collector sources, and the source
mapping and SHA256 of 22 evidence files. Six patches total 15,065 bytes. The
remaining source versions are restored directly from published commits. No
repository bundle, new implementation, benchmark run, or qualification result
is included.

The main baseline discovery is useful: the complete tracked `src` tree and
listed project/build inputs at local `fb8d57a8efc364068860f74ea41414d595ee976c`
equal those at public
[`81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6`](https://github.com/hashgraph-online/hol-guard/commit/81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6).
Most subsequent measured versions need only a few exact file restorations.
The original Python baseline
[`2e672d2d950c6ec471005ddba46e49bba16dc23b`](https://github.com/hashgraph-online/hol-guard/commit/2e672d2d950c6ec471005ddba46e49bba16dc23b)
is also public.

| Runtime snapshot | Recorded local revision | Reconstruction |
| --- | --- | --- |
| Original Python | `2e672d2d9` | Public original baseline |
| Takeover Python | `fb8d57a8e` | Public `81ef6195c` has equal scoped bytes |
| MCP A, before prefilter | `c8f017831` | Public base and file restoration |
| MCP B, prefilter | `d811b08f0` | Public base and file restorations |
| MCP C, request facts | `1dbfdbb8e`, equal scoped `4cc1aa836` | Two small production-source patches |
| MCP D, structural facts | `1dbc20f31` | Public risk module plus the C/D runtime patch |
| Package, initial optimized Python | `640b47ae5` | Public base and file restorations |
| Package, pre-correction Python | `e79c4bf02` | Public base and file restorations |
| Package, final Python and native example | `f0aba7317`, equal scoped `af1106a5b` | Public base and file restorations |
| Scanner, initial optimized Python | `8ab23abd5` | Public base and file restorations |
| Scanner, rich-workload Python | `5ea667e15` | Public base and file restoration |
| Scanner, older native reader | `ea8c7b8eb`, equal scoped `0d0bd553a` | Public base and file restorations; old collector attribution remains incomplete |
| Scanner, final corrected reader | `66d86b3c9` | Public base and file restorations |

Each runtime recipe verifies the entire tracked `src` tree, `pyproject.toml`,
`uv.lock`, `rust-toolchain.toml`, and `.gitattributes`, including absence where
appropriate. Native snapshots also verify the entire tracked `rust` tree.
Package snapshots additionally include the five test/support files imported by
their fixture helpers. The manifest lists exact scope, file modes, tree/blob
identities, individual changed-file SHA256 values, and verified aliases.
Unlisted tests, documentation, workflows, and repository metadata are outside
that source-equivalence claim.

| Harness set | Exact-byte source |
| --- | --- |
| MCP A → B comparison | Two files already public at `ae33987d0` |
| MCP B → C comparison and text boundary | Two patches against public `abf319d5a` |
| MCP B → D comparison, text and container boundaries | Public driver; small profile-script patch |
| MCP near-limit component | Already public at `abf319d5a` |
| Initial package campaign, final local harness | Already public at `81ef6195c`; this does not recover its earlier harness |
| Package continuation matrix | Two exact files already public at `5ee52a03e` |
| Final package correction and native comparison | Four exact files already public at `abf319d5a` |
| Package unversioned route witness | Already public at `abf319d5a` |
| Final scanner reader confirmation | Five-file set, with one small helper patch against public `ae33987d0` |

The resumed package matrix collector is already published as
[`rsp-package-continuation-resume-source.txt`](../../performance/rsp-package-continuation-resume-source.txt).
Its exact SHA256 is
`5d5520e8f1051127cfe55af9e881237e1ca1436bf28dbc744410a06c4db5ecac`.
It replaces the matrix driver beginning at the retained segment's cell 19; the
local evaluator harness remains the one in the original matrix recipe. The
targeted original-versus-final deny control also has its exact
[`wrapper source`](../../performance/rsp-package-deny-postfix-runner.txt)
published, SHA256
`482bf23e45ea2878a39d3980978b39dbd82cf44de63ef5e25420d6defb2be7b5`.
Its fixed historical paths need an explicitly recorded replay adaptation.

To reconstruct a source arm, use a fresh disposable checkout of the chosen
snapshot's `public_base`, with Git line-ending conversion disabled. Keep this
artifact directory outside that checkout. Fetch the public commits named in
the recipe if the clone is shallow. Apply the ordered operations in that
snapshot:

1. For `restore_public`, restore `path` from the exact `source_commit`. The
   normal runtime operations have identical `source_path` and `path`; use Git
   restoration so the tracked mode is retained.
2. For `apply_patch`, **first restore that path from `patch_base_commit`**,
   even when it differs from the snapshot's `public_base`. Check the recorded
   `before` SHA256 and the patch SHA256, then run `git apply --check --index`
   followed by `git apply --index`. This extra restoration is required because
   each patch uses the smallest exact delta from a public version.
3. Verify each resulting `expected` SHA256, byte count, mode, and Git blob ID.
   Check the complete scope identities with the staged Git tree. Do not treat
   matching only the changed files as verification of the full source tree.

For example, the operation shape is:

```sh
git config core.autocrlf false
git restore --source=PUBLIC_SOURCE_COMMIT --staged --worktree -- SOURCE_PATH
git apply --check --index /absolute/path/to/reproducibility/patches/EXACT.patch
git apply --index /absolute/path/to/reproducibility/patches/EXACT.patch
```

The placeholders come directly from the selected manifest operation. For an
operation that only restores a public file, omit both patch commands. These
commands are intended for the disposable reconstruction checkout.

Harness sets are a separate source overlay. Restore **only the files listed
in the harness `scope`** from its `public_base`, then perform its operations.
Do not replace the whole runtime checkout with the harness base. The manifest
pins every resulting harness file. For the scanner's ordered five-file
aggregate, hash each basename, a NUL byte, and its file bytes in the listed
order. The individual SHA256 values are also recorded. The scanner runtime
aggregate uses relative paths and differs between the historical initial,
rich-workload and final-reader collectors; `recorded_source_digest_checks`
preserves the exact file lists and formulas separately.

A new local reconstruction commit will have a new commit ID. If a runner
requires a clean checkout, commit the verified reconstructed files locally
and retain the manifest snapshot ID, new commit ID, and source digest mapping
in the new run. Do not rewrite a report's historical commit field to make it
appear that an unavailable old commit was checked out. Recorded interpreter,
dependency, toolchain, fixture, invocation, cache preparation, sample counts,
process accounting and coordination constraints still apply to any replay.
Native examples need a fresh build with the original locked inputs; this
source audit does not promise a byte-identical binary or installed wheel.

Verification used isolated temporary Git indexes, public objects read through
an alternate object directory, and `git apply --check --cached` followed by
`git apply --cached`. Every resulting scoped path/mode/blob map matched the
retained historical Git snapshot, including unchanged files and deletions.
Separately, the audit checked the recorded MCP runtime file hashes, historical
scanner source aggregates, final native-source aggregate, exact harness maps,
and the two archived collector hashes. All verification ran under the shared
measurement lock. Production worktrees and original evidence were unchanged;
no tests, native builds, or benchmarks were run for this audit.

Historical attribution limits remain visible:

- The initial 41-case MCP campaign pins runtime files but has no per-cell
  execution-harness hash. Its collector changed across the retained 19-cell
  pause/resume. A later exact collector cannot be assigned to every earlier
  observation. The separate A → B, C, and D campaigns have their own exact
  harness maps.
- The early pure-Python and rich scanner reports pin runtime aggregates but
  do not pin their execution-harness bytes. The first two native scanner
  reports do record collector aggregates, but those hashes do not match the
  scripts at their separate Python-root commits. Retained scanner Git
  snapshots did not establish the missing collectors. The final corrected
  reader's five-file aggregate is verified and remains the authoritative
  NO-GO cohort; the older cohorts remain excluded from that decision.
- The initial package report pins an earlier local harness as
  `4866aa2692cac48ef8a92b66864a8c63de63a6fba4ef099736d2755e2230811f`.
  Those exact bytes were not located in the retained root/package Git
  snapshots. Its final local harness is available and separately verified;
  assigning it to the earlier measurements would erase a real provenance
  difference. The historical outer collector is not fully pinned.

These are source-attribution limits, not reasons to discard an observation.
The evidence SHA256 pins preserve the original failures, censored cases,
regressions, interrupted states, API-only unversioned cells, and bounded
NO-GO decisions. All qualification and activation claims remain at their
original scope. Source reconstruction supplies neither a new timing result
nor four-platform installed qualification. The later MCP native text-facts
campaign was outside this published checkpoint at audit time; its final
source and outcome provenance belongs to its separate report, although the
B and D runtime recipes here can be reused.
