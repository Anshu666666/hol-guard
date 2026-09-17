# Later native pilot source reconstruction

The exact public commit
[`a4a2bd0437f3229d669f210cda224a3ed5cb44e3`](https://github.com/hashgraph-online/hol-guard/commit/a4a2bd0437f3229d669f210cda224a3ed5cb44e3)
has Git tree `8e44126d6fc29df3d828749f8482a3a0b06d3038`. This supplement
recovers the source versions recorded by the Claude component and subsequent
focused integration checks, and the completed MCP native 60-cell comparison
and eight-cell positive-marker campaign. The earlier
[source reconstruction audit](../reproducibility/README.md) explicitly excluded
that later MCP campaign; its original scope and evidence remain unchanged.

[manifest.json](manifest.json) contains five scoped reconstruction recipes,
six exact patches totaling 11,570 bytes, the raw evidence hashes, and checks
against the earlier MCP B/D recipes. Every resulting scoped path, file mode
and Git blob matches the corresponding retained historical source. This is
a source audit: it does not rerun a build, test suite or measurement, create
a new qualification result, or change production source or selection.

| Source snapshot | Recorded source | Exact reconstruction |
| --- | --- | --- |
| Claude final source component, 81 Python tests | `bb43eceab649e0c6604ea86e4fff13c1ec00326a` | Start at public `ae33987d0`; restore the declared additions from `a4a2bd043`, with two patches for the earlier fallback and its test. |
| Claude focused integration, 27 builder and 43 handoff tests | `6862c2b29e6efd1cb62e9c80088c97ed39714387` | Start at public `a4a2bd043`; three small patches restore the earlier builder and two integration tests. |
| MCP native Rust build | `3e1e8bdabe2943848dccd60b982cd5862ee39c78` | Public `81ef6195c` has the exact original Rust tree and locked inputs; restore the single example file from `a4a2bd043`. |
| MCP main collector and final source tests | `49ea9db7edb50a2cb9b1a4b4de845ee672270471` | All four recorded collector/adapter files already match `a4a2bd043`. One patch restores the historical D-based stdio test assertions. |
| MCP positive-marker collector | `525d2f0ef` | All five recorded collector/adapter files already match `a4a2bd043` exactly. |

The Claude component receipt matches 24 of its 26 declared implementation
files directly in the public tree. Its fallback and test were subsequently
changed to use explicit bridge keywords and exact integer validation. The
two patches recover their original hashes, including fallback SHA-256
`2d581027c787dc5211b4752139f1726d97363ef7852264e7bd90013acd70103d`.
They are archival reverse deltas, not proposed changes to the current helper.
The 81-test component result remains attached to those earlier bytes. The
later focused checks do not relabel it as a full native rerun.

The integration report has three further historical differences from the
public checkpoint: its builder, builder test and prior-artifact ordering
test. Their patches preserve the report's recorded hashes without removing
the later interpreter-fixture integration from production. The two source
recipes also verify the complete tracked `src` and `rust` trees and the
listed project inputs. Only the explicitly listed test and script files
are included; this audit does not assert equivalence of every repository
test, workflow or environment. The integration recipe excludes the later
`.gitattributes` changes.

The MCP build's recorded Cargo.lock SHA-256 is
`1b295e7099fe90a41f1a8463a3c309c711d5efc6ca627e105023173577a84d66`.
The latest public workspace has later changes, so building its current
Rust tree would not reproduce the recorded build inputs. The `81ef6195c`
base plus the public example file reconstructs the **entire** original
tracked Rust tree, not just the one file whose hash appears in the build
receipt. Its example hash and lockfile hash both match that receipt.

The MCP 30-test, 72.85-second final gate used the D-based clone's historical
stdio assertions. The campaign owner confirmed those bytes remained at
`49ea9db7`; the later B-default assertion corrections were not applied to
that clone. The sixth patch retains that test revision. It does not change
the collector hashes or measured traces. This source attribution is recorded
separately from the actual test execution already retained in the build
report; no tests ran during this audit.

For the measured MCP runtime arms, use the earlier manifest's
`mcp-b-prefilter` and `mcp-d-structural-facts` snapshots. Their complete scoped
identities were checked against the frozen B and D sources, and every
runtime-file hash in the new main and marker receipts agrees with the
respective snapshot. The ordinary controls use B; near-limit and marker
controls use D. The main and marker harnesses are separate overlays and
must not replace those runtime sources with the public checkpoint's default.

To reconstruct a recipe, use a fresh disposable checkout of its
`public_base`, disable line-ending conversion with `git config core.autocrlf
false`, and fetch any public commits named by its operations. Keep this
artifact outside that checkout. Apply the operations in order:

1. For `restore_public`, restore the named path from `source_commit`,
   preserving its Git file mode.
2. For `apply_patch`, first restore that path from `patch_base_commit`.
   Check the recorded `before` and patch SHA-256 values, then apply the patch
   with `git apply --check --index` followed by `git apply --index`.
3. Check the resulting `expected` hashes and the complete `scope_identity`
   maps. Missing paths recorded as `null` must remain absent. A match on only
   the changed files is insufficient for a full scoped-tree comparison.

For a harness overlay, restore only its listed scope from its public base
before applying its operations; do not overwrite the separate runtime
checkout. A locally created reconstruction commit has a new identity.
Record that identity and the recipe used, rather than changing a historical
report to claim that the old local commit was available from GitHub.

Verification used isolated temporary Git indexes under the shared
measurement lock, exact public blob restoration, `git apply --check --cached`
and `git apply --cached`, and complete scoped path/mode/blob comparisons.
All declared source hashes were checked. The frozen Claude bridge/auth
module hashes also match both their original public `ae33987d0` source and
the new public tree. No original evidence file was rewritten.

The earlier Claude debug, 68-test and 71-test attempts still lack retained
working-tree snapshots. These recipes do not recover or relabel them. Source
reconstruction also supplies no promise of an identical executable or wheel:
the original compiler, dependencies, environment, fixtures and execution
boundaries still matter. Claude's source component remains distinct from
installed daemon performance, and the completed MCP experiment retains its
scoped NO-GO, unchanged 30%/5% gate and false activation/qualification flags.
