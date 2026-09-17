# Owned-preparation E source reconstruction

This supplement attributes the single completed 64-cell B/E campaign. It does
not change prior C/D/native outcomes or fill the original 41-cell collector
attribution gap. [manifest.json](manifest.json) pins the three changed runtime
files, complete runtime and contract tree identities, project/lock blobs, four
harness files, and the exact patch.

Reconstruct frozen B using the earlier
[B source recipe](../reproducibility/README.md), which starts with public
81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6 and restores the recorded B files.
Its contracts tree also equals that public base. In a separate disposable
checkout of the verified B source, apply [B-to-E-runtime.patch](B-to-E-runtime.patch)
with line-ending conversion disabled. Check the patch SHA256 and use
`git apply --check --index` before `git apply --index`. Verify the entire staged
`src` and `contracts` trees and the `pyproject.toml`/`uv.lock` blobs against E's
manifest identities. All other files in these runtime scopes are unchanged.
An independent temporary Git index check of these complete scopes passed; no
worktree or frozen measured source was mutated.

Restore only the four listed `scripts/` paths from public
9db62e8844c2ba2627f55b6b00e58cb5b175185d, preserving absence for the two new files.
Apply [published-to-E-harness.patch](published-to-E-harness.patch) and verify all
four SHA256 values. The manifest identifies an already exact public file and
every patch operation. An independent temporary-index reconstruction passed
all four byte comparisons. Do not restore the newer publication's runtime:
these files are a separate harness overlay on the reconstructed B/E arms.

The historical local implementation is cabb22960afaab329f800f154d51dd69628d99ab;
the final harness-only correction is bbb1323d1d58e528cc5094d7e59ecf0aa4904579.
The public-base recipes and retained patches recover their measured scopes
without requiring those local commit objects. The original runner pins all
four imported runtime modules in every cell and also pins the modules actually
imported by its public API preflight oracle.

The historical E checkout was a complete archive of bbb1323d1, containing 4,135
tracked files. Its initial incomplete export omitted a required contract and
failed before the oracle or any timing. Both that zero-cell attempt and the
successful complete-source attempt are retained. A replay must retain the
runtime contracts and imported assets; source files alone are insufficient.

Use the same dependency lock and record the actual interpreter, runtime/harness
hashes, source/fixture devices and any path adaptations. The original command
and environment files are linked by the
[completed report](../../rust-performance-mcp-owned-preparation.md). This source
reconstruction is not a new measurement or a claim that another machine can
reproduce the shared host's wall times.
