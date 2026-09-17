# Reconstruction of the stopped F run1 source

This supplement reconstructs the exact source scopes used by the
[incomplete first B/F comparison](../../rust-performance-mcp-streaming-preparation.md).
It does not resume its 19-complete/one-failed/44-never-attempted schedule or
authorize another experiment. Product B remains unchanged and F inactive.

Both measured arms used the same source/harness commit
`5a5ad6d3873d83ac6411bf9204f704c449580c41`. The separate historical public oracle
export came from `d811b08f081d72c348b95f0cf9e45349fb1787e6`. Each patch below starts
independently from public commit
`9db62e8844c2ba2627f55b6b00e58cb5b175185d`.

| Reconstruction | Retained patch | Verified scope |
| --- | --- | --- |
| Common B/F runtime | [9,708-byte runtime patch](common-runtime-from-public-9db.patch) | Complete `src` and `contracts` trees; `pyproject.toml` and `uv.lock` blobs |
| Historical oracle | [90,633-byte oracle patch](historical-oracle-from-public-9db.patch) | Complete `src` and `contracts` trees; `pyproject.toml` and `uv.lock` blobs |
| Explicit F harness, imported helper and plan | [Harness patch](explicit-F-harness-and-plan-from-public-9db.patch) | Four directly pinned Python files, imported frozen E worker and fixed JSON plan |

Apply the runtime and harness patches together to one checkout of the public
base. Apply the oracle patch to a separate checkout of that base. The runtime
and oracle source patches are alternatives for their respective checkouts,
not consecutive changes to one source tree. Keep both measured arms pointed at
the same reconstructed runtime; the oracle tree is only the historical
reference. The fixed collector rejects a substituted or identical reference.

The oracle helper imports `profile_guard_mcp_session.py` at module load. Its
exact measured bytes are included as a fifth Python file, even though the F
collector runs the separate explicit F worker. This retains import closure
without editing or executing E. The four direct harness pins and the fixed
measurement plan remain unchanged. Independent review identified this extra
dependency in the first reconstruction draft; that draft's patch, manifest,
verifier and successful narrower proof are retained in the campaign evidence.

The [manifest](manifest.json) records full patch SHA-256 values and expected Git
objects. The runtime `src` tree is
`ee76be084f3c8b9e6ce12db1b064982e808be503`; the oracle `src` tree is
`e0d5cd477ce4dc9a89026ad25d404c5fbaa51ac4`. Both use contracts tree
`fad957713888b328c2b0aad33fb13b824fb1f402`, project blob
`9b7b297cd060ff808a43743c873847bb9ae2855b` and lockfile blob
`afd00d9bb1a698cd53dba0e3b7909d5440157aa4`. The complete original exports contain
additional unrelated tracked repository files; these patches do not claim to
reconstruct those unrelated files. Their actual before/after bytes are retained
in the [campaign export evidence](../evidence/mcp-streaming-run1/manifest.json).

The [verification program](verify_reconstruction.py) applies each patch to a
separate temporary Git index, checks the full declared trees/blobs or file
hashes and reports its own source identity. It does not modify a working index,
change exported source, import a candidate or run a benchmark. It requires the
public base object and a writable Git object database because `write-tree`
records the reconstructed tree. The owner ran it under the shared lock:

```sh
flock /workspace/scratch/c911dc702e23/performance-measurement.lock \
  /workspace/scratch/c25672eb4c10/hol-guard/.venv/bin/python \
  docs/guard/rust-performance/reproducibility-streaming-preparation/verify_reconstruction.py \
  --repository /dev/shm/hol-guard-takeover/mcp-f-report-worktree \
  --temporary-root /dev/shm/hol-guard-takeover
```

All three reconstructions passed. The exact final
[verification output](verification.json) and [static-check receipt](static-checks.json)
are retained. An initial lint check identified an unbound loop closure and an
overlong description; the final verifier binds the index environment directly
and wraps the description. The earlier source and successful pre-correction
reconstruction are preserved in the campaign evidence. These changes affected
only the reconstruction utility after the stopped campaign.

The historical launch was:

```sh
PYTHONPATH=/dev/shm/hol-guard-takeover/mcp-f-5a5ad6-run1-20260917/runtime-frozen/src \
TMPDIR=/dev/shm/hol-guard-takeover/mcp-f-5a5ad6-run1-20260917/fixtures \
/workspace/scratch/c25672eb4c10/hol-guard/.venv/bin/python \
  /dev/shm/hol-guard-takeover/mcp-f-5a5ad6-run1-20260917/runtime-frozen/scripts/compare_guard_mcp_streaming_preparation.py \
  --runtime-src /dev/shm/hol-guard-takeover/mcp-f-5a5ad6-run1-20260917/runtime-frozen/src \
  --oracle-src /dev/shm/hol-guard-takeover/mcp-f-5a5ad6-run1-20260917/oracle-frozen/src \
  --samples 30 \
  --lock-file /workspace/scratch/c911dc702e23/performance-measurement.lock \
  --json /dev/shm/hol-guard-takeover/mcp-f-5a5ad6-run1-20260917/comparison.json
```

The retained launcher captures cwd, selected environment, exact arguments and
exit status. Both source arms and both fixture stores used tmpfs device 27.
The bytecode policy, hash seed and timezone were inherited unchanged and are
recorded; generated caches are individually inventoried after the campaign.
CPython was 3.12.14. The exact 69-distribution dependency set, interpreter and
metadata identities, frozen project/lockfile hashes and verified RECORD file
counts are in the before/after environment manifests. Merely using the same
Python version does not reproduce that dependency set or its binary identities.

No new measurement follows from successful reconstruction. Run1 remains
incomplete, including its stderr/ledger/worker-detail/OOM-attribution gaps. A
future diagnostic harness or environment change needs its own reviewed plan
and complete attempt history; it must not overwrite this raw evidence or pool
the older E campaign with this different common-source placement.
