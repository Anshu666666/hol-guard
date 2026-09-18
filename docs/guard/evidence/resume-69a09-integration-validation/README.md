The combined implementation source is `69a09bc94b22bd5a789f137b9b7ebf3132296f83`. Integration began at `b8f27c919ec4a8d71c4a36dd8ee8e6b641aa9a34`; a missing ownership declaration and a local type-checker interpreter-selection error were found and retained before correction. The required affected gates then passed. No hosted qualification or performance campaign ran in this validation.

The reviewed source includes the public `1d8467bd` MCP request/write/receipt binding checkpoint, the separate scalar-type identity correction, private retirement observation, macOS lookup diagnostics, bounded receipt failure diagnostics, safe pending-read retry in the launcher approval fixture, and private macOS interpreter provisioning. All original PRD/TODO requirements, unchanged baseline and qualification thresholds remain in force. The later saved-state callback authority repair and inactive per-call prototype are outside this source cutoff.

| Validation | Original b8f27 result | Corrected 69a09 result |
| --- | --- | --- |
| Native authority ownership | Failed: new receipt-diagnostics module had no ownership mapping | Passed after exact persistence/privacy declaration |
| Python hook semantic call graph | Passed | Source unchanged; original pass retained |
| Rust I/O ownership | Passed | Passed again because privacy serializer inventory gained the helper |
| Production Ruff | Passed | Production source unchanged; original pass retained |
| Full production types | 52 missing-library import errors using the default interpreter | 0 errors with the validation interpreter selected explicitly |
| Combined observer/interpreter/transition cases | 135 passed in 6.67 seconds | No relevant source change; pass retained |
| Ownership contract cases | Not run in initial set | 19 passed in 5.73 seconds |

The source correction adds only `src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_diagnostics.py` to the existing `evidence_persistence` / `persistence_only` node and the privacy serializer list. Removing those two entries reproduces the entire original manifest object. No gate logic, wildcard, owner role, route, policy authority, threshold, or serializer exclusion changed. The diagnostics classify persistence failures into fixed public labels; they do not decide hook actions.

The first type-check command launched basedpyright through the validation interpreter but did not select that interpreter for its child analysis. All 52 errors were unresolved library imports. The libraries were already installed in the validation environment. The corrected invocation adds `--pythonpath /workspace/scratch/c25672eb4c10/validation-venv/bin/python`; no dependency, source, typing exclusion, language-version configuration, or CI gate was changed. Its full-source output is `0 errors, 0 warnings, 0 notes` with `--level error`. This does not erase separate historical direct-script type-check results.

The independent source integration proof accounts for all 31 changed code paths relative to the public MCP checkpoint. Thirty files match their reviewed source commits byte for byte. The combined transition driver has fourteen function/class bodies: its provisioning function matches the macOS repair, every other body matches the observer repair, and its provisioning import is verified separately. The two-functionality overlap was also exercised by the combined 135-case suite. The exact original and corrected ownership manifests are retained.

All 395 actual Desktop source bindings still match the unchanged fixture and generator at this cutoff. The inventory was evaluated from the actual declaration without executing generation. The fixture digest remains `2b60b7fa1eb771a3f8d0cff456a26997f31b914836c06d7857044ba2a1cce754`. This statement does not cover later source changes to bound MCP runtime files, which require their own generation and validation.

Every validation command has its original log, exit code, start time, duration including lock acquisition, and digest. Initial and corrected runs have complete before/after inventories of their declared source roots and clean-worktree readbacks. The initial inventory includes src/rust/scripts/tests/ci/workflows; the corrected inventory also includes ownership contract files. No tracked input changed during either run. The original failed assertions from the orchestration runner remain consistent with the retained two failed checks.

The root manifest verifier also had an initial schema-compatibility failure on the receipt package's `records` array. The original verifier and correction history are retained. This was a verifier invocation failure, and the package passed all checks before integration; no evidence payload was rewritten. The individual package readbacks, source proof and executable validation runners are included for review.

The installed hosted evidence at 590 remains separate: all native-wheel jobs passed, all paired qualification jobs failed, CI shard 75 failed, CodeQL still reported 11 high alerts, and no new approval or release was established. These local checks do not promote smoke, observer data, pilot point estimates, or historical security reviews to qualification.
