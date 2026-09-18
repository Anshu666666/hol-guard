The daemon's periodic authority refresh now starts with a shared reader lease. It retries the existing exclusive read only when the store raises `NativeCommandControlMutationRequiredError`, after the shared context has unwound. The exclusive retry reads the authority again, so a mutation committed between the two leases is observed.

This repairs a reachable lock conflict in immutable implementation commit `7a387128e2cf2ec79b890dfebe2697e8a49eb45d`. `GuardDaemonServer` starts its extension-control refresh worker with a default interval of five seconds. That worker calls `_GuardDaemonHTTPServer.refresh_extension_control_runtime`, whose original registry read defaulted to `read_only=False` and acquired an exclusive lease even for unchanged authority. A native evaluation holds a shared lease on the same lock file.

The retained pre-fix test uses a separately opened file description and a real POSIX `flock(LOCK_SH)` lease. Its unchanged protected authority became `DEGRADED_UNACKNOWLEDGED` when the original refresh attempted the conflicting exclusive lock. The original production source, regression source, command, source hashes, and complete failing output are retained. This witness uses a zero-second lock timeout inside its fixture to make a real conflict fail immediately; no production timeout was changed.

The five new regression cases verify these behaviors:

- Unchanged refresh and an independent native-style shared reader coexist, and refresh does not revoke the independent reader's lease.
- A missing authenticated catalog manifest requires a retry, with an independent exclusive lock acquisition proving that the first shared lease has been released before the retry.
- A tampered manifest MAC remains fail-closed without an exclusive retry.
- An unavailable authority credential store remains fail-closed without an exclusive retry.
- A second `GuardStore` commits revision 1 after the shared read unwinds, and the exclusive retry observes the newly authenticated revision and controls.

Fresh local validation on 2026-09-18:

| Check | Result |
| --- | --- |
| Pre-fix held-reader regression | Expected failure: 1 failed in 0.66 seconds |
| Five focused regression cases | 5 passed in 1.20 seconds |
| Existing authority, publication, catalog-manifest, and resident-runtime suites | 56 passed in 10.05 seconds |
| Ruff lint and format checks | Passed for all three changed source/test files |
| Production server type analysis, basedpyright 1.39.8 | 1 file, 0 errors, 319 warnings, 3.103 seconds |

The existing resident-refresh test stub now accepts the store API's keyword-only `read_only` argument. Its one-second observation deadline remains unchanged. Source identities matched before and after every recorded command. An AST comparison confirms that the remainder of `server.py` is unchanged when the one modified method is excluded.

Startup initialization, the five-second refresh interval, lock primitives, mutation guards, policy markers, revision floors, and runtime installation rules retain their prior implementation. Tampered or degraded authority does not trigger the mutation retry. The retained code patch and source hashes specify the exact change.

The new lock witnesses run on POSIX and are explicitly skipped on Windows. These results establish a local lock regression and its repair. They do not establish installed-wheel performance, native route conservation, Windows interoperability, or a completed soak. The earlier hosted error objects matching `native_command_control_mutation_in_progress` do not identify their historical lock holder; this repair does not assign that cause to those individual requests. A follow-up audit of the exact Desktop source inventory confirmed that `server.py` is not one of its 395 bound files and every current source binding still equals the retained report fixture; this server-only change does not require regenerating that fixture.

`manifest.json` inventories every retained file by length and SHA-256. Compressed files also carry decoded length and SHA-256, preserving complete original bytes. Per-command JSON receipts record the exact command, environment overrides, source identities, timing including lock wait, exit status, and output identity. `validation-runner.py.gz` preserves the runner used to record them.

The original claim that Desktop source bindings needed regeneration was incorrect. `desktop-binding-proof.json` records every resolved source path, binding identifier, current SHA-256, and matching fixture SHA-256 at commit `e6bed36e47f17a349cfd9356e62af076ce568955`. The fixture and inventory remain unchanged, and the 51,000-case report generator was not invoked. The complete original README and manifest are preserved in `original-readme-before-binding-correction.md.gz` and `original-manifest-before-binding-correction.json.gz`; the latter retains its original SHA-256 `f6b0d8af86ce68b61c3596c6fd564d246e3c10e067d9bcdb78ef38e872dd8049`. An initial invocation failed to import the repository test module before any proof ran; that attempt and the successful corrected invocation are both retained.
