# Installed route and control correctness

RSP-136 requires actual launchers, default auto without development overrides,
aliases, source references, Watch, availability and approval flow from each
selected package. Its dependencies RSP-135 and RSP-015 remain separate. This
fixture closes a concrete source-reference probe gap and exposes the existing
registered correctness cohorts without running the separate timing population.

Use an explicitly selected native wheel from the normal four-platform build. Retain its original
archive/wheel/member identities, hash-enforced installation inputs and installed
inventory. Invoke these scripts with that installed environment's lexical Python
path and `-I`, from an empty working directory. `BUILD_SHA` is the wheel's actual
native build commit, which can be the PR merge commit rather than the branch tip.
Each entry rejects editable/source imports, proof overrides, package-content
mismatch and a different native build. It retains target, rules and runtime digests.
Before the registered cohorts, use the existing
`scripts.native_qualification_interpreter.provision_venv_interpreter` on the owned
venv's lexical Python invocation and retain its proof. This avoids trusting a
group-writable hosted interpreter target through a venv symlink. The helper copies
and verifies the owned interpreter; do not chmod the shared hosted interpreter.
This setup is not route warmup or additional workload evidence.

```sh
"$INSTALLED_PYTHON" -I "$SOURCE/scripts/ci/verify_installed_route_controls.py" --scope priority-controls --wheel "$WHEEL" --source-sha "$BUILD_SHA" --output "$OUT/priority-controls.json"
"$INSTALLED_PYTHON" -I "$SOURCE/scripts/ci/verify_installed_route_controls.py" --scope priority-approval --wheel "$WHEEL" --source-sha "$BUILD_SHA" --output "$OUT/priority-approval.json"
"$INSTALLED_PYTHON" -I "$SOURCE/scripts/ci/verify_installed_route_controls.py" --scope registered-aliases --wheel "$WHEEL" --source-sha "$BUILD_SHA" --output "$OUT/registered-aliases.json"
"$INSTALLED_PYTHON" -I "$SOURCE/scripts/ci/verify_installed_pi_sources.py" --wheel "$WHEEL" --source-sha "$BUILD_SHA" --output "$OUT/pi-source-correctness.json"
```

The Pi/OMP diagnostic currently declares POSIX scope and requires Node with erasable
TypeScript support. Its Windows refusal is a fixture boundary, not a statement
that the product lacks Windows Pi/OMP support. The other cohorts retain
their original platform-specific refusals and unsupported-surface reports. A
passing implemented cohort does not erase those reports or complete RSP-136.

| Requirement boundary | Executed provider | Remaining distinction |
| --- | --- | --- |
| Claude/Codex registered pre/post, Watch and availability faults | Existing `run_registered_contract_corpus`, original fixed semantic oracle and selected setups | Default-auto HTTP authentication probes are separate from registration execution. Availability delivery is not native evaluated allow. |
| Priority approval continuation | Existing `run_registered_approval_corpus`, real password-bound compatibility approval | This is not native v3/v4 approval consumption or actual tool execution. |
| Nonpriority registrations and aliases | Existing `run_registered_surface_corpus`, actual adapter installation and config readback | Fourteen declared event slots across Cursor, Copilot, Kimi, Grok, ZCode and Cline; actual platform unsupported entries remain explicit. No full external-host activation claim. |
| Pi/OMP pre/post and private source reference | New ten-call registered-extension callback probe | Reads actual settings registration; executes unmodified callback code under Node. Does not launch the complete Pi/OMP host. Windows remains unqualified. |
| Ollama contribution/control lifecycle | Existing `verify_native_ollama_install.py` with its original wheel/source/contribution/program bindings | Preserve all five control phases and budgets. Resolved legacy approval does not enable unsupported reuse. Settings rollback is distinct from package-version rollback. |
| Distribution update and rollback | Existing `verify_installed_artifact_transitions.py` with an explicitly selected baseline/candidate pair | Requires its own final-artifact run. Historical failed transitions are not credited by these commands. |

The ten Pi/OMP calls are safe and blocked Bash pre-tool calls plus clean Read,
Read with a synthetic scanner marker beyond the 12,000-character excerpt, and
Read whose actual file differs from the output. Each harness uses its actual
adapter registration and generated callback. Large source proofs travel in the
existing encrypted `guard_payload_ref` envelope. The observer forwards the native
call unchanged. It freezes a bounded entry descriptor, rejects mutation across the
call, then hydrates that frozen still-owned private envelope to bind the declared
correlation and source proof. The Node and native-entry ciphertext digests must
also match. Neither payloads nor encryption keys
are exported. This observation adds work, so no performance result is claimed.

The delivered callback/model behavior, typed native edge, ACK generation/digest/
runtime/rules, writer admission and exact full committed receipt are checked
separately. Offered and terminal callback rows are retained. Missing, duplicate,
unreturned or mismatched observations fail. Cleanup failures stay alongside the
first failure; an uncontained private root is retained rather than removed.

The existing two Claude Post checks and twenty-one default-auto HTTP routes are
prerequisite evidence, not newly expanded installed-route coverage. The separate
88-call priority launcher timing diagnostic is not repeated here. Source controls
use modeled HTTP/native responses where declared; they do not substitute for a
fresh artifact-bound execution of the commands above.

The selected POSIX run declares 62 priority control attempts, three priority
approval attempts across two cases, 29 alias attempts, ten Pi/OMP callbacks and
22 Ollama policy-review calls: 126 heterogeneous offers per platform. This is
not a count of native evaluations. The existing Codex approval continuation can
evaluate more than once inside one launcher attempt. Each original producer
retains its own timeouts, semantic checks and failure behavior; the outer driver
stops after a failed cohort and preserves its partial records.

| Windows surface | Current source boundary | Required installed evidence remaining |
| --- | --- | --- |
| Claude/Codex registered pre/post, Watch, availability, compatibility approval | Existing generated launchers and registration readers support Windows. | Run the existing original registered correctness cohorts with the selected Windows wheel. Earlier HTTP default-auto checks do not satisfy these launchers. |
| Cursor, Copilot, Kimi, Grok and Cline aliases | `native_slo_registered_surfaces.py` reads the Windows command/PowerShell registrations and preserves their arguments. | Execute supported registrations, checking delivered output, route and original cleanup. The present POSIX matrix gives no Windows credit. |
| ZCode | The existing reader refuses the generated Windows ` # HOL_GUARD_MANAGED_ZCODE` suffix because `cmd.exe` does not interpret it as a comment. | Keep `zcode_windows_shell_comment_unqualified` explicit; no argument stripping or invented successful host invocation. |
| Pi/OMP | `pi_extension_runtime_ownership.py` has a Windows owned Python/bootstrap route. `resident_protocol.rs` advertises `post-tool-source-read-windows-handles-v1` on Windows. | Add a bounded Windows callback/registration execution with actual private source read and receipt attribution. This POSIX-only probe does not waive it. |
| Source references | `native_slo_source_witness.py` binds support to the actual installed runtime capability. | Prove content/identity review on a capable Windows artifact; preserve a denial as denial where the capability is absent. |
| Ollama and package transitions | Existing installed verifiers have their own original artifact/control/transition contracts. | Windows execution and package-version rollback remain separate from POSIX Ollama settings rollback. |

The route entry passes the admitted native binary to the original `DaemonFixture`.
That fixture starts its Python child using its own installed `sys.executable`;
those two executable roles must not be interchanged. A test-only source successor
may reuse an earlier wheel only when the driver proves the exact allowed test
delta and unchanged package, native source and provider trees. Both source
identities and the wheel's original build identity must remain in the report.

RSP-140 export scope is checked within these same ten Pi/OMP calls: the completed
or failed report must not contain the declared scanner canary, output marker,
either raw command string, or the owned private-root path. This checks callback,
receipt, metric and error evidence together without removing valid receipt
fields. A rejected export is withheld and identified by digest; its raw contents
are not uploaded. Controls inject each marker into receipt, metrics and failure
surfaces and prove that a complete valid receipt survives the check unchanged.
This is an exact negative-leak assertion for the declared fixture inputs, not a
claim covering every secret, partial-output fragment or other exporter. Raw
inputs can legitimately exist inside private request/source handling; this probe
does not change private journal semantics. Original priority Watch/availability
checks distinguish delivered availability responses from native evaluated allow;
the Pi receipt checks require an actual matching native decision and current ACK.
