# Installed nonpriority launcher smoke contract

`scripts/native_slo_registered_surfaces_run.py::run_registered_surface_corpus`
accepts an otherwise idle installed `DaemonFixture` prepared with the frozen
`normal` policy and the existing `case_before` / `case_result` witnesses. It
calls shipped installers in that fixture's private home, reads their actual
configuration files, and starts the registered process with its exact argv,
environment and working directory. This is an `INSTALLED_LAUNCHER` semantic
smoke boundary, including process creation, stdin, stdout, stderr and exit.
It is not full vendor application activation or latency qualification.

| Surface | Registration readback | Process cases | Delivered boundary |
| --- | --- | --- | --- |
| Cursor | All six entries in `.cursor/hooks.json`, event flag, `failClosed`, worker digest | Shell allow/destructive block; intrinsic MCP/read/write review; two post aliases with benign/secret 1 KiB output | Read review is deny/exit 2; write and MCP review ask/exit 0; both post aliases emit `{}`/exit 0 and remain observation-only |
| Copilot | Global `.copilot/config.json` and project `.github/hooks/hol-guard-copilot.json`, both pre/post aliases, platform-selected command, environment and cwd | Shell allow/destructive block; benign/secret 1 KiB post output, separately for each registration scope | Native top-level `permissionDecision`; post delivery is observation-only and does not prove output withholding |
| Kimi | Both events in installed `.kimi-code/config.toml` | Shell allow/destructive block and benign/secret 1 KiB post output | Canonical native fields; restrictive pre exit 2 plus nonempty stderr explanation |
| Grok | Actual `.grok/hooks/hol-guard-pretooluse.json` catch-all registration | Shell allow/destructive block | Native decision plus pre exit 0/2; post is unavailable |
| ZCode | Actual `.zcode/cli/config.json` nested `hooks.events`; exact 18 matcher registrations | Bash allow/destructive block through the identical registered command | Pre native fields and exit 0/2. All matcher strings are checked, but other tool families are not process-qualified. Post normalization is not an installed hook |
| Cline | Canonical persisted filesystem slots and worker files, both digests, active `hooks` transport | Pre allow/destructive block and benign/secret 1 KiB post output | Pre `cancel` controls execution; post never cancels and remains observation-only |

Each invocation checks registration and worker digests before and after the
process. Reads are capped at 1,000,000 bytes per registration/worker. The smoke
request cap is 256 KiB, process output cap 2 MiB, and process-tree deadline
10 seconds. A timeout, containment failure, output overflow, wrong exit,
wrong delivered fields, stale registration, missing setup/native witness, or
nonconserving route count fails the block. Raw requests, stdout, stderr,
configuration paths and authentication material are not written to evidence.
The report retains hashes, fixed case identifiers, delivery classifications,
counts and durations. Synthetic command strings are hook input and are never
executed as tools.

There are explicit installation limits. Cline's shipped worker does not embed
`context.guard_home`; it executes the CLI with the production default beneath
its private HOME. Therefore the fixture must use `root/.hol-guard`; the current
generic `AdapterSession` layout `root/guard-home` is reported unsupported for
this surface. The probe does not inject the Cline canary override, manufacture
CLI flags, or redirect authority to make the sample pass. Production Cursor
and Cline interpreter attestation remains intact; synthetic readback fixtures
in unit tests are not installed runtime evidence.

Windows command strings written using `list2cmdline` are read using the actual
`CommandLineToArgvW` ABI and require a lossless roundtrip. Cursor's installer
writes POSIX `shlex.join` strings on all platforms, so its reader preserves
that serialization. ZCode appends an unquoted `# HOL_GUARD_MANAGED_ZCODE` marker
after its command on Windows. The host shell interpretation of that marker is
not proved, so the Windows ZCode path remains unsupported; the reader does
not silently remove possible arguments and claim actual host execution.

The source baseline `58548bb2e` has a demonstrated Copilot delivery mismatch:
`bounded_cli_hook_daemon._daemon_response_to_native` passes through a
Claude-shaped daemon response containing `hookSpecificOutput` while the
published Copilot CLI emitter produces top-level `permissionDecision`.
The new installed oracle rejects that mismatch. The separate production repair
now normalizes pre/post command responses from both the daemon fast path and
the compact CLI fallback. It preserves restrictive decisions, original reasons,
supported approval/scanner evidence, existing native availability notices,
Watch's effective allow/warn disposition, and nonzero fallback process exits.
Permission-request routing remains separate. Post responses carry native binary
metadata with exit zero; they do not promise output withholding. The oracle
continues to reject the old daemon-shaped stdout.

Pi/OMP are owned by the separate
`ci/native_runtime/probe_installed_pi_output.py` probe, which imports generated
extensions and invokes the registered `tool_result` callback. That scope does
not establish full host application activation. Hermes requires both the
actual `config.yaml` `hooks.pre_tool_call` entry and its exact shell allowlist
pair; neither process is exercised here. OpenCode installs a global plugin
with `tool.execute.before`; generated-plugin execution and host activation
remain unqualified in this tranche. OpenClaw's installer writes a managed
overlay and pretool bundle; reading that managed JSON alone is insufficient
proof that a host activated it. Their post surfaces remain unavailable.

All reports keep `qualification_complete=false`. Remaining dimensions include
load, cold residents, large output, source references, Watch, availability and
integrity faults, approval resume, non-Bash ZCode matchers, and full vendor host
activation. Local source unit tests validate registration logic, frozen
expectations, bounded subprocess mechanics and reporting. Socket-enabled,
coherent installed artifacts must produce the final per-platform observations.

Local validation on the locked Python 3.12 source environment: 57 tests passed
across the new suite and frozen qualification-corpus suite; the real Win32 ABI
test skipped on Linux. The new suite uses the disconnected `tests.package_offline`
fixture. Ruff passed and BasedPyright reported zero errors (65 advisory warnings).
This is source/readback evidence, not a completed installed native hook run.

The delivery repair has an independent code review of denial precedence,
existing native replies, Watch, post behavior and fallback exits. Regression
tests compare the actual published Copilot CLI emitter with the repaired
converter, and run the real bridge entry point using configuration read from
actual installed Copilot registrations. Those transport replies are synthetic
and disconnected; they are not described as live daemon or installed process
evidence. The installed subprocess corpus still requires coherent platform CI.
The final repair regression batch passed 208 tests with one Windows-only skip;
Ruff passed and BasedPyright reported zero errors (77 advisory warnings).

The runner accepts `evidence_file=Path(...)` for strict baseline/candidate
comparison. It exclusively creates a mode-0600 JSONL file and flushes/fsyncs
each offered and terminal record outside the measured child-process interval.
The file is limited to 1 MiB / 4,096 records, each at most 1 KiB; space for a
terminal record is reserved before offering its case. Existing files and
symlinks are never overwritten. Records contain only a fixed schema, scoped
case identifier, registration digest, offered/completed/failed status, fixed
stage, recognized route when witnessed, and attempted process exit. They do
not contain raw requests, output, stderr or exception messages. A strict
semantic exception is still raised after its failure record is retained;
the candidate does not pass because a baseline failure was recorded. A failure
before route accounting has a null route, rather than an inferred native route.
The evidence/readback regression batch passed 39 tests with one Windows-only
skip; Ruff passed and BasedPyright reported zero errors (64 advisory warnings).
