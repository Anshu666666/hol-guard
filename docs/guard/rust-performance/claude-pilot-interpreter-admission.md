# Admit the exact uv interpreter alias for the installed pilot

The first installed Claude experiment at published source
`d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`,
[run 35233552830](https://github.com/hashgraph-online/hol-guard/actions/runs/35233552830),
failed before measurements in all 20 jobs. The 15 POSIX jobs reached the builder
and failed `qualification_interpreter_destination_invalid`. The five Windows
jobs failed their journal/archive contract tests earlier; that is a separate
file-identity problem and is not repaired by this interpreter change.

The builder passed `sys.executable` to a helper that deliberately owns only the
virtual environment's canonical `bin/python`. uv can invoke the versioned
`bin/python3` alias. A local functional inspection reproduces that invocation
form, with `python3` and `python3.12` pointing through canonical `python`.

The builder now admits only a recognized interpreter name inside the same
external physical virtual environment, resolving to the canonical executable
before preparation. The existing helper still validates source ownership,
permissions, identity stability and exact copied bytes. The selected alias must
resolve to the resulting private canonical executable afterward. An alias
detached from the canonical path fails instead of continuing to use shared
interpreter bytes. Every version/build/wheel-assembly and pip command uses that
canonical executable. Production distribution and origin validation are unchanged.

Six regression cases exercise canonical and chained aliases, an interpreter
outside the selected environment, a different executable, and an alias still
pointing directly at the shared source. The combined interpreter/pilot suite
passed 45 tests; Ruff and formatting pass after correcting one long source line.
Independent source review found no remaining admission issue. Actual POSIX
execution of the installed experiment remains required; no latency or native
benefit is inferred from the source correction.
