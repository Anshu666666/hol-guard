# Claude experiment discovery diagnostics

These are fixture observations before measurement. They do not select the
dormant launcher, change ordinary availability delivery, repair authority
files, retry a native request, or qualify installed performance.

At head `96a69725eab018674174dabc6f205a4087d6ff4b`,
[experiment 35247986580](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986580)
completed all 20 jobs: nine passed and eleven failed measurement. All 20 jobs
passed encrypted retention. Six Linux/Mac failures occurred on the optimized
Python control's benign PostToolUse response. Five Windows failures occurred
on the native pilot's first benign PreToolUse offer. The fixed target-binding
and package preparation checks had already passed.

The retained journals contain decoded-capture byte lengths and hashes, plus
canonical response hashes, but no raw stdout. Independently serializing the
fixed source-defined responses gives these exact canonical hash matches:

| Cohort | Canonical SHA-256 | Source-defined response semantics |
| --- | --- | --- |
| Six Linux/Mac failures | `eb9b263d6ae4001ca42efb654d79b40f4e74a5da92c85a1499eb61b3a8e12ef4` | PostToolUse availability result with `native_post_tool_unavailable` |
| Five Windows failures | `8b17e297b7ed0f9a969e189d22467108148d8a044346cdf238b344968f4a2653` | Initial launcher discovery unavailable |

These are known-response identity matches, **not recovered stdout or proof of
the underlying cause**. Initial native discovery maps key/state read, JSON,
authentication and peer-identity failures to one availability response. No
individual subcheck can be selected from that response alone.

The new Windows-only preflight records independent current observations of the
fixture's Guard directory, discovery key file and signed state file. Fresh
`OPEN_EXISTING` handles request only `READ_CONTROL | FILE_READ_ATTRIBUTES`,
reject a reparse object and unexpected file type/link count, and invoke the
existing verify-only protected-DACL contract. No create, write, delete,
`WRITE_DAC` or `WRITE_OWNER` right is requested. Handles are closed on all paths.
The preflight also uses the existing bounded Python discovery reader and
signature verifier, and compares the current peer fields against the
digest-checked prepared config. The checks never disclose file bytes, paths,
SID/ACL text, keys or arbitrary exception text.

This Python preflight does not execute the native reader's relative ancestry
walk, its strict canonical JSON profile, or a daemon challenge. Each result
explicitly sets `native_reader_executed`, `failed_request_cause_proven` and
`authorization_evidence` to false. A positive check is not an authorization
decision. A failed check does not replace the original launcher response or
change the experiment's semantic gates. An observer failure is retained as
such; both arms are still offered under the existing plan.

The independent inspection runs once after preparation and before timed
offers. Its extra reads are outside the measured interval; comparison remains
an explicitly prepared-resident experiment. The existing four-platform
workflow runs a Windows-only regression distinguishing an ordinary inherited
file from an explicitly protected file without repairing either. Local tests
exercise the fixed API arguments, closure and failure projection, but do not
establish actual Windows behavior or a passing installed rerun.
