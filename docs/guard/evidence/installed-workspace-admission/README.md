# Installed priority fixture workspace admission

The shared priority launcher fixture now marks its owned workspace as explicit.
Both the frozen baseline and the candidate use this same fixture. Codex then
includes the workspace in its actual registered query, fallback arguments, and
authenticated manifest context. Claude already includes a supplied workspace;
the new flag preserves its actual registration identity. Other harness
registration functions are untouched.

This follows the Linux baseline failure in
[qualification run 35276260804, job 105387531453](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260804/job/105387531453)
at implementation head `7a387128e2cf2ec79b890dfebe2697e8a49eb45d`.
The retained build metadata pins the baseline to
`2e672d2d950c6ec471005ddba46e49bba16dc23b`; its wheel digest in the original failure
is `fd4ac4285719f1d5099b5236595ccb4a4b88354a555885bba395bb48be49ec0b`.
The failed case is `codex.PostToolUse.benign.1m`, with a
`reviewed_output_sha256` projection mismatch. The aggregate failure does not
retain that attempt's native response. Historical attribution to source-path
denial remains an inference; the registration and admission defect is reproduced
independently below.

`install_priority_launchers` previously supplied `workspace_dir` while leaving
`workspace_override_explicit=False`. The unchanged Codex adapter deliberately
omits that workspace from its registration. `_run_registered` adds the existing
tool-use identifier but does not add `cwd`, and subprocess working directory is
not HTTP request context. The unchanged receiver therefore admits no workspace
for such a request. Both pinned Rust source versions select `.` when request
`cwd` is absent and confine ordinary Codex source references to that base. A
fixture source outside that base cannot receive completed source-review credit.
The direct daemon corpus explicitly supplies workspace, so it exercises a
different delivery path from installed registrations.

`registration_witness.py` runs the real adapter and receiver methods in separate
processes against baseline and candidate source snapshots. All 1,264 materialized
baseline source and supporting contract files, totaling 17,725,447 bytes, were
verified against their original Git blobs after the witness. No baseline bytes
were edited. The four JSON reports retain the actual registered query, manifest
workspace, fallback-workspace presence, receiver-admitted workspace, source
hashes, and payload hashes. Both source versions admit `None` before the fixture
change and the owned workspace afterward, for each priority event.

The witness uses the frozen `codex/PostToolUse/benign/1m` case and a separate
empty command input. All four reports retain 386 declared cases and the unchanged
1 MiB content digest
`6aeb57a86380870445759dc201905df48c3750c9836ed503204d7bb6c664e674`.
The corpus oracle, payload construction, expected fields, selection, and deadline
constants remain byte-for-byte unchanged. The witness uses an inert owned
interpreter solely for registration and stops at the receiver's normal
admission-to-policy boundary. It does not execute authenticated HTTP transport,
native review, performance sampling, or installed-wheel qualification.

Validation recorded here:

- Four added regression cases fail against the unchanged fixture in 0.78 seconds:
  both Codex events omit the query workspace, and empty-command/empty-output
  delivery admits `None`. With the correction, all 42 priority launcher and
  registered-contract tests pass in 3.55 seconds, including preservation of
  Claude registrations and exact subprocess input without an injected `cwd`.
- Ruff check and format check pass for the three changed Python files and the
  witness. Focused BasedPyright analysis of the fixture reports zero errors and
  28 warnings. It is not a new full-repository type qualification.
- Removing only the added `workspace_override_explicit=True` keyword restores
  the original fixture AST. Removing only the assertion message described below
  restores the entire original approval test AST. Production Python, Rust,
  workflows, corpus, deadlines, original PRD/TODO, and requirement ledger are
  unchanged by this commit.

The unrelated Codex empty-command approval failure in
[CI run 35276260830, shard 20](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260830/job/105387963658)
reported only `failed` versus `resolved` after 218 passing and eight skipped
tests in 45.87 seconds. Its assertion now displays the controller's existing
bounded result, which already contains sanitized failure category, origin,
location, digest, and durable resolution metadata. The two-second resolver
budget, three-second poll budget, predicates, and approval policy are unchanged.
This is a diagnostic improvement, not a claim that the original failure's cause
has been established or fixed.

Original failures remain available. The first new admission test also expected
the receiver to retain `guard_remaining_ms`; the receiver already consumes that
hint before policy admission. Its initial log is preserved separately from the
corrected four-case regression log. Two initial baseline witness attempts failed
during imports because the source-only extraction lacked unchanged supporting
contract files and one public contract document. Their logs are retained; the
successful attempts followed exact materialization from the same baseline.
The first type-check launcher exited before analysis because its restored
entrypoint referenced a previous environment; the successful invocation used
the same installed checker module through the available interpreter.

The Mac baseline failures remain separate: both retained startup stacks stop
inside `socket.getfqdn`, called by `HTTPServer.server_bind` during daemon
construction. This workspace registration change does not address those
constructor failures, the candidate's native command-authority contention, or
the outstanding performance/release gates. No qualification status is advanced.
The full hosted records are retained under
`docs/guard/evidence/implementation-7a387-hosted-final`; exact extraction ranges
and decoded hashes for the small excerpts here are in
`extraction-provenance.json`. The manifest lists each local artifact and, for
gzip files, both encoded and decoded identities.
