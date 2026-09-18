# Configured hook context reaches the daemon receiver

The bounded CLI hook bridge previously omitted configured `--home` and
`--workspace` values when it used the daemon fast path. The generated project
command contained those values, but the actual request had no query parameters.
The unchanged receiver therefore reached policy preparation with no workspace.
Source commit `d8a4259a7145a5cecc0524b80ea8cb27e287eb21` forwards the original
command arguments to the daemon helper, reuses the existing strict argument
validator, and URL-encodes only the admitted context. The receiver now admits the
configured project workspace. This is a separately demonstrated defect; the
retained hosted failures did not identify their failing cases or native witnesses.

## Before and after witnesses

All three witnesses install the real Copilot registration, read its generated
global and project commands, construct the actual bridge request, and pass its
query and the frozen `copilot/preToolUse/benign/small` payload through the real
receiver. Request construction stops immediately before network I/O. Receiver
execution stops immediately before the original policy preparation barrier. No
daemon, launcher process, native evaluation, or performance experiment runs.

| Witness | Source used | Actual global request | Actual project request |
| --- | --- | --- | --- |
| [Frozen baseline](baseline-receiver-context-witness.json) | Immutable Git source `2e672d2d950c6ec471005ddba46e49bba16dc23b` | No query; no explicit home admitted, workspace absent | No query; no explicit home admitted, workspace absent |
| [Before repair](candidate-receiver-context-witness.json) | Native CI Linux wheel with source bytes verified against `590ce01334a7724f3f1349b2ab252110a5a268f5` | No query; no explicit home admitted, workspace absent | No query; no explicit home admitted, workspace absent |
| [After repair](after-receiver-context-witness.json) | Committed local source `d8a4259a7145a5cecc0524b80ea8cb27e287eb21` | Configured home admitted; workspace remains absent | Configured home and project workspace admitted |

Here “no explicit home admitted” means the query validator received no home;
the daemon still owns its original home context. The two earlier witnesses also
feed a control query made only from the existing
configured flags into the unchanged receiver. That control already admits the
project workspace. The after-repair actual request matches that control.
Registration digests differ across witnesses because registrations embed each
isolated temporary location. The frozen payload digest is identical in all three
witnesses; no `cwd` was added. Existing receiver removal of transport metadata is
recorded explicitly. The after-repair witness also checks unchanged request body,
authentication value, POST method, and five-second timeout.

The native CI wheel came from artifact `10541723683`, containing
`native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl`, built at test merge
`6981551052e75dfee9f372513177caed76df53a8`. That merge has the identical source tree
as source590. [Source materialization](source-materialization.json) retains the
archive and wheel digests. The complete hosted identity and artifact inventory
remain in the separate
[terminal source590 package](../implementation-590ce0-hosted-final/TERMINAL.md).
This package contains the exact relevant source modules, not the full wheel ZIP.
The paired installed baseline wheel was not uploaded; the baseline witness uses
immutable Git source and makes no claim to have observed that wheel.

## Preserved admission and fallback behavior

The reused parser requires the exact configured guard home and harness. Optional
home/workspace values must be absolute, and duplicate, missing, or unknown flags
are rejected. For nonfrozen commands with unrecognized grammar, the helper
returns before reading daemon state or authentication; the original CLI fallback
receives the original arguments, body, working directory, and timeout. Existing
frozen-command rejection remains unchanged.

The [unchanged receiver controls](candidate-receiver-negative-witness.json)
exercise trusted flags, relative paths, duplicate flags, unknown flags, missing
values, wrong harness, and cross-session paths. In the existing native-required
receiver, invalid metadata records its existing path rejection and continues to
the policy barrier with daemon-owned context and no workspace. These controls
do not assert an HTTP rejection. The existing exception for admissible owned
temporary workspaces remains intact. Repair tests separately reject a workspace
outside the admitted roots and that exception.

The [source preservation receipt](source-preservation.json) checks the entire
receiver, configuration scope, registration factories, frozen workload, and
qualification workflow bytes. AST comparisons establish that the bridge differs
only by forwarding its original arguments, and the daemon module differs only
by the optional parameter, admitted context projection, URL encoding, and their
required imports. The strict validator is unchanged. Body, authentication,
timeout calculation, response limits, verdict rendering, and CLI fallback keep
their existing implementation.

## Validation and independent review

[Validation](validation.json) records 198 passing tests in the complete bounded
CLI family. The [exact final test output](final-tests.log) and its
[tool receipt](final-tests-tool-result.json) are retained. The real registration
test includes spaces, quotes, query delimiters, and Unicode in paths; it checks
that those characters remain path data through encoding and receiver admission.
Additional controls cover malformed argument fallback, receiver path rejection,
loopback validation, and missing authentication. Ruff check/format and the
production-module typecheck passed; those two results are owner observations
without separately retained stdout. An initial five-failure test iteration is
recorded with its test-only corrections in `validation.json`.

The [independent review](independent-review.json) captured the four exact source
digests before and after inspection, found no substantiated issue, and confirmed
the AST and receiver boundaries. That reviewer ran no tests; its review is
separate from the execution receipts.

## Evidence and qualification limits

The frozen baseline bytes, global registration, payload, and `cwd` behavior are
unchanged. Global registration still has no configured workspace, so this repair
does not establish global route correctness. The controlled fresh store has no
managed installs after the authority fixture and Copilot registration, and its
unmanaged gate results are recorded only for that assembly. Those observations
do not identify historical daemon state.

At source590, both Linux priority-input arms retained only
`priority_launcher_input_route_mismatch`; the candidate registered-surfaces
failure retained an assertion at `_run_registered_surface_corpus:273`. The old
artifact contains no private case journals or actual failing route witness.
Neither failure can be attributed to this project context defect from an
assertion digest. This package does not clear either failure, the baseline
projection failure, global scopes, or any performance or migration gate. Future
failure context is covered separately by the bounded
[registered-surface diagnostic](../registered-surface-failure-context/README.md).

## Package layout

`manifest.json` uses paths relative to its own directory, with explicit schema
and path-base metadata. Every indexed file is contained in this package.
`source-preservation.json` maps immutable repository source paths to frozen gzip
copies and decoded byte digests. Gzip copies preserve the exact source bytes and
use a zero timestamp; the manifest records both stored and decoded lengths and
digests. The original before/negative witness reports, scripts, and independent
review receipt are copied without rewriting their bytes.

The earlier witness scripts retain the original materialization layout they
used. Replaying them requires the pinned repository sources and the identified
native CI wheel. The after-repair script accepts explicit source-root,
fixture-root, output, and source-commit arguments. The frozen modules in this
package support byte-level review; they are not an installable Python checkout.
No private temporary authority state, credentials, raw request paths, or journals
are included in the witness reports.
