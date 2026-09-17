# Streaming exact MCP binding experiment (F)

F is an inactive, source-only follow-up to the completed
[E experiment](rust-performance-mcp-owned-preparation.md). It replaces temporary
completed binding buffers during freshness checks with a sequential comparison
against the same retained immutable binding. It also corrects an inherited
selection error found during independent review. B remains the product default,
E's source and all 64 measured cells remain unchanged, and RSP-100 remains OPEN.
The first preregistered F comparison later stopped at cell 20; its
[partial result and failure](rust-performance-mcp-streaming-preparation.md)
retain 19 completed cells, one failed baseline cell and 44 never-attempted cells.
No completed F campaign or activation is claimed.

## Exact comparison and retained boundaries

The separate `scripts/guard_mcp_streaming_preparation_pilot.py` file is an
explicit fork of E. Initial request, artifact and command bindings still use
E's restricted CPython protocol-4 Pickler and individually retain its 16 MiB
serialized limit. Each later comparison passes Pickler's exact output chunks
to a sink that checks them sequentially against the corresponding reference
range. The sink keeps a reference, byte offset and Boolean result. It never
copies or accumulates a second complete binding. Final equality also requires
equal total lengths, so a matching prefix or appended bytes cannot pass.

The sink rejects custom reference/chunk types before invoking their length,
equality or buffer callbacks. It continues serialization after a mismatch;
later custom values and the aggregate serialized limit still encounter the
original checks. There is no hash substitution, pickle decoder, new input-size
selection or omission of an authority boundary. Bindings remain private and
are absent from logs, stores, receipts and profile outputs.

F retains E's strict finite plain-JSON owner, alias-independent non-memoizing
codec, callback order, full original and owned input checks, current command
checks, per-preparation categories, exact saved-claim rebuilding and one-request
admission. Unsupported/custom/package and busy/nested requests continue through
B. The final 5 ms quiet barrier and original forwarding/inline deadlines are
unchanged. After encoding, F compares the value decoded from the actual immutable
wire bytes and forwards those same bytes through the unchanged framing writer.
Restoring a mutable owner after producing changed wire bytes cannot authorize
those bytes. A mutation after completed execution does not rewrite its outcome.

Python's [Pickler interface](https://docs.python.org/3.12/library/pickle.html#pickle.Pickler)
permits a custom `write(bytes)` sink. The existing deprecated `fast=True`
non-memoizing switch remains specific to the pinned CPython experiment. F does
not supply a portability decision or support a new kind of input object.

## Inherited method-selection limitation and F correction

Independent review found that E selected the final protected write by examining
the mutable message's method. Changing the owned method during the final quiet
barrier could select the original unbound writer, bypassing final equality. A
custom method could invoke its inequality callback before rejection. The
initial F fork inherited that selector. Two actual child-pipe regressions failed
before its correction: a changed plain method reached the child, and a hostile
method invoked its callback. The complete failure output is retained.

F now selects the admitted frame by object ownership:
`message is request.owned_message`. This identity selects the checks; complete
byte equality still authorizes the forwarded content. The pinned non-package
runtime passes that exact object through its final `_forward_message` call.
Separate multiplexed replies and notifications have distinct objects and
retain the original writer. The two new method tests now fail closed without
executing custom callbacks or writing the changed frame.

This is an additional, concrete limitation of frozen E's tested boundary. Its
earlier passing tests did not cover owned-method mutation at this point. The
existing E source, historical test result and measured raw campaign remain
unchanged; their finite scope must not be described as universal alias safety.

## Allocation feasibility, with the actual limits

The retained feasibility run compared E with the initial streaming prototype
before the final F file was created. It used six fixed synthetic shapes and
three alternating checks per shape on CPython 3.12.14 under the shared
measurement lock. Retained input objects, the complete owned object and the
reference binding were created before tracing. Values below are the additional
traced peak bytes for one comparison. All three observations of each arm and
shape had the displayed peak. They are neither process RSS nor route results.

| Synthetic payload | E temporary comparison peak | Streaming prototype peak | Largest Pickler output chunk |
| --- | ---: | ---: | ---: |
| 1 KiB ASCII | 9,082 B | 9,074 B | 1,142 B |
| 128 KiB ASCII | 263,231 B | 132,157 B | 131,072 B |
| Near-limit ASCII | 8,388,671 B | 4,194,877 B | 4,193,792 B |
| Near-limit Unicode | 8,388,671 B | 4,194,877 B | 4,193,792 B |
| Near-limit dense integers | 4,274,019 B | 71,021 B | 65,547 B |
| Near-limit nested records | 3,758,063 B | 71,189 B | 65,548 B |

The profile records all 36 allocation observations, their separate single-check
CPU observations and the observed chunk counts. Those few CPU values vary substantially
and cannot establish route performance. The prototype includes extra chunk
counters; these numbers are not relabeled as measurements of the final F file.
The [raw profile, exact historical profiler and manifest](rust-performance/evidence/mcp-stream-binding-feasibility/manifest.json)
preserve the attempt and source hashes. The historical profiler is retained
verbatim, including the source and output paths used for that attempt.

Large strings still cause CPython to allocate a complete UTF-8 output chunk.
The sink's serialized bound is checked when that chunk arrives; it is not an
earlier bound on Pickler's internal allocation. Initial retained bindings,
strict owned containers, the final decoded wire copy and the existing JSON
encoder are also still allocated. The observed reduction supports investigating
F; it does not prove that F removes E's Unicode/dense RSS regression or meets
the 30% benefit and 5% nonregression requirements.

## Source validation and remaining measurement

The final F-focused gate passed 44 tests in 11.39 seconds. It runs E's existing
authority predicates against F's own module and adapter, including the complete
96-case authority/browser comparison, actual child forwarding, mutation with no
child write, saved-claim consumption/rebuilding, original approval budgets and
fallback/custom-callback behavior. Those 96 comparisons are within the 44-test
result, not an additional disjoint count. The old external profile worker still
explicitly installs E; its profile/campaign tests are not credited as F.

New predicates cover arbitrary chunk boundaries, truncated and extended
references, exact type/order/signed-zero distinctions, alias-equivalent JSON,
cycles and limits, rejection of a custom value after an earlier mismatch,
freshness checks with the completed-binding buffer disabled, and a complete
forward that creates only the three retained request/artifact/command bindings.
An actual child-pipe test changes the final encoded value and restores the
owner before returning the bytes; F rejects the changed wire and writes nothing.
The final gate also covers unrelated child replies and real nested handle
calls: the nested call uses the captured B authority evaluator with a cleared
context, then restores the identical outer request and admission ownership
after both normal and exceptional inner returns.

The first invocation stopped during collection because the shared predicate
module lacked this repository's `tests` package prefix. It ran no test. The
corrected initial gate passed 39 tests before independent review identified the
method-selector issue. The collection failure, 39-test pass, two failed method
regressions and final 44-test pass are all retained; the test counts overlap.
Changed Python files pass Ruff and formatting. Product files and the frozen E
adapter, harness, tests, boundary document, report and raw campaign compare
exactly to the recorded base revision.

The independent source review found no remaining blocker after the selector
correction. It verified both final source hashes, all eight retained artifact
hashes/sizes and all seven frozen E source/evidence hashes. The reviewer read
the pre-fix failures and final test receipt without running duplicate tests.
That source review supplies no GitHub CODEOWNER approval or performance gate.

The [fixed first comparison plan](rust-performance/mcp-streaming-preparation-plan.md)
declared its route, unchanged input schedule, exact source/harness identities and
measurement lock before starting. That attempt stopped on a baseline-worker EOF
and preserves all completed, failed and never-attempted cells. Its evidence does
not identify a unique failure cause, establish a five-block performance gate or
supply a final-F phase profile. Any later experiment must keep this attempt
intact and declare a separately reviewed plan. No installed/platform/concurrent
qualification, general memory bound or release decision follows from the source
gate or partial campaign.
