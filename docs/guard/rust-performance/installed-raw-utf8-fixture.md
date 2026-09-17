# Installed malformed-byte launcher observation

This fixture adds one exact malformed UTF-8 input for each installed Claude and
Codex PreToolUse/PostToolUse registration. It runs separately from the existing
16 text-input cases and from every timed series. It does not change a launcher,
default registration, runtime decision, deadline, or performance gate.

The source cutoff for this addition is `17d42da4eacdd44e3f3ef02f9e0556b99fd6da91`.
The earlier text-only runner could not offer invalid UTF-8: its `input_text`
argument was encoded to UTF-8 before writing. It also replacement-decoded both
captured streams. The existing text cases still list malformed UTF-8 as missing
qualification; this addition provides observations needed to settle that gap,
without changing their original expectations or claiming RSP-136 complete.

## Exact boundary

[`native_slo_raw_process.py`](../../../scripts/native_slo_raw_process.py)
passes the read-back registered argument vector directly to the installed
process launcher. It uses the same working directory, registration environment,
proof-override removal, daemon preparation, and contained process lifecycle as
the text fixture. Input is bytes, and stdout/stderr remain separate bytes. There
is no shell, interpreter wrapper, environment-selected runtime, semantic oracle,
or new native request.

The reused spawn, wait, group/Job termination, stream cleanup, and quarantine
primitives in `codex_hook_launch_runtime.py` and
`codex_hook_process_runtime.py` are byte-identical between frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` and this source cutoff. The fixture
retains the existing 10-second process deadline and no-breakaway Windows Job
containment. This new diagnostic has a 64-KiB combined capture budget; overflow
terminates through the same containment primitive and retains the collected
prefix with the overflow flag. The existing text fixture's 2-MiB limit is
unchanged. Accepted stdin bytes, successful
flush, I/O failure, truncation, timeout, containment, and exit are separate facts.
The actual wait result is retained as `observed_exit` even when failed containment
makes the existing accepted `exit` unavailable. Captured bytes are the exact
collected prefix; overflow or incomplete containment does not prove full EOF.
Accepted pipe bytes and flush do not prove the child interpreted every byte.

Each input is a short JSON-shaped object with the selected event and one `FF`
octet outside a JSON string. It is invalid UTF-8 and remains invalid JSON under
the tested single-byte decoding profile. This does **not** establish a universal
installed delivery result. The existing Codex `bounded_hook_input` reads through
Python's configured stdin codec before its bounded UTF-8 re-encoding check:

| Explicit test profile | Existing source boundary observed |
| --- | --- |
| UTF-8, strict errors | Initial read raises a decode error |
| UTF-8, surrogate escape | Re-encoding rejects the surrogate and returns `None` |
| CP1252, strict errors | Input reaches JSON parsing as text; the object is invalid |

Those are component source tests, not assertions about the actual codec or final
delivery on any runner. The raw fixture leaves Python's installed stdin profile
unchanged. Actual platform observations must establish and review their own
expected delivery profile before a parity gate can claim success.

## Retained facts and limits

[`native_slo_launcher_utf8.py`](../../../scripts/native_slo_launcher_utf8.py)
offers exactly four cases against the actual installed registrations. It checks
registration identity before and after each process, records route counters
around the attempt, and retains the fixture's actual native result separately
from the shape of stdout. A missing inner-result authority field is recorded as
`not_present`, never inferred to be Python or Rust. An unchanged allow-shaped
response does not prove Rust authority; an empty response or engine bypass does
not become native allow.

The existing offered/terminal journal is flushed for each case. Immediately
after process collection, before parsing or post-process assertions, an
exclusively created owner-private JSON file retains exact input/stdout/stderr as
base64. Separate fact files retain byte lengths and SHA-256 commitments, process
flags, exit, finite response shape, route counters, and observed native authority.
These flat JSON/JSONL files enter the existing encrypted private-sample archive;
public reports contain only bounded facts and commitments. Post-process failure
retains collected bytes and a failed terminal record. Unconfirmed containment
retains its facts and stops further offers. A hard interruption can
leave an offered record without a terminal result; it cannot create success.

The separate `priority_utf8` report uses `passed=false`,
`qualification_complete=false`, `native_allow_claimed=false`, and
`headline_timing_eligible=false`. `collection_complete` means that four process
observations were retained, not that their delivery, I/O, or authority passed.
It is not added to the current implemented semantic pass gates or latency
series. Existing failed text cases and the remaining malformed-input coverage
item remain visible.

The fixed indexed pair adds 20 files for both arms. A regression serializes all
eight maximum-size diagnostic captures with separate base64 padding and their
facts/journals/summaries: the increment remains below 0.7 MiB. Source inventory
checks count 49 total files for the current indexed plan, including its pair
manifest, below the unchanged 256-file cap. Individual diagnostic capture files
are below 88 KiB and therefore below the unchanged 32-MiB per-file cap. This is
an incremental footprint and file-count proof, not a formal bound on all other
journals. The unchanged 128-MiB total archive admission still rejects overflow.
Custom or unsharded multi-pair plans have no new capacity guarantee and remain
unsupported if their combined inventory exceeds those existing limits.

Local correctness tests exercise exact bytes through a real contained stdlib
child, combined capture limits, partial writes and failed flush/read handling,
codec boundaries, untrusted response shapes, registration/environment fidelity,
and capture retention after readback failure. They run no installed workload or
performance measurement. Four-platform installed execution, interpretation of
the observed delivery profiles, and any future parity acceptance remain pending.
