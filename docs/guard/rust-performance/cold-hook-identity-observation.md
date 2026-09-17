# Cold lifecycle identity observation

The additional `runtime_identity_cold` scenario measures identity work in a new
fixture child before the real daemon constructor, through its first ordinary
Claude `PostToolUse` request and two warm controls. It preserves the existing
`runtime_identity` prepared-resident three-hook scenario unchanged. Source and
synthetic correctness tests do not establish installed cold measurements;
RSP-025 still needs the actual platform observations.

The child interval begins after interpreter startup, imports and private journal
admission, before observer installation. It includes observer installation
overhead, real daemon construction, policy publication, resident preparation
and the first handler return. The fixture may prepare the resident before the
first request: this is recorded lifecycle work, not a claim that the hook itself
starts with an unprepared resident. No executable, capability, proof or OS cache
is cleared. The scenario does not claim a cold OS cache, cold executable cache,
whole-process CPU, or interpreter/import identity coverage. The parent's existing
fixture-startup interval and each HTTP/request-call interval are retained as
separate, potentially overlapping spans; they are not added together.

The observer forwards each original call once and preserves its return value or
exception. It observes canonical runtime status, full executable validation,
accepted SHA-256 bytes, live-proof lookup, capability-cache calls and actual
capability subprocess calls. Main-thread preparation, policy-publication work,
hook work, cleanup and unassigned work have separate owners. The child journal
retains exact per-call counters, start/end phases and timestamps, per-hook
start/return timestamps, and parent call IDs. Thus each of the three hooks keeps
its own identity latency/hash-byte record even though the compact public
summary omits the detailed call list. Status wall and calling-thread CPU spans
are inclusive. Nested status calls, phase crossings, unfinished calls,
unassigned work, ambiguous concurrent capability-cache deltas, unexpected hooks
or missing/mismatched runtime identity prevent complete attribution. No
process-global cache delta from overlapping work is credited as a hook hit.

The expected native build, runtime digest and installed-package digest are
bound into both journals and the summary; the enclosing pair manifest/archive
also binds the exact source and arm. Each returned status is checked against the
expected native build/runtime identity. The three requests use the existing
1,024-byte benign workload and independent native route, native result, setup
and delivered-response oracle. Instrumented timings do not enter headline
latency series or alter any acceptance flag.

All original bounds remain: the ordinary constructor path, 400 ms native
readiness, five-second HTTP request, 30-second fixture control wait and existing
worker containment. Incremental child writes add diagnostic I/O inside those
original deadlines. No failed operation is retried. The observer uses the
existing one-second drain bound and records incomplete drain. A startup failure
before any request retains three unoffered requests; a missing terminal keeps
request-start state unknown. The original startup failure and the exception
returned after startup cleanup are separate fields. A failure in cleanup after
successful requests is explicitly reported. Normal completion additionally
requires the contained child to exit successfully.

Three new flat private files are added per arm:

| Suffix | Bound | Contents |
| --- | ---: | --- |
| `-identity-cold-observer.jsonl` | 262,144 bytes | Incremental child records, including interrupted preparation |
| `-identity-cold-cases.jsonl` | 98,304 bytes | One header, three offer/terminal pairs, final summary |
| `-identity-cold-summary.json` | 36,864 bytes | Compact summary, final journal metadata and failure wrapper reserve |

The child admits at most 96 calls, 224 records and 4,096 bytes per record, with
an independently enforced 256 KiB file cap. A regression calculates the closed
record shapes at maximal 64-bit counter width, including all 32 reserved
non-call records, and proves they fit that cap. The parent permits exactly three
attempts; its reachable bound is seven 8 KiB records plus a 32 KiB summary and
8 KiB envelope reserve. The summary-file bound includes final journal metadata
and the outer retained-scenario failure wrapper. The exact new pair addition is
at most **794,624 bytes across six files**. The suffix inventory is **20**, and
the fixed pair inventory is **59 files**, below the unchanged 256-file archive
limit. The existing 32 MiB per-file and 128 MiB archive limits are unchanged;
this incremental bound is not a claim that arbitrary other scenario output
can consume unlimited remaining space.

Child journal creation reuses protected Windows DACL/0600 atomic creation and
retained-parent descriptor identity validation; reads use the existing private
bounded reader. Raw hook bodies, file paths, exception text and executable bytes
are excluded. Unknown or malformed journal fields cannot enter the finite
summary. Journals and summaries remain part of the encrypted private archive;
public projections preserve explicit missing/incomplete states.
