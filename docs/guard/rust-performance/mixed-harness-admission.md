# Mixed-harness HTTP admission diagnosis

This is correctness diagnosis for the legacy daemon acceptance workload at source
base `6971a4331`. It is not installed Rust qualification or a paired performance
comparison. The test uses actual daemon TCP connections and authenticated
challenge/hook requests, with the existing test-only Python semantic oracle.

## Proven request-capacity failure

Round-four CI run `35206822177`, job `105154822764`, failed the frozen
`mixed-harness-fairness` workload: 23 of 24 secret requests were denied, 208
routine requests were allowed, and nine requests had generic HTTP 503 failures.
The old fixture discarded the response body, so it did not identify the failing
admission layer.

Bounded local tracing reproduced a request-capacity rejection after correcting
the fixture concurrency. The rejected request transitioned from `critical` to
`general`, ran on `guard-http-general-30`, and encountered 32 held general
permits with 42 accepted sockets. Transport rejections and runtime scheduler
rejections were both zero. The request was rejected before runtime scheduling.

The identity challenge keeps its TCP connection and handler alive for the next
request. Initial socket classification can place that handler on either executor;
the next hook directly acquires a general permit. A client can receive a complete
response and offer another request before the previous server handler finishes
and releases its permit. Thus 32 concurrent clients do not imply at most 32
retained general permits at every handoff.

General acquisition now tries immediately, then waits for at most 50 ms when
saturated, capped by the remaining original socket admission deadline. Permanent
saturation still returns HTTP 503. Request, connection, executor, queue and
per-harness limits are unchanged. The existing three-second hook admission
deadline is not restarted. No hook retry was added.

This small wait does not establish full control-worker isolation. Once admitted,
a hook on a control worker can still occupy it for its existing execution budget.
The focused critical-capacity test proves separate semaphore availability during
the bounded handoff, not independent executor availability during arbitrary hook
execution.

## Fixture correction and evidence

The manifest declares four clients, each with 60 requests and concurrency eight.
The original single 32-worker FIFO pool enqueued all of one client's requests
before the next client's batch. One client could therefore borrow all 32 slots.
The corrected driver gives each client its declared worker count and offers
clients in round-robin order. The 240 requests, secret stride, total concurrency,
latency assertions and all-zero-error acceptance criteria are unchanged. An
existing challenge retry remains unchanged; failed hooks are never retried.

Error diagnostics read at most 4,097 bytes to admit at most 4,096 bytes of response
content, then export only fixed reason names. Unknown bodies are not copied.
The result separately retains transport, HTTP request-capacity and runtime
scheduler rejection counters. Deterministic tests verify per-client progress and
concurrency, exact single execution of every offered request, and bounded error
classification.

The companion JSON retains four complete local aggregate results, including every
failure from those executions. They ran on a shared host without a timing
reservation and must not be compared as a measured speedup:

| Local stage | Routine allow | Secret deny | Typed deadline failures | Generic failures | p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Corrected fixture, coverage | 177 | 21 | 41 | 1 | 5585.747 |
| Corrected fixture, untraced | 214 | 22 | 0 | 4 | 1999.191 |
| Corrected fixture, boundary trace | 215 | 24 | 0 | 1 | 1914.524 |
| Fixture plus bounded handoff | 215 | 24 | 0 | 1 | 1708.144 |

The final execution had no HTTP 503 or capacity rejection but retained one HTTP
408 and exceeded the frozen untraced 1,000 ms p95 limit. It **failed** acceptance.
The preceding untraced execution also retained a disconnect and two broken pipes.
No failure was converted to an expected pass, and no budget was raised.

Earlier executions without a retained full aggregate also failed: the original
untraced fixture returned 20 secret denials, 194 routine allows, 24 typed deadline
failures, one disconnect and one broken pipe. The original-concurrency coverage
run recorded 18 HTTP request-capacity rejections, zero transport rejections and
no scheduler rejection. Those partial observations are not reconstructed as full
JSON results.

Independent review also identified separate unclassified-header watchdog races:
header consumption can precede classification, and an expired snapshot can become
stale before socket closure. The separate correction below does not establish the
cause of the observed HTTP 408.

## Buffered-header watchdog handoff

The worker now checks for complete buffered headers before starting the HTTP
parser and transfers their ownership under the unclassified-connection lock.
The watchdog revalidates the exact socket/deadline entry under that same lock
before closing it. A previously captured expired entry cannot close a connection
that another thread has since classified.

The old `recv(MSG_PEEK | MSG_DONTWAIT)` could still wait in CPython's positive
timeout readiness check, and `MSG_DONTWAIT` is absent on Windows. The probe now
uses a context-managed duplicate with independent Python timeout metadata. For
an already admitted positive-timeout or nonblocking socket, the duplicate keeps
the endpoint in its existing OS nonblocking mode and peeks at most 65,536 bytes.
It neither consumes data nor changes the original socket's Python timeout.
Blocking-mode sockets are rejected by this internal probe. Python documents the
[shared endpoint timeout behavior](https://docs.python.org/3/library/socket.html#notes-on-socket-timeouts)
and [portable socket duplication](https://docs.python.org/3/library/socket.html#socket.socket.dup).

The duplicate shares the OS endpoint and its mode; only the Python timeout
metadata is independent. The no-transient-mode-change argument is therefore a
source contract, not merely a before/after observation:

1. `_guard_admit_request` sets a positive timeout before scheduling. If that
   setup fails, it releases admission and closes the socket instead. The later
   daemon setters request only `False` or positive timeouts; body timeout values
   are checked to be positive before use.
2. CPython's socket constructor either leaves the inherited OS flags alone or
   requests nonblocking mode. `socket.dup` then copies the original nonnegative
   timeout. Neither step requests a temporary blocking mode.
3. `setblocking(False)` requests `internal_setblocking(..., 0)`, which sets
   `FIONBIO=1` or adds `O_NONBLOCK`; it does not clear that shared flag.
4. A socket with `gettimeout() is None` is declined before duplication. The
   dedicated regression makes any attempt to duplicate such a socket fail.

The official source was inspected through GitHub at these exact tags:

| CPython tag | `Modules/socketmodule.c` blob SHA | Constructor and mode functions |
| --- | --- | --- |
| v3.10.0 | `898ec05ab7b1d958c880698065ead0e0ffb9cee8` | [source](https://github.com/python/cpython/blob/v3.10.0/Modules/socketmodule.c#L958) |
| v3.12.14 | `27afd73d9704db9bb0d1bfb28af1e6013c97f7cc` | [source](https://github.com/python/cpython/blob/v3.12.14/Modules/socketmodule.c#L1036) |
| v3.14.0 | `92c9aa8b510dca34095b01063fbc017546a810ea` | [source](https://github.com/python/cpython/blob/v3.14.0/Modules/socketmodule.c#L1100) |

The local Python 3.12.14 duplication wrapper matches the
[tagged Python implementation](https://github.com/python/cpython/blob/v3.12.14/Lib/socket.py#L277),
blob `91782b30ae8d094fbda099fde18ce906f6d8247f`. A syscall-trace attempt was denied
by the environment's ptrace restriction; no syscall-trace proof is claimed.

The synchronous transport call graph adds
`_process_request_worker → _buffered_request_headers_complete → gettimeout / dup /
setblocking(False) / recv(MSG_PEEK) / duplicate close`. The background watchdog
uses the same bounded probe, then the existing shutdown/close operation under
the expiration lock. The accepted socket, its original deadline and its
connection-bound identity proof are retained.

The two race regressions failed against the original source while empty/trickle
controls passed; all four pass with this correction. The tests use real socket
pairs, the actual request worker and HTTP parser, event barriers and a manually
advanced clock. They start no database or semantic engine. Tests also cover an
empty positive-timeout socket, non-consuming complete-header peeks, original
timeout/socket usability, and operation without `MSG_DONTWAIT`.

That first correction covers complete headers already buffered at worker handoff
and stale expiration snapshots. The follow-up below covers the separate initially
incomplete-header and overload-eviction boundaries. No header/body deadline or
framing limit was increased. Simulating absence of a flag on Linux is not an
actual Windows runtime qualification.

## Initially incomplete headers and overload eviction

The follow-up starts from integrated source `27da1a51b`. If a connection remains
unclassified at handler setup, `InitialHeaderReader` observes each raw read and
the initial header terminator while holding the existing classification lock.
Only the nonblocking receive and bounded observation occur inside that lock;
readiness waits occur outside it. Complete framing therefore transfers ownership
before the standard buffered HTTP parser can consume it. This closes the case
where an initially partial header finishes after the earlier worker probe.

The reader retains two trailing bytes to recognize a terminator split between
reads. It does not interpret the request line, impose a new aggregate header
limit, or alter CPython's syntax, line-size or header-count validation. In
particular, CPython still parses headers after a two-word HTTP/0.9 GET request;
that request line alone must not remove the initial deadline. Header bytes,
binary body bytes and subsequent requests remain in the buffered input stream.

The original absolute 400 ms header deadline is checked before and after each
initial receive and before every readiness wait. Receiving another byte cannot
reset it, and an expired reader cannot resume reading through a later retry.
After complete framing, subsequent raw reads use the original socket and its
existing body/keepalive timeout. Auxiliary selector and duplicate descriptors
are closed at the handoff or during handler cleanup; the original socket remains
owned by the existing server lifecycle.

The added synchronous call graph is
`_GuardDaemonHandler.setup → InitialHeaderReader → gettimeout / dup /
setblocking(False)` and `BufferedReader → readinto → recv_into / selector
register / select`. The selector wait uses only the remaining original header
budget. Its nonblocking receive and framing update share the classification
lock, and its wait does not. Once framing completes, selector/duplicate close
precedes the next original-socket `recv_into`. The same admitted-socket mode
argument documented above applies; blocking-mode callers are refused before
duplication. The complete-buffered worker fast path does not install this reader.

Overload eviction now revalidates its exact selected socket/deadline entry and
closes it while holding the same classification lock. A connection classified
after selection retains its socket and permits. Capacity release occurs after
leaving that lock, preserving the existing idempotent release logic and avoiding
a recursive classification-lock acquisition. No connection, request or executor
capacity was raised.

The independent stale-eviction regression failed against the preceding source
while its cleanup controls passed. With the correction, classification after
selection preserves both the live connection and its held request permit;
actual eviction and concurrent worker/discard cleanup each release capacity
exactly once. Three real-parser completion regressions also fail when the new
reader installation is disabled, across CRLF, LF and mixed valid terminators.
That is a deliberate mutation of the corrected source, not a separately pinned
full-workload baseline run.

## Focused validation

The handoff regression uses actual TCP and the production identity challenge,
pauses the previous response before its permit is released, and releases it only
after the replacement begins bounded admission. Additional tests verify original
deadline retention, no wait after expiry, no permit leak on rejection, and
separate critical-request capacity. Broader adversarial framing, slow-client,
overload and liveness checks accompany the change. Installed and full workload
acceptance remain separate obligations.

The combined handoff, fixture and adversarial transport suite passed 33 tests in
169.41 seconds. After adding three further fixed error-name cases, the final
fixture diagnostic suite passed all 12 tests in 0.39 seconds. Ruff and whitespace
checks passed. BasedPyright reported zero errors; the existing large server module
still emits warnings, so this is not a warning-free claim.

With the paired watchdog correction, all 24 adversarial transport and request
handoff tests passed in 180.09 seconds. The six header/probe regressions passed
in 2.09 seconds; the subsequently added blocking-socket refusal test passed in
0.84 seconds. Final Ruff, formatting and whitespace checks passed. These checks
do not turn any retained 240-request workload failure into a pass.

For the initially incomplete-header follow-up, 62 focused reader, real-parser,
handoff and eviction tests passed in 2.62 seconds. They cover every split point
of a complete header, all three accepted line-ending terminators, binary bodies,
subsequent buffered requests, HTTP/0.9 partial-header expiry, unchanged HTTP
414/431 parser limits, valid aggregate headers above 64 KiB, deadline crossing,
descriptor cleanup and exact single capacity release.

The first broader run retained **32 passes and one failure** in 204.16 seconds.
Its 24 adversarial/handoff cases passed. The bounded-server overload case passed
its live HTTP 503 and latency assertions, then failed because its test compared
the process-wide historical high-water mark of 12 against that test's two-slot
server limit. A separate test-only correction retains the cumulative collector,
compares its high-water mark with the prior snapshot, and requires exact deltas
of two accepted requests and one rejected request. Production admission limits
are unchanged. The final normal pytest invocation passed all nine bounded-HTTP
tests in 17.34 seconds, and the overload regression passed in 0.49 seconds with
the preceding high-water mark explicitly seeded to 12. An exploratory attempt
to seed the entire suite through `python` stdin retained eight passes and one
test-harness failure: Python's multiprocessing spawn could not reload a
`<stdin>` main module. The subsequent normal pytest invocation uses a reloadable
entrypoint; no production timeout or admission criterion was changed.

The new transport module has explicit entries in both ownership inventories and
the semantic and I/O call graphs. Socket operations are admitted only in their
named lexical class methods; content reads, hashing, JSON decoding and semantic
evaluation receive no exemption. All three targeted I/O inventory and mutation
checks passed in 144.83 seconds. The full ownership/semantic/capability run
initially retained 71 passes and two failures: the new socket classifications
omitted their lexical class prefix, and the capability-count test still expected
104 files instead of 105. After correcting these explicit inventory entries, the
three I/O checks above and both capability checks passed; the latter took 206.35
seconds. Together with the 71 passing cases, these cover all 73 distinct tests
from that full run. Ruff, formatting and whitespace checks passed.
Scoped type checking reported no errors after correcting the existing protocol
cast at the I/O gate's observation boundary; warnings remain in the large server
and gate modules, and the raw buffer adapter uses an explicit `Any` annotation.

No local 240-request workload was repeated after the watchdog corrections. The
frozen all-zero-error and latency acceptance criteria remain unproven by these
component correctness tests and require the unchanged real CI workload. No
Windows runtime, installed native qualification or performance speedup is claimed.
