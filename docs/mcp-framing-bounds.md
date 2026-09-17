# Local MCP transport limits

RSP-101 adds explicit framing, queue and unmatched-response limits to the
managed runtime MCP proxy and the generic stdio proxy. These are Python
transport changes. They do not establish a Rust migration benefit or replace
the optimized proxy benchmark required by RSP-103.

| Boundary | Limit | Failure behavior |
| --- | --- | --- |
| A JSON line, including its newline | 4 MiB in UTF-8 | Reject an oversized or invalid UTF-8 frame and stop the session |
| Incomplete pipe frame | 30 seconds from the first received bytes | Stop even if an idle client otherwise has no timeout |
| Runtime child output queue | 64 frames and 16 MiB of encoded lines | Nonblocking admission; overflow marks the session terminal and quarantines the child |
| Unmatched responses, per direction | 64 responses and 8 MiB of encoded JSON | Stop before adding the response that exceeds either limit |
| Frames in one operation and its nested operations | 4,096 | Stop a notification/request flood |
| Nested transport operations | 16 | Stop recursive requests before an unbounded call stack |
| Child response and ordinary writes | Existing configured timeout, capped at 30 seconds | Stop the child on timeout or ambiguous write failure |
| Inline approval input | Existing configured approval timeout, default 120 seconds | Return the existing cancellation outcome on timeout |
| Nested request timeout error delivery | At most 250 ms after expiry | Only a JSON-RPC timeout error is permitted; it cannot extend or replace the expired request |

These byte ceilings describe retained encoded data, not exact Python RSS.
Decoded objects and tool catalogs have separate storage costs. A proxy can have
one child queue and an unmatched-response buffer in each direction. The
limits are explicit compatibility boundaries for formerly unbounded inputs;
callers that need a result larger than 4 MiB must use a different application
representation rather than expecting this transport to accept it.

On POSIX, all reads use one stateful owner per stream and nonblocking byte
reads. Readiness is followed by `os.read`, never a potentially blocking text
`readline`. Partial bytes, split Unicode code points, and prefetched complete
lines survive quiet polls and nested approval reads. An idle client can wait
indefinitely before sending its first bytes; an incomplete line cannot. EOF
with a partial pipe frame is an error.

Windows anonymous pipes use one reader worker per stream, two bounded 64 KiB
chunks, and the same incremental frame assembly and caller deadline. The
worker owns a duplicated descriptor so retirement cannot redirect a later read
to a reused descriptor. Closing the peer releases a blocked operating-system
read. A retired client stream cannot be reopened by the proxy; a blocked worker
on an externally held client pipe is a daemon thread and is not claimed to have
completed before that peer closes. Generic in-memory fixtures use a bounded
read; an unsupported shared stream without a descriptor is rejected.

Writes are bounded too. POSIX uses nonblocking raw writes with one deadline.
Windows writes raw pipe bytes in a single worker, avoiding text-buffer locks
during timeout cleanup. A failed or timed-out write permanently retires that
stream, marks the proxy terminal, and quarantines the child. The proxy never
retries the frame or forwards another request in that session. Some bytes may
already have crossed the pipe, so the event records uncertain delivery rather
than asserting that no operation occurred. Cleanup avoids closing a buffered
writer while another thread might own its lock.

Output-pump retirement is bound to the captured queue and process generation.
An old pump cannot poison or kill a replacement child. An idle runtime client
is checked every 100 ms for terminal transport state without imposing an idle
session timeout. A failed notification has no JSON-RPC response ID, but it
still ends the session with a failure exit; another client message is never
required to trigger cleanup. A terminal failure is also checked before a
buffered or freshly handled normal result can be returned.

An operation has one monotonic deadline. Notifications, unmatched responses,
and nested requests cannot replenish it. While waiting for approval input or a
nested client response, the runtime proxy polls the child at most 50 ms apart,
forwards notifications, and applies catalog invalidation. Queue admission does
not block the producer indefinitely if the client stops reading.

The final prewrite catalog drain still requires the existing 5 ms quiet period.
It processes every admitted queued frame and validates the same catalog
generation, lifecycle state, and complete fingerprint before writing the tool
call. A flood cannot keep this drain alive forever: its enclosing deadline and
frame budget produce a terminal failure. Launch identity quarantine and the
existing approval consume checks remain in their original ownership paths.

Validation covers real partial/full POSIX pipes, Unicode fragmentation,
oversized/unterminated frames, a simulated Windows pipe-worker branch, bounded
worker reuse, queue and response-count/byte ceilings, deadline preservation
under notifications, and pending-approval catalog invalidation. Existing
runtime approval, final-prewrite, launch-identity, and harness proxy regressions
are exercised alongside the new tests. Actual Windows runner execution remains
part of release qualification; the simulated branch is not platform evidence.
