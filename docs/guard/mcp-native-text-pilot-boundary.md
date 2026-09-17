# Experimental MCP text-facts boundary

This is an explicit source-route qualification experiment. No product import,
configuration option, launcher, or installed default activates the helper. The
retained runtime default is optimized Python B; universal structural-facts D
activation was rejected by its frozen comparison. RSP-100 remains OPEN.

The experiment replaces only four boolean text-predicate groups, expressed by
the existing 13 Python patterns. Python still owns input copying, exact request
binding, JSON serialization, camel-case and lowercase normalization, category
ordering, schema and argument interpretation, IP checks, current policy,
approval identity, receipts, catalog invalidation, and final forwarding. The
existing external 4 MiB request/reply line ceiling, queue limits, frame budgets,
and final 5 ms prewrite freshness barrier are unchanged.

## Request, response and identity

The private request is the 16-byte MFT1 header (magic, big-endian unsigned
64-bit sequence, unsigned 32-bit UTF-8 body length), then the exact immutable
Python-normalized text. The 16 MiB packet limit includes the header. Rust checks
that advertised length before allocating or reading the body. Nonzero sequence
numbers must increase strictly within the one private process generation. Normal
EOF before a new header exits cleanly; partial frames, invalid UTF-8, incorrect
magic, non-increasing identity, excessive length and failed writes exit with a
static failure and never echo input.

The reply is exactly 13 bytes: MFR1, the same sequence, and four predicate bits.
The Python owner validates every field, then probes at most one additional byte
to reject already available surplus output. It also requires a quiet stream
before each subsequent request. A delayed surplus reply therefore cannot be
accepted as the next response with a different sequence. Neither policy nor
trust decisions, credentials, catalog text or normalized text are returned.

One admission lock precedes encoding; there is one in-flight packet and one
helper per benchmark worker, with no additional private request queue. The
adapter keeps flags only inside one category-analysis invocation, bound to the
same immutable normalized string and exact known pattern tuple. Unknown groups
use the unchanged Python matcher. Context is discarded on every return or
exception; flags do not survive a new classification, approval wait, catalog
change or authority preparation. No mutable input identity replaces the existing
owned matching and freshness checks.

## Deadline, memory and process ownership

Admission, encoding, executable provenance, process startup, both IPC directions,
response validation and diagnostic helper RSS sampling consume one absolute
deadline, capped at 30 seconds and at the remaining enclosing operation budget.
Chunked reads and writes cannot replenish it. A selected helper failure retires
the session, kills the helper and allows at most 250 ms to reap it; an exceeded
reap allowance is recorded. It does not retry or switch the selected operation
to Python. A test delays RSS sampling beyond the budget and verifies zero native
completions, one terminal failure and one reap. An actual pipe test verifies that
a failed helper leads to zero child tool forwards.

Small text (fewer than 262,144 normalized characters), unsupported platforms or
exact text types, invalid UTF-8 and input exceeding the packet bound select
Python before native dispatch. These controls are counted. A retired helper
cannot recover through a later small-input selection. The full semantic oracle
sets the threshold to zero, proving native execution rather than accidental
small-input fallback.

Python encodes at most 65,536 characters per chunk, avoiding an additional joined
packet copy. Accepted chunks together fit the whole-packet ceiling. Detecting an
overflow can temporarily allocate one additional UTF-8 chunk of at most 256 KiB
plus its bounded string slice. Rust retains at most the admitted body, a fixed
header and reply, and the fixed RegexSet whose compiled and DFA limits are each
2 MiB. During one successful operation, the Python encoded chunks and Rust body
together retain fewer than 32 MiB of request bytes, plus fixed headers and the
recorded pipe capacities; they belong to the same single admitted operation.
An overflow chunk is detected before dispatch, so it does not add a second
admitted Rust body. Actual Linux pipe capacities are recorded in both directions. These are
explicit retained-data and admission bounds, not a global RSS ceiling: the
original normalized string, Python objects, allocator overhead and process
runtime remain additional memory. The C=1 measurement reports sampled helper
RSS, sampled whole-process-tree USS/RSS and whole-worker OS peak RSS separately.
It does not establish concurrent-session aggregate admission or a long-soak
memory bound.

The helper receives an empty environment, a fixed root working directory, an
absolute executable argv and closed inherited descriptors apart from its own
pipes. The requested executable is hashed before spawn. On Linux the actual
running executable is hashed through its process executable handle and must
match; the report records path, size, digest, device and inode. Source and actual
executable identities are checked before and after each case. Evidence contains
only those artifact identities, static counters, sizes and timing/memory data.
There is no payload log or normalized-text export.

## Exact predicate semantics

Rust receives Python's normalized text without normalizing it again. Its fixed
patterns spell out Python's Unicode whitespace set, including U+001C through
U+001F, instead of depending on a different regex engine's shorthand. Consuming
ASCII boundary alternatives preserve existence of a match for these fixed
predicates; the helper returns neither match counts nor offsets. The six Rust
tests cover protocol bounds and whitespace. The compiled Python oracle adds
adversarial boundaries, Unicode, exact categories, approval hashes and complete
policy results against frozen source.

## Comparison and selection limits

The ordinary 1/16/128 KiB controls use optimized Python B. Near-limit top-level
ASCII and Unicode text use frozen D as their stronger applicable Python
comparator. Both arms of every pair load the same runtime source; the native arm
adds only this explicit adapter. No native gain is credited to B-to-D changes or
to avoiding a known D container regression.

Five independent process blocks alternate arm order for each shape. Separate
instrumented cells attribute classification (including Python normalization),
facts snapshots, native IPC (including Python encoding), catalog hashing, policy,
persistence, serialization, waits and wrapping. Complete client latency retains
the deliberate barrier. Process-tree
CPU includes the proxy, synthetic child and native helper; helper RSS and both
private IPC byte counts are recorded. Every attempted cell and incomplete
oracle retain their failure and progress counts; completed traces are checked
for exact response, decision, notification, catalog and forwarding parity.

This source pilot supplies a conditional selection decision. It is not installed
CLI, Windows, macOS, TLS/live remote, release-tail or concurrent-load qualification.
No production activation or broad performance pass follows from a component
speedup, three diagnostic samples, or an unmeasured input shape.
