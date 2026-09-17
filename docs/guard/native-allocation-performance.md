# Native codec, identity and edge allocation evidence

The opt-in allocation diagnostic isolates actual timeout parsing, strict protocol
parsing, typed decoding, request identity, edge validation, receipt construction,
response serialization, and shutdown disposition. It covers small envelopes and
the exact 6 MiB native request limit. The counters identify remaining copies;
they do not substitute for installed latency or peak resident memory.

Evidence is [native-allocation-phases.v1.json](evidence/native-allocation-phases.v1.json),
with source commit `d9802fac2142bda7cd69906cb202748d24558abc`, executable hash,
process resource usage, 47 component records, and explicit unmeasured scope.
The instrumented allocator is pinned `stats_alloc=0.1.10` behind the optional
`diagnostic-allocations` feature and installed only under `cfg(test)`. Default
production builds contain no allocation observer, and application code retains
its prohibition on unsafe Rust.

## Measurement contract

Each component runs 30 samples in one isolated ignored test with one test thread.
Fixture preparation and input cloning happen before the counter/timer snapshot;
returned-value destruction and correctness verification happen afterward.
Destruction of consumed inputs remains inside the operation. Counters are
process-global, so other tests must not run concurrently. They report allocation,
deallocation, reallocation, and requested/freed byte totals; they do not report
peak live bytes. The reallocation byte delta overlaps the allocator's accounting
of allocation/deallocation bytes and must not simply be added to them.

The maximum fixtures use six strings no larger than the independent 1 MiB JSON
string limit, with the final string shortened to reach exactly 6,291,456 encoded
bytes. Padding is synthetic metadata. It exercises the wire/identity size limit,
not a claim that every semantic pretool field accepts 1 MiB strings: the pretool
extractor retains its tighter command-string bounds and can reject that payload.
The small pretool cases include an exact benign command and a destructive one.
Posttool fixtures carry benign inline output. No fixture command is executed.

The strict parse and typed decode use the same production functions. Identity
measurement includes the existing semantic payload copy and canonical hash.
Edge validation includes its serialized-size check and that identity work. The
combined edge component includes native evaluation, receipt construction and
response encoding with no policy store. These components overlap and cannot be
summed. Receipt and response encoding also have isolated measurements.

The timeout reference reproduces a full strict decode followed by reading the
deadline, while the current path uses the strict deadline projection. Both still
validate the complete JSON input. The shutdown reference reproduces the removed
post-evaluation full parse; the current path reads the already validated typed
disposition. Neither reference restores redundant work to production.

## Reserved local run, 2026-09-17

Linux x86_64, Rust 1.88 release profile. Other team agents paused builds and tests
for the serial run. Shared-host scheduling remained uncontrolled. All counts
below are per-call p50; the full evidence retains p95 and maximum values.

| Component | Small benign pretool allocations / bytes | Maximum pretool allocations / bytes |
| --- | ---: | ---: |
| Current strict timeout projection | 50 / 2,714 | 52 / 2,750 |
| Full timeout decode reference | 66 / 5,545 | 75 / 6,296,610 |
| Strict protocol JSON | 66 / 5,545 | 75 / 6,296,610 |
| Typed resident request decode | 29 / 3,627 | 38 / 6,294,930 |
| Request identity and payload copies | 108 / 11,950 | 131 / 33,563,834 |
| Edge bounds and identity validation | 109 / 12,974 | 132 / 41,953,658 |
| Typed receipt construction | 91 / 10,031 | 91 / 10,041 |
| Typed edge response serialization | 1 / 2,048 | 1 / 2,048 |

Maximum-size posttool identity allocates 33,563,988 bytes, and its edge bounds plus
identity phase allocates 41,953,820 bytes. These byte totals make request identity
copies and the serialized-size buffer the next measurable allocation targets.
Any change must preserve the exact canonical request digest, root-only omission
of transport aliases/timestamps, source binding, unknown-field rejection, and
the original deadline. No optimization to that identity contract is claimed by
this diagnostic commit.

For maximum shutdown input, the typed disposition performs zero allocations.
The historical full reparse performs 18 allocations totaling 6,293,196 bytes.
The current timeout projection allocates only bounded metadata despite scanning
the entire maximum input, whereas the full-decode reference materializes the
6 MiB JSON value. These counts substantiate the earlier duplicate-work changes.

Instrumented maximum-pretool p50/p95 times are 1.81/2.95 ms for timeout projection,
2.56/4.38 ms for its full-decode reference, 17.52/51.12 ms for identity, and
27.34/124.37 ms for combined bounds/identity validation. They include allocator
counter overhead and are not production latency qualification. The complete
diagnostic process used 6.47 seconds wall, 5.26 seconds user CPU, and 65,572 KiB
maximum RSS; that process RSS includes fixture preparation and allocator tooling.

## Reproduction and acceptance scope

Build first, then run the one ignored test under a measurement reservation:

```sh
cargo test --locked --manifest-path rust/Cargo.toml --release -p hol-guard-runtime \
  --features diagnostic-allocations --no-run
cargo test --locked --manifest-path rust/Cargo.toml --release -p hol-guard-runtime \
  --features diagnostic-allocations native_protocol_edge_allocation_phases \
  -- --ignored --nocapture --test-threads=1
```

RSP-037 now has small/maximum codec and allocation attribution, including the
client timeout parse, protocol parse, removed shutdown reparse, and edge copies.
These records contribute native inner-phase evidence to RSP-008. They do not
measure process startup, native connection, queue wait, policy-store authority
leases, asynchronous evidence submission, installed response latency, or peak
live allocations. The separate catalog/control matrix measures the J interpreter;
the installed phase profiler and platform gates must cover the remaining route.

## Follow-up: borrowed identity and bounded counting

Source commit `dc22fa6f0` replaces the allocation-heavy identity recipe with
borrowed, canonically ordered serialization into SHA-256. It also replaces the
temporary serialized envelope buffer with a checked, bounded byte counter. The
original baseline above remains intact. The paired follow-up evidence is
[native-allocation-streaming.v1.json](evidence/native-allocation-streaming.v1.json).

The complete semantic payload is still hashed. Dynamic object keys are explicitly
sorted; scalar encoding retains the existing canonical JSON representation.
The borrowed policy and source fields have the same lexicographic order and
null behavior as the prior JSON value. Only the same root transport keys are
omitted. No identity version, digest domain, request-size limit, source authority,
or deadline changes. The size writer checks integer overflow and rejects an
excess write before accepting it. Neither writer materializes an encoded payload.

A second reserved run executed the retained baseline binary and then the new
binary, serially, with 30 samples for each of the same 47 components. Both exact
binary hashes and all distributions are retained. New and baseline executable
rule digests naturally differ because source bytes are part of that identity;
the independent canonical-byte and fixed-digest tests establish request-contract
parity for identical semantic inputs. The diagnostic itself verifies every
returned identity and edge result against its untimed result within each binary.

| Fixture / component | Allocations before → after | Allocated bytes before → after |
| --- | ---: | ---: |
| Small benign pretool identity | 108 → 10 | 11,950 → 273 |
| Small benign pretool bounds + identity | 109 → 10 | 12,974 → 273 |
| Maximum pretool identity | 131 → 10 | 33,563,834 → 273 |
| Maximum pretool bounds + identity | 132 → 10 | 41,953,658 → 273 |
| Small posttool identity | 114 → 10 | 12,296 → 276 |
| Maximum posttool identity | 137 → 10 | 33,563,988 → 276 |
| Maximum posttool bounds + identity | 138 → 10 | 41,953,820 → 276 |

All rows report p50; allocation counts and byte totals were constant across all
30 samples for these fixtures. These shapes have a fixed number of object keys,
so allocation no longer scales with their string payload length. Arbitrary
payloads still allocate a bounded vector of borrowed entries per object to sort
its keys. This is not a claim of constant allocation for every JSON shape.

Instrumented maximum-pretool identity p50/p95 changes from 22.02/31.65 ms to
9.15/18.04 ms; combined bounds/identity changes from 27.67/44.42 ms to
12.29/17.38 ms. Small benign identity changes from 7.36/9.19 µs to 1.72/1.77 µs.
These times include allocator instrumentation and shared-host scheduling. Both
runs retain their outliers; they are component evidence rather than an installed
SLO. Whole diagnostic wall time is 6.26 → 3.26 seconds and process maximum RSS is
66,112 → 42,788 KiB, including fixture preparation and unrelated component phases;
neither value is per-request peak live memory.

Verification includes an independent copy of the previous identity recipe,
the existing cross-language golden SHA-256, benign/destructive/mixed-path inputs,
all root omissions with nested-key commitments, policy/source changes, Unicode
and escaping, JSON scalar kinds, and 4,096 deterministic floating-point bit
patterns with finite values checked against the existing canonical encoder.
The exact 6 MiB envelope passes; one extra byte, counter overflow, malformed
payloads, invalid request IDs, and serializer errors reject. Full Rust workspace
tests pass (254 tests, seven explicitly ignored diagnostics), as do all-target,
all-feature Clippy and the approval source gate. Both new production modules are
included in the Rust source-byte contract and its independent Python inventory,
which now contains 67 components.
