# Optimized Python package route attribution

This diagnostic extension was designed from source `6fcb746da`. It investigates
the remaining local route cost identified in [the first CI report](FIRST_CI_EVIDENCE.md),
without attributing those historical measurements to a newer source. The next
workflow records the exact candidate commit, production source/lock hashes,
shared environment and every package harness file. No local performance matrix
was run while preparing this collector.

The `phase-attribution` plan adds an independent Linux job to the existing
package component workflow. Its original cardinality, format and five-pair hot
route jobs remain unchanged. The new job has a ten-minute cap and ten bounded
worker attempts, each with a 30-second **whole-worker** limit including import,
setup, route, output validation and evidence. Worker limits total at most 300
seconds before separate bounded process cleanup, setup, tests and encryption.
The ordinary existing 567-case correctness manifest is unchanged; no full
567-case timing matrix is selected.

| Scope | Workload | Attempts | Purpose |
| --- | --- | ---: | --- |
| `phase-validation` | Original npm exact protect D=B=1,000; original npm exact evaluator D=B=10,000 | Two candidate workers | Uninstrumented semantic validation, with no latency output |
| `phase-attribution` | Exactly those same two original fixture inputs and route functions | Three fresh candidate workers per case | Calling-thread CPU attribution only |
| `registry-resolved` | 100 explicit unpinned npm `*` requests, 1,000 signed bundle records, actual local protect dry run | One frozen-baseline/candidate pair | Separate resolver/delivery/evidence correctness witness |

The attribution profiler wraps no production function and changes no policy,
matching, parser or persistence behavior. It uses `cProfile` with the calling
thread CPU clock. Finite module/qualified-function identities admit counts and
inclusive/exclusive CPU for input capture/hash, parse/structure/projection,
bundle decoding and model construction, immutable index construction, signed
payload canonicalization, verification, package identity, match lookup,
finalization and evidence/SQLite operations. Unknown functions contribute to an
explicit unattributed profile total; arbitrary names and source paths are not
public fields.

Inclusive rows contain their callees and **overlap**. They are never summed as
independent work. Exclusive rows are disjoint. The report retains total profiled
exclusive CPU, selected exclusive CPU and the remaining unclassified profile
CPU. It also retains the signed difference between process CPU and profiled
exclusive calling-thread CPU. That difference can include other threads and
instrumentation; it is not assigned to a named phase or clamped to a fake zero.
Three instrumented invocations do not establish a tail distribution, paired
speedup or native benefit. Their wall and process CPU totals remain inside an
explicit `headline_eligible=false` phase record, separate from ordinary timing
fields.

The measured route consumes a cached bundle admitted during setup. Setup loads
and genuinely verifies the RSA-PSS signed fixture, then caches it before the
route. A completed worker explicitly records
`bundle_admission_verified_before_route=true`. The current evaluator decodes and
constructs the cached bundle/index inside the route but does not repeat the
signature verifier there. Zero in-route verification or signed-payload
canonicalization calls are legitimate observations of this boundary. The
collector does not move fixture admission into the historical measured interval
or claim those cryptographic costs explain its residual CPU.

Every instrumented invocation must pass the existing complete package/evidence
oracle. Finalization additionally compares its fixture, semantic, evidence,
entry and protect commitments with the uninstrumented validation observation.
Missing, censored or semantically different attempts prevent a complete result.
The private journal records attribution as soon as the route leaves the profiler,
including exceptional exits; a killed worker may have only its offered/started
records. A partial profile never becomes a completed public observation.

## Separate unpinned-range resolution witness

The historical `unversioned` case deliberately invokes the bundle kernel with
`package_version=None`. It exercises highest-risk selection across known
versions. The actual evaluator instead resolves a concrete version before
calling bundle matching. A signed bundle alone cannot make these boundaries
equivalent.

The new supplemental case intercepts only `runner.managed_urlopen` inside the
private worker. It admits exactly 100 known npm registry GETs with the fixed
Accept/User-Agent headers, no request body and the unchanged one-second initial
and retry budgets. It returns bounded frozen UTF-8 JSON bytes. Actual retry
dispatch, JSON decoding, semver selection, evaluator, protect delivery and
evidence persistence execute normally. All other network attempts still fail.
The transport is restored on every exit, and the public report commits to exact
request metadata, response bytes and call counts. This proves no external
network or HTTPS latency.

Version 1.0.0 has risk 999 and the known-malware reason; version 2.0.0 has risk
100 and the ordinary `bundle_match` reason. The oracle requires requested `*`,
resolved 2.0.0, the lower risk, direct identity and matching persisted evidence.
Accidentally substituting the None-version highest-risk lookup fails that oracle.
The supplemental case does not replace the original unresolved or kernel cases.

Bare requests without `@*` remain outside this witness: the current and frozen
baseline `_resolved_target_version` accept `_exact_version("latest")` as the
literal version before reaching registry resolution. A functional fixture attempt
observed zero registry calls for that route. This is an identified product gap,
not a fixture justification for changing matching semantics. No production fix
or bare-request coverage claim is included here.

## Evidence and decisions

The public finalizer validates every nested phase/transport field and rejects
unknown text, booleans in counters, inconsistent sums, forged scope and ordinary
timing fields in attribution observations. Exact completed non-kernel attempts
must retain their private semantic projection. All known offered/started/terminal
journals and fixture records are staged in finite private groups and encrypted
with the existing public recipient. Public upload paths contain only the fixed
aggregate and archive receipts; plaintext journals are never upload paths.

RSP-050/RSP-054 remain subject to their original criteria. This collector can
locate a candidate kernel after successful CI observations; it does not prove
that Rust improves the optimized Python route by 30%, qualify installed startup
or tails, or authorize native activation. The prior measured package medians
remain bound to their original source and workload.
