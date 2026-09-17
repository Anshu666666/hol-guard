# Windows source-reference qualification

The frozen baseline implements a Windows restriction:
`rust/crates/guard-secure-fs/src/secure_open.rs` returns `PathChanged` from
its non-Unix `secure_open` implementation because an equivalent handle-bound
walk is unavailable. The native source reviewer consequently returns
`no_output_to_review`. Source-reference-only fixtures cannot establish content
inspection, a clean result, or source identity verification for that artifact.

The candidate now contains the handle-bound Windows reader documented in
`docs/guard/windows-secure-source-read.md`. It advertises the new
`native-source-handle-read-v1` feature. The older `post-tool-source-read-v1`
feature is insufficient: the frozen Windows baseline already advertises it.
Qualification verifies the default bundled runtime's availability,
compatibility, readiness, and exact selected executable path before reading
its capabilities. Missing or mismatched identity fails the experiment; it
cannot select the unsupported baseline oracle. The safe aggregate field
`reference_reader_capability` retains the exact feature label or `absent`.

The qualification harness preserves this baseline behavior. Every unsupported
Windows source-reference case retains its original file, payload, route, and case ID.
It must match the exact existing native refusal and the corresponding harness
delivery. Watch retains the raw `no_output_to_review` denial, then delivers
warn/allow without invented `observe_mode` or `observed_policy_action` fields.
Allowing delivery in Watch mode does not prove that source bytes were reviewed. Inline cases and Unix source expectations
remain unchanged. Capability-advertising Windows artifacts instead receive
those same original full-content, digest, malicious-content, and Watch
oracles. A candidate refusal cannot silently fall back to baseline behavior.

Validated platform refusals are reported separately from semantic coverage.
They never enter `semantic_observations`, successful size latency series, or
the full-review acceptance scope. For unsupported artifacts the standalone SLO runner probes
all three large sizes, records exact native and delivered refusals without an
`Observation` or latency field, and continues warm, cold, recovery, readiness,
capacity, and launcher work. Missing large-size latency gates stay false.
Ordinary source timing still requires one native allow, the exact fixture
digest, and a completed-review reason; a claimed digest alongside
`no_output_to_review` cannot satisfy that witness.

`platform_scope_summary(cases, validated)` in `scripts/native_slo_workloads.py`
provides the corpus integration contract. Its persisted fields use finite
aggregate names that survive the existing privacy sanitizer:

- `reference_review_supported` and `reference_review_qualified` distinguish
  platform capability from observed complete coverage.
- `platform_denial_declared_cases`, `platform_denial_validated_cases`, and
  `platform_denial_contract_passed` describe only the refusal contract.
- `platform_denial_case_digests` binds validated cases without retaining raw
  case IDs; `semantic_coverage` uses `file_reference` for the representation.
- `missing_scopes` explicitly lists `source_reference_full_content_review`
  and `source_reference_identity_verification` for unsupported Windows artifacts.
- `platform_denial_timing_eligible` is always false.

The corpus runner must attach this object as `platform_scope` and require an
empty `missing_scopes` list before marking the full corpus complete. A
successful refusal contract can qualify its observed safety behavior while
the full program remains incomplete. Independent supported scopes retain
their own acceptance gates.

`tests/test_native_slo_platform_source.py` covers platform oracles, native and
delivered refusal mutations, false clean and digest claims, exclusion from
successful latency series, continuation of supported SLO work, and saved
report roundtrips through the unchanged privacy sanitizer. These deterministic
tests exercise explicit Windows platform selection on the test host. They do
not substitute for execution of both installed wheel artifacts on Windows;
that paired run must supply the actual platform proof. The candidate's new
capability does not itself qualify any case or latency: complete observations
are still required, and frozen baseline missing scopes remain visible.
