# Windows source-reference qualification

The audited baseline and candidate implement the same Windows restriction:
`rust/crates/guard-secure-fs/src/secure_open.rs` returns `PathChanged` from
the non-Unix `secure_open` implementation because an equivalent handle-bound
walk is unavailable. The native source reviewer consequently returns
`no_output_to_review`. Source-reference-only fixtures cannot establish content
inspection, a clean result, or source identity verification on Windows.

The qualification harness preserves this production behavior. Every Windows
source-reference case retains its original file, payload, route, and case ID.
It must match the exact existing native refusal and the corresponding harness
delivery. The resident edge preserves the intrinsic `no_output_to_review` denial
even in Watch. Python delivery changes its final action to allow/warn and
preserves that reason; it does not add the direct-hook `observe_` prefix or
observe metadata. Allowing delivery in Watch does not prove source review.

Validated platform refusals are reported separately from semantic coverage.
They never enter `semantic_observations`, successful size latency series, or
the full-review acceptance scope. The standalone installed SLO runner probes
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
  and `source_reference_identity_verification` on Windows.
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
that paired run must supply the actual platform proof.
