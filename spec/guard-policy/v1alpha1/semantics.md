# GuardPolicy v1alpha1 semantics

`GuardPolicy` is the portable semantic source. Portal graph state is editor metadata; signed Cloud bundles and local SQLite rows are compiled projections. A projection MUST reject a rule it cannot represent without changing meaning.

## Action compatibility

| Canonical effect | Portal `GuardPolicyRule` | Cloud bundle v1 | Local `PolicyDecision` | Classification |
|---|---|---|---|---|
| `allow` | `allow` | `allow` | `allow` | Lossless when scope is representable |
| `block` | `block` | `block` | `block` | Lossless when scope is representable |
| `review` | `review` | `review` | `review` | Lossless; remains an approval gate, never downgraded to `warn` |
| `ignore` | `ignore` | `ignore` | no row | Lossless inert projection; never compiled as `allow` |

Runtime-only actions are not rule effects: local `warn`, `sandbox-required`, and `require-reapproval`; bundle default `warn`; and changed-hash `warn`/`require-reapproval`. They remain typed defaults or legacy runtime results. Importing one as a rule effect is unsupported.

## Status, mode, rollout, and lifetime

- Portal `active`/`disabled` maps losslessly to `enabled: true/false`.
- Cloud modes `observe`, `prompt`, and `enforce` map losslessly to `spec.defaults.mode`.
- Cloud rollout states map losslessly to `spec.rolloutState`.
- `once`, `session`, `project`, `machine`, `workspace`, `team`, and `permanent` preserve Portal review durations. `30d` and `90d` normalize to `until` plus an absolute UTC `expiresAt` at creation time.
- A local null `expires_at` maps to `permanent`; a non-null UTC expiration maps to `until`. Consumed local one-shot approvals map to `once` but remain execution state rather than durable policy rows.
- `until` requires `expiresAt`. Every other mode has a null or omitted `expiresAt` and MUST NOT invent an expiration.

## Matcher compatibility

| Canonical matcher | Existing projection | Classification |
|---|---|---|
| `actors` | Portal `actor` | Lossless |
| `harnesses` | Portal `harness`; Cloud `harnesses`; local `harness` | Lossless |
| `tools`, `paths`, `repositories`, `commands`, `mcps`, `skills`, `packages`, `domains`, `secretTypes` | Corresponding Portal scope | Lossless in Portal; Cloud/local compiler MUST reject unless its fixed matcher-family projection is exact |
| `agents`, `devices`, `ecosystems`, `environments`, `locations` | Corresponding Cloud bundle scope | Lossless |
| `artifacts`, `publishers`, `workspaces` | Local artifact/publisher/workspace decision keys | Lossless for exact singleton values; multi-value rules fan out deterministically |
| `browserIntents`, `browserOperations`, `browserProfiles`, `origins`, `pathPrefixes`, `sensitiveSurfaces` | Portal browser scope and Cloud browser scope | Lossless in signed bundle; unsupported in SQLite because a row would broaden the rule |
| `operations` | Cloud matcher families (`file-read`, `mcp`, `mcp-tool`, `package-request`, `prompt`, `prompt-env-read`, `tool-action`) or a typed Portal operation such as `package.install` | Lossless only through an explicit registered mapping; unknown operations are unsupported |
| empty `match` | Global rule | Lossless; an empty individual matcher array is invalid |

Cloud bundle v1 uses singular browser keys and plural fleet keys. The canonical adapters use the plural names in the schema and MUST perform a named field mapping; unknown keys never pass through as core matchers.

## Defaults compatibility

`defaultAction`, `unknownPublisherAction`, `changedHashAction`, `newNetworkDomainAction`, `subprocessAction`, `telemetryEnabled`, and `syncEnabled` preserve the current signed bundle values. Portal defaults that do not exist in bundle v1 are unsupported until capability negotiation. Local SQLite has no independent defaults projection.

## Provenance

Provenance is immutable semantic data. Suggested Memory emits `source: suggested-memory`, stable `receiptIds`, `suggestionId`, `createdAt`, and `createdBy`. User export MAY redact IDs but MUST record that redaction in an `x-*` extension. Raw secrets, credentials, authorization headers, and secret values are forbidden; `secretTypes` contains categories only.

## Merge and identity

Files are never merged implicitly. An explicit import assembles an ordered effective set, then fails if any rule ID appears more than once, including byte-identical rules. Document IDs identify documents; they do not scope rule IDs. Rule order is presentation order and does not resolve conflicts.

Suggested Memory rule IDs are deterministic from immutable suggestion identity plus the semantic rule digest. Retries reuse the same ID. Editing content does not silently mint a second rule.

## Current runtime precedence (frozen)

This representation release does not change runtime precedence:

1. An eligible local one-shot approval is atomically claimed first.
2. Active persisted rows are ordered by scope: artifact, workspace, publisher, harness, global.
3. Within workspace/harness/global, an artifact-constrained row precedes an unconstrained row.
4. Remaining ties use `updated_at` descending. Source is not a tie-breaker: a local and remote row at the same specificity follow the same timestamp rule.
5. Expired rows do not participate. Integrity-invalid local rows are skipped; a valid next candidate may win.
6. A signed Cloud `block` or `review` does not receive absolute priority over a more-specific or newer local `allow`; changing that rule requires a separate safety contract.

The decision fixtures freeze exact-vs-broad, active-vs-expired, once-vs-permanent, and local-vs-remote outcomes. Compilers and representation changes MUST preserve them.

## Extensions

An object may contain keys matching `x-[a-z0-9][a-z0-9.-]{0,62}`. Extensions are preserved and participate in canonical hashing/signing. Core enforcement ignores them unless both producer and consumer negotiated that extension contract. An unnegotiated extension cannot affect matching, action, precedence, or lifetime.

## Authority path examples for policy help

Choose the authority path before explaining a winner. There is no single
Cloud-over-local priority rule across these paths. "Shadowed" below means that
another applicable input did not determine the effective result; it does not
mean that the input was deleted.

| Authority path and applicable inputs | Winner | Shadowed input | Reason and execution reference |
| --- | --- | --- | --- |
| Generic persisted rows at the same specificity: older valid Cloud `block`, newer local `allow` | Local `allow` | Cloud `block` | When both rows coexist and are eligible, `updated_at` breaks the tie; source is not a priority. `StorePolicyMixin.resolve_policy_decision_lookup`; `test_generic_row_recency_is_not_a_cloud_priority_rule[True]`. |
| Generic persisted rows at the same specificity: older local `allow`, newer valid Cloud `block` | Cloud `block` | Local `allow` | The same timestamp rule applies in the other direction. `test_generic_row_recency_is_not_a_cloud_priority_rule[False]`. |
| Generic persisted rows: exact artifact `block`, newer global `allow` | Artifact `block` | Global `allow` | Artifact scope has higher specificity than global scope. The persisted-row ordering applies before timestamp ties; `store_policy.py` and the frozen precedence vectors. |
| Generic eligible one-shot approval and persisted Cloud rule | The eligible one-shot decision, consumed atomically | Persisted row for that generic lookup | This is the generic store's one-shot path. It does not remove managed restrictions or native intrinsic blocks in other enforcement paths. |
| Managed/extension permission: signed Cloud `disabled`, local administrator `enabled` on the same permission | Permission remains disabled; control factor blocks | Local `enabled` | `compose_control_layers` gives disable dominance regardless of layer order. Resolver reason is `control.disabled-permission`; `test_managed_permission_disable_retains_its_reason_against_local_enable`. |
| Managed-restrictive publication attempts `enabled` | Publication fields are rejected | No enablement is applied | `_append_control` raises `managed_restrictive_broadening`. This authority supports restrictions only; there is no accepted enable rule to compare for recency. |
| Shared Cloud enable targets a non-configurable permission | Enablement is rejected | No enablement is applied | `_append_control` rejects `immutable_floor`; catalog authority determines configurability. |
| Native pre-tool intrinsic `block`, authenticated native policy `allow` | Intrinsic `block`; deny | Policy `allow` | `apply_pre_tool_policy` joins action floors and validates the typed decision. Native test `policy_allow_cannot_lower_intrinsic_review_or_block`. |
| Native intrinsic `block` in observe mode | Intrinsic `block`; deny | Any weaker policy-only action | Observe mode does not remove intrinsic blocks. Native tests `observe_pre_policy_floor_is_non_blocking_but_intrinsic_block_is_hard` and `observe_preserves_intrinsic_block_but_does_not_enforce_policy_only_floor`. |
| Extension global lockdown on typed trusted local recovery surface | Only documented recovery access | Command execution remains blocked | `resolve_extension_controls` preserves observations and exempts the typed recovery surface from the control block; this is not a general command approval. Existing test `test_global_lockdown_preserves_observations_and_allows_only_typed_local_recovery`. |

The generic examples describe selection among existing rows, not write merge
behavior. Today `_upsert_policy_locked` replaces an exact stored selector key
before inserting a local decision, regardless of the previous source. If that
write removed the other row, a help view must describe replacement instead of a
recency winner between two still-existing rows. The signed-sync proving tests
create the local row first and then apply the Cloud bundle so both inputs are
present for the timestamp comparison. This documentation does not change that
write behavior or claim that deleted rows remain enforceable. This limitation is
about generic stored rows; it grants no authority to remove managed restrictions
or native intrinsic safety floors.

Source references: `src/codex_plugin_scanner/guard/store_policy.py`,
`src/codex_plugin_scanner/guard/managed_controls_policy_fields_core.py`,
`src/codex_plugin_scanner/guard/runtime/extension_control_resolver.py`, and
`rust/crates/guard-runtime/src/policy_enforcement.rs`. Python examples execute in
`tests/test_policy_authority_explanations.py`; native examples refer to the
existing tests in `rust/crates/guard-runtime/src/policy_enforcement_tests.rs`.
These examples do not substitute for a signed installed-runtime workflow test.
