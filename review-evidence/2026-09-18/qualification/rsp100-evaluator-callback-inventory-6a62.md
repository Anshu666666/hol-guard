Read-only callback inventory at `6a62b7406216601d687130fff393113845364dcf`

Scope: original `RuntimeMcpGuardProxy._evaluate_tool_call_authority` → `build_tool_call_hash` / `evaluate_tool_call`, with `claim_saved_approval=False`, `fresh_authority_provider=None`. This is a finite application-boundary inventory, not a proof that the Python heap is immutable. No source changes or measurements were performed.

| Application entrypoint | Reachability in this path | Source |
| --- | --- | --- |
| `proxy._check_tool_call_preparation()` | Before hash, between hash and evaluate, after final callback | `guard/proxy/runtime_mcp.py:1346`, implementation3171 |
| `config.resolve_action_override(...)` | Hash policy context and current-policy evaluation | `guard/mcp_tool_calls.py:519`,964 |
| `config.resolve_artifact_or_publisher_action_override(...)` | Delegated from canonical config lookup | `guard/config.py:439` |
| `store.resolve_policy_decision_lookup(...)` | Each temporary-grant selector while original action is review; also delegated by memory-pattern lookup | `guard/mcp_tool_calls.py:757` |
| `store.read_local_mcp_grant(...)` | This-device local MCP grant on review/reapproval/warn and usable server identity | `guard/local_cli_trust.py:123` |
| `store.read_extension_control_authority_for_registry(...)` | Contributed MCP package grant after local grant did not resolve | `guard/runtime/mcp_server_grants.py:80` |
| `store.resolve_policy_decision_lookup_with_memory_pattern(...)` | Saved lookup after temporary/local/contributed grant processing | `guard/mcp_tool_calls.py:651` |
| `store.approval_reuse_validation_reason(...)` | Saved lookup has neither usable decision nor ignored integrity row | `guard/mcp_tool_calls.py:672` |
| `store.approval_reuse_claim_disposition(...)` | Accepted saved allow is selected, including preview-only `claim_saved_approval=False` | `guard/mcp_tool_calls.py:714` |
| `proxy._disable_saved_allow_without_complete_catalog(...)` | Final callback around the evaluated decision | `guard/proxy/runtime_mcp.py:1363`, implementation1144 |

The existing risk/hash policy function inventory still matters: direct module aliases such as runtime `build_tool_call_hash` and `evaluate_tool_call`, local grant helpers, contributed MCP helpers, and the current authority check are callable application code. The observed candidate already has a separate source/function admission mechanism; this report does not replace it or assert that source-file hashes alone prove live function identity.

The actual `GuardStore.resolve_policy_decision_lookup` MRO entrypoint is `StorePortableProjectMemoryMixin.resolve_policy_decision_lookup`, which calls `_portable_project_workspace` and delegates to `StorePolicyMixin` using `super()`. Comparing the public method only to the latter implementation would reject the real repository store. With `consume_one_shot=False`, the portable layer does not claim an approval.

Canonical `read_local_mcp_grant` also calls replaceable public `read_local_cli_command_catalog` and `read_local_cli_command_states` for an allowed grant. Blocking grants return without those reads. Canonical registry authority lookup does not delegate public `read_extension_control_authority`; it calls the shared private schema, lock, key, manifest, managed-control and authority-reader helpers directly.

Saved lookups, diagnostic lookups, and local grant reads cross `_connect` and the store's integrity helpers. These can themselves be replaced on the store. There is also a real, explicitly registered opaque callback even with unmodified canonical methods: `StoreSecretPolicyIntegrityMixin.set_policy_integrity_state_listener` stores `_policy_integrity_state_listener`; `StoreConnectionSchemaMixin._connect_once` calls `_publish_policy_integrity_state_notification` after a transaction with a queued notification, and that method calls the listener. A public-method identity inventory alone does not cover this listener. The same connection exit path calls profiler and outbox-wake objects; those are repository internals, not a claim that arbitrary replacements are safe.

`claim_approval_reuse_decision`, claimed-approval revalidation, and the fresh-authority provider are not reachable under the requested flags. Local CLI shell identity callbacks in `matching_local_cli_grant` are a different route; the MCP path uses `matching_local_mcp_grant` instead. Inline approval UI callbacks and actual transport forwarding occur outside this evaluator segment and must not be claimed covered by this inventory.

Conservative boundary choice: opaque store/proxy/config entrypoints must force the original uncached path and permanently revoke previously admitted reuse assumptions for that prototype instance. Rechecking only that an opaque callback restored its own method afterward is insufficient: it may leave other callable/library state changed. If the implementation cannot finitely admit transitive store callbacks, stop reuse before entering the store boundary rather than expanding admission into the entire heap. The useful hash-to-current-risk reuse has already occurred by the first store call; any stronger optimization across those callbacks needs its own proof.

No negative exploit was executed by this reviewer. The calling agent already reproduced the saved-policy callback failure and owns the correction and controls. This report supplies the finite entrypoint list and the additional registered-listener finding for that correction.
