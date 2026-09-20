# Codex browser continuation: post-native refusal map

This read-only assessment binds current product `e44008445630aad28ccc291ec234f55a14892e6d` and the three original installed approval attempts retained in packet `5faf5827b8bb3efca9e6326e3006c8be2a41efef`. It makes no new execution or root-cause claim.

All three rows preserve the same observed state: Claude initial ask and resolved retry validated; Codex browser wait offered, durable local allow resolved, two native deny/review results observed, pending suspended response retained, no `complete_codex_live_decision` callback captured. `native_resident` count increases from two to four. These observations prove neither successful exact authority revalidation nor the identity of the refusing branch.

The native completion function records `native_resident` and queues its verified receipt before the following remaining checks:

1. Build the current native review policy binding. This can raise and be converted into `fresh_policy_revalidation_failed`.
2. Compare current binding with stored `action_envelope_json.native_review_policy_binding`.
3. Compare the fresh Rust receipt's `request_digest` with stored `native_review_request_digest`.
4. Compare that digest with the approval row's `artifact_hash`.
5. Require an exact allowed tuple or the reviewable deny/review/review tuple. Recheck original waiter liveness and absolute deadline.
6. Only then call `complete_codex_live_decision(...fresh_allow_authorized=True, require_consumed_once_for_replay=True)`.

The retained rows contain the reviewable tuple, but omit both full exact bindings and the relevant equality outcomes. They cannot distinguish policy binding mismatch, request/source/generation mismatch, expiry/liveness, or a caught exception. The empty completion list is consistent with a refusal before step6; it is not a unique branch witness.

Rust `edge_identity.rs` commits the exact canonical raw payload, policy generation and policy/rule/runtime/scope digests, source cwd/home/guard-home and external-source permission. Only root event aliases and root adapter timestamps are omitted. Nested arguments remain bound. `native_codex_request_digest` explicitly documents that renewed policy generation requires a new browser approval. Existing `test_native_codex_continuation_binding.py` controls intentionally reject ancillary input and generation changes while retaining the unconsumed authority. Neither ordinary local resolution nor a fresh native review alone permits relaxing these checks.

A bounded future diagnostic can wrap only the real invocation and record return/error category and observation-only equality booleans at these existing boundaries, together with initial/fresh generation and hashes already present in the stored and returned receipts. It must retain callback order, actual inputs, absolute deadlines, current native floors, exact waiter identity, and original failure. No additional retry, replacement receipt, forced generation, or relaxed approval oracle is justified by this source map. Diagnostic source and result would require separate binding and review before any run.
