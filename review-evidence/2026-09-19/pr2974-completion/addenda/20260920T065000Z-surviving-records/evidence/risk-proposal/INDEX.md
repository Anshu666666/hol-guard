# RSP-100 bounded authority-pair proposal — UNEXECUTED

Base product commit: 4d10758e2cb44e5afa72a08aa631a02541dad534  
Base product tree: fbc00caa3788eb422158a2263a578e83ac626183  
Requirements checkpoint: 13a1520b056a6946d84cd18957bc2d075c67c695, addenda/20260920T055900Z-interim-4d107.

This standalone Git tree preserves an in-memory proposal after the shared hosted sandbox reset from tfbs to asnf. It is not a commit, branch update, executed patch, selected optimization, benchmark result, qualification, or RSP-100 completion. Nothing in this tree changes the 144 original task objects, 119 original evidence-catalog entries, or any frozen campaign bytes. No old E/F adapter, benchmark worker, or campaign was run.

## Requirement and exact missing behavior

Original RSP-100 remains OPEN and depends only on RSP-099. Its acceptance is: “Compute categories/signals once for unchanged exact inputs; recompute after any authority/catalog/input change.” PRD 12F.2 requires local facts once and reuse for decision and summary. Neither requires a 30% improvement from this small helper, or fresh permission to implement the already authorized functional obligation. The original program's broader measured-benefit gates remain separate.

In exact 4d, runtime_mcp.py:1342–1369 calls the public hash and decision aliases with three preparation checks. mcp_tool_calls.py:510 derives categories for the hash and :984 derives them again after the current-policy callback. Signals already derive once within a decision (:1015) and its summary reuses them.

A separate gap remains in runtime_mcp.py:3979 and :4034: approval payload summary and approval-pending receipt derive facts again. This proposal deliberately leaves that route unchanged. Binding it requires explicit authority/input provenance across ensure_guard_daemon, browser/launch-target, queueing and receipt callbacks. A pair-only pass cannot close the complete RSP-100 acceptance.

## Proposed source scope

- proposal/src/codex_plugin_scanner/guard/mcp_request_risk.py: new private expiring invocation token, reviewed helper binding, nested/concurrent admission exclusion.
- proposal/src/codex_plugin_scanner/guard/mcp_tool_calls.py: preserve existing ToolCallRiskFacts matching; distinguish the exact new private token; populate it at the existing hash category site and consult it at the current decision site after current-policy resolution and authority check.
- proposal/src/codex_plugin_scanner/guard/proxy/runtime_mcp.py: supported bound requests may carry the token through the existing optional risk_facts keyword; unsupported/replaced aliases receive their original argument set.
- proposal/tests/test_mcp_invocation_risk_pair.py: unexecuted fresh functional/adversarial controls. Importing the existing _session test fixture does not install or execute its historical adapter.

The token contains pure categories only, never policy, approval, authority results or wire bytes. It expires in finally, clears its retained values, and is not returned in _ToolCallAuthority. A ContextVar is solely an ownership marker preventing nested admission; consumers receive the explicit token rather than looking up ambient facts.

Admission requires the existing proxy authority scope, an already owned request binding and identical bound arguments, the current captured authority check, exact GuardConfig, unchanged supported public aliases, policy methods and reachable package risk helpers. Pure helper capture follows package-local function globals and records object/code/default identities and mutable dictionary/list values. Imported standard-library callables bind their own object/code, without trying to freeze the Python interpreter. Unsupported callbacks keep the original path. Helpers are rechecked after the second policy callback; input/authority mutation uses the existing fail-closed checks, and a subsequent fresh authority invocation recomputes.

Both original public calls and both policy callbacks remain. The pair retains all three preparation calls. This proposal does not edit _forward_message, its final preparation/authority check, its required method/immutable frame checks, or the final 5 ms quiet fence. No risk facts survive an approval wait, claim, catalog refresh or later invocation.

## Independent design review received

Partition's read-only design review preferred an explicit invocation-owned token using the existing keyword over ambient cache lookup. It identified the legacy matcher (_input_binding) distinction, exact class descriptor/__func__ policy binding, reachable category/schema/argument/description/browser helper identities, post-policy rechecking, original unsupported kwargs, and nested/reentrant lifetime as required controls. Those points informed this draft. Partition has not reviewed the resulting source afterimages or run the draft tests.

## Validation state and next review

Execution status: UNEXECUTED. No pytest, import, compile, Ruff, format, type, native, installed, benchmark or campaign result exists for these afterimages. The tfbs sandbox reset occurred before the source edit script was applied or any proposal test ran. The standalone afterimages were assembled from the exact GitHub 4d blobs in functions memory after remote work was stopped. Earlier 4d/e8f/3780/ed7313 results do not validate this proposal.

The source is a review draft, not a ready publication candidate. Before adoption:
1. Materialize exact 4d in an isolated restored environment and compare every changed original to the manifest.
2. Review helper-graph capture/admission, type compatibility, nesting/concurrency semantics and callback fallback; check that capture itself cannot reject module import unexpectedly on a supported Python version.
3. Run and fix the new controls plus existing request-risk-facts, runtime-authority-callback, tool-call-binding, browser and approval parity controls. Retain failures separately.
4. Run scoped Ruff/format/type checks and source-contract gates appropriate to the changed product files. No timing/performance claim follows from passing them.
5. Have an independent owner review the actual tested patch. Keep approval-summary reuse and full RSP-100 closure explicitly open.
6. Only after those steps consider publishing a separate source change under root's direction. Do not repin or resume a stopped campaign.

The manifest binds base source and proposed file contents by Git blob SHA-1 and byte count. The tree object itself is the immutable preservation receipt; it is not attached to a branch by this action.
