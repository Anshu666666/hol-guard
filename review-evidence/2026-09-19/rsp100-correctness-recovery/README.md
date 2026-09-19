# RSP-100 dependency correctness recovery

Source preparation only. Baseline source is commit
`44353b20262f1ca56b56204f4c764b047710454f`, tree
`b60a25c740e817b8eb4966e89cfe3466364047fb`.
No Python parse, import, collection, test, benchmark, native qualification, or
workflow execution has run for this packet. The historical lost optimization
has not been reconstructed byte for byte. No selected implementation changes
are proposed here.

The selected B evaluator still derives categories twice: once in
`build_tool_call_hash` and once in `evaluate_tool_call`. The exact current
`RuntimeMcpGuardProxy._evaluate_tool_call_authority` passes no `risk_facts`
argument to either public function. The existing default-selection regression
also forbids entering `prepare_tool_call_risk_facts`.

## Retained constructor witness

The new finite fixture preserves the reported event order:

1. Prepare input-only facts for the ordinary `summarize` call. Its expected
   category tuple is empty. The fixture explicitly selects ordinary-call
   `allow` and dangerous-tool `review`, so these actions do not depend on the
   default configuration being `allow`.
2. During construction of the initial `ToolCallDecision`, a one-shot callback
   replaces `PurePath.name` with a property returning
   `run_terminal_command`. The callback restores the original
   `ToolCallDecision` constructor before returning.
3. Keep that descriptor replacement in place. The complete request values and
   the captured proxy/config/catalog/artifact authority still match. Both risk
   function objects and their code objects remain the same.
4. Invoke the actual selected B authority evaluator later, on the same artifact
   and arguments under the existing authority check. It is expected to derive
   `command_execution` twice and return `review`.
5. Invoke the existing optional input-only facts consumers with the original
   facts. Their matcher still accepts those facts, so they are expected to
   return `allow` with empty categories and a different approval hash.

These are assertions in an **unrun test**, not newly observed execution
results. The retained earlier observation remains separate evidence. The
fixture does not restore the descriptor before B runs, replace the risk
function to manufacture the descriptor case, weaken B to `allow`, or install a
historical pilot.

The negative-control helper is intentionally unsound. It calls the existing
public optional APIs with stale facts to make the divergence reviewable. It is
not a proposed cache, is never imported by production, and cannot earn an
optimization or qualification pass merely because the witness test succeeds.

Three additional prepared cases keep the same constructor/restore/later-use
sequence while changing a risk function binding, its code in place, or mutable
contents of its closure. The closure case leaves function and code identities
unchanged. There are four prepared cases in total; none has been collected or
executed.

## What the current bindings cover

| Boundary | Actual current binding | Consequence for a reuse design |
| --- | --- | --- |
| Wire request | Owned exact plain JSON, ordered/type-sensitive original frame, live and owned frame checks, parent binding for replacements | Preserve the existing request and final byte-writer fences. Unsupported Python objects do not gain reuse eligibility. |
| Proxy/config/catalog | Exact ordered values and explicit owner identities captured before artifact callbacks | Reuse cannot replace fresh current configuration or exact catalog content with a coarse fingerprint. |
| Artifact | Complete exact dataclass fields, including private metadata, plus original and any consumed owned copy | Match all fields again; a separately owned analysis input is not new authority. |
| Optional risk facts | Exact private artifact/argument shape and scalar leaves | This covers data changes, not the semantics of the functions that analyze those data. |
| Final forwarding | Catalog drain/quiet boundary, request check, authority check, bound byte writer | No facts or decisions may survive a wait, nested request, claim, package handoff, or final forwarding boundary as newly granted authority. |

The authority owner tuple includes the current config, context, store, complete
catalog, and current-config provider. The value tuple includes both selected
and current configs when distinct; complete catalog definitions; command,
context, harness, server name, scope, config path, transport, server identifier,
configured environment keys, server identity, active executable/runtime/env
identities, catalog generation/state, and normalized effective workspace.
Arguments are covered directly or by the owned wire request. The artifact
binding remains separate. The existing authority mechanism deliberately makes
no risk-function or risk-dependency cache claim.

## Why function-identity checks are insufficient

`tool_call_risk_categories` calls
`_tool_call_risk_category_set`, whose first statement reads
`PurePath(...).name`. No assignment to either risk function is required for
that descriptor to change the result.

The reachable implementation is broader than the two risk functions:

| Dependency family | Actual examples from the pinned source |
| --- | --- |
| Path behavior | `PurePath` construction and its inherited/concrete path behavior; `name` descriptor and getter |
| Text and schema helpers | Argument serialization, normalization, recursive key/ref/anchor traversal, description analysis |
| Pattern behavior | `re.search/finditer/sub/escape`, literal-pattern class, cached literal-pattern constructor and returned records |
| Address behavior | Imported `ip_address` and its own implementation dependencies |
| Browser behavior | Imported browser normalizer; operation/profile/sensitivity tables; helper functions; normalized result class |
| Browser URL behavior | `urllib.parse` functions and attributes such as the parsed result's `hostname` descriptor |
| Python callable state | Live binding, `__code__`, defaults, keyword defaults, closure cells and mutable contents, downstream globals |
| Consumer callbacks | Current policy resolution, normalization, decision construction, saved-state lookup and authority callbacks |

This is a concrete list of reachable dependency families, **not a certified
exhaustive runtime dependency manifest**. A module-source hash does not prove
that loaded objects still implement those source bytes. A top-level owner
identity misses an in-place code change. A descriptor identity misses a changed
getter or mutable state used by it. Closure-cell identity misses changed cell
contents. A before/after equality check can also miss a temporary mutation that
is restored after affecting a computation.

Broadly walking arbitrary module/class/closure graphs would add callback,
cycle, mutation, interpreter-state and size-bound problems. This packet does
not claim that such a walk is a complete or efficient solution.

## Bounded strategy and selection decision

The strategy that is justified by the current source is conservative
invalidation:

- Keep any prospective facts as a private local value of one authority
  preparation. Do not store them on the proxy, in a global cache, in a
  ContextVar that outlives that preparation, in returned authority objects,
  or in approval/receipt state.
- Preserve the existing wire/authority/artifact checks and all public callback
  ordering. Unsupported inputs or unproved bindings fall through to the
  existing uncached behavior.
- Treat every call into mutable Python policy, normalization, constructor,
  authority, saved-state, or external callback code as invalidating a reuse
  ticket. Discard it before a later authority preparation, nested operation,
  wait, claim or handoff, even if object identities and input values appear
  unchanged.
- At the next consumer, derive categories through the current B path. A changed
  dependency is thereby observed at the same fresh derivation point as B;
  an authority/input mutation continues to be rejected by the existing fences.
- A cached tuple alone never authorizes execution. Policy, grants, saved
  approval and final write authority are evaluated at their existing current
  boundaries.

There is already a mandatory policy callback between the hash's category
derivation and the decision's category derivation:
`_build_tool_call_hash_for_categories` obtains its capabilities first, then
calls `_tool_call_policy_context`, which calls
`GuardConfig.resolve_action_override`. The decision resolves current policy
again before its category derivation. Unconditional invalidation at these
callbacks therefore leaves **no justified reuse hit between these two
consumers** in the current implementation.

No enabled or supposedly complete request-facts cache prototype is supplied.
Writing an always-fresh wrapper would add code without implementing a reuse
optimization. Selected B remains the concrete safe implementation of this
strategy. The separate test helper is only the stale-facts negative control.

A future nontrivial reuse prototype would need a separately reviewed closed
evaluator boundary: bounded immutable inputs, a complete immutable semantic
dependency closure, no caller callbacks inside the reusable computation, and
a non-reusable authority-preparation lifetime. It would also have to preserve
B's callback order and its behavior when callbacks change dependencies, rather
than silently treating those changes as unsupported. An immutable build/source
identifier alone is insufficient. That larger boundary has not been
established here, so this packet does not assert equivalence or readiness to
select a candidate.

## Next finite validation, when an environment is authorized and available

First parse and inspect these exact bytes. Run the four explicit witness
cases against the pinned source in an isolated process so the temporary global
descriptor/code modifications cannot overlap other test workers. Retain the
full log and exact source/environment bindings. The expected negative-control
divergence must stay visible.

For a future proposed implementation, add an independent comparison that
requires it to match B's complete hash, ordered categories/signals, action,
source and summary under the same mutations. Do not replace the negative
control's expected divergence with a weaker predicate to obtain a pass.
Preserve the existing request-facts, authority-callback and final-byte-writer
controls, including input types/order, private metadata, policy changes,
catalog/environment/server identities, owned-copy mutation, nested scopes,
approval claims and completed-write semantics.

The current source review found no concrete new selected-B security defect.
The callback is an adversarial in-process dependency mutation used to assess
semantic equivalence; no remote exploit or installed qualification is claimed.

Original E/F campaign source, stopped attempts and failure receipts remain
untouched. No performance run, new measured deferral, task promotion, budget
change, reviewer disposition or PRD acceptance change follows from this
packet.
