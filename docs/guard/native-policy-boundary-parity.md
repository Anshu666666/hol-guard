# Policy parity at explicit capability boundaries

`test_native_policy_boundary_parity.py` compares the actual Python hook consumer
and snapshot compiler with one exact native scoped-composition test. Its 18
cases cover allow/review/block, enforce/prompt/observe, and configured publisher
matches, missing publishers and foreign publishers. The Python test recreates
every checked-in fixture through the actual configuration loader, Store and
hook renderer. The slow test then runs Rust and compares its actual result with
those independently recreated Python results. No command in the fixture is
executed.

The comparison preserves three distinctions:

| Input | Supported interpretation | Refused or unavailable interpretation |
| --- | --- | --- |
| Python `prompt` mode | The real compiler projects it to native `enforce`; review still denies execution pending approval. | A literal uncompiled native `prompt` snapshot is rejected. |
| Publisher selector | A matching configured publisher key selects its action. Missing and foreign keys retain the configured fallback. | A payload publisher string is not verified publisher provenance. All these fixture publishers remain unverified. The generic hook cases do not prove artifact-scoring use of `unknown_publisher_action`. |
| Artifact content hash | The Python artifact diff and changed-hash policy require reapproval when content changes. | Native scoped shell composition does not support content-hash rows; both unchanged and changed rows explicitly refuse. No native content authority is inferred. |

The native result exposes its exact reason code. Python's generic JSON result
exposes composition fields and currently lacks the same reason-code field.
The tests bind those distinct presentations and the actual decision, action,
floor and observation results; they do not claim literal reason-code equality
or complete policy parity for every artifact producer. A content-capability
refusal is not a successful parity evaluation.

These are source component controls. The Python oracle is explicitly enabled
only during Python evaluation and removed before Cargo runs. The Rust test
exercises real composition with strict decoded fixture snapshots; it does not
authenticate a resident, issue or consume an approval, prove an installed
adapter, or establish a timing result. Native execution is credited only after
the exact named Rust test or the slow comparison actually passes.
