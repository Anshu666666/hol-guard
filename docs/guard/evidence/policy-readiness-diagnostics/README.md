# Native policy refusal diagnostics

The private qualification fixtures now retain a bounded publisher label that
the existing failure path had already observed. This is additional evidence
for a future occurrence. It does not identify or repair either historical
Windows failure, and it is not an installed qualification result.

Source/test commit: `288409b6b95ced2cc85b804b7a7804e3dfc0b6f2`.
Source tree: `e2d3b9b1000fe4972b35fb24dcd6f643839feb97`.
Parent: `69a09bc94b22bd5a789f137b9b7ebf3132296f83`.
The three instrumented fixture files at the parent are byte-identical to
the observed public source `590ce01334a7724f3f1349b2ab252110a5a268f5`.

## What the original Windows evidence establishes

Paired run `35330471726`, Windows job `105553416357`, artifact `10541486704`
contains eight JSON members and no wheel or separate publisher trace. The
archive SHA-256 is
`4989afbe1b210d6bfdf0fcfa9421ed9359f09c03e88531a1ed13b8ec8b42bbad`.
Its metadata identifies candidate 590 and frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. The reported paired wheel SHA-256
is `7888659f1a24365ce998ecb61c5c7f9495382c9a45a720710bbd2a6f6b856c89`.
The paired wheel is not available in that archive, so this review makes no
installed Python byte-identity claim for it. The separate native-wheel job
used test merge 698155 and must not be substituted for this paired build.

`pi.PostToolUse.empty-output.empty` failed the route validator with
`allow`/`native_policy_not_ready`. The wrapped hook-native call and completion
counts were zero; worker timeout, containment and resource-limit flags were
false. That count covers the wrapped hook review function, not every native
publisher IPC operation in the process. No publisher error or case-specific
readiness duration survived in the retained candidate failure.

The separate installed Ollama probe completed two initial cases and then
failed enabled-phase readiness at revision 1. It recorded elapsed 0.0 ms,
budget not exhausted, no snapshot, publisher not ready or closed, and
`publisher_error="unclassified"`. That value establishes that a nonempty
publisher error outside its old allowlist was observed; it does not identify
the error. The retained digests hash generic assertion/reason text, not the
missing publisher code. The full retained job log adds no specific cause.

These readiness observations do not establish a common cause with the
separate Windows receipt failure counts (3 at public 7a, 1 at public 590).
Those original counts and the distinction between failed persistence attempts
and post-commit exceptions remain documented in the separate
`receipt-failure-diagnostics` evidence directory.

## Why the cause was missing and what changed

The existing policy preparation code skips its readiness wait when a
nonempty publisher error is already present, then attempts to reuse an
acknowledged snapshot. The observed zero duration is not proof that the
400 ms budget was exhausted or should increase.

On a refusal, `_native_policy_not_ready_reason` reads the publisher's current
error and returns an explanatory string. PostToolUse rendering drops that
string. The helper's AST is identical in frozen 2e and candidate 590. The
fixture now observes the helper's original return once, only for the exact
daemon it owns, before rendering discards it. It returns the identical object,
lets original exceptions propagate, and reads no publisher or clock state.
Its helper patch is installed after successful fault setup and restored by the
existing context stack. Optional recording failures cannot replace the
original return; incomplete recording makes the count unavailable.

The Ollama failure collector already holds `publisher.last_error` after its
two timing reads. It now serializes that same local value after constructing
all original readiness fields. Its legacy `publisher_error`, timing reads,
deadline, readiness/property calls, exception, and acceptance logic remain
unchanged.

The serializer accepts only exact plain strings. It contains 140 reviewed
literal codes and reuses the existing 155 fixed resident lifecycle codes,
plus the fixed Windows ACL failure base. Unknown values retain a SHA-256 of
at most the first 128 characters, encoded with UTF-8 replacement, and an
explicit completeness flag. Known parameterized ACL failures export only the
fixed base plus that fingerprint. No suffix, path, raw error message or ACL
detail is exported. Custom inputs cannot invoke conversion, hashing,
attribute, equality or metaclass callbacks through the new serializer.

`policy_refusal_diagnostic` is a shallow bounded record;
`policy_refusal_count` is an observed count or `null` when the observer or a
complete count is unavailable. Missing errors and unsupported inputs have
explicit states. Both fields are copied into the existing corpus failure
envelope. Zero wrapped native calls remain zero. There is no inferred claim
that an explanatory cached error was the sole cause: asynchronous publisher
state can change, and details discarded before `last_error` was set remain
unavailable.

## Validation and limits

- Initial focused tests: **81 passed** in 1.85 seconds. After the bounded
  recording-failure test and typing corrections, final focused and related
  tests: **140 passed** in 2.71 seconds. These cover actual production
  preparation and PostToolUse rendering with inert publishers, unchanged
  route rejection and zero hook-native calls, original argument/return/error
  identity, owned versus unowned daemons, worker-thread capture, subsequent
  publisher changes, resets/restoration, missing observers, optional recording
  failures, callback-free custom inputs, bounded private/Unicode/ACL values,
  exact Ollama call order/deadline/legacy fields, and privacy round trips.
- Final changed-file Ruff and formatting checks pass. Initial Ruff failed
  on three overlong test lines and one non-raw regex; initial formatting
  required three files. All initial outputs and the formatting change receipt
  are retained.
- Initial direct type checking reported seven errors: three in additions
  (corrected), and four existing errors in `native_slo_corpus_run.py`.
  The final baseline/candidate comparison explicitly selects
  `/workspace/scratch/c25672eb4c10/validation-venv/bin/python`. It retains the
  **same four errors** with identical messages, rules and source statements.
  Baseline has 143 warnings; candidate has 148 (the five added warnings arise
  from existing `Any` session plumbing and the unused patch return). The new
  serializer has no errors or warnings. This is a no-new-errors comparison,
  not a claim that these private fixture files fully pass type checking.
- An explicit AST audit removes only the recorded diagnostic imports, state,
  observer block, report fields and post-timing serializer. The remaining AST
  exactly matches all three original instrumented fixture files. Eleven
  underlying readiness, publisher, oracle, privacy and session files are
  byte-verified unchanged, and no production package source differs.
- The actual Desktop inventory has **395** bindings, all matching the retained
  fixture. None of the eight changed paths are bound. The existing generator
  and fixture remain unchanged and no report generator ran. Fixture SHA-256:
  `2b60b7fa1eb771a3f8d0cff456a26997f31b914836c06d7857044ba2a1cce754`.
- No installed/native transport or Windows qualification run was performed
  for this change. Readiness budgets, production responses and policy,
  thresholds, corpus count/order, validation predicates, privacy depth and
  frozen baseline remain unchanged.

The retained read-only witness predates implementation. It shows two distinct
injected fixed codes collapsing into identical old Ollama failure data and
PostToolUse responses, while their original helper strings differ. It uses
inert doubles and is a demonstration of information loss, not a reproduction
of either hosted cause. Its first invocation lacked the repository root in
`PYTHONPATH` and failed to import `ci`; the corrected invocation used `src:.`.

`manifest.json` records saved and decoded hashes for the original reports and
job log, source captures, source/type/binding audits, candidate patch, tests,
initial failures and final validation. `PLAN.initial.md` is the approved
read-only proposal; this file states the completed implementation and limits.
