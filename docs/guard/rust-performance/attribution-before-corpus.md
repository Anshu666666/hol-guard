# Attribution before later qualification gates

The tenth candidate Windows indexed run at source
`095074cda6a751ffaf12b070ecc46a3091f12471` failed its c16 route gate before
reaching Python phases, prepared identity, or fresh-child identity collection.
Those candidate observations remain missing; Windows baseline observations do
not replace them.

The later source moves those three existing collectors into
`run_attribution_scenarios`. Each block calls it after native runtime and receipt
profile admission, before the daemon/launcher corpus and headline work. It uses
the same independent fixtures, `4 * phase_count` phase requests, three prepared
identity requests and three fresh-child identity requests. The existing
`phase_count = min(100, priority_per_run)` choice, request payloads, native and
delivery checks, filenames, writer limits, fixture containment, deadlines and
archive inventory remain unchanged. No failed request is retried.

Each collector keeps its existing private journals, summary and finite failure
wrapper. One collector's retained failure does not become a pass or discard the
other collectors. A later corpus or c16 failure still raises its original
exception and stops at that gate. There is no final-report requirement for
retaining the earlier private files: the existing archive includes the private
directory inventory, including partial journals and summaries, when the final
numeric file and block report are absent.

The local handoff is a six-key mapping: fixed schema, receipt profile,
`headline_timing_eligible=false`, and the three unchanged reports. Later
`run_additional_scenarios` requires that mapping, validates its exact keys,
schema/profile, scope, exact boolean pass state and successful count shapes
before any remaining offers, and embeds the same report objects. The original
finite failure wrapper is accepted only as a failure for its expected scope.
There is no fallback collection path or second attribution-summary write. This
is an in-process orchestration check; source/artifact authentication still comes
from the enclosing installed qualification and evidence archive contracts.

**This changes execution order and defines a new source cohort.** Earlier
attribution can warm operating-system, executable or process-external caches
before later corpus/headline work, even though collectors use independent
children. No cache is cleared. Subsequent measurements must retain the new
source identity and must not be pooled with tenth or earlier timings. The
fresh-child interval still starts after interpreter startup/imports and private
journal admission, before its real constructor; normal resident preparation
may precede its first hook. This change does not establish cold OS-cache or
import-time coverage, repair a production route failure, or supply a new
performance result.

Focused regressions cover collectors called once, independent fixture cleanup,
unchanged report objects and private files, schema/count rejection before later
offers, retained censored collector failures, and the same downstream exception
object and terminal traceback. The failure test encrypts and authenticates the
partial file inventory without a final block report and verifies every recovered
byte. Local validation passed 101 focused tests, Ruff check/format on the five
changed Python files and diff checks. Independent source review and AST checks
confirmed all eight collector bodies and the retained writer were unchanged.
Actual execution of this reordered source remains required.
