# Installed recovery failure evidence

The macOS Intel native-wheel job
[105198454725](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287375/job/105198454725)
failed recovery sample 1 on PR head `107606388ad55f924a4e2924b4ff84e5fa08e6ff`.
Its error combined the delivered-allow and native-resident assertions into a
single message. The retained stop diagnostic reported verified containment;
neither that diagnostic nor the generic failure establishes which subsequent
recovery condition failed. The underlying recovery cause is not established.

The corrected collector retains the original preparation and recovery
observations: delivered-allow Boolean, route, explicit overload Boolean, a
closed response-reason vocabulary and bounded finite response latency. It
captures the reason only after stopping the original response timer. There is
no extra probe, retry, changed deadline or substituted observation. Unknown
reasons become `other`; unknown routes become `unclassified`. Neither is a
successful native observation.

The failed recovery still raises after its measured elapsed value reaches the
private numeric journal. The exception uses the existing qualification-failure
outer schema so the actual paired-worker exporter retains its fields. The same
finite projection appears in the legacy runner's exception text because that
runner does not use the paired exporter. No response body, command, output,
private path or arbitrary error message enters this projection.

Validation at this source change: **68 tests passed** across recovery privacy,
real paired failure export, original lifecycle timing, interrupted numeric
collection, capacity accounting, daemon fixture and generic failure handling.
Both in-process and separate-process session tests prove reason projection runs
after the original timer stops. A deliberately allowed availability continuation
on `native_fail_safe` remains a failed recovery and retains its original sample.

Scoped Ruff/format/whitespace checks passed. Four directly checked source
modules have zero BasedPyright errors and 102 warnings. Including the existing
daemon-fixture module yields ten errors on unchanged declarations/conversions;
this is not a clean five-module typecheck claim. Actual installed recovery
execution and the four-platform qualification remain pending.
