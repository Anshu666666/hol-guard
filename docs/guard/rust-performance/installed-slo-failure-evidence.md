# Installed SLO failure evidence

The native-wheel runner now writes `--json` evidence and exits with status 1
when `run_slo` raises. This closes the diagnostic gap where a source-review
witness or registered-launcher failure ended the job before its SLO artifact
existed. The failure envelope uses
`hol-guard.native-installed-slo-failure.v1`, sets `passed` and
`qualification_complete` to false, and retains the existing bounded
`failure_evidence` contract. Failure never depends on `--enforce` being set.

The source witness still requires exactly one Rust decision, `allow`,
`allow_original`, the expected reviewed digest, and the existing accepted
full-review reason. On failure it retains at most two native observations,
their closed action labels, hashes of their reasons, and booleans for native
authority and digest equality. A missing result is explicitly unavailable.
The capped observation count is marked as a lower bound when the cap is
reached. The session adds the delivered verdict, actual route-counter
snapshots, harness, event, and size. The size loop records the failed sample
index and count of preceding completed cases.

The registered-launcher diagnostic records whether failure occurred during
process execution, JSON decoding, route validation, or semantic validation.
It retains before/after route counts, the observed route delta, fixed fixture
class, harness/event/size, sample index, elapsed time when available, and
process exit/containment/timeout/stream-bound flags. Parsed delivered actions
and hashed reasons remain available when execution reached decoding. It does
not claim access to the native verdict from the separate launcher process.
The enclosing measurement records completed preflights and timed samples.
Both error paths retain preceding completed measurement phases and counts.

`verdict_evidence` uses `semantic_diagnostic(cases=())`: every reason becomes
the SHA-256 of its compact JSON encoding. It uses the finite aliases
`model_action` and `model_action_digest` so the existing generic privacy
sanitizer preserves action evidence without accepting fields containing
`output`. The final report passes through that sanitizer before stdout or
file serialization. It contains no exception text, response body, source
bytes, filesystem path, registered command, stdout, or stderr. Existing local
exception messages remain available to callers; exporters use sanitized
details only.

Validation exercises `main` through the actual source witness and the actual
launcher validation functions, with controlled native/process boundaries:
a successful size followed by a failed source review; two launcher
preflights and one timed success followed by wrong route, nonzero exit, or
malformed JSON; missing and repeated native results; an unstructured OS
error; nested progress; and unchanged successful-run gate exit semantics.
The persisted, sanitized JSON is checked for the exact failed observations
and absence of private markers. These are functional diagnostic tests. They
do not reproduce the macOS Intel or Linux CI failure, establish its cause,
or qualify an installed performance result. The next affected CI run must
supply that evidence. No production code, platform source-opening contract,
semantic expectation, time budget, or SLO threshold changes here.
