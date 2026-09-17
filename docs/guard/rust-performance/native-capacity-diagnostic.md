# Bounded capacity failure observations

The retained [9db Linux wheel failure](evidence/takeover-9db62e/wheel-linux-native-installed-slo.json)
delivers 36 allows and 28 explicit capacity responses, while its route counters
record only 22 resident decisions and 14 native fail-safes. The existing strict
conservation gate rejects this wave. Its original artifact does not identify
the 14 individual failure reasons, and remains unchanged.

The subsequent fixture collector observes the same capacity wave without
repeating requests or modifying deadlines, policy, readiness, routing, admission,
or the conservation gate. It captures closed action/reason labels and bounded
unknown-string digests after the existing delivered-response timer. A thread
context keeps each load operation's response separate. Counts are capped at the
wave size (at most 64), and exceptions remain separate from returned deliveries.

During the wave, a wrapper invokes the original native worker operation exactly
once with the same arguments. It retains at most eight missing-edge diagnostics
from the actual worker context, including already-computed native-edge stage
facts through the shared reentrant `capture_native_edge_stages` fixture. That
observational wrapper's overhead remains included in request latency. It never
refreshes runtime health or policy. Flat diagnostic fields survive the complete
failure-report privacy boundary without increasing its depth or byte limits.

Native and delivered records are independent aggregates. Their order does not
establish a per-request join or native route attribution. Additional calls beyond
the bounded collector are still executed once and explicitly mark counts as a
lower bound. A missing native result, overload, unknown denial, or transport
exception receives no new acceptance rule.

The [source validation](evidence/native-capacity-diagnostic-validation.json)
records 71 passing focused tests, lint/format checks, exact source bytes, and the
dependency on root diagnostic commit `962365d34777221ae87c178f44729008103d9085`.
The regression reproduces the retained 64-wave accounting shape and verifies
that it still fails while its closed semantic counts are retained. No local
installed execution or new hosted performance claim is made by these tests.
