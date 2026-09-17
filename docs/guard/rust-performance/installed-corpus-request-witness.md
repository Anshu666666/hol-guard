# Original installed-corpus request failure context

The seventh native-wheel Windows job (`35264203634`, attempt 1,
`105347152805`) at source `79cb6921ff722a597b545350485864dcd9310bdc`
first completed the standalone 21-route normalized corpus. Its later installed
SLO fixture failed inside another normalized corpus request: the original
`urllib.request.urlopen(..., timeout=5)` raised `TimeoutError` while reading the
HTTP status. That record does not identify the harness/event or prove a server,
native-readiness, policy, or transport cause. The earlier successful corpus and
the later failure remain distinct observations; no final SLO report was produced.

`scripts/native_probe_request_witness.py` now wraps only each original request
in that normalized corpus. On an exception it emits one bounded JSON diagnostic
to stderr containing the closed harness/event, already validated route count,
the client's unchanged five-second transport timeout, and a finite failure
category. Direct `TimeoutError` and `URLError` wrapping an actual `TimeoutError`
are classified as timeout; exception text is never used as evidence. Unknown
labels become `other`. Paths, URLs, tokens, payloads and exception messages are
not included. The record does not assert a native route or a root cause.

The wrapper makes no additional request, changes no deadline, and re-raises the
same exception. Diagnostic emission failure cannot replace it. Success and the
semantic checks following the request are unchanged. The record observes a
transport exception; it does not measure a fresh five-second budget or claim
that the configured transport timeout bounds the whole corpus.

Focused regression coverage verifies the exact exception identity, original
single-call transport timeout for all three client branches, successful response
preservation, validated-prefix conservation, unknown-value privacy and a failing
diagnostic sink. This change adds diagnostic context, not an installed passing
rerun or a correction to the observed timeout's unknown cause.
