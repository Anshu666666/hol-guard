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

## Aggregate validation after returned responses

The eighth native-wheel Windows job (`35270079893`, attempt 1,
`105366900977`) at source `a933921372ddb3772eff8a9d86771fe15da063b1`
returned all 21 normalized corpus requests, then failed the unchanged aggregate
route-count check: 19 `native_resident` plus one `native_fail_safe` totaled 20.
The request-exception witness had no exception to observe. This record does not
identify which request lacked a counter or establish the cause.

`scripts/native_probe_corpus_witness.py` adds at most 32 retained delivery rows
with closed harness, event, decision, permission, model-action and reason labels.
It captures the existing single `is_allowed` result per request. Unknown strings
become `other`; excerpt text and arbitrary response fields are excluded. A
failure-only diagnostic emits these rows separately from aggregate route counts
when the existing corpus validation raises. Missing, invalid or over-cap counts
remain `null`; an observed zero remains zero. Truncation and projection failures
are explicit.

Allowed delivery does not prove a native route. The diagnostic neither assigns
an aggregate route to an individual request nor identifies the missing counter's
cause. Requests, payloads, deadlines, waits, retries, validation predicates and
successful receipt fields are unchanged. Projection or emission failure cannot
replace the original validation exception. Focused regressions cover the 21/20
mismatch, a complete count with insufficient native decisions, quiet success,
closed labels, bounded counts and exception preservation. This is a source-only
diagnostic follow-up; it does not establish that the Windows corpus now passes.
