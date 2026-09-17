# Capacity-wave native availability diagnostics

This fixture diagnostic was added after the native-wheel run at source
`2ebb01ff356101aea8d658ce639fe2c87188bd0d`. It does not establish a production
cause or qualify that source. Existing conservation gates and deadlines remain
unchanged.

## Actual failed evidence

In [native-wheel run 35240794111](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794111),
the Linux concurrency-64 wave completed 64 responses without transport errors.
It delivered 48 allows and 16 explicit overload responses, while the worker
counters recorded 32 native-resident and 16 native-fail-safe routes. The native
overload delta was zero. The existing gate correctly rejected the missing
resident attribution, native-overload mismatch, and incomplete conservation.
Those delivered allows are not evidence of 48 native-authorized decisions.

The Windows wave also completed 64 responses without transport errors: 35
allows, 29 explicit overloads, 34 native-resident routes, one native-fail-safe
route, and zero native overloads. It failed the same conservation checks. The
report's inferred 28 bypassed requests do not establish a conserved wave.
Windows separately had one ordinary availability fallback. Intel failed its
unchanged concurrency-16 latency gate at 1,014.141 ms against 1,000 ms; its route
counts conserved. The ARM job passed. These observations are retained failures;
no counter correction, retry, or relaxed acceptance follows from them.

## Diagnostic contract

`capacity_none_witness` wraps only the fixture's own
`HookWorker._review_raw_hook_native` once per wave. It remains installed through
the existing bookkeeping wait and restores the original method on every exit.
The original method is called exactly once with unchanged arguments. Original
returns and exceptions propagate. No new status, client, receipt, authority, or
retry operation is added.

Only original `None` returns are retained. The report contains at most 64
records and a count saturated at 65, with overflow, observer-error, supported,
and incomplete flags. Each record projects fixed harness/event names, snapshot
presence/positive-generation state, and the remaining original deadline after
return, clamped to 0–9,000 ms. It does not retain payloads, commands, file paths,
generation values, response bodies, or exception text. A projection failure
marks diagnostic incompleteness without replacing the native result.

Before and after failure codes are read from the existing invocation thread's
context and projected to the existing finite code vocabulary. The context is
not cleared. An early bridge return can precede the native client's reset, so
even a nonempty after-code may describe an earlier call. A changed context is
reported as a change, not proof that this request reached the client or that
the code caused this `None`. Bridge stages and per-request engine attribution
remain explicitly unproved. This helper does not reuse the single-thread bridge
stage observer for parallel calls.

The report freezes on context exit. Late original calls can finish but cannot
change published records; incomplete bookkeeping remains visible. Missing
worker support, callback exceptions, overflow, and unfinished bookkeeping are
not fabricated as complete observations. Transport exceptions remain in the
original wave error count rather than being converted into `None` records.

The diagnostic is attached to capacity reports and bounded warmup-failure
evidence. It is excluded from dataclass comparison so the existing independently
reconstructed counter proof is unchanged; absent diagnostics retain the prior
report shape. Public evidence is projected through the closed schema again.

## Sixth-source serialization correction

At source `9d3907a2e6ed1ec201281901cb878836a7dad32d`, Linux native-wheel job
`105323757981` recorded 15 actual raw bridge `None` returns and zero unclassified
responses in its failed concurrency-64 wave. The unchanged six-level aggregate
privacy bound replaced every record field with `truncated`: the old path was
`concurrency.sixty_four.wave_evidence.none_witness.records`. The printed report
and uploaded JSON share that rendering, so neither preserves the lost fields.
Their values and the underlying native availability cause remain unknown.

The later report correction puts closed-schema diagnostics at
`capacity_none_witnesses.sixteen` and `capacity_none_witnesses.sixty_four`, omitting
their deep duplicates from `wave_evidence`. Reports without diagnostics retain
their prior shape. Standalone wave and warmup-failure reports keep their existing
schemas. The global depth, redaction, collection and byte limits are unchanged;
every diagnostic still passes `capacity_none_report` and final privacy admission.

The regression uses the actual final SLO renderer for each wave, demonstrates
the original truncation, then checks JSON round-trip and repeat privacy admission
of the shallow records. It retains the 64-record bound, overflow/incomplete flags,
finite-code projection and non-authoritative attribution; arbitrary fields and
values cannot escape. All counters, failed gates and other report fields remain
equal to the report without diagnostics. This is a source-only export correction,
not recovery of the sixth records or proof of a production cause.

Correction validation passes 64 focused capacity, witness, failure-envelope and
contract tests. Both changed source modules typecheck with zero errors and zero
warnings; Ruff check/format and diff checks pass. No installed or performance
workload was run for this correction.

## Measurement and qualification limits

The pre-call context read and post-`None` callback execute inside the original
request interval and consume its existing budget. The short record lock is
never held across native evaluation. Report construction occurs after the wave
and bookkeeping wait. This is diagnostic instrumentation, not a zero-cost
observer or an independent latency measurement. It does not establish a client
pool, resident admission, or scheduler root cause. No local performance run or
new installed qualification is claimed by this source change.

Source validation passed 74 focused capacity, conservation, failure-envelope,
load-executor, and contract tests. The new regressions include parallel context
isolation, stale-code retention, original exception identity, late completion,
overflow, finite projection, and unchanged failed gate outcomes. Four changed
Python source files passed type checking with zero errors (69 warnings); Ruff
and diff checks passed. Independent source review found no additional native
calls or changes to original return, exception, or conservation semantics.
