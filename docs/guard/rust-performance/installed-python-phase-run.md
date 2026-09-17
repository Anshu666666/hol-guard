# Installed Python phase measurement driver

`scripts/native_slo_phase_run.py::measure_installed_phases(session, count,
evidence_file)` wires RSP-008/RSP-037 attribution into the installed diagnostic
fixture. The caller supplies a **separate**
`DaemonFixture(runtime, setup="normal")`; the headline `policy="normal"` fixture
has no native-result capture and is rejected before any instrumentation begins.
The existing `case_before` / `case_result` controls capture actual native results,
and the existing `phases_start` / `phases_finish` controls scope instrumentation.
No daemon/dispatcher or production-runtime change is needed.

`count` is an integer from 1 through 100 **per case**. Each size runs both a
benign and a synthetic-sensitive-content case, for `4 * count` total requests.
Each size has a separate profiler lifecycle and report. These requests cross the
real authenticated daemon adapter through `session.request`; their latencies
never replace or join headline SLO samples.

| Size | Exact serialized HTTP body | Classification |
| --- | ---: | --- |
| `small_inline` | 1,024 bytes | Entire output is inside the request body. |
| `maximum_supported_inline` | 1,000,000 bytes | Exact current production HTTP ingress limit, checked against the frozen corpus contract. |

The driver uses the actual `_GuardDaemonHandler._MAX_BODY_BYTES` and checks the
corpus contract agrees. The native envelope limit is separately identified as
6 MiB. It does not claim that a 1,000,000-byte HTTP body produces an equally sized
native envelope: native metadata adds bytes. A 5 MiB source-reference workload
has a small HTTP envelope and is **not included** as a substitute for this
maximum-inline fixture. The helper uses ASCII content and checks the exact JSON
serialization used by the real adapter. Tests independently capture the real
adapter's serialized argument, run the actual server body parser at the bound,
and prove a body one byte larger is rejected before reading.

Each case uses the existing frozen `native_slo_workloads` delivered/native
expectation factories and strict projection oracle. A benign result must use
`output_scan_allow`; the sensitive fixture must use `output_secret_match` and
block. An availability response, excerpt, different denial reason, missing native
result, or ambiguous/wrong/bypassed engine route cannot pass. Before/after native
route counters must show exactly one `native_resident` result. These are parsed
adapter-delivery assertions, not a fabricated HTTP-status observation: the
session API does not expose actual status, and its capacity substitution is
still subject to the strict semantic/route oracle.

After all cases for a size validate, the driver additionally requires exact
handler, envelope, native-client and edge-JSON invocation counts in the returned
phase report. Observed buffered HTTP body bytes must equal the configured wire
size times the actual attempt count. Missing spans or discarded timing/series
attribution fail the diagnostic run. The full phase report is journaled before
these completeness assertions, preserving evidence even when attribution fails.
The profiler report and its individual inclusive spans remain explicitly
ineligible for headline timing.

The evidence file is an exclusively created, owned **0600 JSONL journal**. It
reuses the existing qualification evidence file checks and refuses overwrite.
Each offered attempt is flushed and fsynced before request work; terminal rows
retain validation/failure, stage, whether a request actually started, raw request
call timing, session-reported request timing when present, route-counter
snapshots, and actual delivered/native semantic observations. Full parsed JSON
objects are identified by serialized byte count and SHA-256, without copying
response text. Known scalar semantic fields are retained; unexpected strings or
values are represented by their exact JSON value digest and size. Input bodies,
source text, credentials, paths and exception messages are not copied to the
journal. A failed native-capture reset cannot reuse a stale previous result.

The journal is bounded at **8 MiB**, **810 records**, **8 KiB per attempt/control
record**, and **256 KiB plus record overhead per phase report**. It reserves
terminal/report space before offering more work. The existing private control
protocol separately enforces its 256 KiB response limit. Failures do not remove
previous attempts, and available route/native observations are collected even
when the HTTP adapter raises. `phases_finish` is attempted after request/oracle
failures and even after a missing start acknowledgment. The owner must close the
separate fixture if its control process fails; this helper does not claim it can
restore a crashed process remotely.

Tests exercise success, actual serializer/body-limit parity, wrong delivered and
native results, missing native results, wrong/multiple/no engine transitions,
request/control errors, incomplete profile counts/bytes, attribution drops,
invalid count/setup, private-file overwrite and capacity safeguards. Controlled
session tests prove orchestration and failure retention. They are **not an
installed daemon qualification result**. Full baseline/candidate platform runs
must execute this helper and preserve its journal alongside the uninstrumented
headline evidence before RSP-008/RSP-037 acceptance can be completed.

Local validation: 54 tests passed across the new run helper, phase profiler and
isolated daemon-fixture tests. Ruff, formatting and whitespace checks passed.
Explicit BasedPyright inspection of the run helper reported 0 errors and 62
warnings, primarily dynamic fixture/private diagnostic access. This work was
built from `9d43b7cf6` plus the Python profiler change `02ff15c37`; no installed
baseline/candidate timing result is claimed by these controlled-session tests.
