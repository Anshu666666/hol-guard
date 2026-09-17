# Qualification startup and source fixture corrections

The installed smoke run [35201516872](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516872)
tested candidate `92cf3c72d80d932b2a0ec4d72ec4d102a06da010` against pinned baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. Native wheels built on Linux, macOS ARM,
and Windows before the reported failures. These are failed qualification
artifacts, not passing latency or platform evidence.

The macOS ARM baseline's bounded startup stack identified the blocking call:
`socket.getfqdn` inside `HTTPServer.server_bind`, reached from the daemon
constructor. It did not identify a keychain or native policy publication block.
The production HTTP server now delegates binding to `TCPServer.server_bind` and
sets the HTTP metadata from the actual numeric bound address and port. The
daemon has no consumer that needs the reverse-resolved `server_name`; its
configured runtime host, authentication, and request admission are unchanged.
Tests prohibit reverse DNS and exercise actual listener binding/cleanup where
the host permits it.

That candidate fix does not repair the immutable baseline. The workflow's
separate macOS resolver preflight runs on its disposable CI host, before either
arm is measured. It probes the real `getfqdn('127.0.0.1')` in an isolated Python
child with a five-second deadline. If this fails, it adds one fixed dotted
localhost alias while preserving existing hosts entries, flushes the macOS
resolver caches, and repeats the same probe. Every maintenance command has a
ten-second deadline. `aggregate/runner-resolver.json` records before/after
statuses and timings, fixed-entry booleans, and whether repair was attempted;
it publishes no machine hostname, hosts-file contents, or child diagnostics.

Successful maintenance commands do not establish successful repair. The real
post-repair probe and the subsequent installed run remain decisive. The
preflight is diagnostic and does not itself declare qualification passed. Any
baseline measured after this step is explicitly conditioned on the shared
runner environment, applied equally to baseline and candidate. Neither wheel
is changed or monkeypatched, and the 30-second fixture control deadline and
400 ms native readiness limit remain intact. A first passing macOS retry is
still required to establish that this environment treatment resolves the
observed baseline startup failure.

Linux and Windows progressed to `claude-code/PostToolUse/benign/1m` and failed
its delivered projection. The source files had a `.txt` suffix under the
neutral `native-qualification` directory. The frozen source-path classifier
rejects that shape before content scanning. The corpus now uses `.rs`, a
source suffix admitted by the baseline and candidate, while retaining the
same content, hashes, byte classes, and exact allow/block/reason expectations.
The fixture tests check actual classifier admission and reject a regression
back to the non-source shape. The oracle has not been loosened to accept the
pre-scan rejection as a content result.

A local diagnostic using the prebuilt pinned baseline runtime
(`sha256:d3b3613713db36ea5ac836288a33ea03ab1d5e309cb3bba3575c0e315eb0a8b3`)
confirmed both sides with identical 1 MiB content:

| Suffix | Content | Native decision | Native reason |
| --- | --- | --- | --- |
| `.txt` | Benign | deny/block | `no_output_to_review` |
| `.txt` | Synthetic malicious | deny/block | `no_output_to_review` |
| `.rs` | Benign | allow/allow_original | `source_full_scan_allow` |
| `.rs` | Synthetic malicious | deny/block | `source_secret_match` |

This was the bounded v1 native component, not the installed resident route and
not a performance sample. The next installed artifacts must still validate the
repaired large-output cases and every subsequent corpus case.

## Release benchmark policy mismatch

The same candidate's Linux runtime performance jobs `105137131092` and
[105137129040](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516617/job/105137129040)
reached a healthy native resident, then rejected benign `allow/allow_original`
because its reason was outside the expected content-scan result. This fixture
uses inline output and has a separate cause from the `.txt` source references.

The release script had published the default warning policy while expecting
the intrinsic `output_scan_allow` reason. A native component diagnostic ran
the exact benchmark payload through `guard_hook_core::review_post_tool` and
the compiled `apply_post_tool_policy` using the Python-produced effective
policy projections. Its four actual outcomes were:

| Policy fixture | Content | Native result after policy |
| --- | --- | --- |
| Default warning | Benign | allow / allow_original / `native_policy_warning`, action warn |
| Explicit allow | Benign | allow / allow_original / `output_scan_allow`, action allow |
| Default warning | Synthetic malicious | deny / block / `output_secret_match`, action block |
| Explicit allow | Synthetic malicious | deny / block / `output_secret_match`, action block |

The benchmark now prepares the same explicit protected allow policy for both
arms before any samples, and validates the acknowledged mode, action settings,
empty selector overrides, and risk settings before native readiness timing.
The exact scan verdict/reason oracle remains unchanged; `native_policy_warning`
is named in bounded failure diagnostics but is still rejected as a scan result.
Report metadata identifies the shared policy fixture. This diagnostic is actual
native scanner and policy execution, not installed transport or performance
qualification. A passing release benchmark and the installed matrix are still
required on the next candidate.
