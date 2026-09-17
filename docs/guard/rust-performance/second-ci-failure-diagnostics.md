# Diagnostics for the second installed CI checkpoint

The native-wheel run for published head `24ba2d130a90f36b676139f03cabea98a2c3b00e`
failed on all four platforms. These changes preserve those failures and improve
the evidence available from the next run; they do not establish qualification.

The Windows RSS fixture failed before wheel construction because the nested
readiness relays compared binary LF with text-mode output, which Windows can
translate to CRLF. Every relay now writes binary LF. The standard-library-only
fixture launches the base interpreter so its intended three-process tree does
not acquire virtual-environment redirector processes. The exact three-process,
memory, thread, handle and exited-root assertions remain unchanged. A portable
test runs the actual nested program under the existing process-containment
runner. The focused memory suite passed 29 tests with one Windows-only skip;
the actual Windows assertions still require CI.

Linux failed the RSS warmup route proof in job `105225647938`. The former error
did not retain the wave's route counters. A bounded failure envelope now retains
the original attempted/completed/error and delivered-response counts, finite
engine routes and proof-failure codes. It performs no retry and preserves the
existing `qualifies(..., allow_overload=False)` decision. Unknown counters stay
unavailable, unknown codes become `other`, and the report explicitly makes no
per-request native-route attribution claim.

macOS ARM job `105225648136` failed the source full-review witness at `cursor/5m`;
macOS Intel job `105225648434` failed at `pi/1m`. Each recorded one native edge
call with no admitted result. The witness now records the existing thread-local
client failure context before and after that original call, using a finite
allowlist. It adds no I/O, retry, state reset or deadline extension. Its explicit
`thread_context_before_after` scope prevents a stale failure code from being
misrepresented as proof of a new client attempt. The cause of either installed
failure remains unestablished until new evidence is collected.

The combined diagnostic, route-conservation, load-executor and failure-export
suite passed 68 tests. Ruff, formatting and independent source review passed.
These source suites overlap with the focused memory and witness checks and
must not be summed. Production performance targets and admission conditions
are unchanged.
