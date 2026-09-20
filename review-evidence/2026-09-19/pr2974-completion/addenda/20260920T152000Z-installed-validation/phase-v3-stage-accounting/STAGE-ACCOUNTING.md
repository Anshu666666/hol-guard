# What the completed 88-call observation measures

The original result in tree `bd63025378a0cfe65a6fee2d3783498e0b85bf32` has 88 complete, strict parent/daemon joins. The following arithmetic reads those retained rows only. No launcher, native call, installer or original workload was repeated. `OBSERVER-ACCOUNTING.json` contains every per-route minimum, median and maximum; `account_original_spans.py` preserves the calculation.

The measured bottleneck is the broad parent wait for the real child process. Its median share of the original launcher timer is 95.9–98.4% for the serial samples and 91.5–96.7% at concurrency 16. That interval includes the child’s Python startup, imports, authenticated HTTP path, server work, response handling, exit and the parent’s polling/reaping behavior. These data do not divide that interval into those causes.

The table gives medians in milliseconds. Each serial group has two samples and each concurrent group has sixteen. All intervals are instrumented. The daemon intervals come from the daemon process; the parent wait comes from the parent process. They are displayed alongside one another, never subtracted across processes.

| Route | Population | Launcher | Parent wait/reap | Daemon handler | Policy admission | Runtime status | Native client exchange |
|---|---|---:|---:|---:|---:|---:|---:|
| Claude Pre | serial | 202.341 | 198.246 | 44.821 | 8.431 | 8.178 | 25.316 |
| Claude Post | serial | 231.223 | 221.524 | 48.545 | 19.764 | 9.408 | 15.684 |
| Codex Pre | serial | 264.800 | 259.744 | 40.641 | 17.614 | 7.844 | 12.606 |
| Codex Post | serial | 276.627 | 272.062 | 43.754 | 15.640 | 8.430 | 17.036 |
| Claude Pre | c16 | 1476.443 | 1417.950 | 48.820 | 10.329 | 12.709 | 13.423 |
| Claude Post | c16 | 1599.906 | 1564.372 | 73.924 | 10.891 | 18.555 | 30.952 |
| Codex Pre | c16 | 1530.931 | 1487.493 | 47.631 | 6.927 | 10.534 | 21.576 |
| Codex Post | c16 | 1424.508 | 1346.028 | 70.543 | 18.142 | 13.039 | 25.435 |

Native status and native exchange are material measured daemon paths. On macOS the identity module deliberately keeps full executable validation; Linux live-child digest reuse does not apply. Native exchange is inclusive Python client/RPC work, not an exclusive Rust evaluation clock. Its pool-lease medians are 0.004–0.025 ms in serial and 0.004–0.006 ms at c16. Scheduler acquisition medians are 0.052–0.112 ms. The two workspace-policy calls together have medians 0.071–0.117 ms serial and 0.055–0.072 ms concurrent. Those small stages do not support increasing capacity or weakening publication/currentness checks.

Policy admission’s measured workspace call leaves 8.334–19.676 ms serial and 6.829–18.094 ms concurrent in other admission work. Exact source includes live managed-install lookup and harness canonicalization there. The original store getter reads/decodes the managed-install row through the ordinary connection/recovery/permission path. No inner SQL/connection span was captured, so this is a source-based candidate for further inspection, not proof that SQL accounts for that interval.

Receipt-submit medians are 0.070–0.126 ms serial and 0.072–0.103 ms concurrent. They prove submission returned true on this observed path; they do not measure asynchronous durable SQLite commit, filesystem sync or physical I/O.

## Diagnostic work and its actual brackets

There are 440 parent spans and 1,232 daemon spans, 1,672 starts and ends in total. Each span takes a clock sample before its start-lock bookkeeping and another before append-lock bookkeeping. Thus start bookkeeping is inside its own interval; end append and the after callback are outside its own interval but normally inside an enclosing span. The counts are source-derived and matched to actual recorded stages. Their individual execution/lock-wait costs were not measured.

| Diagnostic work | Position relative to original timing | Available duration evidence |
|---|---|---|
| Driver imports, 37 provider hashes/Git identities, wheel/runtime/manifest admission, owned-interpreter preparation | Before the producer and individual launcher timers; corresponding after checks follow the entire block | No per-operation duration; startup/cache/scheduling effects are not removed |
| Extra observer imports in the daemon fixture child and attachment after real service entry | Inside the 4,807.083 ms fixture startup; outside all 88 individual launcher timers | Fixture startup only; no import attribution |
| Parent coordinate/registration validation and ContextVar setup | Before the original observation function starts its timer | Not individually timed |
| Capture of the real immutable input string; contained-process wrapper | Inside the original launcher timer | Original timer versus contained-process interval provides the same-parent remainder below |
| Parent input JSON parse, full freeze, semantic/full/input/output hashes, result facts | After the contained-process end timestamp, before returning to the original launcher timer | Included in the measured parent remainder; not a separately timed pure diagnostic interval |
| Parent spawn PID callback and each span’s lock/stack bookkeeping | Outside each leaf endpoint, inside its enclosing contained-process interval | Mixed with original process-helper glue in same-process direct-child remainders |
| Daemon immutable entry freeze, route validation and context setup | Before the handler span begins, on the actual handler thread | Individually unavailable; can affect the containing HTTP/child interval |
| Worker consumed-input freeze/comparison | Before the worker span, inside the handler span | Mixed into the handler remainder |
| Envelope/reply hashes, typed identity projections and event appends | After their leaf endpoints, inside the enclosing worker/native-edge intervals | Mixed with original glue in their same-process remainders |
| Receipt identity projection | Before receipt-submit span, inside worker span | Mixed with original worker glue |
| Daemon full exit freeze and entry/exit hashes, mutation check, finish/unbind | After the handler span; handler body already performs its normal response writes | Individually unavailable; do not assume it is all on the client’s critical path |
| JSON snapshots, full report export, strict join recomputation | After the producer and original fixture cleanup | Outside all original launcher samples |

The parent timer outside the contained-process span is 0.210–0.355 ms by serial route medians, and 0.123–0.152 ms at c16. Across those 72 rows it ranges from 0.040 to 0.576 ms. This bounds that particular post-process callback plus surrounding wrapper/timer work in each sample; it is not the total observer overhead and is never subtracted to manufacture uninstrumented latency.

The handler interval outside its three direct children has route medians 1.304–1.788 ms serial and 1.430–2.365 ms concurrent, with an observed concurrent maximum 26.061 ms. This includes original validation/response glue, diagnostic work and scheduling. Native-edge remainders have medians 0.275–0.743 ms serial and 0.447–0.609 ms concurrent. Worker remainders have medians 0.180–0.409 ms serial and 0.159–0.437 ms concurrent. These calculations subtract only sequential immediate children from the same process and row, then summarize the per-row remainders. Nested medians are not added or subtracted.

Each call performs one parent full-input freeze and three daemon freezes (entry, worker comparison, exit): 352 freezes in total. The parent input is 149–155 bytes for PreToolUse and 1,231–1,237 for PostToolUse. Actual native envelope sizes are 832–974 and 1,909–1,921 bytes respectively; replies range from 1,390 to 3,812 bytes. The parent callback hashes output once; the daemon hashes the actual envelope after encoding and again after exchange for a join. This is real extra diagnostic work. Its placement and sizes are known, but assigning an unsupported per-byte or total millisecond overhead would be speculation.

No observer module is injected into the actual registered launcher children in this run. Their product module imports, HTTP authentication/challenge, network queueing and shutdown remain uninstrumented. The parent wait cannot be relabeled import time. Changing host load, artifact history and diagnostic work also prevent a clean regression comparison with the earlier 154–181 ms serial medians. The older failed observer rows remain failed.

## Next boundary

No source optimization or native launcher activation is selected from the unmeasured child remainder. The next concrete proposal is a separate small child-attribution diagnostic using the existing four registered routes and original result/receipt contract, with explicit diagnostic-environment provenance and untimed forwarding/negative controls. It will inspect retained profiles first, preserve registered argv/product bytes/deadlines, and measure actual child import/bootstrap/authentication/HTTP boundaries without repeating the 88-call population. The completed older native pilot and pure-package lazy-export experiment remain historical evidence, not work to repeat.

All original serial p95 50 ms/p99 100 ms and c16 p99 200 ms ceilings remain unchanged and missed. No qualification, population-minimum, resource or release claim follows from this accounting.
