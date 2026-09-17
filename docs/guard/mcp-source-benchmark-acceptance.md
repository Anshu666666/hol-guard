# MCP source benchmark acceptance audit

The original RSP-098 acceptance is: "Measure startup, catalog hashing,
classification, policy, barrier, child/network/human wait and serialization with
identical synthetic traces." That finite source-benchmark task is complete in
the frozen evidence below. It is distinct from the installed and release
qualification requirements of PRD sections 5 and 6.

| Required observation | Completed evidence and boundary |
| --- | --- |
| Startup | All 41 initial stdio cells record worker spawn through initialization, initial catalog delivery and Guard imports separately. These are source-worker observations, not installed launcher measurements. |
| Catalog hashing | Real catalogs with 10, 100 and 1,000 tools, five alternating cached/uncached process blocks and separate exclusive catalog hash/capture phases. Full response traces, generations and forwarded IDs match each pair. |
| Classification | Full category analysis and request-identity phases in the original, optimized prefilter, C and D source comparisons. The 128 KiB original hotspot and near-limit residual are retained rather than hidden by the ordinary controls. |
| Policy | Actual current-policy lookup and real temporary-store evaluation under warn/review configurations. The report does not represent a large user database or configuration-file reload workload. |
| Barrier | The unchanged configured 5 ms quiet/freshness barrier is separately timed and retained in complete client latency. Catalog-refresh and pending-approval invalidation use actual child notifications. |
| Child wait | A declared 20 ms synthetic child delay, separate child CPU and response-wait phases. Deliberate waiting is not labeled removable Guard computation. |
| Network wait | The shipped RemoteGuardProxy helper runs against actual loopback HTTP with identical synthetic bodies at 0 and 20 ms server delay. Both controls verify 21 ordinary responses and one 204 notification. This is not TLS, live remote or the draft hosted MCP route. |
| Human wait | Real elicitation exchanges use a declared 30 ms synthetic client approval delay, with accept, cancel and catalog-invalidated outcomes. Wall time is separately attributed; it is not human reaction-time evidence. |
| Serialization | Nested exclusive JSON serialization and pipe-write phases include catalog/request processing and complete result wrapping/forwarding. Instrumented attribution remains separate from ordinary latency comparisons. |

The [initial report](rust-performance-mcp-rebaseline.md) and
[41-cell raw evidence](../../release-metadata/mcp-stdio-rebaseline.json) retain
3,362 successful forwards, four cancellations and four invalidations, with no
unexpected outcome. The source-worker pause/resume control preserves zero
requests in the paused next cell and does not discard or retime a decision.

That historical 41-cell report pins its runtime but did not record execution
harness hashes per cell across the documented pause/resume and integrity
corrections. It therefore does not establish exact reconstruction of one
unchanged historical harness for all 41 cells. This attribution gap is retained;
the later A-to-B, C/D and native campaigns have their separate frozen source and
harness identities. Completing the named measurements does not close that
historical reproducibility limitation.

The later [structural-facts report](rust-performance-mcp-structural-facts.md)
freezes the completed optimized residual rerun: 46 cells, 3,196 successful
forwards and 23 exact paired traces. Five alternating ordinary blocks and
separate near-limit ASCII, Unicode, dense and nested diagnostics measure local
CPU and process memory, including transient whole-worker RSS. These results
reject universal D activation; they are not missing measurements merely because
the candidate failed the performance gate. The earlier adverse B-to-C comparison
remains separately available and unchanged.

RSP-103's overhead/memory measurement is therefore available, while its RSP-100
dependency remains OPEN and the explicit native selection experiment has its
own evidence and decision. No completed source-benchmark row closes that
dependency, grants an installed or platform pass, or changes a failed candidate
into a qualified one. The RSP-010 qualification requirement still demands the
declared larger sample counts, supported installed platforms and confidence
intervals; all these source campaign qualification flags remain false.

The four native text predicates are an additional bounded selection experiment,
not a prerequisite to recognizing the already completed measurements above.
Credentials, live remote orchestration, full policy ownership and the complete
proxy rewrite remain outside that kernel boundary.
