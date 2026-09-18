# Terminal hosted cohort for cleanup c9ed06b

This record covers exactly `c9ed06bbcb7cef2ecbb93955fdad34be71710aa7`, the signed cleanup commit whose parent is `590ce01334a7724f3f1349b2ab252110a5a268f5`. Collection was read-only. No workflows were rerun or cancelled, and no source, ignore entries, or security alerts were changed by this collector.

All 37 workflows are terminal: 34 succeeded and 3 failed. Every workflow's jobs and artifacts were fully paginated: 201 unique jobs (175 success, 20 skipped, 6 failure) and 229 artifact metadata records. Check runs were independently paginated with both filters: `all` has 207 records (180 success, 20 skipped, 7 failure); `latest` has 204 (177 success, 20 skipped, 7 failure). The separate CodeQL security check accounts for the additional failure beyond workflow jobs; its summary reports 11 high alerts. A successful CodeQL workflow does not clear that check or those alerts.

| Workflow | Run | Result |
| --- | --- | --- |
| CI | [35341986143](https://github.com/hashgraph-online/hol-guard/actions/runs/35341986143) | Success; 114 jobs: 111 success, 3 skipped; 195 artifact records |
| Native wheel | [35341986076](https://github.com/hashgraph-online/hol-guard/actions/runs/35341986076) | Linux, macOS ARM64, and Windows success; macOS Intel failure |
| Security Gates | [35341986015](https://github.com/hashgraph-online/hol-guard/actions/runs/35341986015) | Gitleaks failure; privileged workflow policy, Semgrep, and Trivy success; no uploaded artifacts |
| Native performance | [35341985948](https://github.com/hashgraph-online/hol-guard/actions/runs/35341985948) | All four platform jobs fail; original qualification remains incomplete |

The native wheel workflow checked out test merge `5406663a4420f0585b9a36002ee49f86e0970154`, whose parents are base `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and candidate c9ed06b. Its tree, `5d51e2d3adf6114111fad1558c0e2435b4f37597`, exactly matches the candidate tree. All four native wheel ZIPs were downloaded, their API sizes and SHA256 digests verified, every archive member hashed, and each actual embedded native runtime's bytes matched against the included installed identity report. Paired performance builds the candidate directly and records frozen baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b`; those paired report archives contain no wheel binary. These are distinct build identities and evidence scopes.

The actual wheel failure is macOS Intel, not Linux. Its installed SLO report has exactly one false gate, `recovery_latency`. The two observed recovery samples have p95/max 1080.857 ms, above the unchanged 1000 ms installed adapter threshold used by `scripts/native_slo_reporting.py:270` at c9ed06b. All other report gates pass; its evidence class remains smoke and qualification remains false. Linux's installed SLO report passes all its smoke gates.

All four native default-auto reports observe 21 accepted and 21 processed receipts, zero failures, zero drops, and zero durable pending receipts. These snapshots precede shutdown. The fresh Windows zero does not erase the earlier Windows observations of 3 failures at 7a and 1 at 590, establish their causes, or establish a persistence repair. The c9 commit is a cleanup checkpoint, and the later bounded diagnostics are not part of this cohort.

Paired Windows candidate run 0 stops with `GuardConfigSourceError` at `config_source_io.capture_guard_config:219`. Its diagnostic digest exactly equals SHA256 of the public code `guard_config_source_unavailable`, which the exact candidate source raises when converting an `OSError` or `RuntimeError`. The underlying exception was not retained, so this does not identify a narrower cause. The frozen baseline stops at `copilot.postToolUse.watch.1m` with a route mismatch and zero recorded hook-native calls. Both worker records show no timeout, containment failure, or worker limit breach. Zero hook-native calls does not establish zero policy-publisher IPC. Neither arm produces a completed Windows block or a comparison.

The Windows installed Ollama probe fails during enabled readiness after two initial cases and one completed phase. It retains an unclassified publisher error, elapsed readiness 0 ms, and no exhausted 400 ms budget. The report has no underlying publisher exception detail. No linkage to the candidate configuration-source failure or earlier receipt failures is established.

Both macOS paired frozen baselines stop at `daemon_fixture_deadline_at_construct_daemon`, with a retained stack through `socket.getfqdn` and HTTP server binding. Both candidates reject an interpreter with `codex_hook_interpreter_permissions_unsafe`: the captured metadata describes a regular, root-owned, group-writable file of mode 0775, with an invocation symlink. The original integrity policy remains enforced. The failure records do not report worker timeout, containment failure, or worker limit breach.

Linux completes one block per arm and produces a paired smoke comparison. Sampling, qualified-scope count, migration benefit, and program qualification remain false. The priority input route mismatch occurs in both arms. Candidate registered surfaces retains an unclassified failure at `native_slo_registered_surfaces_run._run_registered_surface_corpus:273`; the failing case and observed route were discarded by this version. Frozen baseline registered surfaces instead retains the specific `copilot.preToolUse.benign.small` projection mismatch, and its Python phase cleanup is not acknowledged. The candidate Python phase scenario passes its implemented scope.

Linux mixed-contention receipt accounting must be read separately from default-auto:

| Arm | Writer accepted / processed | Writer drops | Writer failures | Receipt accepted / processed | Receipt failures | Receipt drops / pending |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Frozen baseline | 906 / 906 | 304 | 7 | 605 / 605 | 6 | 0 / 0 |
| Candidate | 905 / 905 | 303 | 17 | 604 / 604 | 11 | 0 / 0 |

Drain does not make these observations error-free. The candidate also fails the mixed control-action enforcement and RSS-growth checks. Both arms fail resource coverage. Exact reports retain all counters and scope limitations, including unavailable SQLite VFS metrics.

Gitleaks v8.24.2 scanned the exact base-to-candidate range, reported 1264 commits and 96 findings, and exited 1. The hosted log does not contain individual findings and the job uploaded no report artifact. The separate local reproduction used the same pinned scanner version, exact range, and exact c9 ignore bytes, reproducing 96 findings. `gitleaks-historical-digest-audit.json` individually compares those reproduced fingerprints with the exact removed entries and retrieves their full historical source locally. All 96 match removed fingerprints; zero are outside that set. It verifies 75 module source values, 6 exact source values, and 1 archived-patch reconstruction, and separately records 14 installed launcher digest provenance chains. Only digests and provenance are published. Original runtime identity and qualification limitations remain unchanged; the audit is not a claim of fresh hosted success.

The immutable manifest retains exact connector response bytes and archive report member bytes in lossless gzip, with both compressed and decoded SHA256 digests. Windows CRLF bytes are preserved exactly. Eight downloaded native/paired archives were verified locally; every member digest is retained, while the publication omits wheel binaries and private journals. All 229 artifact records are retained, but only those eight archives were downloaded. Full raw evidence belongs to the separate evidence branch and must not be restored into the release PR cleaned by c9ed06b.
