# PRD status after installed validation

The implementation remains the reviewed risk reuse, Windows persistence and inactive-namespace repair integrated in `ad9d9238`. Current head `f8f190a2` adds a three-file test conformance correction. It preserves historical authentication vectors and their generator, checks the exact reviewed Windows-only reader insertion and its two provider hashes, and rejects additional source drift. Its affected cohort passes 74 cases with 29 explicit platform or unavailable-binary skips; the focused binding controls pass 29 cases. No production source changed in that successor.

Request-local risk reuse still requires exact input, authority, catalog and implementation identity, with revalidation around effectful callbacks and the original final 5 ms fence. Windows replacement still uses positive platform and exact-handle capability admission before mutation, preserves original Unicode reader behavior, and never retries after a native rename attempt. The publisher repair still admits a first generation only from a completely observed, unchanged empty namespace. These are implemented source changes; the remaining acceptance is measured separately.

Fresh normal Mac ARM, Mac Intel and Windows wheels were built from test-merge commit `753850955c33eb15f992d1fe7ca375dd26c3a070`, whose tree equals current `f8f190a2`. Their archive, wheel member, runtime and source identities are verified in the attached platform packets. Both Macs pass 24 native controls, 21 default-auto decisions with accepted/processed receipts, and all 14 ordinary smoke gates. Windows passes 149 private-file cases with 3 POSIX skips, all 53 mandatory cases, 90 original child frames, 18 Unicode pairs, the original manager selector and 40 storage/namespace cases. Its 21 installed native decisions and receipts pass. The separate Windows resident suite passes 5 cases but has no retained binary hash.

The fresh Windows all-evidence journal counter still reports `journal_checkpoint/os_permission:1`; native receipt failures remain zero. The original record does not identify the failed OS operation. A bounded failure-only diagnostic is being prepared to capture fixed operation/source identities and OS error scalars without exporting private paths or changing the original result.

| Installed observation | Actual outcome | Acceptance limit |
| --- | --- | --- |
| Corrected Mac ARM phase diagnostic | 88 parent/daemon joins; 84 allow, 4 deny; no capture loss; contained cleanup | Every original 50/100/200 ms route ceiling missed; small instrumented population |
| Fresh Mac ARM ordinary concurrency | c16 p99 423.803 ms | Ordinary 1,000 ms gate passes; original 200 ms target missed |
| Fresh Mac Intel ordinary concurrency | c16 p99 735.212 ms | Ordinary 1,000 ms gate passes; original 200 ms target missed |
| Original 100-workspace expiry cell | Pass; accepted registration to ACK 190.295685 ms; strict workspace-99 request and receipt checks pass | One instrumented cell; original 400 ms bound unchanged |
| Original 100-workspace service restart cell | Pass; accepted registration to ACK 367.173894 ms; strict request, receipt and drain checks pass | Does not equate this interval with full service startup |
| Lost metadata hint and key rotation cells | Fail in authenticated/current ACK admission | Earlier validated ACK/readiness observations do not prove later admission |
| First-admission-fault cell | Fails initial setup before the injected fault | No post-fault recovery sample |

The lifecycle command ran once with the original built-in observer, witness and clocks. Its original exit is 1 and the full 1/10/100 matrix was not visited. It provides no uninstrumented performance or complete lifecycle qualification. Failed cells have no recovered receipts. Its selected authentic Linux wheel came from the cancelled parent run; matching product source and exact installed identities support this separate finite diagnostic, while the missing soak and pure-wheel members remain missing.

The performance contract remains 50 ms p95/100 ms p99 for installed 1–16 KiB at c1, 200 ms p99 at c16, native warm 20 ms/cold 150 ms, and 400 ms readiness after materialization. At least five independent matched-host alternating runs, original route sample counts, payload/concurrency/offered-rate matrix, relative-benefit requirements, full descendants and the 12% mixed RSS limit remain. Ordinary 1,000 ms concurrency and 50% long-soak limits do not replace them.

Full six-file artifact validation, signing/frozen provenance, actual registered routes and controls, live version update/downgrade/rollback, mixed load and canary evidence remain incomplete. The current native Linux soak and strict four-platform collector have not completed at this snapshot. Eligible final-head GitHub review is still required; technical peers do not supply that approval.
