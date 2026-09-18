# Foundation 26cd: terminal cancellation addendum

This addendum closes the earlier incomplete observation for foundation `26cd4dff3f138990a8e9f6a729a970c1dbd90fa4` without changing its published interim receipts. It was collected from GitHub between `2026-09-18T08:36:05Z` and `2026-09-18T08:46:42.010934+00:00`. All 25 workflows and 178 distinct check records are terminal; both check pages and both CI job pages were fetched and their totals and unique IDs verified.

| Population | Final result |
| --- | --- |
| 25 workflows | 23 success, 1 failure, 1 cancelled |
| 178 checks | 149 success, 22 skipped, 5 failure, 2 cancelled |
| Main CI, 114 jobs | 106 success, 6 skipped, 2 failure |
| Native wheel matrix | Windows success; both Macs failure; Linux cancelled |

Native wheel [run 35273135609](https://github.com/hashgraph-online/hol-guard/actions/runs/35273135609) is cancelled, updated at `2026-09-17T21:15:09Z`. Linux job `105377132699` is cancelled, completed at `21:15:08Z`. Its enforced soak step ran from `20:51:54Z` to cancellation at `21:15:03Z`: 23 minutes 9 seconds. This was an interrupted attempt. Neither its earlier successful probes nor the distinct completed cdd or a001 soaks makes this soak complete. The other cancelled check is Kilo.

The terminal Linux artifact `10520262970` is available and its 6,720,391 bytes match GitHub SHA-256 `5880f50420f4bd2a4e2b7f73ed733c884209634c1ddb0f4cba8526e7963346a1`. Its embedded runtime manifest and executable size/hash match, and the manifest names build `eafc8038f2d3051991768d944e0bd855fdcc5889`. That merge's tree equals the 26cd tree and its parents are release base `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and 26cd.

The ZIP contains one native wheel and exactly four JSON receipts: default-auto, Pi output, installed SLO, and authenticated native stop. It has no `native-soak.json` and no `native-artifact-evidence.json`. The exact four JSON members and embedded runtime manifest are retained in lossless gzip, alongside complete job metadata and the cancellation log. The decoded log SHA-256 is `bdf0627b6d5dfe97a52fa94ca61115cc10a2d53320d53518888d1515c109c7b7`.

The existing failed CI and macOS attempts remain failures. The original 26cd interim catalog and manifests remain byte-for-byte intact at their prior source; this new terminal folder records cancellation separately. No workflow was rerun or cancelled by this collection, no review or alert state changed, and no incomplete measurement is promoted to release qualification.
