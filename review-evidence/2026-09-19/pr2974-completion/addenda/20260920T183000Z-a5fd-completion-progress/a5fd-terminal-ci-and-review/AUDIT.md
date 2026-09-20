# Current a5fd normal CI and review census

At 2026-09-20 18:17:05 UTC, all 195 check runs on `a5fdde302aba2a06265c2e6e934b6ac9b76750df` are terminal: 176 success and 19 skipped, with no failure. All 32 normal workflow runs report success. The four native platform jobs and the strict artifact collector finished; native run 35526539085 last updated at 18:13:42 UTC.

The actual test-merge build is `d7f30a0ad61d72d96d1a9e7970943404c4cc19dc`. Its tree and the product head tree are both `ee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9`; the identities remain distinct. The product commit is a sole child of e440; the PR base remains 4b89.

The Linux original log reports 100,000 responses for 100,000 requests, 250,000 receipts, zero errors, 21,164 health checks with zero failures, stable PID, and a passing soak. RSS increases from 617,193,472 to 640,372,736 bytes (3.7556%); p95 is 546.45 ms and maximum 624.07 ms. These are the original runner records, with authentic Linux archive/member admission owned separately by partition. The workload is count-bounded with settle-seconds 0; there is no fixed 30-minute duration. The whole Linux job has a 45-minute timeout.

The current Mac edge log ends with 15 passing original Python edge cases. This does not establish the cause of the historical recovery failure. Windows and Mac artifact result packets are linked by immutable tree in SUMMARY.json; current Windows clean persistence counters do not erase previous journal or SQLite failures.

All 59 review threads are resolved. The 51 formal reviews are COMMENTED, with zero formal approvals, and GitHub still reports the PR blocked. CodeRabbit explicitly skipped review for the base branch. Gitar's separate comment says Approved/three closed findings while declaring no rules evaluated and functional validation disabled. Sonar's current quality gate passes while reporting three new issues, zero accepted issues and zero security hotspots; the connector refused its individual annotation endpoint, so this packet does not claim an updated direct issue inventory. No Kilo check appears in the current 195-check cohort; earlier advisory results remain historical.

The original Gitleaks log reports no leaks found. Its previous genuine scanner failure and reviewed exact false-positive fingerprint exemption remain separate evidence. Neither scanner success nor ordinary CI establishes full product qualification, release signing or approval.

This packet retains original API records and four original logs exactly as returned, plus an explicitly derived soak JSON. It does not include binary ZIPs or wheels. The current native archive quartet and collector artifact metadata are retained, while byte verification remains attributed to their named owners. No workload or workflow was replayed.
