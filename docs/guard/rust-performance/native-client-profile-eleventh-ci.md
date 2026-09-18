# Eleventh native client profile: public corroboration

All four first-attempt jobs in [run 35287994878](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994878)
pass the installed diagnostic build, tests, collection and retention gates.
The four verified public reports each record 40 completed hooks, zero failures
and zero uncompleted offers. This note preserves the new producer reports and
public artifact/source verification. **No eleventh encrypted archive was
downloaded or authenticated, and no eleventh private journal was recomputed.**

The independently authenticated and recomputed [tenth evidence](native-client-profile-tenth-ci.md)
remains the basis for RSP-085's completed measurement criterion. These eleventh
observations neither replace that evidence nor create a paired benefit result.
RSP-086/087, installed performance/resource qualification and production
selection remain separate. No task status or original acceptance is changed.

## Source and actual execution

The workflow explicitly checks out source head
`23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d`, tree
`e3fa69336ff37d8e91add1ecd0a5a89b5cca35d9`; every public runtime identity and
artifact API record binds that head. Run 35287994878 is attempt 1. The selected
wheel uses the default-off `diagnostic-native-client` feature. Normal production
selection and registration are unchanged.

The Rust tree, profile builder, collector, observer, record/report/resident
helpers, retention verifier, workflow and dependency lock have no changes from
the tenth measured source `095074cda6a751ffaf12b070ecc46a3091f12471`. All 24
reported collector/helper/lock source digests match exact Git bytes or the
separately recorded Windows CRLF expansion. This checks reported source-byte
correspondence; it is not an independent wheel download or executable rebuild.

| Platform | Actual job | Python tests | Runtime profile tests | Windows companion tests | Producer offers / completed / failed |
| --- | --- | ---: | ---: | ---: | ---: |
| Linux x86_64 musl | [105424488106](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994878/job/105424488106) | 125 | 9 | Not selected | 40 / 40 / 0 |
| macOS ARM | [105424488292](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994878/job/105424488292) | 125 | 9 | Not selected | 40 / 40 / 0 |
| macOS Intel | [105424488272](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994878/job/105424488272) | 125 | 9 | Not selected | 40 / 40 / 0 |
| Windows x86_64 MSVC | [105424488295](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994878/job/105424488295) | 125 | 9 | 2 | 40 / 40 / 0 |

These counts come from the actual job logs. The nine selected Rust tests are
client/resident/relay tests, not a full runtime-suite count. The two Windows tests
exercise the captured stderr pipe and explicit handle-list containment. Its
separate zero-test filtered doctest result is not added to the count. All four
collection, sealing, public/encrypted uploads and final retention steps pass;
no failed first attempt is substituted.

## Verified public custody and producer claims

The [manifest](evidence/eleventh-client-profile-23bef/manifest.json) records exact
job/artifact identities, independently verified public ZIP sizes/SHA256 values,
public member commitments, producer encryption receipts, test log observations
and source-byte correspondence. The four committed summaries are byte-identical
to their downloaded ZIP members. The corresponding encrypted ZIP sizes/digests
are **GitHub metadata only**. Their producer receipts report five encrypted
files each, but this review does not independently inspect the ciphertext or
recover its contents. No raw journals, captures or keys are published here.

Each public summary reports 20 benign and 20 synthetic credential Claude
PostToolUse requests through the installed persistent helper and resident.
Each reports one helper, 42 total client records, 43 resident records and 40
successful matched hook socket opens. The extra records are auxiliary activity,
not additional completed hooks. The producer sets `collection_complete`,
`resident_capture_complete`, `evaluation_isolated` and
`worker_summary_available` true. It reports cleanup `already-stopped`, worker
return code zero, and no outer timeout or containment failure.

The reviewed collector requires final unique selected-hook matches, complete
helper/reader EOF coverage and relay chains before setting these flags. In this
cohort those facts remain **producer-validated claims**; this note does not
assert a second raw-record verification. The same checks were independently
recomputed from authenticated private journals for the separately retained
tenth cohort.

## Reported diagnostic spans

The [Linux](evidence/eleventh-client-profile-23bef/linux.json),
[ARM](evidence/eleventh-client-profile-23bef/macos-arm.json),
[Intel](evidence/eleventh-client-profile-23bef/macos-intel.json) and
[Windows](evidence/eleventh-client-profile-23bef/windows.json) reports retain all
phase distributions and artifact identities. The table contains the reported
p95 milliseconds, with 20 observations per case; these quantiles have not been
independently recomputed from eleventh private observations.

| Platform / case | Connect p95 | Authentication p95 | Resident edge p95 |
| --- | ---: | ---: | ---: |
| Linux / benign | 0.118 | 4.852 | 1.005 |
| Linux / credential fixture | 0.109 | 2.862 | 0.549 |
| macOS ARM / benign | 0.146 | 18.960 | 0.848 |
| macOS ARM / credential fixture | 0.129 | 21.765 | 0.864 |
| macOS Intel / benign | 0.113 | 30.994 | 0.586 |
| macOS Intel / credential fixture | 0.148 | 31.635 | 0.552 |
| Windows / benign | 4.596 | 2.755 | 5.800 |
| Windows / credential fixture | 4.757 | 2.749 | 2.570 |

The unchanged [source contract](native-client-profile-diagnostic.md) defines
inclusive monotonic spans. Authentication includes transport/scheduling wait;
resident edge time includes validation, snapshot/fence work, evaluation and
receipt encoding. Response read still includes queue/evaluation/transport.
No span is added or subtracted to infer exclusive CPU, removable cost or native
benefit. Ninth, tenth and eleventh samples are not pooled or treated as matched
before/after measurements.

All four reports keep headline eligibility, normal-release-runtime measurement,
resource comparison, production selection and qualification false. The new
Python config-binding observer belongs to the separate installed qualification
phase collection; this native-profile run does not validate its per-binding
coverage or complete RSP-008/RSP-025.
