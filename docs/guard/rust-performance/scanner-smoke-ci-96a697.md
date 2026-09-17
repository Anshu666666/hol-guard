# Scanner smoke: first actual runner attempt

The [first scanner smoke run](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986730)
failed before timed work. It checked out source
`96a69725eab018674174dabc6f205a4087d6ff4b`, tree
`7da3dcf25df5dc75b61f773c40a3a4dd96bbf2fa`, and selected only
`working_provider_large`, independent run zero. This is an immutable failed
attempt; a later corrected run must remain separate.

## Observed result

| Boundary | Actual result |
| --- | --- |
| Plan job `105292961896` | Passed; 24 planned timed attempts |
| Native build and native tests | Release binary built; four Rust tests passed |
| Bridge and collector tests | 69 passed, zero skipped, using that actual native binary |
| Collector in job `105293019928` | Failed before source identity was retained |
| Timed offers / completed / unoffered | 0 / 0 / 24 |
| Fixture / experiment preflight / cache / CPU | Not observed |
| Private snapshot | Two records retained and encrypted; no raw decryption performed |
| Public and encrypted uploads | Both succeeded |
| Collection and aggregate gates | Both failed; no comparison or benefit claim |

The public shard reports `collector_failed`, `source=null`, no fixture identity,
and all 24 planned attempts as `unoffered`. It cannot distinguish the specific
identity subcheck that failed. Passing actual-binary tests establishes their
functional scope; it does not establish the absent experiment preflight or any
full-command performance benefit. Both cache-state cohorts have zero samples and
zero independent runs, with `benefit_gate_passed=false`,
`minimum_independent_runs_met=false`, and `installed_qualified=false`.

The [exact public checkpoint and hash manifest](evidence/scanner-smoke-96a697/manifest.json)
retain the original summary, aggregate, receipt and association record. Artifact
ZIP hashes were checked against GitHub metadata. The encrypted archive was also
downloaded and its 3,726 bytes and SHA-256 checked against the receipt; its two
private records were not decrypted. Artifact IDs are `10507869349` (public shard),
`10507629973` (encrypted snapshot), and `10508303395` (aggregate).

## Source corrections for the next smoke

`identities()` incorrectly reused the private-evidence reader for hosted Python
and the Cargo executable. That reader requires the current user's ownership and
exactly one link. A hosted root-owned interpreter or a Cargo executable with a
hardlink is a valid toolchain layout but fails that contract. A discriminating
test proves that an actual hardlinked fixture fails the unchanged private reader
and passes the new executable reader. The original artifact lacks the metadata
needed to identify which particular admission check stopped this runner; this
source diagnosis is not a reconstructed exception from the failed job.

The separate Linux executable reader accepts root or current-user ownership and
positive link counts while requiring a resolved regular executable, no group or
world write permission, a 64 MiB bound, and matching path/opened/final metadata.
It hashes the observed bytes and checks byte count, inode, ownership, link count,
mode, size and modification/change times. The experiment still compares source
and binary digests before and after its work. The private archive reader is
unchanged. Finite source, dependency, Python-executable and native-executable
failure codes now identify the next failure stage without publishing exception
text or paths.

Two separately reviewed retention edges are also corrected. Artifact names and
the aggregate download selection include the GitHub run ID and attempt, so a
rerun cannot collide with or admit the previous attempt's uploads. An excess
summary inventory now writes a bounded failed aggregate with the original
planned denominator, admits no arbitrary subset, and derives no benefit or
independent-run claim. Neither edge caused this first fresh run's failure.

## Next action and limits

Run the same explicit `scanner-regex-pilot-smoke` selection on the corrected
source, with the full `scanner-regex-pilot` label absent. Require all actual-native
tests, experiment preflight, 24 timed terminal observations, verified cache
states, full public semantic/HMAC identity, process-tree CPU evidence, exact
post-run identities, and both retained artifacts. Unsupported eviction stays
unavailable and prevents a complete smoke. Do not infer it from elapsed time.

Only after inspecting a complete smoke should the release owner select the
unchanged 35-job, 840-attempt full experiment. One smoke cannot satisfy five
independent runs or qualify installed scanner behavior. No production regex
activation, native selection, timing threshold, 120-second command deadline,
30-second native exchange deadline, or corpus semantics changed.

Source verification of these corrections: 53 focused identity, retention,
projection and workflow tests passed; the five changed source modules typecheck
with zero errors (284 warnings). After the final workflow test entry and portable
metadata-test adjustment, 31 identity, workflow and privileged-workflow tests
passed. Ruff, format and diff checks pass. No local build or performance run was
performed.
