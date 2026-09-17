# Offline scanner release decision and one remaining experiment

Source review: 2026-09-17, integration `bb9135df3d144e5ef2f6cb400fd3be2e43ba9b89`.
This is a decision from retained evidence, not a new timing run, installed
qualification, production native activation, or edit to the original task
dependencies.

Retain optimized Python scanning and the separately isolated Python archive
worker. Defer a parser-only archive port for this release. Complete one finite
full-source-CLI comparison of the existing experimental regex boundary before
deciding whether its finding-heavy workload benefit justifies further work.
A blanket conclusion that richer Rust detection cannot help is unsupported.

## Source identities and retained evidence

The scanner digest hashes sorted `guard/secrets/*.py`, then sorted
`checks/security*.py`, with each relative path, NUL, and source bytes. Its 12
files still match the optimized rich baseline and remote experimental pilot:
`41b1d7cc163835ecb03653eeafd188c583d1122492bf3d5cbfbc0f7d4a882383`.
This does not attest all CLI imports, dependencies, or installed artifacts.

The [rich workflow report](../rsp-scanner-qualification.md) retains 21
equivalent Linux workload/cache rows and five unavailable eviction rows,
with five fresh-process trials per arm. It covers all 17 provider/context
rules, independent context/HMAC expectations, complete public results,
staged bytes differing from the worktree, repeated Git objects, and exits
0/2/3. Variable controls prevent a stable native-selection claim. Detection
accounts for approximately 54–71% of complete CLI CPU in the large rich-file
diagnostic, leaving a plausible opportunity.

The experimental pilot is retained in Git object
`ae33987d0c8675c36a77375e03419aee920825f6`:

- `docs/guard/rsp-scanner-regex-pilot.md` describes its scope and protocol.
- `docs/guard/evidence/rsp-scanner-native-regex-initial-linux.json` has SHA-256
  `f4e3ab6fc888307f6114452337bed9ed9985896497300fbb05d564e589b9df57`.
- `docs/guard/evidence/rsp-scanner-detector-profile-replay-linux.json` has
  SHA-256 `b43b176e6d8992868cb414d5f65463d84b23ef400bdf32d6a1b19d71a6821646`.

Its measured Python commit is `ea8c7b8eba057e7a6a6c0a7621adb2c133c9972b`;
its recorded scanner digest matches above. The initial native source digest
is `7e61ea8b2e41d32a5c4481abd18ef847be70c24eacce2e3277eea6aee3952874`,
binary digest is `bda6936a350d361b0de0422c54ea57842c9353d9e7de11c554880532bdcebe35`,
and bridge/runner digest is
`abad00f516a477d2a6b0c67bfcba25b54bf4d01391f8c1965ae4aa78563f357c`.
Later failure-recording improvements are not retroactively attributed to
the initial measured controller.

The pilot executes the real Python CLI in fresh processes, including Rust
child startup, regex compilation, JSON transport, all retained Python work,
public output, cleanup, and reaped Rust/Git CPU. It is a source-CLI experiment,
not merely an inner-kernel benchmark and not an installed/default route.

The initial report has seven completed **clean** workload/cache states with
30 paired calls each. None passes its 30%/5% point gate or conservative
interval gate. Three eviction states are unavailable. A working-tree clean
state retains 17 complete pairs and fails the native call in pair 18. No
finding-heavy timed state completed. The affected state overlapped an
unlocked executable relocation; failure output was not retained, so its
cause remains unproven and its samples cannot qualify a benefit.

The separate rich-file iterator profile assigns 61–78% of detector CPU to
regex iteration. These instrumented fractions must not be multiplied into
a formal attainable CLI speedup. The short native-boundary diagnostic also
lacks the timestamps needed to exclude overlap with the relocation.

## Fixed next experiment

The source-only opt-in experiment compares the current optimized Python
implementation with the selectively reviewed existing regex pilot. It
does not select a whole scanner rewrite or activate native detection.

| Dimension | Fixed scope |
| --- | --- |
| Fixtures | `working_provider_small`, `working_provider_many`, `working_provider_large`, `staged_provider_diverged`, `staged_provider_repeated`, `history_provider_repeated`, and interrupted clean control `working_many_unique` |
| Cache states | Prewarmed fixture data and independently verified fixture-data eviction; unsupported/unverified eviction remains unavailable |
| Independent runs | Five |
| Repeats per run/state/fixture | Six alternating arm pairs |
| Denominator | 7 × 2 × 5 × 6 × 2 = **840 planned timed CLI attempts**, separate from correctness preflight |
| Boundary | Fresh source CLI; actual native startup, serialization, finding work, public output and child cleanup included |
| Metrics | Full wall time and complete reaped process-tree CPU; per-state counts and independent-run uncertainty |
| Native admission | ASCII at most 4 MiB per logical file; explicit original-Python fallback outside that domain |
| Retained Python | Suppression, context, entropy, positions, ordering, deduplication, caller HMAC, traversal/Git reuse, limits and exits |

Preflight must compare every public finding field and independently expected
outcomes, HMAC identities, file/byte occurrence coverage, staged-index content,
default/explicit bounds, and exits 0/2/3. Unicode/fallback and adversarial
contracts remain explicit; unsupported inputs cannot be counted as native.
Each offered attempt and its terminal failure or result must be retained,
including unfinished or unoffered work after a bounded controller failure.
Private inputs/results/journals are encrypted; public output is a closed
numeric/status/hash projection. Preserve the existing command and protocol
deadlines and use contained child cleanup on an isolated CI runner.

Apply the original at-least-30% full-operation p95 or process-tree CPU benefit
and at-most-5% regression in the other primary metric. Analyze independent
runs rather than claiming all within-run samples are independent. Thirty
observations per arm/state do not establish an installed-route tail claim.
A positive result advances the selected boundary to installed/platform and
adversarial qualification; it does not complete those gates. A nonqualifying
result supports a release-scoped deferral with a specific reopening condition
(changed workload distribution or a materially cheaper reviewed boundary),
not another open-ended profiling program.

## Archive and task scope

The [archive report](archive-worker-qualification.md) already identifies
interpreter, integrity-read, expansion and member-processing costs through
510 unmodified inspections and 60 diagnostic children. Its exact-result gate
failed: 508/510 expected results, two retained fail-closed timeouts, and one
separate warmup timeout. All 330 hostile/bounded-failure calls remained
non-clean. No equivalent native worker has been measured.

The five archive files still hash to
`38e540def8038dc689a5ec6dcc9f8984827f26754798db9eb4afccf9ceafd7d9`;
the two harness files still hash to
`3637fb521ead05b0db95ee99cd17efec85f3578c7773c258c4071d5bbc568b84`.
RSP-070's literal profiling evidence is present. Retaining Python is a release
selection decision, not a proven impossibility of faster whole-worker Rust.
No archive parsing moves into the resident. All HMAC, immutable identity,
launch, containment, resource, expansion and incomplete-result contracts stay.

RSP-066 still needs the one experiment above. RSP-072 can report this current
decision and retained scopes, but complete installed/platform native parity
and conditional RSP-067–071 work are not claimed. The original PRD/TODO and
execution ledger remain authoritative and unchanged by this note.
