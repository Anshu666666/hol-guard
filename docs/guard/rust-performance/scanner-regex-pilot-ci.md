# Fixed offline regex source-CLI experiment

This opt-in Linux experiment implements the single comparison in
[scanner-current-decision.md](scanner-current-decision.md). It does not
activate production detection, ship a new installed entrypoint, qualify
macOS/Windows, or replace the isolated archive worker. The rich Python
detector still owns context, suppression, entropy, positions, ordering,
deduplication, caller HMACs, traversal/Git reuse, completeness, limits and
exit behavior. Native admission is ASCII text at most 4 MiB per logical file;
other files use the original Python detector with explicit fallback counts.

The extractor and bridge are selectively retained from
`ae33987d0c8675c36a77375e03419aee920825f6`. The workspace/lock changes add only
that experimental crate using already locked regex/serde dependencies.
No remote branch is merged wholesale. One reviewed cleanup correction
restores all patched functions even when child cleanup fails, preserves the
original scan exception, and retains a finite sticky cleanup-failure signal
and the process handle while termination is unconfirmed.

## Selection and finite work

The workflow is `.github/workflows/scanner-regex-pilot.yml`. It accepts only
manual selection or an explicit label on a same-repository PR. Every checkout
uses the exact PR head, all actions/toolchain versions are pinned, permissions
are read-only, and later pushes/unrelated labels do not cancel offered work.
The publication owner applies labels; this implementation performs no remote
write.

- `scanner-regex-pilot-smoke`: only `working_provider_large`, run 0, two cache
  states, six alternating pairs: **24 planned timed CLI attempts**. Inspect
  its actual evidence before enabling the full label. It cannot meet the
  five-independent-run requirement, and cannot report a benefit gate pass.
- `scanner-regex-pilot`: seven declared fixtures × five independent Linux
  jobs, each with two cache states × six pairs × two arms: **35 jobs and 840
  planned timed attempts**. The seven fixtures are the six finding-heavy
  cases plus the interrupted working-tree clean control listed in the
  current decision note.

Fixture creation, correctness preflight, file-cache preparation, code identity
checks, and artifact writes occur outside timed CLI boundaries. Each arm runs
the actual source CLI in a fresh Python process, including its imports,
Git/Rust children, native compilation-on-start, JSON transport, retained
Python finding work, public serialization and child cleanup. Both arms use
the same exact Python/dependency environment and fixture. Their order
alternates by pair and independent-run index.

The original **120-second CLI timeout** and **30-second native exchange
timeout** remain. An explicit collector alarm bounds its execution to 6,000
seconds, plus finite process cleanup (up to five seconds for reaping the
direct child) and evidence finalization. This is not a hard kernel/filesystem
wall-time guarantee. The collection step allows 105 minutes; setup/build/tests
have a combined 25-minute ceiling; sealing/uploads/final verification have
12 minutes. Their 142-minute total fits the 150-minute shard job budget.
The separate plan and aggregate jobs allow five and ten minutes.

The private denominator is written before dependency installation or build.
Every timed attempt has separate offered, process-terminal and semantic-
verified records. A hard exit between records remains interrupted; unoffered
work remains in the fixed denominator. Unknown cleanup or transport failure
stops subsequent offers. A surviving process-group member invalidates the
sample and complete CPU accounting even if the CLI itself exits zero.
Unverified/unsupported fixture-data eviction remains unavailable; it is never
relabelled cold, replaced with a warm sample, or treated as native success.

## Semantic and identity evidence

Preflight runs independent existing 17-provider/14-context/HMAC expectations
through both real boundaries. Real CLI calls verify complete findings and
public-field/order equality, file/byte coverage, staged content, missing
targets, default/explicit bounds and exits 0/2/3. Default incompleteness still
takes precedence over `--fail-on-findings`. A completed process is not a
verified sample until its full result matches the preflight oracle and its
expected native/fallback counters pass.

Evidence records exact source commit/tree, production Python tree, scanner
digest, pilot source tree, controller/bridge/fixture/cache-source digest,
Python executable, dependency inventory, both lockfiles and pilot executable
digests. Generated fixture bytes (including Git metadata) are retained
privately with per-file digests, bounded to 5,000 files and 16 MiB total, and
verified unchanged after collection. Source and executable identities are
also checked again. Runner OS/architecture/CPU count and image/kernel hashes
are public; exact image identifiers stay in the private host record.

Each process retains exact stdout/stderr byte captures and identities. The
combined capture is capped at 8 MiB; on overflow, the retained prefix is
marked failed and its length is a retained-byte count, not a claim that all
output was captured. Process-tree CPU comes from the completed and reaped
CLI/Git/Rust descendant tree. Failed/unconfirmed cleanup yields unavailable
complete CPU, not zero. No OS I/O or resource-completeness qualification is
invented by this collector.

## Retention and interpretation

The existing bounded private-archive format and public recipient are reused.
The public projection validates the exact immutable byte snapshot passed to
encryption. Its report, receipt and source/case/run association are checked
together. Both public and encrypted uploads and their artifact IDs are
required. Aggregation rejects missing/inconsistent receipts and clears all
derived benefit claims when upstream retention fails or an invalid shard is
present. A successful numeric summary with failed encryption cannot pass.
Raw input, output and diagnostic text is never uploaded unencrypted.

Public shard records contain only fixed labels, dimensions, counts, hashes
and finite numeric observations. Private records are bounded to 24 MiB each
and 120 MiB per shard within the existing archive limits. A bound failure
stays a failed or interrupted attempt; evidence is never dropped to make a
passing comparison.

Each fixture/cache state is compared separately. The report retains pooled
nearest-rank p95/mean-CPU point ratios across 30 samples per arm and a paired
bootstrap over the five independent run summaries (six samples per arm in
each run). The bootstrap does not treat 30 within-run observations as 30
independent environments. The benefit flag requires the original ≥30%
improvement and ≤5% other-metric regression both at the pooled point and at
the conservative independent-run interval; thresholds use unrounded values.
Six-sample within-run p95 equals that run's maximum. Neither it nor a
30-sample pooled p95 establishes installed-route tail qualification.

No measurement result accompanies this implementation. A qualifying result
only justifies the next installed/platform/adversarial qualification for the
selected boundary. A nonqualifying result supports the explicit release
deferral and reopening conditions in the current decision note. Original
RSP-066/067–072 and boundary-choice dependencies remain unchanged.

## Source verification

The final focused Python run passed **63 tests**, with **11 actual native-
binary cases skipped** because this workspace did not build or execute the
pilot. The workflow builds it explicitly and supplies the binary to those
tests before any samples. The suite covers process timeout/descendant cleanup,
the first failed attempt, unmatched offers, unavailable eviction, immutable
archive snapshots, failed encryption after projection, recipient/context/hash
mismatches, missing or duplicate shards, failed encrypted uploads, smoke
versus full denominators, and threshold rounding. An earlier test incorrectly
assumed Python would emit its first line within a 100 ms test-only timeout;
the test now accepts termination before that first write. The production and
experiment deadlines were not changed.

The six Python modules have zero scoped BasedPyright errors (417 warnings,
principally dynamic fixture/JSON types). Ruff, formatting, the privileged
workflow policy tests, Rust formatting, and diff whitespace checks pass.
Independent source reviews covered the retained regex/bridge and the
controller/process/evidence/workflow changes. No local Rust build,
performance matrix, installed qualification, or remote execution is claimed.
