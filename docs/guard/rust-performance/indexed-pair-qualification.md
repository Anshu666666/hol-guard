# Indexed installed qualification

Full qualification collects five indexed baseline/candidate pairs on each of the
four declared platforms. Each pair runs both installed artifacts on one runner,
using the same wheel bundle built once for that platform. Pair indices retain the
original order: baseline/candidate at 0, 2 and 4; candidate/baseline at 1 and 3.
Jobs may execute concurrently: the index defines the statistical pairing and
order within a pair, not a claim of global wall-clock ordering across machines.

Every full worker receives `--runs 5`. Its plan remains 2,000 samples per priority
series, 200 per other daemon series, 20 per cold/recovery series and 30 resource
samples. Each completed arm commits all 38 numeric series, totaling 29,564
observations per block, including 22 policy-readiness and daemon-startup samples.
Five pairs retain 10,000 priority, 1,000 other and 100 cold/recovery observations
per artifact. No route or artifact is pooled into another route's distribution.
Smoke selects one index and its existing small plan; it cannot satisfy the full
sample gates.

## Time and failure contract

The former single platform job allowed ten workers of up to 60 minutes under a
360-minute job limit. Indexed pairs give each worker its unchanged 60-minute
outer limit, with one 125-minute collection step per pair. A 200-minute job
reserves 15 minutes for checkout/Python/uv setup, five for artifact download, 20
for installation, 15 for encryption and ten for upload, leaving ten minutes of
margin beyond the sum of those step ceilings. This is a bounded orchestration
budget, not a measured prediction that a full block finishes within its limit.
No hook deadline, native readiness barrier or acceptance threshold changes.

Contained baseline failure still permits the candidate arm on the same runner.
Lost containment stops the pair. A controller interruption preserves offered
arms as failed and never infers completion from leftover files; unoffered arms
remain explicitly unattempted. The aggregation job runs after failed collection
jobs and requires every expected index. Missing, duplicated, mismatched or
unarchived evidence prevents comparison.

## Identity and comparability

The platform build emits both immutable wheels and hash-pinned exports from the
respective frozen dependency locks. Both exports use the candidate lock's exact
benchmark-only psutil version and distribution hashes. Each consumer checks the
baseline source pin, candidate source SHA, target, wheel and package hashes,
requirements hashes, Python version, runtime hash and installed distribution
version inventory. Measured installations live outside the checkout. A separate frozen source
controller environment provides reviewed Windows retained-handle I/O before the
wheel environments exist; it never serves as either measured arm. Hash-required
installation proves the selected dependency inputs; the version inventory is
an additional installed-state check, not a replacement for content hashing.
Each freshly created POSIX arm receives the reviewed private byte-identical
interpreter fixture before package installation; shared toolcache permissions
and production validation are unchanged. Compiler and interpreter build
provenance remain in a separate retained build artifact.

Every pair and encrypted receipt binds the GitHub run ID, run attempt, platform,
index, candidate SHA and exact bundle hash. Aggregation keeps the existing strict
CPU model/count, effective CPU allocation, RAM, OS, Python and artifact checks,
and adds the runner image/OS identifiers. Different cohorts are rejected rather
than pooled. A runner image change can therefore require a fresh complete run;
this intentionally does not broaden comparability to make hosted runners pass.

The common workload digest and per-arm semantic scope remain distinct. Frozen
Windows baseline source-reference refusals remain unsupported content-review
evidence; they cannot count as reviewed benign content or as comparable source
performance. Existing CPU coverage limitations, cold-resident gaps and missing
qualification scopes retain their current meaning.

## Retention and acceptance

The controller recomputes each raw numeric series' exact count and existing
confidence summary before marking an arm complete. The pair manifest commits
its public report and raw numeric digest/length/counts. The exact manifest is
included in the private encrypted inventory with completed observations and
interrupted journals. Encryption checks completed numeric commitments against
the exact byte snapshot being sealed. Missing or changed numeric files are
retained as failed retention evidence and cannot be hidden by unrelated journals.

The encrypted context and public receipt commit the pair manifest, bundle and
expected numeric inventory, with a Boolean reporting exact numeric retention.
Aggregation requires encrypted status, the pinned recipient, matching context,
ciphertext hash and length, exact public report hashes, offered-arm conservation
and every required numeric count. Only bounded public JSON and ciphertext are
uploaded; raw observations and environment directories are excluded. Recovery
with the private recipient key preserves the manifest and journal bytes; public
aggregation does not possess the private key or claim to decrypt them.

The shared comparator uses the existing per-block quantiles and paired-run
bootstrap estimator. Collection completion, performance acceptance and complete
program qualification remain separate. Full qualification exits nonzero while
sample gates or a required implemented scope are false. Smoke may exit zero
only for complete collection/comparison and stays explicitly unqualified.
Installed Ollama/Builder checks run independently once per platform, using the
same immutable candidate wheel, so a paired baseline failure does not erase
that evidence.

This change is source- and synthetic-contract validated. It supplies no new
installed measurements, all-platform pass or performance qualification.
