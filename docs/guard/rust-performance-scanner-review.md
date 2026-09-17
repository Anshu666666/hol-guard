# Scanner performance workstream

The subsequent [rich workflow qualification](rsp-scanner-qualification.md)
adds all 17 provider/context rules, caller-scoped HMAC checks, finding-heavy
source workloads, explicit CLI completeness/exit gates and verified fixture
file-data cache states. It also records why the observed host variability
prevents a release performance claim and why large-source native work remains
an open measured opportunity.

This work implements the algorithm changes required before a rich offline
detector port can be justified. The reviewed baseline is
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. The standalone Secrets CLI continues
to use the Python detector. The existing Rust hook scanner is not an equivalent
implementation of that detector.

## Implemented boundaries

Historical and staged scans enumerate NUL-delimited raw Git changes, retaining
the immutable object ID and every path occurrence. A scan owns at most two lazy
`git cat-file` processes: metadata and contents. Metadata admission precedes
content reads. The reader checks OIDs, object type, declared size, bounded
headers, exact payload length, terminator and the SHA-1/SHA-256 Git blob digest.
Only hexadecimal OIDs enter its line protocol, so newline-containing filenames
cannot inject requests. Replacement objects and lazy object fetching are
disabled for these streams. A deadline covers pipe writes and reads; broken
streams are terminated and their children are reaped.

Staged scanning reads the OID captured during index enumeration even if the
index or working tree changes afterward. History retains every changed
path/commit occurrence. Missing or corrupt historical objects now explicitly
mark the result incomplete, instead of silently appearing clean. Existing
oversized-file behavior is retained: staged scans report incomplete coverage;
history skips oversized blobs. Gitlinks retain their existing staged
incompleteness behavior, while history skips non-blob objects.

Finding reuse is local to one scan and bounded to 1,024 entries and 10,000
findings. It stores findings rather than whole file bodies. The key includes
the verified Git OID, detector version, binary-exclusion suffix and every
path-sensitive detector input: documentation, fixture, public client config,
high-signal and source-code context. Path, source and commit metadata are
rebuilt for each occurrence. Files and bytes counters still count occurrences,
not unique objects. A smaller finding budget reuses only a known-complete
result that fits. Truncated results are rescanned, preserving provider priority
before the final finding sort. Any new path-sensitive detection behavior must
extend `secret_detection._path_policy_key` and its parity tests.

Plugin security checks now enumerate once and give the hardcoded-secret and
approval-default checks the same bounded text for each file. Text is retained
for one file at a time. The existing safe reader, containment, exclusions,
entry/file/byte/depth budgets and per-check incomplete results are retained.
A failure in one check does not prevent the other check finishing its relevant
inputs. The standalone check entry points preserve their selective read scope.

## Rich detector capability matrix (RSP-061)

Sources: [`secret_detection.py`](../../src/codex_plugin_scanner/guard/secrets/secret_detection.py),
[`guard-scanner`](../../rust/crates/guard-scanner/src/lib.rs),
[`secret_repository_scanner.py`](../../src/codex_plugin_scanner/guard/secrets/secret_repository_scanner.py),
[`secret_staged_scanner.py`](../../src/codex_plugin_scanner/guard/secrets/secret_staged_scanner.py).

| Capability | Offline Python detector | Existing Rust hook scanner | Port requirement |
| --- | --- | --- | --- |
| Provider catalog | 17 ordered rules plus contextual assignment | 10 hook classifier patterns | Separate versioned offline catalog; do not equate pattern count with coverage |
| GitHub, AWS, OpenAI, Anthropic, PEM | Provider-specific candidates, bounds and metadata | Some same-named classifiers, with different regex bounds or accepted formats | Differential parity for each format, including GitHub fine-grained and Anthropic variants |
| GitLab, Slack token/webhook, Stripe, Hugging Face, PyPI, Google, SendGrid | Dedicated provider rules | No equivalent dedicated classifiers | Implement explicit provider rules before claiming rich coverage |
| npm | Direct `npm_` token recognition | Assignment-oriented npm auth recognition | Preserve standalone token coverage and provider validation metadata |
| Database/basic-auth URLs and JWT | Candidate capture plus contextual acceptance | No equivalent rich rules | Preserve credential extraction and contextual scoring |
| Generic assignment | Name filtering, matching quote backreference, expression/reference suppression, context thresholds | Broader marker/assignment classifiers and different suppression | Implement bounded parsing where Rust regex cannot reproduce Python backreferences directly |
| Entropy and confidence | Shannon entropy, rarity, character classes, score, label and reasons | Sensitivity and static classifier reason | Preserve exact scoring thresholds and serialized rounding |
| Path policy | Documentation/fixture/high-signal/source-code/public-client-config decisions | Caller-supplied sample/documentation flags and hook-specific rules | Include complete path policy in the offline contract; avoid cross-path result reuse |
| Context | Per-match line and bounded surrounding context, fixture rules and indirect-code-reference filtering | Window classification and separate sample/inert-expression checks | Preserve surrounding-line behavior, Unicode and sample precision |
| Location and occurrences | Line number, path, source, commit; no column field today | One classification per family, without occurrence positions | Preserve all existing occurrences and ordering; do not invent existing column support |
| Result schema | Rule/family/severity/confidence/entropy/validation/context reasons and occurrence metadata | `ScanMatch` classifier/family/sensitivity/reason | Separate offline result schema and completeness contract |
| Evidence identity | Raw candidate private to finding; optional caller-keyed HMAC over rule and candidate | No corresponding candidate/HMAC contract | Keep HMAC scoped to caller and raw candidates out of public evidence |
| Limits | CLI defaults: 5,000 files, 2 MiB/file, 128 MiB total, 500 findings, 500 commits | Hook byte/match/chunk/time budgets | Preserve explicit user bounds and 0/2/3 CLI exits independently of hook budgets |
| Isolation | Dedicated hostile-archive subprocess with identity and expansion checks | Resident scanner operates on supplied text | Keep hostile archive parsing outside the resident process |

The Rust scanner also has hook-specific Hedera, bearer and marker recognition;
these are not substitutes for omitted offline provider and context semantics.
The presence of a test named `test_guard_secrets_native_cli.py` establishes CLI
dispatch coverage, not a Rust detector consumer.

## Reproducible algorithm baseline (RSP-062 and RSP-066)

Run the following using the repository's locked development environment and a
separate clean checkout of the baseline commit:

```sh
uv sync --frozen --extra dev --python 3.12
uv run python scripts/bench_guard_secret_scans.py \
  --baseline-root /absolute/path/to/baseline \
  --output /absolute/path/to/scanner-benchmark.json \
  --repeats 5
```

The script creates synthetic repositories only. It compares small/large staged
scans, many unique/repeated objects, repeated history, a working-tree control
and combined plugin checks. It records separate full CLI wall time, instrumented
scan time, Python and child CPU, detector CPU/call count, object-I/O time,
subprocess counts, bytes/files/findings, source identities and output digests.
The two implementations must produce identical complete public results on
every sample. Full CLI output must also match the instrumented scanner output.
Runs alternate implementation order. Reports contain aggregate metrics and
digests rather than input text, finding paths or raw credentials.

These measurements are a local synthetic algorithm diagnostic. The full CLI
sample uses a fresh interpreter with the `hol-guard` dispatch entry point and
the selected source tree; it is not an installed wheel/native consumer proof.
Filesystem cache is uncontrolled. The safe-text fixtures isolate traversal,
Git transport and no-match detector work; the separate correctness tests cover
credential findings and suppressions. No Rust boundary is benchmarked. A native
port therefore remains **unqualified**, with no measured native go/no-go claim.
Release hardware, macOS/Windows, controlled cold-cache trials, rich finding
workloads, native startup/serialization cost and installed artifacts still
require qualification before RSP-066 can pass.

The recorded Linux run compares the baseline with implementation commit
`8ab23abd55d2c4dddf2e2ffb3ad2c2f594e5665a` and verifies that the source identities
do not change during the run. It uses Python 3.12.14, Git 2.51.1, x86-64 Linux
6.18.44 and five alternating-order repeats per implementation. Every sample
has identical complete public output. The raw aggregate evidence, individual
samples and source digests are in
[`rsp-scanner-python-baseline-linux.json`](evidence/rsp-scanner-python-baseline-linux.json).

| Synthetic workload | Baseline full CLI median | Optimized full CLI median | Object subprocesses, baseline → optimized | Detector calls, baseline → optimized |
| --- | --- | --- | --- | --- |
| 10 unique staged files, 256 B each | 220.0 ms | 182.2 ms | 20 → 2 | 10 → 10 |
| 1,000 unique staged files, 256 B each | 4,735.2 ms | 1,042.1 ms | 2,000 → 2 | 1,000 → 1,000 |
| 1,000 repeated staged files, 256 B each | 6,658.1 ms | 217.2 ms | 2,000 → 2 | 1,000 → 1 |
| 8 repeated staged files, 256 KiB each | 856.8 ms | 254.5 ms | 16 → 2 | 8 → 1 |
| 480 historical versions plus 80 working files | 2,505.6 ms | 248.9 ms | 960 → 2 | 560 → 82 |
| 1,000 working-tree files, unchanged scan control | 584.4 ms | 611.2 ms | 0 → 0 | 1,000 → 1,000 |

Combined plugin checks over 1,000 generated files measured 444.6 ms → 239.9 ms
median in-process wall time; a separate full plugin CLI was not measured.
Plugin file/byte dimensions in this diagnostic are the generated corpus sizes,
with actual detector-call counts reported separately. Other scan counters come
from their public scan results. The working-tree control is 4.6% slower in full
CLI median, and individual timing samples vary substantially. These are local
observations, not a release performance pass or a native port decision.

## Validation and remaining tasks

Focused tests cover byte-for-byte staged selection during mutation, repeated
path/commit occurrences, path-sensitive suppression, budget-dependent provider
ordering, public HMAC parity, SHA-1/SHA-256 objects, newline paths, empty/binary
files, oversized admission, missing history objects, Git replacement objects,
gitlink coverage, partial reads, malformed frames, truncated content, digest
mismatches, timeout cleanup and subprocess counts. Combined plugin tests prove
one enumeration/read, immutable shared bytes, independent check parity and
incomplete coverage after input or match-budget failures. Existing CLI tests
preserve complete/error/findings exits 0/2/3 and public redaction.

The focused suite passed 178 tests. Ruff and whitespace checks passed. Targeted
BasedPyright analysis reported zero errors; existing warnings and private-helper
usage warnings remain. Cross-platform execution is still required; the newline
filename integration fixture uses a Unicode filename on Windows, where newline
filenames cannot be created, while raw Git protocol tests retain newline cases.

| TODO | Work in this change | Remaining evidence or conditional work |
| --- | --- | --- |
| RSP-061 | Exact rich-detector/Rust capability matrix | Revalidate when either detector changes |
| RSP-062 | Reproducible current/optimized Python synthetic benchmark | Full platform, cache-state, finding-heavy and release-hardware baseline |
| RSP-063 | Bounded scan-scoped Git object reader; immutable staged OIDs; child cleanup | Cross-platform CI execution |
| RSP-064 | Bounded identity/policy-aware finding reuse with occurrence counters | Platform qualification follows the reader |
| RSP-065 | Shared safe plugin enumeration and immutable per-file text | Production workload profiling |
| RSP-066 | Optimized Python is now an available comparison baseline | Native boundary comparison and ratified performance gate; not passed here |
| RSP-067–069 | No offline native contract, detector or CLI port introduced | Conditional on RSP-066; required rich semantics listed above |
| RSP-070 | Archive worker and containment unchanged | Dedicated archive profiling/qualification; no resident migration |
| RSP-071 | Python scanner, transport and shared-input adversarial coverage | Native differential coverage and archive qualification after selection |
| RSP-072 | Local Python evidence format and reproducible runner | Installed/native/platform coverage and justified go/no-go report |

Do not mark the conditional native tasks complete merely because the Python
algorithm changes pass tests. The next decision is whether an equivalent
offline native boundary improves a complete command over this optimized Python
baseline enough to justify the additional implementation and release surface.
