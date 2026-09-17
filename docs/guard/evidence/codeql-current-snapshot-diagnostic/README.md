# Current immutable CodeQL diagnostic preparation

The diagnostic matrix now analyzes foundation commit
`cdd14176ef0e0a258d4655c64210524d7047a257` and prepared implementation commit
`d8bde000de992009be3b2ed009347d2b3707ef0d`, each in Actions, JavaScript/TypeScript,
and Python. These are six fixed jobs. The historical e449/abf profiles and their
original observation data remain in the collector and retained evidence; this
matrix does not rerun those six historical jobs.

This directory records preparation and local validation. It contains no hosted
diagnostic SARIF for the new matrix and establishes no security-gate pass. The
workflow's next eligible PR #2954 synchronize event will run the prepared matrix.

The foundation source tree is `efb4e859e19b5456f2bdfbac17b2de784adf36a7`, identical
to analyzed merge `c92e557349cabd633db408912c644471c002ee4d`. The prepared
implementation tree is `1967a2127a325ae340d313bf73e80c60abb4d1f6`. The collector
requires the exact selected commit and tree, clean tracked files, the original
workspace layout, and the captured collector/workflow hashes before accepting a
complete diagnostic.

Foundation [Actions run 35269310464](https://github.com/hashgraph-online/hol-guard/actions/runs/35269310464)
completed all three analysis jobs successfully. Its separate Advanced Security
check `105364546143` reported eight high-severity findings. The exact retained
check-page response and decoded job logs support that observation. The three
logs confirm CodeQL 2.27.0, CLI build
`b47b3e59262c95aff4eeb84ac72d09e25a9c37e9`, query packs Actions 0.6.35,
JavaScript 2.4.5, and Python 1.8.10, and the 300-file diff-cap warning. Individual
current alert identities and their overlap with prior findings remain unknown.

The prepared d8 commit has no observed original security-analysis run. Its
original merge, run, analysis-job, alert-check, count, CLI-build, query-pack and
path-ignore observation fields are null. A future diagnostic can complete and
retain findings while those original observation fields remain null. It does
not inherit abf's three findings or cdd's eight findings.

The workflow retains its existing CodeQL action and bundle pins, default query
selection, path-ignore configuration, three languages, 30-minute job limit,
maximum parallelism of three, same-repository PR restriction, and read-only
token permissions. Diff filtering remains disabled; security-result upload is
`never` and database upload remains false. Raw SARIF and `diagnostic.json` are
the only uploaded files, retained for 14 days. No alert was changed or dismissed
by this preparation.

The final focused diagnostic and workflow-token-permission selection passed
138 tests in 2.77 seconds. Ruff and formatting passed. Collector-only typing
reported zero errors and zero warnings; its exact bytes were unchanged between
that check and final validation. Every check records before/after hashes for the
three edited files. The initial 135-test pass is also retained: review then
added the three cdd language provenance cases to the existing parameterization,
and the final 138-test selection passed. Driver elapsed times include lock wait
and process startup and are recorded separately from pytest's reported time.

[manifest.json](manifest.json) binds the final source hashes and all 21 retained
payloads, including each stored and decoded byte count and SHA-256. Large decoded
GitHub logs and the original check page use lossless gzip.
[preservation-proof.json](preservation-proof.json) records that parsed workflow
semantics differ only in the fixed profile matrix, historical profile
constructors remain identical, and source/SARIF/layout verification functions
remain identical. The initial and final validation receipts and exact driver
programs are preserved alongside that proof. The staged whitespace check identified
extra EOF blank lines in two exact archived drivers. Their unchanged bytes now
use lossless gzip; [packaging-receipt.json](packaging-receipt.json) preserves the
failed preflight and subsequent local packaging correction. Validated source
files and test outcomes did not change.

After the hosted run finishes, retrieve its six artifacts by run ID and verify
each manifest against the pinned source, workflow identity, analysis outcomes,
and unchanged SARIF bytes before inspecting findings. Artifact names are
`codeql-foundation-cdd-<language>-<run_id>-<attempt>` and
`codeql-implementation-d8-<language>-<run_id>-<attempt>`. A diagnostic produces
source-analysis evidence; the actual PR security check and required independent
reviews remain separate release requirements.
