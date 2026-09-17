# Native command program: component evidence

The native implementation admits the trusted program once and reuses the same
immutable nodes and candidate indexes across decisions. Each hook uses one
canonical command model and memoizes repeated matcher nodes within that decision.
The packaged 291-rule catalog contains 249 declarative rules and 42 compatibility
identities. Compatibility admission remains explicitly conservative for context
proofs that have not been ported.

The complete declarative observation corpus contains 828 independently generated
CPython 3.12 reference models. The comparison includes rule order, duplicate
segment evidence, every safe variant, uncertainty, and effective segment indexes.
Additional option, operand, structured, Common CLI, specialized and compatibility
fixtures test their own independent contracts. The runtime source identity covers
the interpreter, parser helpers, authority protocol and packaged program bytes.

## Reproduction

Run these from the repository root with the locked Python development environment
and the repository Rust toolchain:

```sh
PYTHONPATH=src python scripts/bench_native_command_program.py
cargo test --manifest-path rust/Cargo.toml -p guard-command --release \
  native_command_program_component_diagnostic -- --ignored --nocapture
```

The Rust diagnostic measures 100 fresh in-memory admissions separately from 100
warm samples per command. Parsing and observation are measured separately;
correctness checks occur after each timing interval. The Python diagnostic uses
the existing registry with the same command strings, cached reference models,
100 samples, and independent expected observations. No transport, installation,
policy publication, marker I/O, approval, or activity persistence is timed here.

## Local diagnostic, 2026-09-17

Environment: Linux x86_64, CPython 3.12.14, Rust 1.88 release profile. The shared
runner had concurrent builds, so especially tail values are diagnostic and do
not qualify a release latency budget. Arms ran separately, not as the installed
paired-artifact protocol. All values below are microseconds.

| Command | Python observation p50 | Rust observation p50 | Python p95 | Rust p95 |
| --- | ---: | ---: | ---: | ---: |
| `ollama push model` | 132.763 | 39.968 | 334.935 | 79.657 |
| `ollama push model --help` | 179.092 | 45.511 | 5,263.959 | 128.345 |
| `ollama rm first && ollama push second` | 273.707 | 95.928 | 5,224.508 | 178.364 |
| `aws s3 rm s3://bucket/key` | 1,238.494 | 282.029 | 9,430.854 | 432.021 |
| `printf café` | 83.869 | 28.810 | 557.496 | 57.420 |

Native candidate counts for these inputs were 56, 56, 70, 93, and 51 of 291;
these counts include compatibility and unindexed candidates. Native parsing p50
was 2.027, 2.516, 3.809, 5.593, and 1.892 microseconds respectively. Python parsing
p50 was 106.595, 148.822, 204.976, 182.829, and 80.111 microseconds.

Cold admission p50 was 181,234.235 microseconds, p95 339,373.513, and maximum
558,243.803. This work belongs before readiness; it must never reappear per hook
or on unchanged control reconciliation. Subsequent control admission reuses the
cached immutable program. The cold number warrants continued startup profiling,
while the warm result supports moving the existing Python observation work into
the resident. Neither number establishes installed p95, memory or concurrency
acceptance; those remain exact-artifact CI gates.


## Admission profiling and duplicate removal

A second diagnostic held the shared measurement reservation while other agents
paused builds and tests. Each arm constructed 100 fresh admitted programs in a
single release benchmark process; final program destruction stayed outside the
timed admission. This measures compilation of an immutable resident program and
excludes process startup, daemon initialization, and installed hook transport.
The raw phase distributions and resource usage are recorded in
[evidence/native-command-admission-phases.v1.json](evidence/native-command-admission-phases.v1.json).
The baseline benchmark binary hash was not recorded; the source baseline was
`573c03ca5` plus the same diagnostic phase observer used in the optimized arm.
These observations support the identified implementation change and do not
replace the exact-artifact installed release gate.

| Admission phase | Before p50 (ms) | After p50 (ms) |
| --- | ---: | ---: |
| Initial JSON value parse | 19.572 | 11.150 |
| Canonical program digest | 34.424 | 9.095 |
| Typed program decode | 21.620 | 5.722 |
| Catalog validation | 0.511 | 0.475 |
| Matcher digest and compile | 49.120 | 15.969 |
| Rule and candidate indexes | 1.033 | 0.958 |
| Temporary value cleanup | 14.239 | 0.141 |

Total admission changed from 144.363 ms p50 / 365.628 ms p95 to 43.796 ms p50 /
58.826 ms p95. The optimized maximum was 70.598 ms. User CPU time for each
100-sample process changed from 19.523 s to 5.184 s, and maximum RSS from
43,376 KiB to 24,244 KiB. Phase medians do not sum to the total median.

The change consumes the JSON tree already checked for canonical bytes and the
full program digest, then moves each node configuration into its typed matcher.
It removes the second full parse, a cloned tree during canonical hashing, and
two cloned per-node trees. Node fields serialize in explicit canonical order;
every one of the 2,242 node digests still matches the independent Python compiler.
Unknown fields, duplicate/noncanonical input, graph limits, hashes, the Unicode
profile, and the full observation fixtures retain the same rejection semantics.
Phase callbacks have a no-op production observer and record timings only in the
explicit ignored diagnostic. Allocation counting and the wider valid catalog,
control, and false-review matrix remain separate follow-up diagnostics.
