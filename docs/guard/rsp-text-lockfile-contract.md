# Text lockfile single-parse contract (RSP-052)

**Source-history scope:** this page records the complete-v2 RSP-052 implementation and its validation/status at that stage. The later [RSP-059 coverage and correction](rust-performance/package-format-parity-coverage.md) advances the current parser to **complete-v3**: malformed four-space Bundler specs invalidate all projections, saved v2 approval identities do not carry forward, and targetless Bun binary fallback remains metadata-only. Supported extraction order, all numeric bounds and one-parse evaluation scope remain unchanged. Historical v2 results and the status paragraph below are not claims about the current release ledger or measured v3 performance.

This source change starts from integration `41c3b3724`. The package evaluator now obtains validation, completeness, manifest dependencies and direct-selector records from one traversal of Yarn, pnpm and Gemfile.lock input. JSON, JSONC and TOML retain their shared document decode. No native package parser is introduced or activated, and this tranche has no timing measurements.

`text_lockfile_parse.py` consumes an iterator with exactly the previous `str.splitlines()` line boundaries, including CRLF and Unicode separators. It admits each line before retaining extracted records and does not allocate all line objects or selector substrings before resource admission. Every result contains immutable tuples; consumers do not receive a mutable text parse tree. The existing evaluation-local cache keys the result by format/path spelling and exact source bytes, with case folding for the format name. Both successful and typed incomplete results are reused within that evaluation. A new evaluation parses again, and a filename or timestamp never authorizes reuse.

Previously, incomplete parses were excluded from this cache, allowing a later consumer to retry even a deadline failure. `complete-v2` deliberately keeps that first typed failure for the rest of the evaluation, including a transient deadline failure. This is conservative complete-or-fail behavior: repeated consumers cannot switch from an earlier incomplete view to a later complete view. The changed deadline-cache regression requires reuse only inside the current evaluation and a fresh parse after its context ends.

## Supported behavior and duplicate resolution

| Format/view | Preserved behavior |
| --- | --- |
| Yarn manifest | Classic quoted `version` and Berry `version:` syntax; comma-separated and scoped selectors; npm alias names; metadata exclusion. The last version written for a package name wins. |
| Yarn direct resolution | A selector index retains its first source occurrence and ordinal. A target uses the earliest occurrence matching any of its existing expected selectors, independent of expected-selector ordering. Repeated target identities still select the last target's requested selector set. No requested selector means no lockfile direct resolution. |
| pnpm manifest | Existing `packages` and `snapshots` entry syntax, peer suffix handling, last package version, and the snapshot `dependencies` fallback are preserved. Optional snapshot blocks retain their existing exclusion. Legacy slash-only package keys remain outside this manifest grammar. |
| pnpm direct resolution | Legacy top-level dependency sections and the `.`/`default` importers remain supported. Other workspace importers are excluded. Each record retains an inline candidate and its first nested version candidate; existing exact/source/alias rules take the first valid candidate, then the last valid record for the dependency name. Thus legacy direct versions remain available even where the manifest entry grammar emits nothing. |
| Gemfile.lock | Existing `specs:` blocks, GEM/GIT/PATH sections, platform and prerelease version text, heading termination, and last duplicate package version are preserved. Nested dependency constraints do not become resolved entries. |

This parser deliberately preserves Guard's supported line grammar and fallback behavior. It does not claim complete YAML, Bundler or Yarn specification validation. Existing NUL/tab, top-level Yarn header, pnpm line-shape and line-level bracket checks remain. Quoted scalars retain the existing bracket accounting; the change does not reinterpret them as a general YAML tree. Unsupported/ambiguous dependency declarations retain their existing omission or fallback behavior within a complete supported parse.

## Admission and failure

The numeric budgets remain **8 MiB of source, 100,000 entries per retained dependency view, 250,000 nodes, depth 128**, and the existing size-scaled **0.5–1.5 second cooperative parser deadline**. `complete-v2` distinguishes the strengthened text admission and immutable projection contract in evidence and persistent evaluation identity. Structured decoding and the exact source hash algorithm are unchanged.

Text accounting is explicit because the old separate text validator did not apply the structured node/depth limits:

- One document root and each nonempty, noncomment source line consume nodes. Each Yarn selector part consumes an additional node, including ignored metadata or empty parts. These count the grammar actually traversed; opaque scalar contents are not represented as a decoded YAML tree.
- Depth counts the active indentation levels and flow bracket nesting. A larger indentation width alone does not invent additional levels. The maximum is enforced while traversing ignored content as well as dependency sections.
- The manifest map, pnpm direct-record list, current Yarn selector list and retained Yarn selector index each obey the entry cap. A selector list referring to one package cannot evade the cap through the manifest map's smaller cardinality. pnpm candidates have at most two scalar values per record.
- Deadline checks occur for each line, selector part, bracket and expanded Yarn projection. The parser checks again after extraction; target matching consumes the frozen records without parsing text again. The parser retains its cooperative deadline model, not a preemptive process watchdog or a bound on total application RSS.

Any syntax, byte, decode, entry, node, depth or deadline failure discards **all** dependency and selector views and returns a typed incomplete result with the exact source hash. No parsed prefix becomes a complete allow result. Texts newly exceeding the explicit node/depth or projection cap may now become incomplete; this is intentional admission enforcement, not evidence that previous unbounded acceptance remains identical.

## Source verification

The committed `tests/test_guard_text_lockfile_parse.py` freezes supported manifest/direct outcomes, aliases, workspace exclusion, legacy pnpm fallback, Yarn duplicate ordering, Gemfile sources/platforms, malformed tails, UTF-8/byte rejection, resource boundaries and deadline failure. It includes a real 100,001-selector case whose manifest cardinality is one, and counts one traversal through each of three production package evaluations that resolve a vulnerable direct version and deny. The latter tests make every legacy text dependency scanner fail if it is called again. Cache tests cover both complete and incomplete input, and verify that a new evaluation parses again.

Run the disconnected regression subset with the locked development environment:

```bash
uv run --no-sync python -m pytest -p tests.package_offline -q \
  tests/test_guard_text_lockfile_parse.py \
  tests/test_guard_js_lockfile_resolution_phase11.py \
  tests/test_guard_package_input_snapshot.py \
  tests/test_guard_js_supply_chain_phase11.py \
  tests/test_guard_tier2_supply_chain_phase13.py \
  tests/test_guard_supply_chain_evaluator.py
```

This is source-level RSP-052 verification. RSP-050 still needs its qualified independent-cardinality matrix, RSP-054 still needs a measured optimized-Python/native comparison, and RSP-059 still depends on an implemented native format path. Existing package performance observations predate this text change and cannot be relabeled as its speedup or installed acceptance.
