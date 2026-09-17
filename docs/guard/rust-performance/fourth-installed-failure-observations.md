# Fourth-source installed and CI observations

These facts refer to published source
`2ebb01ff356101aea8d658ce639fe2c87188bd0d`, tree
`1c41bef1979ead9e50ee406a60505ce6894aa461`, attempt 1. They do not qualify a
later correction. Source diagnostics added after this run have no installed
result at this cutoff.

## Terminal CI facts

| Workflow | Observed terminal result |
| --- | --- |
| [Main CI 35240794078](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794078) | 114 unique jobs: 106 success, 6 skipped, 2 failure. 95/96 pytest shards passed. |
| [Security 35240794239](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794239) | All four jobs passed: Trivy, Semgrep, privileged-workflow policy, Gitleaks. |
| [Native wheel 35240794111](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794111) | ARM passed; Linux, Windows, and Intel failed distinct acceptance checks. |
| [Windows resident 35240794142](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794142) | Both jobs passed. |
| [Daemon edge 35240794163](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794163) | Five jobs passed; soak was skipped. |

Main's only underlying source-test failure was shard 54's
`test_actual_instrumented_protect_preserves_oracle_and_single_parse`, with
`package_phase_total_invalid` (227 passed, one failed in that shard). Its
dependent aggregate job also failed. The duration-manifest and Sonar jobs were
skipped. Full artifact pagination established all 96 unique, nonempty,
unexpired `pytest-durations-0` through `pytest-durations-95` artifacts. The
previously missing shard 91 uploaded artifact `10505975276`, 7,996 bytes. This
establishes artifact presence and upload recovery, not aggregate manifest
validation. Security used Gitleaks 8.24.2 and scanned the exact release-to-head
range (1,259 commits) without finding leaks.

Linux's native-wheel concurrency-64 wave received all 64 responses with zero
transport errors: 48 delivered allows and 16 explicit overloads, versus 32
native-resident routes, 16 native-fail-safe routes, and zero native overloads.
Windows received 64 responses with zero transport errors: 35 allows and 29
explicit overloads, versus 34 native-resident routes, one native-fail-safe
route, and zero native overloads. Both failed the unchanged conservation proof.
Windows also had one ordinary availability fallback. Intel's concurrency-16
wave conserved all 16 native-resident responses but failed at 1,014.141 ms
against the unchanged 1,000 ms limit. Counts alone do not identify a client
pool, daemon, or native admission cause.

## ARM paired launcher rejection

In [qualification job 105271491584](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794284/job/105271491584),
artifact `10505079814` retained a baseline reverse-DNS construction failure and
an independently attempted candidate. The candidate completed 386/386 daemon
corpus cases and 62/62 registered-launcher corpus cases. It then failed during
the numeric `INSTALLED_LAUNCHER.c16.codex.PostToolUse` batch.

The failed batch offered 16 calls and retained three returned latency values
before rejection. The numeric journal retained 126 offered observations and
113 returned values overall, including 35 validated batches before the failed
batch. Unreturned outcomes cannot be reconstructed. This is not a completed
paired comparison.

`priority_launcher_codex_schema_mismatch` occurred after the existing validator
had accepted the `PostToolUse` event, the event-only nested object, and absence
of top-level `decision` and `model_output_action`. It rejected additional
top-level keys. Neither rejected stdout nor its key set was retained among the
nine recovered files. A daemon availability reply containing `continue` plus
the event object is compatible with this boundary, but that field and its
underlying cause were not observed. No native authority is inferred from this
shape explanation.

## Failure-only witness added after this run

The narrow observer surrounds only the existing `validate_launcher_stdout`
call. Process completion, its timer stop, exit/containment checks, JSON decoding,
and object checks have already occurred. The original validator is called once;
its exception object, message, and traceback are preserved. Existing failure
export includes the bounded diagnostic attached to that error. The private
numeric journal retains its original offered/returned counts and failed batch.
No full stdout copy is added to the public report or to a new journal.

The diagnostic contains fixed top-level and nested key-presence flags, counts
saturated at 65, finite outcome labels, and process outcome flags. Unknown
names, free-form reasons, commands, paths, and response text are not exported.
Presence labels `event_container`, `suppress_reply`, `model_action`, and
`updated_mcp_reply` stand for the corresponding fixed output-bearing schema
keys; these labels allow boolean facts to survive the existing privacy filter.

The byte count and SHA-256 identify **UTF-8 re-encoding of already decoded
stdout**, not original stream bytes. A response claiming native metadata still
leaves `native_authority_proven=false` and `availability_cause=unproved`.
Diagnostic capture and export errors cannot replace the original rejection.
Success performs no failure hashing or capture. The accepted schema, timers,
deadlines, cancellation, route checks, and retry behavior remain unchanged.

The focused source suite passed 58 launcher, failure-export, and numeric-journal
tests. It includes the exact Codex extra-key rejection, UTF-8 byte identity,
unknown-key privacy, unchanged exception identity, projection failure, and
failed-batch conservation. The first run had 57 passes and one new test using
the wrong recovery-field name (`count`); correcting it to the existing `offered`
schema produced the passing run without source or acceptance changes. Three
changed Python source files passed type checking with zero errors (89 warnings);
Ruff and diff checks passed. No installed workload or timing run was performed
for this diagnostic addition. Independent source review confirmed the original
validator, exception, timing, and privacy boundaries remain intact.
