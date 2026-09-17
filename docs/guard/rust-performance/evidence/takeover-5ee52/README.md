# Retained evidence for candidate 5ee52a03e

These are all 16 JSON members from the four artifacts of
[Native performance qualification run 35213401779](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401779)
at candidate `5ee52a03e62b9e4940063b348185bedaddf0cb53`, compared with
baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b`. Every platform stopped
before completing paired sampling. The separate installed Ollama reports
contain the component outcomes below; they do not make the paired workflow
a qualification pass.

| Platform | Artifact ID | Baseline failure | Installed Ollama outcome |
| --- | --- | --- | --- |
| Linux | 10493947566 | `claude-code.PostToolUse.watch.1k`, `field:reason_code` mismatch | Overall pass; native pass with 22 lifecycle cases |
| Windows | 10494407946 | `claude-code.PostToolUse.watch.1k`, `field:observed_policy_action` mismatch | Readiness failure in `stale_write_rejected`: **406.0 ms** against **400.0 ms**, expected revision 4 |
| macOS ARM | 10494172464 | `construct_daemon` deadline; startup stack begins in `socket.getfqdn` | Overall pass; native pass with 22 lifecycle cases |
| macOS Intel | 10493874671 | `construct_daemon` deadline; startup stack begins in `socket.getfqdn` | Readiness failure in `enabled`: **430.438 ms** against **400.0 ms**, expected revision 1 |

**All four Builder components passed**, including generated CLI/MCP
validation, deterministic replay, and idempotent apply. The Windows and
Intel Ollama failures both report `snapshot_returned: true`,
`publisher_ready_after_failure: true`, and `budget_exhausted: true`.
Those late readiness results remain failures. Their partial native case
lists were not uploaded, so this retention does not reconstruct them.

Both macOS resolver experiments installed and cleaned up the exact-loopback
PTR configuration. Each custom responder recorded **zero received and zero
answered packets**, and each `before`, `after`, and `after_cleanup` probe
exceeded its deadline at approximately five seconds. Neither experiment
qualified. Both baseline failures record the inner construction deadline;
their outer `timed_out` and `containment_failed` flags remain false. The
resolver records state that the baseline artifact, runtime, and fixture
deadline were unchanged. Linux and Windows explicitly report `not_macos`.

The Linux and Windows failure reports retain delivered `policy_action:
warn` and native `decision: deny` / `policy_action: block`. The native
`reason_code` is already `redacted` in each uploaded member. It cannot be
recovered from these artifacts and has not been replaced with an inferred
reason or a later corrected expectation.

[manifest.json](manifest.json) follows the `takeover-42579` record format:
original ZIP member, artifact ID, platform, original SHA-256, and retained
SHA-256 for every file. It also records the four ZIP hashes and exact run and
head identities. Retained JSON uses sorted keys and normalized formatting;
each decoded value is identical to its original member. All JSON keys and
values were inspected for privacy before retention. They contain aggregate
labels, hashes, build metadata, and bounded diagnostics, with no raw request
or response bodies, credentials, personal paths, or private exception text.
Existing redactions and qualification flags are preserved.

The uploaded members do not record the selected workflow mode or include a
completed paired timing matrix. Linux and ARM native Ollama still explicitly
leave interactive enrollment, native approval consumption, and package
downgrade unqualified. Both build arms report package version `3.0.1`.
This evidence does not close installed performance, release, or rollout
acceptance.
