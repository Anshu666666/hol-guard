# Installed checkpoint ae33987

These records retain the actual four-platform results for PR head
`ae33987d0c8675c36a77375e03419aee920825f6`. The paired workflow builds that exact
head. The native-wheel workflow builds GitHub's test-merge commit
`a224cc2e01e1eb8d74182fa32d78f46e9b417348`, as recorded by all four selected wheel
runtime manifests and installed identity reports. The comparison baseline remains
`2e672d2d950c6ec471005ddba46e49bba16dc23b`.

The [paired run](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841349)
attempted both arms on every platform. Each arm failed before a complete paired
sample was available, so no speedup or whole-program qualification follows from
this checkpoint. All four independent installed Ollama lifecycle probes passed
their 22 native cases, and all four Builder installation probes passed.

| Platform | Original baseline failure | Candidate failure | Stopped artifact transition |
| --- | --- | --- | --- |
| Linux | Codex interpreter integrity validation | Short-lived expiry publication did not authenticate | First three phases pass; original-baseline rollback fails readiness |
| macOS ARM | `socket.getfqdn` stalls during daemon construction | Same expiry publication failure | First three phases pass; original-baseline rollback fails readiness |
| macOS Intel | `socket.getfqdn` stalls during daemon construction | Same expiry publication failure | First three phases pass; original-baseline rollback fails readiness |
| Windows | First recovery sample fails | Same expiry publication failure | First baseline worker did not produce valid JSON evidence |

On both macOS hosts, the exact loopback resolver configuration was present,
root-owned, and selected by the system configuration. Its UDP self-probe
succeeded. The responder received no libc resolver packets; the before, after,
and cleanup `getfqdn` probes all exceeded their deadlines. The baseline bytes and
startup deadline remained unchanged. These observations do not establish a DNS
repair or justify a broader network change.

The three Unix transition runs preserve all six prior receipts and protected
control revision 4 before the original-baseline rollback loses readiness. The
uploaded evidence does not include the publisher's inner rejection or a proven
failed-start retirement. Candidate restore was not attempted. Later diagnostic
or recovery code must not retroactively change these outcomes, erase command
authority, or qualify an unsupported original-baseline downgrade.

The [native-wheel run](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841356)
passed on Windows and macOS ARM. Linux and macOS Intel failed the capacity-phase
route-count check after completing runtime identity, installed corpus, cold,
cold-session, warm, size, recovery, and pool-warmup phases. These per-job results
do not replace a completed paired comparison.

`manifest.json` records all eight downloaded ZIP digests, every original JSON
member digest, and every retained member digest. The 47 JSON members are formatted
for review with decoded values unchanged. Five wheel member digests are retained
without copying binaries; macOS ARM contains both its native platform wheel and
an additional universal wheel. The compatible prior-candidate rollback selects
only the explicitly pinned native platform wheel from each immutable artifact
and must validate its actual `a224cc2` build identity, separately from the PR head.

The earlier `takeover-5ee52` records remain historical evidence. No record in
either checkpoint was resampled, repaired, or promoted to a passing result.
