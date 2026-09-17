# macOS loopback resolver evidence

The round-four macOS ARM artifact `10489674299`, from job `105154527916`,
retained these observations in `aggregate/runner-resolver.json`:

- `/etc/hosts` already contained an IPv4 `localhost` entry.
- The fixed loopback alias append, cache flush and mDNSResponder HUP commands
  returned successful exit status.
- The isolated `socket.getfqdn('127.0.0.1')` probe exceeded its five-second wait
  both before maintenance (5,004.208 ms including cleanup) and afterward
  (5,006.764 ms including cleanup).
- Separately captured baseline startup stacks reached the standard HTTP server's
  reverse-name lookup. The frozen baseline did not complete daemon construction
  within the existing fixture deadline.

These facts establish unsuccessful maintenance. They do not establish that a
missing hosts entry, hostname choice or a particular upstream DNS server caused
the stall. The current workflow therefore preserves those failures and adds an
optional, bounded PTR-resolver experiment around both qualification arms. Its
effect on the observed macOS stall has not been established. Baseline
source/runtime `2e672d2` and all startup, readiness and product performance limits
remain unchanged. The candidate's numeric server-bind fix is a production change
and must be measured separately.

## Bounded diagnostic distinction

`scripts/ci/native_loopback_resolver.py` now emits schema
`hol-guard.native-loopback-resolver.v2`. The existing `before` and `after` fields
continue to describe the exact legacy `getfqdn` call. `probes_before` and
`probes_after` retain three distinct isolated subprocess outcomes. When the
optional PTR fixture is used, `after_cleanup` and `probes_after_cleanup` retain
the same observations after its configuration is removed:

| Probe | Fixed operation | Interpretation |
| --- | --- | --- |
| `legacy_getfqdn` | `socket.getfqdn('127.0.0.1')` | The operation used by the baseline server. |
| `reverse_getnameinfo` | `getnameinfo` with `NI_NAMEREQD` and `NI_NUMERICSERV` | A separate reverse-name API with numeric service handling. |
| `numeric_getnameinfo` | `getnameinfo` with `NI_NUMERICHOST` and `NI_NUMERICSERV` | Numeric address/service conversion without a hostname lookup. |

Apple documents the numeric flags and the name-required reverse lookup behavior
in its [getnameinfo manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getnameinfo.3.html).
Its [DNS hostname guidance](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/ResolvingDNSHostnames.html)
distinguishes the reverse-resolution APIs. These references support the probe
distinction; they do not prove that changing a runner setting would repair the
observed legacy call.

The three subprocesses start concurrently and share the same five-second phase
deadline. A delayed worker receives only the remaining time; an expired phase
cannot launch another full probe. A fixed flushed marker after imports records
whether the child entered its resolver call. This distinguishes a missing
call-start witness from a started call without a completed result. Cleanup time
remains included in elapsed observations. There are no added sleeps or retries.

Every fixed probe outcome, including failure or timeout, remains in the report.
Only a Boolean classification of the returned label is retained; actual resolved
names, process tracebacks and stderr are discarded. No result is a hook decision,
authority witness or performance pass. A completed numeric control with a timed
out reverse query narrows the next investigation; it does not by itself identify
the underlying macOS resolver defect.

## Optional exact PTR experiment

The workflow invokes `native_loopback_resolver.py` as a wrapper around the entire
paired build-and-measure command. On macOS, when the initial legacy resolver
probe does not complete, it starts one loopback UDP responder on an OS-selected
port. The responder accepts only the exact case-insensitive DNS label sequence
for `1.0.0.127.in-addr.arpa`, with the IN/PTR type. It returns one fixed
`hol-guard-qualification.localhost` answer with zero TTL. Queries are bounded to
512 bytes; compressed names, other names/types and malformed frames are rejected.
It does not forward queries or offer a general DNS service.

An isolated privileged helper may exclusively create only
`/etc/resolver/1.0.0.127.in-addr.arpa` with fixed contents identifying this run
and the loopback responder. Existing files and symlinks are preserved. Cleanup
checks the complete owned contents and file identity before removal; it does not
delete another configuration. The helper accepts no caller-selected path,
domain, nameserver or file contents. This experiment replaces the earlier hosts
append, cache flush and mDNSResponder HUP operations; those operations are no
longer part of the workflow.

The same responder and configuration remain active across both immutable arms.
Failed setup still allows the real paired command to run and retain its result.
Cleanup is attempted after normal completion or a command exception, including
when setup timed out. A cleanup failure cannot turn a successful command into a
successful wrapper result. Existing configuration is left untouched. Non-macOS
runners and macOS runners whose initial probe completes run the paired command
without installing this fixture.

The diagnostic probes retain their shared five-second phase budget, the helper
retains its ten-second supervisory bound, and application/startup/readiness
deadlines are unchanged. No installed baseline code, Python resolver function,
hook decision or qualification oracle is patched. `experiment_finished` records
fixture lifecycle completion; `qualification_pass` remains false. Responder
counters and completed probe labels do not establish installed readiness or an
SLO pass. Abrupt runner termination can prevent cleanup and evidence upload;
missing evidence is not success.

A contained baseline failure must remain failure evidence while the candidate
is still attempted independently. Actual macOS results are required to assess
this environment experiment. Linux packet/file fixture tests establish only the
bounded protocol and ownership behavior, not macOS resolver efficacy or
successful installed qualification.
