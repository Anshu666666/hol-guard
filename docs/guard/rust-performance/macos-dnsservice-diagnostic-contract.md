# macOS DNSService reverse-query diagnostic

The retained `abf319d5a345d761d88e26ba787026e98370c26f` ARM and Intel
resolver reports record timed-out libc lookups, a matching exact reverse-zone
configuration, a successful private UDP self-probe, and zero other responder
packets. They establish neither missing hosts mappings nor a DNSService
callback result. Original reports remain in
`evidence/takeover-abf319/perf-macarm-runner-resolver.json` and
`perf-macintel-runner-resolver.json`; neither failure is reclassified.

The v2 lookup witness adds one actual Apple-system query after the original
three libc probes: `/usr/bin/dns-sd -m -Q 1.0.0.127.in-addr.arpa PTR IN`.
It also reads the canonical macOS hosts file through held, no-follow regular
file and directory descriptors, and captures `/usr/sbin/scutil --dns` to
project only blocks matching the existing exact zone, loopback address and
owned responder port. The fixed order is libc probes, hosts inventory, matching
resolver configuration, then DNSService query. These queries can populate
caches; they occur after qualification and are never timing samples or
before/after performance comparisons.

The query is a distinct diagnostic of `DNSServiceQueryRecord`, not an equivalent
replay of libc. In Apple's pinned
[dns-sd client](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/Clients/dns-sd.c),
`-m` exits after a callback without `MoreComing`; for `-Q` it also suppresses
`ReturnIntermediates`. PTR queries add `LongLivedQuery`. It does not select
`ForceMulticast`, whose separate option is `-fmc`. Apple's pinned
[Libinfo lookup](https://github.com/apple-oss-distributions/Libinfo/blob/39b70c515baee5b609e7e91693edbd934b6845a1/lookup.subproj/mdns_module.c)
adds `ShareConnection`, `ReturnIntermediates` and `Timeout`, and may use
`QueryRecordWithAttribute` with `AllowFailover`. These sources explain the
distinction; they do not identify the exact installed runner implementation.
The actual command output determines whether this host supports the syntax.

Each new subprocess retains the existing five-second absolute diagnostic
deadline, a combined 128 KiB output bound, and at most one second of retirement.
Terminal observation uses `waitid` with `WNOWAIT`: the leader remains unreaped
until its owned process group is retired, including descendants that outlive
an exited leader or retain its pipes. Platforms without that observation API
report it unavailable. No externally supplied process ID is accepted. The
original five-second libc probes, two-second nested sampler cap, qualification
deadlines, and qualification exit code are unchanged.

Process status and return code remain separate from callback observations.
The projection counts recognized positive, negative, removed and unclassified
PTR callback rows, bounded numeric API errors and flags, unsupported-syntax
evidence, and responder packets in that diagnostic window. A callback captured
before timeout remains a callback beside the timeout. No captured callback means
only that none appeared in retained output: buffering, a truncated output or
unsupported format can prevent observation. No diagnostic emits a passing
qualification result or establishes that libc now works.

The hosts projection records finite file identity, ownership, mode, size,
modification time and content SHA-256, plus exact canonical IPv4/IPv6 localhost
mapping counts, duplicate records, conflicting addresses and malformed records.
It rejects symlinks, nonregular files, oversize files and changed reads.
Exact spelling is the presence contract; absence of an exact token is not proof
that an equivalent alias cannot resolve. This inventory is not a repair
eligibility decision and does not collect ACL/xattr or service-state dumps.
The scutil projection retains numeric reachability and allowlisted flags only
for matching blocks; a configuration match is explicitly not proof of query
routing. Other hostnames, addresses, answers, configuration, exception messages
and raw child output are never exported; bounded byte counts and SHA-256s remain.

No hosts write, service restart, cache flush, new resolver, synthetic answer,
baseline edit or runtime edit is introduced. Hosted execution is still required
to obtain the missing diagnostic observations.

Source validation on the final helper ran the lookup, resolver-wrapper and
configuration-diagnostic test modules: **56 passed in 3.63 seconds**. This
includes real Linux process-group retirement with an exited leader and a
descendant retaining or closing its pipes, held-file replacement and parent
replacement, callback-plus-timeout accounting, and synthetic macOS output
projections. It is not an execution of DNSService on macOS. The earlier source
run passed 55 tests before adding the parent-replacement witness. Ruff and
format checks passed. The first type-check attempt recorded 28 errors and
104 warnings; explicit responder/report annotations and selector descriptor
typing corrected the errors. The final check records **0 errors, 46 warnings**
for dynamic report values, rather than a warning-free claim.

Retained source-validation output SHA-256s are
`131e3414e8a8dc671134bc142b7e135004c5a99c9e71ee6029c9564784a92471`
(first test run),
`c7f82b07481eee88f56d9db111209637ca424c653d648d71f6bc5ce3801a2ebc`
(final test run),
`1c92dea6f847e00e74b92b5d8a315d7d1309038ea13e2b3624c365df4bf9dac5`
(first type-check attempt), and
`307728aa246fcbf9091524593ecdf9baed23d3052969ab796f302e5affdba7f2`
(final type-check JSON).
