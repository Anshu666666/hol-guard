# macOS loopback lookup witness

The retained `ae33987` macOS qualification reports show a selected exact
`1.0.0.127.in-addr.arpa` resolver and a successful direct UDP self-check. They
also show zero resolver packets beyond that self-check, timed-out five-second
`getfqdn` probes, and a baseline daemon constructor stopped at its unchanged
twenty-second deadline. Those observations do not establish the native cause
of the system lookup stall. The original failures remain failures.

`scripts/ci/native_loopback_lookup.py` adds a read-only witness after the entire
build and qualification command returns and before
`native_loopback_resolver.py` removes its exact owned configuration. The wrapper
records configuration readback on both sides of the witness. The original
qualification packet count is captured before these extra lookups, and each
diagnostic reports its own packet-count window. Those windows can include
other system activity; they are not exclusive attribution to a child.

Each of three separate isolated Python children receives only a fixed numeric
loopback address. The operations are a numeric-only `getnameinfo` control,
`gethostbyaddr('127.0.0.1')`, and `getnameinfo` with `NI_NAMEREQD`. Each has the
same five-second process deadline as the existing resolver probe, a combined
1 KiB output limit, and bounded child retirement. Neither the baseline
artifact nor a qualification process is patched, retried, sampled, or given a
longer deadline. The lookup results are not qualification timing samples.

If either name lookup remains pending after 250 ms, the witness invokes
`/usr/bin/sample` for its own still-unreaped child only, requesting one second
at a ten-millisecond interval. The sampler has a maximum two-second process
deadline within the lookup's original absolute deadline and a combined
64 KiB output limit. The target PID comes directly from the child created by
the witness and cannot be supplied by a caller. The original qualification
process is never sampled. Diagnostic failure cannot change the qualification
command's return code; existing exact-byte resolver cleanup remains mandatory.

Only allowlisted categories from recognized native call-graph function frames,
frame count, byte counts, SHA-256 digests, containment status, return codes, and
bounded lookup status are retained. Raw native stacks, headers, paths, memory
addresses, hostname answers, and exception messages are discarded. Empty
categories are a valid inconclusive observation, including when sampling is
unavailable or symbols do not match the allowlist.

The allowlist is guided by primary source code. CPython 3.12.10 implements
`getfqdn` by calling `gethostbyaddr`. Apple's Libinfo source forwards
`gethostbyaddr` through `si_host_byaddr(si_search(), ...)`; its mDNS lookup path
constructs a PTR query, invokes DNSService APIs, and waits through `kevent`.
The categories distinguish those paths from directory lookup and other
explicitly named waiting functions. They do not assert that the tested macOS
runner uses this exact source revision or that a source-code path caused the
recorded stall. Actual host stack categories are required for that next
diagnostic step.

- [CPython 3.12.10 socket implementation](https://github.com/python/cpython/blob/v3.12.10/Lib/socket.py)
- [Apple Libinfo public lookup implementation, pinned revision](https://github.com/apple-oss-distributions/Libinfo/blob/39b70c515baee5b609e7e91693edbd934b6845a1/lookup.subproj/libinfo.c)
- [Apple Libinfo mDNS query and wait implementation, pinned revision](https://github.com/apple-oss-distributions/Libinfo/blob/39b70c515baee5b609e7e91693edbd934b6845a1/lookup.subproj/mdns_module.c)

Source tests cover fixed numeric loopback operation, actual bounded child
output/deadline/reaping, ownership of the sampled PID, call-graph-only
allowlisting, private-output removal, packet accounting, configuration
lifetime, and unchanged qualification results on diagnostic failure. These
tests do not qualify a macOS resolver fix. No additional resolver, hosts file,
cache, service, external DNS, or system network change is introduced by the
witness.
