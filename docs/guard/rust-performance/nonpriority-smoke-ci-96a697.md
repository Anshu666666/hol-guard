# First nonpriority installed smoke: failed admission retained

The fixed Cursor `beforeShellExecution.global` smoke ran in qualification
[35247986949](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986949),
attempt 1, at source `96a69725eab018674174dabc6f205a4087d6ff4b`.
It planned two timed observations per arm on each of four targets, after two
separate benign/block preflight cases. This is not the 1,000-observation
qualification. The [manifest](evidence/nonpriority-smoke-96a697/manifest.json)
binds the three failed pair archives inspected here; the Linux pair is a
separate successful collection whose aggregate still failed.

| Target and job | Retained result | Limit |
| --- | --- | --- |
| Windows `105295410460` | Both recovered worker reports record four validated native-resident cases each, zero errors and two timed observations per arm. | Both pair arms failed admission. Each report has four host/effective CPUs but `ram_bytes=null`; replaying the unchanged identity validator rejects `surface_tail_hardware_count_invalid`. |
| ARM `105295410495` | Candidate completed its two timed observations. Frozen baseline failed fixture construction. | Its retained stack identifies `socket.getfqdn` during HTTP server binding. There is no completed pair. |
| Intel `105295410659` | Candidate completed its two timed observations. Frozen baseline failed fixture construction. | The same constructor boundary remains unqualified. There is no completed pair. |
| Linux `105295410493` | Both arms completed the two timed observations and semantic preflight; encrypted evidence was uploaded. | Its later aggregate failed the singleton artifact layout check. Collection success is not aggregate or performance qualification. |

All three failed-pair ZIP lengths and SHA-256 values match GitHub artifact
metadata. Exact encrypted bytes match each public receipt. Authenticated private
recovery succeeded for 9 Windows, 8 ARM and 8 Intel records. Only existing public
members and a closed numerical/semantic Windows projection are published here;
the private records remain private. The failed pair manifests are unchanged.

Windows exposes a concrete hardware-identity blocker. The shared qualification
summary called the production capacity helper, whose POSIX `sysconf`/cgroup
implementation yields no Windows RAM value. The later benchmark-only correction
queries the already locked `psutil.virtual_memory().total` on Windows, admits
only a positive bounded integer, and leaves failed or invalid readings missing.
POSIX capacity semantics and production worker policy are unchanged. The tail
identity gate still rejects missing RAM. Both old reports independently fail
that gate; the old controller did not retain its outer worker return code, so
this replay does not exclude an additional process-level failure.

The two Mac resolver experiments retained successful PTR self-tests and exact
resolver registration, but received no resolver queries from the failing libc
lookups. Legacy `getfqdn`, `gethostbyaddr` and reverse `getnameinfo` probes
exceeded their five-second observation limits before, during and after the
experiment; numeric `getnameinfo` completed. Intel's cleanup registration probe
still observed the registration, while ARM's did not. These records do not
prove the underlying resolver cause or a successful environmental correction.
Neither baseline artifact nor a fixture deadline was changed.

The Windows correction passed 84 focused hardware, pair and target tests;
missing-data rejection remains covered. Actual Windows collection on the
corrected source is still required. The separate singleton-download correction
must also run before any full nonpriority collection is selected. No original
failure is converted into a completed comparison, and no native activation,
tail target or resource completeness is claimed.
