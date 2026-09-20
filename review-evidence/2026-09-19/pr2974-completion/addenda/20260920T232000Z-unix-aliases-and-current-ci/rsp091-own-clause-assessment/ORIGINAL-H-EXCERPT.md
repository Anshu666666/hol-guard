
## H. Native transport and narrower ingress

Priority: P2 conditional

Responsible role: Runtime transport engineer

Gate: Begin only if post-optimization profiles justify added protocol complexity.

Source anchors: rust guard-runtime managed_resident*, resident_client.rs, resident_transport.rs, resident_state_discovery.rs; guard/daemon/server.py; hook_process_*; native_resident_client.py. PRD §11; [S04](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/daemon/server.py),[S12](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident_client_stream.rs),[S13](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/rust/crates/guard-runtime/src/managed_resident.rs).



### RSP-085. Profile discovery/connect/auth versus evaluation

Status: OPEN. Depends on: RSP-035,RSP-048,RSP-010.

Acceptance: Measure platform-specific per-request work through the existing persistent helper and resident; count current socket opens.



### RSP-086. Choose connection reuse or ingress consolidation

Status: OPEN. Depends on: RSP-085,RSP-012.

Acceptance: Compare alternatives with full process-tree cost; do not port the entire administrative server to optimize hooks.



### RSP-087. Specify bounded native session protocol

Status: OPEN. Depends on: RSP-020,RSP-021,RSP-086.

Acceptance: Define generation/peer binding, framing, inflight limit, request correlation, idle timeout, cancellation and freshness checks.



### RSP-088. Implement generation-bound persistent connections

Status: OPEN. Depends on: RSP-087.

Acceptance: Reuse only within the authenticated scope and capability contract; bound pools, memory and lifetime.



### RSP-089. Exercise replacement and recovery races

Status: OPEN. Depends on: RSP-088,RSP-021.

Acceptance: Test restart, stale discovery, peer replacement, failed auth, reconnect, concurrent requests, cancellation and ambiguous commit.



### RSP-090. Prototype hook-only native ingress if selected

Status: OPEN. Depends on: RSP-086,RSP-024.

Acceptance: Preserve auth, context binding, scheduler/admission, response and evidence contracts while keeping product/admin APIs on their current owner.



### RSP-091. Preserve Windows and Unix transport guarantees

Status: OPEN. Depends on: RSP-089,RSP-090.

Acceptance: Test DACL/owner/SYSTEM rules, loopback authentication, exact package process, Unix private paths, permissions and peer identity.



