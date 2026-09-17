# Technical contract acceptance review

Reviewed 2026-09-17 against integration source
`a31fcbbee752869f9894cf71ed5d19578e674e44`, tree
`3f55a25bcddf3984f2cead44f34ac08073e0ab0b`, before this note. This is a bounded
source and retained-evidence review supporting RSP-024. It records resolution
of the technical questions below, not human approval of the latest push,
installed qualification, native launcher activation or release authorization.

The immutable [RSP-024 acceptance](TODO.md#rsp-024-approve-the-technical-contract-through-review)
is: “Resolve reviewer questions on current availability behavior, authority
transfer, distributions and rollback. Do not infer safety from a passing old
manifest.” Its direct prerequisites, RSP-016/021/022/023, are recorded DONE in
the [ledger](EXECUTION_LEDGER.md). The review supports closure of this technical
contract criterion; later execution and release gates remain separate.

| Technical question | Reviewed resolution and evidence |
| --- | --- |
| Current availability | [CURRENT_CONTRACT.md, Decision and delivered response](CURRENT_CONTRACT.md#decision-and-delivered-response) separates the native verdict, acknowledged Watch transformation, availability result and final harness response. Ordinary unavailable PreToolUse continuation is preserved; designated integrity failures deny, permission requests have their own behavior, and lifecycle events are observations. `daemon/hook_availability_policy.py::availability_harness_response` and `hook_worker_native.py` retain these distinct paths. Frozen/current Watch vectors preserve the intrinsic native deny and unprefixed reason independently of delivered warn/allow. No additional Python classifier or new availability policy is authorized. |
| Authority transfer | [Native program and control authority](CURRENT_CONTRACT.md#native-program-and-control-authority), [ADR 0013](../adr/0013-native-command-extension-program.md) and the [Codex continuation contract](../native-codex-browser-continuation.md) assign semantics to Rust, require acknowledged program/control identity, and define shared/exclusive mutation fencing. Fresh Codex completion binds the full native request digest to signed artifact identity, preserves six identity fields through final rereads and atomic consumption, and authenticates consumed replay. Ordinary resolved-row reuse and standalone native v3/v4 APIs remain distinct. Compilation, receipt persistence and foreground authority checks are not interchangeable sources of permission. |
| Distributions and executable identity | [Indexed qualification](indexed-pair-qualification.md) fixes five alternating pairs, exact per-series counts, strict runner/artifact cohorts, failed-attempt conservation and the existing paired estimator. Kernel, client, daemon and installed-launcher distributions are separate. Package distribution retains exact version/runtime/manifest identity: [CURRENT_CONTRACT.md, Limits and authority](CURRENT_CONTRACT.md#limits-and-authority) requires full validation before new spawns; an old manifest or stat-only cache cannot authorize replacement. The [dormant launcher design](native-claude-launcher-design.md#proposed-argv-and-package-binding) reuses complete bundled validation, excludes automatic PATH lookup/download, and makes stale registration and unsupported peer profiles explicit. |
| Rollback | [The rollback contract](EXECUTION.md#canary-rollback-and-final-handoff) requires verified package and registration restoration, acknowledged policy, monotonic authority floors and explicit treatment of in-flight work. It forbids replay of ambiguous execution, revision-floor downgrade and reopening Python semantic fallback to manufacture success. [Stopped artifact transitions](installed-artifact-transitions.md) define five ordered phases with exact wheel identities, preserved state, retirement and failure evidence. That experiment does not establish live mixed-generation, signing or program/version downgrade support. Actual rollback transcripts remain required by RSP-139/143. |

The independent benchmark review checked these contracts against the current
source and retained collector/artifact evidence. The native-core reviewer
confirmed no remaining architectural question in its reviewed authority and
continuation scope: full-input identity, signed artifact binding, final identity
propagation, consumed replay, shared fencing, independent floors and recovery
epochs. The background reviewer likewise reported no contrary unresolved
question in its bounded authority/fence/approval reviews. Their earlier concrete
findings were resolved by source corrections; this record does not substitute
a passing ownership manifest for those reviews. These were agent source
reviews, not human code-owner approvals. This audit ran no tests, downloads or
performance measurements and does not revalidate every later source change.

RSP-073 has separate [installed baseline ranking evidence](installed-launcher-baseline-ranking.md).
The audit independently matched the retained ZIP/member hashes, twelve medians
and counts, and frozen collector's real registered argv/stdin/stdout/exit and
native-route checks. The four Claude/Codex routes on one Windows runner support
that bounded observed ordering and an explicit measured/unmeasured surface
inventory. They do not establish a frequency-weighted or stable cross-platform
ranking, qualified tails, or Claude as uniformly highest cost. This meets
RSP-073's own ranking criterion without introducing a tail prerequisite.
Its original RSP-012 dependency remains unresolved and unchanged; selection of
the highest justified production route and native benefit remain separate.

RSP-142 remains open. The [release rules](EXECUTION.md#canary-rollback-and-final-handoff)
require actual-candidate CI, resolved threads and independent latest-push
code-owner approval; agent or bot reviews do not supply that approval. Original
task acceptance, dependency arrays, performance thresholds and release rules
are unchanged by this note.
