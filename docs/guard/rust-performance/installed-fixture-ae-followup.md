# Installed expiry and recovery fixture follow-up

The paired run [35217841349](https://github.com/hashgraph-online/hol-guard/actions/runs/35217841349)
failed on candidate `ae33987d0c8675c36a77375e03419aee920825f6` and pinned baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b`. The original bounded failures,
artifact identities and exact retained member digests are preserved in
[failures.json](evidence/installed-fixture-ae/failures.json). They remain failed
attempts, with no completed pair or latency comparison claimed.

## Expiry renewal

The candidate's expiry fixture rebuilt its three-second snapshot without the
already acknowledged `command_extensions`. The disposable store has a real
protected command-control authority, and the resident's
`policy_store_command_floor::next_floor` rejects removal of that binding with
`native_command_control_binding_removed`. The original fixture discarded the
resident error while decoding an ACK, so the captured host failure identifies
the combined publication/readback assertion but does not independently record
that native rejection code. The omitted field and the resident rejection
contract are established by the corresponding source paths.

The fixture now carries the exact acknowledged control binding into the signed
renewal after checking it against the publisher's current compiled binding.
It rejects any renewal that changes the policy digest, mode, runtime identity
or control binding. Baseline snapshots omit the field and retain their original
builder API; the fixture does not add a candidate schema to baseline.

The starting source in commit `6614021ee` is the publisher's full
`current_snapshot()`, so its renewal correction already carries candidate
controls. The follow-up additionally reads the full Rust authority with the
production MAC-verifying reader before and after renewal. Both full snapshots
must match the publisher/renewal generation, digest, mode, runtime, issue/expiry
times and exact control map. The production compact binding is checked in its
actual shape: it carries `command_extensions_bound`, not the full map. Stripped,
mutated or spuriously present full/compact control witnesses fail. The
`control_binding_preserved` result is established only by the authenticated
readback, separately from preservation of the renewal input.

The exact pinned baseline has `_ack_from_resident_output` in
`native_policy_snapshot_publisher_transport.py` (line 54), and its full authority
reader and compact binding are supported without adding a control field.

The original three-second lifetime, two-second build/publication budgets,
one-second expired-native probe and 400 ms preparation budget are unchanged.
Publication still goes through the production resident client, and readback
still comes from MAC-verified Rust-accepted authority. A missing, rejected or
mismatched ACK, absent or mismatched binding, expired readback, retained expired
authority, unavailable native response or contradictory response cannot pass.
The final probe requires the resident's explicit `snapshot_expired` response.
No production runtime, authentication rule, authority file or clock is patched.

Failure evidence now distinguishes publication from authenticated readback and
retains bounded Boolean matches. Successful setup reports the observed ACK,
authenticated readback and preserved authority; these are scenario witnesses,
not headline timing samples. Source orchestration tests use explicit models
and are not installed qualification evidence. A separate source test builds
real signed renewals from a real protected store and confirms that no
Rust-accepted authority file has been created by that test.

## Recovery failure

The Windows baseline reported `recovery_sample_0_failed`. Its old aggregate
contains neither the returned route nor delivered verdict, so that attempt
does not establish whether recovery exceeded a budget, returned availability
continuation or failed for another reason.

Failure-only observation capture is scoped to the serial recovery call with a
`ContextVar`. Existing before/after route counts and the actual response's
closed action labels or reason digest survive the original failed assertion.
Concurrent threads cannot overwrite the captured sample; nested and completed
contexts are reset. Successful observations do not create semantic diagnostic
records. No recovery retry, extra native call or deadline extension is added.

## Linux interpreter integrity

The Linux baseline's exact diagnostic digest maps to the built-in message for
`codex_hook_interpreter_permissions_unsafe`. The installed failure is therefore
an interpreter-permission rejection, rather than an unidentified package role.
The retained host log does not contain the actual mode, owner or group, so no
permission repair is justified by that evidence. Baseline bytes and the
production integrity validator remain unchanged.

The failure reporter now retains the finite shipped role/reason code. For this
specific interpreter-permission rejection it also reads mode, regular-file
status, invocation-symlink status and owner/group classes from the current
`sys.executable` target. These fields are labelled as observations after the
integrity rejection; they do not reconstruct metadata missing from the original
run. No full path, account name, raw exception text or interpreter content is
exported. The regression uses the real validator on an owned unsafe file and
confirms that reporting changes neither its bytes, mode nor inode.

Installed validation of these fixture corrections must run on supported GitHub
hosts. The local execution environment rejects AF_UNIX socket creation, and
source tests cannot establish installed native startup or recovery acceptance.

## Source validation

[source-validation.json](evidence/installed-fixture-ae/source-validation.json)
binds the final Python files and retains every check attempt. The initial
56-test batch passed in 2.30 seconds; the final annotation cleanup passed the
same 56 tests in 2.15 seconds. The authenticated full-readback follow-up and
existing cache-binding regressions passed 42 tests in 3.26 seconds. These
overlapping batches are not added into a distinct-test total.

Ruff and the diff check pass. The first type check exposed broad mapping/test
annotations, which were corrected. The final eight other changed Python files
have no errors. The ten findings in the daemon fixture's unchanged constructor,
control parsing and request protocol were reproduced from exact parent
`6a2f91e03`; their diagnostic rule/message multiset matches exactly. The last
two-file full-readback check has zero errors and 166 warnings. These existing
daemon fixture findings remain visible and are not reported as a green whole
file type check.
