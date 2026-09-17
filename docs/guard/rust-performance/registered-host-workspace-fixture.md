# Registered host workspace fixture

Qualification run `35233473603`, attempt 2, Linux pair job
`105250374564` retained a baseline failure at
`codex.PostToolUse.benign.1m`: the actual launcher used `native_resident`,
but the native result did not satisfy the exact `reviewed_output_sha256`
oracle. The baseline completed 386 daemon cases first, then offered 27
launcher cases, validating 26. No headline numeric samples or completed
paired comparison were produced. That failed record remains evidence of
the original run; the correction below does not turn it into a pass.

The fixture omitted a host context field needed by the frozen baseline:

1. `install_priority_launchers` uses global registration, with
   `HarnessContext.workspace_override_explicit=False`. Frozen baseline
   `2e672d2` intentionally omits `workspace` from the Codex registration query in this mode.
2. `_run_registered` previously copied `case.payload` and added a tool-use ID,
   while setting only the subprocess working directory. The bridge does not
   serialize that process working directory into the HTTP request.
3. The baseline server chooses an explicit action workdir, payload `cwd`, or
   registration workspace query. With all three absent, the native edge gets
   `cwd=None`; source classification falls back to the resident's working
   directory, which is the runtime executable's parent. A Codex source fixture
   outside that directory is denied without a reviewed-content digest.

The registered corpus now supplies its actual host workspace in payload
`cwd` when that field is absent, identically for both immutable arms and both
priority harnesses. Explicit `cwd` values, including deliberate conflicts,
remain unchanged. Global registration, installed argv and registration hashes,
the original source reference/content hash, request deadline, process timeout,
and semantic oracle are unchanged. No runtime or baseline artifact is patched.

Regression tests install and read back the actual priority registrations,
confirm that Codex's global registration query has no workspace, and inspect the payload
passed to the original process boundary. They verify source-reference
preservation, identical host context, intentional conflict preservation, and
unchanged argv/timeout. These tests observe fixture construction, not an
installed native decision.

The source trace explains a concrete missing-context defect consistent with
the retained failing field. The old launcher journal retained stdout identity,
not the decoded native digest; an exact observed-versus-expected digest value
was not recovered. Installed qualification of the corrected fixture requires
a new run, kept separate from the original failure cohort.
