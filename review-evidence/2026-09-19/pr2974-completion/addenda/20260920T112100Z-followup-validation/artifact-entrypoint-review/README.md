# Actual artifact and release qualification entrypoints

This read-only review binds source `124472b8949805e0dd36052df6894b335d8b519d`, tree `a0c139c4e02535545c5b0e602c240a38affde5fe`, to the existing workflows and validators listed in [REVIEW.json](REVIEW.json). It prepares the remaining artifact work without building, signing, uploading or qualifying an artifact. Original acceptance is unchanged.

| Existing route | What it actually covers | What remains separate |
| --- | --- | --- |
| Ordinary native-wheel CI | Four installed platform wheels on Python3.12, actual bundled identity and default-auto checks | Final selected source, signing/freezing, distinct-version update/rollback and full installed qualification |
| Unix native-wheel jobs | Standalone Pi-output probe, small installed-SLO wave, per-platform artifact validator | Original populations/targets; their Windows omission text is not four-platform aggregate admission |
| Windows native-wheel job | Installed identity, command-control-lock and default-auto; Pi cases inside the latter | No standalone Pi-output probe, artifact-validator JSON or installed SLO step in this source |
| Local four-platform validators | Exact declared wheel/manifest/version/source/rule/runtime and target set | Optional provenance JSON parsing is not cryptographic attestation verification |
| Signed Desktop Core route | Existing macOS ARM path using trusted main, a published stable source/wheel and protected Apple signing context | Actual selected PR artifact, source-to-final-byte record, runtime activation and rollback |
| MDM unsigned fixtures | Mac/Windows fixture packaging; unhealthy unsigned state is expected | Signed production artifact acceptance |

The installed identity probe explicitly restores the same artifact and labels cross-release rollback and signing as not exercised. A passing identity mutation test cannot prove those distinct transitions. Normal CI digest reports are runner records until the corresponding bytes are independently retrieved and hashed.

The full offline wheel check can use the existing local validator with all four explicit platform tags: `manylinux_2_17_x86_64`, `macosx_13_0_x86_64`, `macosx_11_0_arm64`, `win_amd64`. Supplying all four forbids a Windows waiver. The existing aggregate `verify_native_runtime_release.py validate-local` also checks its complete native artifact set; neither local command publishes.

Signing changes runtime bytes, and PyInstaller packaging can change the archived image. The existing pipeline refreshes the first manifest, reseals the packaged manifest, signs the outer file and verifies final identities. The retained admitted source/version/rule inputs and transformation records must connect those stages; an embedded digest check alone does not recover that full chain.

The next artifact campaign must wait for the concrete combined source and its original implementation prerequisites. It then needs exact baseline/candidate artifacts, actual installed registered routes, distinct release transitions and the original performance/resource/receipt/recovery populations. This review does not launch the labeled PR canary, registry publication or trusted release workflow, and it does not infer signing access from source configuration.

All fourteen exact source bodies are attached. No test, workload, release or task status was changed by this review.
