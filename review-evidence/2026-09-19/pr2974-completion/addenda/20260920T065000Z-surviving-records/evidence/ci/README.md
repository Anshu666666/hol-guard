# CI evidence retained after the second workspace reset

This standalone Git tree preserves surviving tool-state content for PR #2974. It does not advance a branch or create a commit. The product source is `4d10758e2cb44e5afa72a08aa631a02541dad534`; its normal merge build is `8d2ad647abd812a78e3666c8bba8eeca51fbeb9c`, with the same tree `fbc00caa3788eb422158a2263a578e83ac626183`.

All four normal native wheel jobs completed successfully. The latest retained check census at 06:32:19 UTC has 187 checks: 166 successful, 19 skipped, one failed Ubuntu transport job and one active Kilo review. The independent failing lane still has two initial policy-push failures. Windows committed all 21 native receipts but also retained one journal_checkpoint/os_permission event in all-evidence diagnostics. Full original qualification remains false, and no formal APPROVED review was recorded.

The logs are the exact decoded strings returned by GitHub and retained in functions state. The API records are either exact retained fetch text or explicitly serialized retained structured tool data, as identified in MANIFEST.json. The recovery summary is newly written from observations verified before reset. It does not impersonate the lost raw artifact JSONs or prior manifests.

The prior tfbs filesystem disappeared when wife resolved to asnf. The original primary workspace was already unavailable. Downloaded archives, raw extracted reports and prior verification JSONs are missing from this selection. Their known hashes and precise scope remain recorded separately in recovery-observations.json. The exact 3,736-byte manifest of the unavailable seven-document packet is preserved; the seven documents themselves are not restored.

The scripts under verification-methods record the previously executed verification method. They have not been rerun after reset. No benchmark, compilation, artifact reconstruction or workflow rerun was performed to create this tree.
