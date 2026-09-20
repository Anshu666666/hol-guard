# Registry count and artifact-readback correction

The preceding checkpoint5cbbd225 has inaccurate wording in README, Takeaway and the RSP100 current action: “both registries admitted174bindings.” The actual record has pair_registry.binding_count=174 and approval_defaults_available=true. The correct statement is: both registries admitted; the pair registry captured174bindings. Approval admission is boolean and does not report an approval binding count. The PR body was already corrected at12:10:22UTC, while the preserved preceding files remain unchanged.

That checkpoint also described the ordinary native archives using GitHub metadata and runner reports because their binaries had not yet been downloaded. A later, separately bound readback actually downloaded the four normal124 archives, verified all bytes/members and matched their runtime hashes to manifests and original reports. This supersedes the metadata-only limit only for those four archives. It does not recover other unavailable historical packets, build future-source artifacts, supply source sdist, attest signatures or prove installed behavior/transition qualification.

The compressed wheel-member report was created in Git with matching local Git blob SHA, but the text connector cannot reverse-read compressed bytes. Local compressed/decompressed SHA256 values are retained. A separate raw Git readback receipt is required after the packet is rooted; no completed Git binary readback is claimed here.

The final scopedPython3.14 run35513920542 subsequently reports173pair bindings, with both registries admitted. This is separate from the earlierPython3.12 count174; neither is an approval-registry binding count.
