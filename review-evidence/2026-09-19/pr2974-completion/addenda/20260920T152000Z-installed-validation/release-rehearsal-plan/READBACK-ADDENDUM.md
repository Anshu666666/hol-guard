# Readback after the reviewed preparation plan

The reviewed PLAN and command templates remain a preparation snapshot. Two later read-only observations now supply concrete metadata; they do not admit a build, artifact or new comparator.

- Current PR2974 product is `ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d`, tree `19977465d6e419f1276d75fb6bd1b3477f5c9720`, sole parent124472. Its reported PR merge `be612a3e562a2041b3732a33c158eeae4f1dad40` has the same tree. `current-source-readback.json` retains the fresh Git API identities. Fill the plan's product fields from that record; fill actual build/run/archive fields only from the subsequent native build and verified downloads.
- The first five returned GitHub releases include stable `v3.0.193` and `v3.0.192`, each with all six Guard filenames, an intoto bundle and MacARM/Linux Core assets. `available-release-metadata.json` records the first two sets' IDs, reported digests/sizes and release metadata. Their tag-to-commit mapping, artifact bytes, signatures, native/schema compatibility and installed rollback behavior were not verified here. They are available candidates for later review, not selected tested rollback comparators.

Both public versions are higher than the PR source's3.0.1. A real update canary therefore needs explicit version selection/stamping and newly bound artifacts; the source3.0.1 rehearsal cannot be silently called an upgrade from current stable. Keep original2e and a224 comparator pins unchanged. This observation creates no publishing or source-change authorization and no task promotion.
