# Scoped configuration for remote package audits

Source `73e83ddfac66ef1e04771a2aa51e96cdb1fbee77` forwards the command worker's existing reader into the `guard.packageShims.audit` helper and its home configuration load. The audit consumes the scoped configuration value, and a rejected home capture returns the existing failure result before the audit callback runs. The three-line production change adds only the optional parameter and its two forwarding keywords. `proof.json` independently compares the production AST before and after removal of that transport.

The remote-reader and existing command-executor update suites pass **18 cases in 5.23 seconds**, including the two new audit cases. The first subsequent type-check wrapper waited 180.259 seconds for the shared lock and executed no analyzer; its empty log and exit code remain retained. The later check of the changed production file passes with **zero errors and five warnings**, with 1.506 seconds of analyzer time. These results are separate from the earlier overlapping scoped-reader suites.

Both runs retain identical before/after inventories of all **1,255 production files**, and every digest was checked against the exact source commit. `manifest.json` records original and stored hashes and lengths. Large source inventories use deterministic gzip, verified after decompression. No performance campaign, full-suite result, final full-production type rerun or hosted security pass is claimed.

Prepared GitHub commit `d8bde000de992009be3b2ed009347d2b3707ef0d` has exactly this local source/evidence tree, `1967a2127a325ae340d313bf73e80c60abb4d1f6`. Its preparation preceded this receipt, so later documentation/evidence children retain their own identities.
