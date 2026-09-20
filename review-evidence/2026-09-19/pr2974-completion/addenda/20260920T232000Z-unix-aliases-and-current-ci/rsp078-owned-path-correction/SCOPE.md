# Driver-only owned catalog correction

First original run 35541914157 failed before installed work in all three cells: 288 collected, 256 passed, 32 failed. Exact original archives and data reader are retained in 652d9e9e0477ee6bcc289de96d6b82f7536f50ea.

The driver now owns a private temporary directory for original case catalog construction; the following result checks use immutable expected fields and do not read catalog files. The modeled report uses pytest-owned workspace. Two new controls refuse unowned paths before the original factory can write, even when tests run as root; then check private mode, deletion after acceptance/refusal, unchanged input and no dynamic path in public accounting. Both failed against the old driver, and all 290 selected controls pass after correction. No product, four fixture leaves, policy, original14-case population, input identities, deadlines or delivery/native/availability oracles changed. Contract is byte-identical. The workflow changes only v2 branch and additive 288-to-290 control requirement.

Candidate driver tree e69d8d7040c91e44a90ee40e8628280dfad6ed9e must be committed with sole parent 3d99b884a73568c2278e829fe53a103880fa69da. Actual artifacts stay a1d509/build9f511; current cbd test-only source is not relabeled as the build. No installed successor execution is claimed by this packet.
