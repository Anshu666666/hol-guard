---
name: hol-guard
description: Check local HOL Guard status from a Runx workflow. Requires the hol-guard CLI on PATH.
runx:
  category: security
---

# HOL Guard for Runx

Use this skill when a Runx workflow needs to verify that HOL Guard is available before protected work continues.

## Prerequisite

Install HOL Guard in an isolated CLI environment, then confirm the command is available:

```bash
uv tool install hol-guard
hol-guard --version
```

`pipx install hol-guard` is also supported.

## Default runner

The `status` runner is read-only. It runs:

```bash
hol-guard status --json
```

Runx plans the exact command, executes it through its governed process boundary, and seals the result in the run receipt. If the `hol-guard` command is missing, stop and install Guard instead of replacing it with a custom policy or approval layer.
