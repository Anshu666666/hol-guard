"""Source-build smoke only: prove the dormant command follows its Cargo feature."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import cast

_CAPABILITY = "claude-launcher-pilot-v1"


def check(runtime: Path, *, enabled: bool) -> dict[str, object]:
    runtime = runtime.resolve(strict=True)
    response = subprocess.run([str(runtime), "capabilities", "--json"], capture_output=True, check=True, timeout=20)
    if len(response.stdout) > 65536 or response.stderr:
        raise ValueError("launcher_capability_output_invalid")
    value = cast(object, json.loads(response.stdout))
    if not isinstance(value, dict):
        raise ValueError("launcher_capability_object_invalid")
    features = cast(dict[str, object], value).get("features")
    if not isinstance(features, list):
        raise ValueError("launcher_capability_features_invalid")
    items = cast(list[object], features)
    if any(not isinstance(item, str) for item in items):
        raise ValueError("launcher_capability_features_invalid")
    if items.count(_CAPABILITY) != int(enabled):
        raise ValueError("launcher_feature_advertisement_mismatch")
    # Missing arguments cannot read stdin, contact a daemon or alter settings.
    # It distinguishes a compiled entry point from capability metadata alone.
    command = subprocess.run(
        [str(runtime), "claude-launcher-v1"], input=b"", capture_output=True, check=False, timeout=20
    )
    expected = b"native_claude_launcher_arguments_invalid" if enabled else b"usage:"
    if command.returncode == 0 or command.stdout or expected not in command.stderr or len(command.stderr) > 65536:
        raise ValueError("launcher_feature_dispatch_mismatch")
    return {
        "schema": "hol-guard.claude-launcher-source-smoke.v1",
        "pilot_feature_enabled": enabled,
        "capability_matches_feature": True,
        "command_matches_feature": True,
        "registration_changed": False,
        "installed_qualification": False,
    }


class _Arguments(argparse.Namespace):
    runtime: Path = Path()
    expect: str = "disabled"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--runtime", type=Path, required=True)
    _ = parser.add_argument("--expect", choices=("disabled", "enabled"), required=True)
    args = parser.parse_args(namespace=_Arguments())
    print(json.dumps(check(args.runtime, enabled=args.expect == "enabled"), sort_keys=True))


if __name__ == "__main__":
    main()
