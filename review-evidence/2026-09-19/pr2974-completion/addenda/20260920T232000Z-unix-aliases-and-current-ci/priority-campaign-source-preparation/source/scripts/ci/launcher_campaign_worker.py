"""Unprivileged, single-arm entrypoint; no implicit benchmark retries.

The stdout document is private intermediate evidence until the unprivileged
post-work reader admits its structure/privacy and joins the host controller.
An exception is retained only as a closed stage by CampaignArm, never its text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from scripts.ci.launcher_campaign_identity import InstalledIdentity, unique_pairs
from scripts.native_slo_launcher_campaign import CampaignArm, original_installed_operations

MAX_CONFIGURATION = 512 * 1024
MAX_REPORT = 8 * 1024 * 1024


def configuration(path: Path, expected: str) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_CONFIGURATION:
            raise ValueError("campaign_configuration_file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            body = stream.read(MAX_CONFIGURATION + 1)
    finally:
        os.close(descriptor)
    if len(body) > MAX_CONFIGURATION or hashlib.sha256(body).hexdigest() != expected:
        raise ValueError("campaign_configuration_binding")
    value = json.loads(body, object_pairs_hook=unique_pairs)
    keys = {"schema", "arm", "block", "host_sha256", "host_class_sha256", "wheel", "python", "providers", "contract"}
    if type(value) is not dict or set(value) != keys or value["schema"] != "hol-guard.launcher-worker-input.v1":
        raise ValueError("campaign_configuration_schema")
    for key in ("wheel", "python", "providers"):
        if type(value[key]) is not str or not Path(value[key]).is_absolute():
            raise ValueError("campaign_configuration_path")
    return value


def run(group: Path, inputs: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    subject: InstalledIdentity | None = None
    arm = CampaignArm(
        group=group,
        arm=inputs["arm"],
        block=inputs["block"],
        expected_identity=inputs["contract"]["expected_identity"],
        host_sha256=inputs["host_sha256"],
        host_class_sha256=inputs["host_class_sha256"],
    )

    def bind() -> Any:
        nonlocal subject
        subject = InstalledIdentity(
            wheel=Path(inputs["wheel"]),
            python=Path(inputs["python"]),
            providers=Path(inputs["providers"]),
            contract=inputs["contract"],
        )
        selected = subject

        def runtime() -> Path:
            if selected.runtime is None:
                raise ValueError("campaign_native_identity_not_read")
            return selected.runtime

        return original_installed_operations(selected, runtime)

    passed = False
    try:
        arm.run(bind)
        passed = True
    except BaseException:
        # The first exception has already traversed original forwarding and
        # cleanup. The owned process exits failure; no exception text escapes.
        pass
    return {
        "schema": "hol-guard.launcher-worker-intermediate.v1",
        "passed": passed,
        "arm": arm.report,
        "installed_inventories": [] if subject is None else subject.inventories,
    }, passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", required=True, type=Path)
    parser.add_argument("--configuration", required=True, type=Path)
    parser.add_argument("--configuration-sha256", required=True)
    args = parser.parse_args()
    try:
        inputs = configuration(args.configuration, args.configuration_sha256)
    except BaseException:
        print('{"schema":"hol-guard.launcher-worker-configuration-refused.v1"}')
        return 1
    try:
        report, passed = run(args.group, inputs)
    except BaseException:
        print('{"schema":"hol-guard.launcher-worker-configuration-refused.v1"}')
        return 1
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > MAX_REPORT:
        print('{"schema":"hol-guard.launcher-worker-export-refused.v1"}')
        return 1
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
