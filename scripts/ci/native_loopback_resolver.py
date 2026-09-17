"""Condition disposable macOS runner DNS without modifying either wheel.

This emits resolver diagnostics, not a qualification pass. Failed repair still
allows the actual baseline/candidate execution to produce its decisive result.
Only the fixed IPv4 loopback entry can be added; no discovered names are logged.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_HOSTS_LIMIT = 1024 * 1024
_ALIAS = "hol-guard-qualification.localhost"
_ENTRY = "127.0.0.1 localhost " + _ALIAS
_QUERY = (
    "import json,socket; name=socket.getfqdn('127.0.0.1'); "
    "print(json.dumps({'loopback_label':name in "
    "('127.0.0.1','localhost','hol-guard-qualification.localhost')}))"
)


def hosts_summary(path: Path) -> dict[str, bool]:
    with path.open("rb") as handle:
        data = handle.read(_HOSTS_LIMIT + 1)
    if len(data) > _HOSTS_LIMIT:
        raise ValueError("resolver_hosts_oversized")
    names: set[str] = set()
    for line in data.decode("utf-8").splitlines():
        fields = line.partition("#")[0].split()
        if fields and fields[0] == "127.0.0.1":
            names.update(fields[1:])
    return {"ipv4_localhost_entry": "localhost" in names, "fixed_alias_entry": _ALIAS in names}


def add_fixed_entry(path: Path) -> bool:
    """Append one known loopback alias, retaining existing hosts mappings."""
    before = hosts_summary(path)
    if before["fixed_alias_entry"]:
        return False
    with path.open("ab") as handle:
        handle.write(("\n# HOL Guard disposable qualification runner\n" + _ENTRY + "\n").encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    return True


def resolver_probe() -> dict[str, object]:
    started = time.monotonic()
    result: dict[str, object] = {"status": "failed", "loopback_label": False}
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _QUERY], capture_output=True, text=True, timeout=5, check=False
        )
        if completed.returncode == 0 and len(completed.stdout) <= 128:
            value = json.loads(completed.stdout)
            if isinstance(value, dict) and type(value.get("loopback_label")) is bool:
                result.update(status="completed", loopback_label=value["loopback_label"])
    except subprocess.TimeoutExpired:
        result["status"] = "deadline_exceeded"
    except (OSError, ValueError):
        pass
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def _run_maintenance(arguments: list[str]) -> str:
    try:
        completed = subprocess.run(arguments, capture_output=True, timeout=10, check=False)
        return "completed" if completed.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        return "deadline_exceeded"
    except OSError:
        return "failed"


def diagnose(*, repair: bool) -> dict[str, object]:
    hosts = Path("/etc/hosts")
    report: dict[str, object] = {
        "schema": "hol-guard.native-loopback-resolver.v1",
        "environment_scope": "disposable_ci_runner_both_arms",
        "baseline_artifact_modified": False,
        "runtime_patched": False,
        "repair_attempted": False,
    }
    try:
        report["hosts_before"] = hosts_summary(hosts)
    except (OSError, ValueError):
        report["hosts_read_status"] = "failed"
    before = resolver_probe()
    report["before"] = before
    if repair and sys.platform == "darwin" and before["status"] != "completed":
        report["repair_attempted"] = True
        report["entry_repair"] = _run_maintenance(
            ["sudo", "-n", sys.executable, "-I", str(Path(__file__).resolve()), "--apply-fixed-entry"]
        )
        report["cache_flush"] = _run_maintenance(["sudo", "-n", "/usr/bin/dscacheutil", "-flushcache"])
        report["resolver_refresh"] = _run_maintenance(["sudo", "-n", "/usr/bin/killall", "-HUP", "mDNSResponder"])
    try:
        report["hosts_after"] = hosts_summary(hosts)
    except (OSError, ValueError):
        report["hosts_read_status"] = "failed"
    report["after"] = resolver_probe()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repair-localhost", action="store_true")
    parser.add_argument("--apply-fixed-entry", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.apply_fixed_entry:
        if sys.platform != "darwin":
            return 1
        try:
            add_fixed_entry(Path("/etc/hosts"))
        except (OSError, ValueError):
            return 1
        return 0
    if args.output is None:
        parser.error("--output is required")
    report = diagnose(repair=args.repair_localhost)
    content = json.dumps(report, sort_keys=True, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(content, end="", flush=True)
    return 0  # Diagnostics complete; actual installed execution remains decisive.


if __name__ == "__main__":
    raise SystemExit(main())
