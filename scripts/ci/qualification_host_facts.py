"""Bounded read-only Linux runner facts before any installed campaign offer.

This is factual preparation, not a matching-class admission decision. Missing
or unexposed required facts are explicit and cannot authorize measurement.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

_TEXT = re.compile(r"[A-Za-z0-9 ._()+@:/=-]{1,160}\Z")


def _read(path: Path, limit: int) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("host_fact_file")
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError("host_fact_bound")
    return body.decode("ascii")


def _text(value: Any) -> str:
    if type(value) is not str or not _TEXT.fullmatch(value):
        raise ValueError("host_fact_text")
    return value


def _cpu(proc: Path, affinity: set[int]) -> dict[str, Any]:
    blocks = _read(proc / "cpuinfo", 1024 * 1024).strip().split("\n\n")
    selected = []
    seen = set()
    for block in blocks:
        values = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = [p.strip() for p in line.split(":", 1)]
            if key in {"processor", "vendor_id", "cpu family", "model", "model name", "stepping"}:
                if key in values:
                    raise ValueError("host_fact_duplicate_cpu_key")
                values[key] = value
        processor = values.get("processor", "")
        if processor.isdecimal() and int(processor) in affinity:
            if int(processor) in seen:
                raise ValueError("host_fact_duplicate_cpu_identity")
            seen.add(int(processor))
            selected.append(
                {key: _text(values[key]) for key in ("vendor_id", "cpu family", "model", "model name", "stepping")}
            )
    if seen != affinity or not selected or any(x != selected[0] for x in selected):
        raise ValueError("host_fact_cpu_class_ambiguous")
    online = os.cpu_count()
    if type(online) is not int or not len(affinity) <= online <= 4096:
        raise ValueError("host_fact_online_count")
    return {"model": selected[0], "eligible_logical_cpus": len(affinity), "online_logical_cpus": online}


def _memory(proc: Path) -> dict[str, int]:
    rows = {}
    for line in _read(proc / "meminfo", 64 * 1024).splitlines():
        key, *rest = line.split()
        if key in {"MemTotal:", "MemAvailable:"}:
            if key in rows or len(rest) != 2 or not rest[0].isdecimal() or rest[1] != "kB":
                raise ValueError("host_fact_memory")
            rows[key] = int(rest[0]) * 1024
    total, available = rows["MemTotal:"], rows["MemAvailable:"]
    if not 0 < available <= total <= 2**63 - 1:
        raise ValueError("host_fact_memory_range")
    return {
        "total_bytes": total,
        "available_bytes": available,
        "ram_class_gib_rounded_up": (total + 2**30 - 1) // 2**30,
    }


def _governors(sysfs: Path, affinity: set[int]) -> dict[str, Any]:
    values = []
    absent = 0
    for cpu in sorted(affinity):
        try:
            value = _read(sysfs / f"devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor", 256).strip()
        except FileNotFoundError:
            absent += 1
        else:
            values.append(_text(value))
    if absent:
        return {
            "available": False,
            "state": "unexposed" if absent == len(affinity) else "partial",
            "visible_count": len(values),
        }
    return {"available": True, "state": "observed", "values": sorted(set(values)), "visible_count": len(values)}


def _os_release(path: Path) -> dict[str, str]:
    values = {}
    # The fixed system metadata path may be the conventional /etc symlink.
    # Resolve that declared path; the actual final open remains no-follow.
    for line in _read(path.resolve(strict=True), 16 * 1024).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"ID", "VERSION_ID"}:
            tokens = shlex.split(value)
            if key in values or len(tokens) != 1:
                raise ValueError("host_fact_os_release")
            values[key] = _text(tokens[0])
    if set(values) != {"ID", "VERSION_ID"}:
        raise ValueError("host_fact_os_missing")
    return values


def capture(
    *, proc: Path = Path("/proc"), sysfs: Path = Path("/sys"), os_release: Path = Path("/etc/os-release")
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.pre-campaign-host-facts.v1",
        "facts": {},
        "unavailable": {},
        "campaign_admission": False,
    }
    facts, failures = report["facts"], report["unavailable"]
    try:
        affinity = set(os.sched_getaffinity(0))
        if not affinity or len(affinity) > 4096 or any(type(x) is not int or not 0 <= x < 4096 for x in affinity):
            raise ValueError("host_fact_affinity")
    except (AttributeError, OSError, ValueError):
        failures["affinity"] = "unavailable"
        affinity = set()
    operations = {
        "cpu": lambda: _cpu(proc, affinity),
        "memory": lambda: _memory(proc),
        "governors": lambda: _governors(sysfs, affinity) if affinity else {"available": False, "state": "unavailable"},
        "os_release": lambda: _os_release(os_release),
        "kernel": lambda: {
            "system": _text(platform.system()),
            "release": _text(platform.release()),
            "machine": _text(platform.machine()),
        },
        "runner_image": lambda: {
            label: _text(os.environ[name])
            for label, name in (
                ("image_os", "ImageOS"),
                ("image_version", "ImageVersion"),
                ("environment", "RUNNER_ENVIRONMENT"),
            )
        },
    }
    for name, operation in operations.items():
        try:
            facts[name] = operation()
        except (OSError, ValueError, KeyError, UnicodeError):
            failures[name] = "unavailable"
    try:
        target = Path(sys.executable).resolve(strict=True)
        metadata = target.stat()
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 128 * 1024 * 1024:
            raise ValueError("host_fact_interpreter")
        digest = hashlib.sha256()
        total = 0
        with target.open("rb") as stream:
            for body in iter(lambda: stream.read(65_536), b""):
                total += len(body)
                if total > metadata.st_size:
                    raise ValueError("host_fact_interpreter_growth")
                digest.update(body)
        after = target.stat()
        if total != metadata.st_size or any(
            getattr(metadata, k) != getattr(after, k)
            for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise ValueError("host_fact_interpreter_changed")
        facts["interpreter"] = {
            "bytes": metadata.st_size,
            "sha256": digest.hexdigest(),
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        }
    except (OSError, ValueError):
        failures["interpreter"] = "unavailable"
    # No hostname, serial, MAC, private path, process identifier or raw
    # environment values beyond the fixed public image keys are exported.
    report["all_declared_facts_available"] = not failures and facts.get("governors", {}).get("available") is True
    return report


if __name__ == "__main__":
    print(json.dumps(capture(), sort_keys=True, separators=(",", ":")))
