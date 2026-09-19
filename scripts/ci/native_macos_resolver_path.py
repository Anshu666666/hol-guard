"""Source-bound read-only macOS resolver-path diagnostic; never qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.native_macos_resolver_capture import clean_completion, run_lookup
from scripts.ci.native_macos_resolver_evidence import MODES, parse_metadata
from scripts.ci.native_macos_service_identity import _capture

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "scripts/ci/native_macos_resolver_probe.c",
    "scripts/ci/native_macos_resolver_path.py",
    "scripts/ci/native_macos_resolver_capture.py",
    "scripts/ci/native_macos_resolver_evidence.py",
    "scripts/ci/native_macos_service_identity.py",
    "tests/test_native_macos_resolver_capture.py",
    "tests/test_native_macos_resolver_evidence.py",
    "tests/test_native_macos_resolver_path.py",
    ".github/workflows/native-macos-resolver-path.yml",
)
COMPILE_FLAGS = ("-std=c11", "-O0", "-Wall", "-Wextra", "-Werror")
PYTHON_CONTROL = """
import json, os, socket
print(json.dumps({'kind':'identity', 'mode':'python_fqdn', 'pid':os.getpid()}), flush=True)
try:
    name = socket.getfqdn('127.0.0.1')
    result = {'kind':'result', 'error':0, 'loopback_label':name in (
        '127.0.0.1', 'localhost', 'hol-guard-qualification.localhost')}
except (OSError, UnicodeError) as error:
    result = {'kind':'result', 'error':getattr(error, 'errno', None) or 1, 'loopback_label':False}
print(json.dumps(result), flush=True)
"""


def _sha(path: Path, maximum: int = 256 * 1024 * 1024) -> str:
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= maximum:
            raise ValueError("identity size invalid")
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(min(1024 * 1024, maximum + 1 - size)):
            size += len(chunk)
            if size > maximum:
                raise ValueError("identity grew past limit")
            digest.update(chunk)
        after = os.fstat(stream.fileno())

        def fields(value: os.stat_result) -> tuple[int, ...]:
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

        if size != before.st_size or fields(before) != fields(after) or fields(after) != fields(path.stat()):
            raise ValueError("identity changed")
    return digest.hexdigest()


def source_identity() -> dict[str, Any]:
    expected = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", expected) is None:
        raise ValueError("workflow source unavailable")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=5, text=True).strip()
    if head != expected:
        raise ValueError("workflow source mismatch")
    digests = {}
    for name in SOURCES:
        digest = _sha(ROOT / name)
        committed = subprocess.check_output(["git", "show", head + ":" + name], cwd=ROOT, timeout=5)
        if digest != hashlib.sha256(committed).hexdigest():
            raise ValueError("source bytes changed")
        digests[name] = digest
    return {"head": head, "sha256": digests}


class IdentityCommandError(ValueError):
    def __init__(self, operation: str, capture: dict[str, Any]):
        super().__init__("fixed identity command failed")
        self.metadata = {
            "operation": operation,
            **{key: value for key, value in capture.items() if key not in {"stdout", "stderr", "argv"}},
        }


def _fixed(arguments: tuple[str, ...]) -> str:
    report = _capture(arguments)
    if report["status"] != "completed" or report["return_code"] != 0 or report["stderr_bytes"]:
        raise IdentityCommandError(arguments[-1], report)
    return report["stdout"].strip()


def tool_identity() -> dict[str, Any]:
    compiler = Path(_fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"))).resolve(strict=True)
    sdk = Path(_fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"))).resolve(strict=True)
    version = _fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"))
    build = _fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version"))
    compiler_version = _fixed((str(compiler), "--version")).splitlines()[0]
    if (
        re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version) is None
        or re.fullmatch(r"[0-9A-Za-z.]{1,32}", build) is None
        or re.fullmatch(r"Apple clang version [0-9A-Za-z.+() _-]{1,160}", compiler_version) is None
    ):
        raise ValueError("identity format unsupported")
    import _socket

    return {
        "compiler_version": compiler_version,
        "compiler_sha256": _sha(compiler),
        "xcrun_sha256": _sha(Path("/usr/bin/xcrun")),
        "sdk_version": version,
        "sdk_build": build,
        "sdk_settings_sha256": _sha(sdk / "SDKSettings.json"),
        "sdk_headers_sha256": {
            name: _sha(sdk / "usr/include" / name) for name in ("dns_sd.h", "netdb.h", "mach-o/loader.h")
        },
        "os_version": platform.mac_ver()[0],
        "os_build": _fixed(("/usr/bin/sw_vers", "-buildVersion")),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "python_sha256": _sha(Path(sys.executable)),
        "python_socket_module_sha256": _sha(Path(_socket.__file__)),
        "compile_flags": list(COMPILE_FLAGS),
        "link_library": "dns_sd",
    }


def _base() -> dict[str, Any]:
    return {
        "schema": "hol-guard.macos-resolver-path.v1",
        "scope": "read_only_no_fork_lookup_controls",
        "qualification_pass": False,
        "installed_baseline_startup_verified": False,
        "libinfo_binary_source_equivalence_claimed": False,
        "private_libinfo_attributes_reproduced": False,
        "service_intervention_attempted": False,
        "configuration_modified": False,
        "private_ptr_resolver_installed": False,
        "descendant_retirement_verified": False,
        "diagnostic_passed": False,
        "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "design_source": "apple-oss-distributions/Libinfo@39b70c515baee5b609e7e91693edbd934b6845a1",
    }


def _eligible() -> bool:
    return (
        sys.platform == "darwin"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "macOS"
        and os.environ.get("GITHUB_RUN_ID", "").isdigit()
    )


def prepare() -> dict[str, Any]:
    report: dict[str, Any] = _base() | {"status": "unavailable", "stage": "platform"}
    if not _eligible():
        return report
    try:
        report["stage"] = "source_binding"
        report["source"] = source_identity()
        report["stage"] = "tool_identity"
        report["tools"] = tool_identity()
        report.update(status="prepared", stage="complete")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="identity_failed", error_type=type(error).__name__)
        if isinstance(error, IdentityCommandError):
            report["identity_command_failure"] = error.metadata
    return report


def collect(prepared: dict[str, Any], binary: Path, save: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    report: dict[str, Any] = _base() | {"status": "unavailable", "stage": "platform", "rows": []}
    if (
        not _eligible()
        or prepared.get("status") != "prepared"
        or any(prepared.get(key) != report[key] for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
    ):
        return report
    try:
        report["stage"] = "source_and_tool_binding"
        report["source_before"] = source_identity()
        report["tools_before"] = tool_identity()
        if report["source_before"] != prepared["source"] or report["tools_before"] != prepared["tools"]:
            raise ValueError("build inputs changed")
        report["binary_sha256"] = _sha(binary)
        report["stage"] = "lookup_controls"
        save(report)
        for mode in MODES:
            arguments = (sys.executable, "-I", "-c", PYTHON_CONTROL) if mode == "python_fqdn" else (str(binary), mode)
            capture, data = run_lookup(arguments)
            metadata = parse_metadata(data, mode, capture["pid"])
            report["rows"].append(
                {
                    "mode": mode,
                    "capture": capture,
                    "metadata": metadata,
                    "lookup_passed": clean_completion(capture) and metadata["complete"] and metadata["loopback_label"],
                }
            )
            save(report)
            if capture["pid"] is not None and not capture["direct_child_reaped"]:
                report["status"] = "direct_child_cleanup_unproved"
                return report
        report["stage"] = "final_binding"
        report["source_unchanged"] = source_identity() == report["source_before"]
        report["tools_unchanged"] = tool_identity() == report["tools_before"]
        report["binary_unchanged"] = _sha(binary) == report["binary_sha256"]
        identities = [row["metadata"]["records"][0] for row in report["rows"][:4] if row["metadata"]["valid"]]
        report["loaded_images_consistent"] = len(identities) == 4 and all(
            all(item[key] == identities[0][key] for key in ("libinfo_uuid", "dnssd_uuid", "cpu_type", "cpu_subtype"))
            for item in identities
        )
        report["diagnostic_passed"] = (
            report["source_unchanged"]
            and report["tools_unchanged"]
            and report["binary_unchanged"]
            and report["loaded_images_consistent"]
            and all(row["lookup_passed"] for row in report["rows"])
        )
        report.update(status="experiment_finished", stage="complete")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="diagnostic_failed", error_type=type(error).__name__)
        if isinstance(error, IdentityCommandError):
            report["identity_command_failure"] = error.metadata
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save(report: dict[str, Any]) -> None:
        pending = args.output.with_suffix(".pending")
        pending.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)

    if args.prepare:
        report = prepare()
    else:
        if args.prepared is None or args.binary is None:
            parser.error("--prepared and --binary are required for collection")
        report = collect(json.loads(args.prepared.read_text()), args.binary.resolve(strict=True), save)
    save(report)
    return 0 if (report["status"] == "prepared" if args.prepare else report["diagnostic_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
