"""Prepare the experiment's own interpreter without changing hosted toolchains."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.native_slo_evidence_format import require
from scripts.native_slo_interpreter import prepare_private_interpreter
from scripts.scanner_pilot_identity import MAX_EXECUTABLE_BYTES, executable_digest
from scripts.scanner_pilot_protocol import private_write

_SCHEMA = "hol-guard.scanner-private-interpreter.v1"
# Fixed, isolated, network-free metadata query; both probes use the same venv
# invocation. Raw path values remain only in the encrypted setup record.
_PROBE = (
    "import hashlib,json,sys,sysconfig;from pathlib import Path;"
    "\nwith (Path(sys.prefix)/'pyvenv.cfg').open('rb') as reader:cfg=reader.read(16385)\n"
    "assert len(cfg)<=16384;"
    "print(json.dumps({'executable':sys.executable,'prefix':sys.prefix,"
    "'base_prefix':sys.base_prefix,'version':sys.version,"
    "'stdlib':sysconfig.get_path('stdlib'),'platstdlib':sysconfig.get_path('platstdlib'),"
    "'config_sha256':hashlib.sha256(cfg).hexdigest()}))"
)
_RUNTIME_FIELDS = {"executable", "prefix", "base_prefix", "version", "stdlib", "platstdlib", "config_sha256"}


def _runtime(python: Path) -> dict[str, str]:
    result = subprocess.run([str(python), "-I", "-c", _PROBE], capture_output=True, timeout=10, check=True)
    require(len(result.stdout) <= 65536 and not result.stderr, "scanner_interpreter_probe_invalid")
    value = json.loads(result.stdout)
    require(isinstance(value, dict) and set(value) == _RUNTIME_FIELDS, "scanner_interpreter_probe_invalid")
    require(all(isinstance(item, str) and 0 < len(item) <= 16384 for item in value.values()))
    return value


def prepare(environment: Path, private: Path) -> dict[str, Any]:
    """Copy once after locked dependency installation and before any offers."""
    root = environment.absolute()
    python = root / "bin/python"
    before = _runtime(python)
    require(before["executable"] == str(python) and before["prefix"] == str(root))
    proof = prepare_private_interpreter(python, environment_root=root)
    after = _runtime(python)
    record = {"schema": _SCHEMA, "copy": proof, "runtime_before": before, "runtime_after": after}
    verify_record(record, executable_digest(python))
    private_write(private, "interpreter.json", record)
    return record


def verify_record(value: Any, python_sha256: str | None) -> None:
    """Bind retained copy bytes to the actual measured interpreter identity."""
    require(isinstance(value, dict) and set(value) == {"schema", "copy", "runtime_before", "runtime_after"})
    require(value["schema"] == _SCHEMA)
    proof = value["copy"]
    require(
        isinstance(proof, dict)
        and set(proof)
        == {"schema", "platform", "private_copy", "bytes", "source_sha256", "copy_sha256", "source", "copy"}
        and proof["private_copy"] is True
        and proof["platform"] == "posix"
    )
    require(type(proof["bytes"]) is int and 0 < proof["bytes"] <= MAX_EXECUTABLE_BYTES)
    require(
        proof["copy"]
        == {
            "mode": 0o700,
            "owner": "current_user",
            "group_writable": False,
            "world_writable": False,
            "regular": True,
        }
    )
    require(proof.get("schema") == "hol-guard.qualification-interpreter.v1")
    identity = proof.get("source_sha256")
    require(isinstance(identity, str) and len(identity) == 64 and all(char in "0123456789abcdef" for char in identity))
    require(identity == proof.get("copy_sha256"))
    require(python_sha256 is None or identity == python_sha256)
    runtime = value["runtime_before"]
    require(isinstance(runtime, dict) and set(runtime) == _RUNTIME_FIELDS)
    require(all(isinstance(item, str) and 0 < len(item) <= 16384 for item in runtime.values()))
    require(runtime == value["runtime_after"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--private", default=Path("scanner-evidence/private_samples"), type=Path)
    args = parser.parse_args()
    try:
        prepare(args.environment, args.private)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("scanner_private_interpreter_setup_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
