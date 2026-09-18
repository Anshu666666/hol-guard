"""Run an additional fixed-artifact Ollama diagnostic without replacing prior evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.ci.record_native_qualification_checkouts import CANDIDATE_SHA, CANDIDATE_TREE, inspect  # noqa: E402


def select_artifacts(candidate: Path, evidence_dir: Path) -> tuple[Path, Path]:
    binding = inspect(candidate, CANDIDATE_SHA, CANDIDATE_TREE)
    if binding["matches_expected"] is not True:
        raise ValueError("diagnostic_candidate_binding_rejected")
    metadata = json.loads((evidence_dir / "build-metadata.json").read_text(encoding="utf-8"))
    if metadata["candidate"]["source_sha"] != CANDIDATE_SHA:
        raise ValueError("diagnostic_candidate_build_rejected")
    python = candidate / ".venv/Scripts/python.exe"
    wheels = tuple((candidate / "qualification-native").glob("*.whl"))
    if not python.is_file() or len(wheels) != 1 or wheels[0].is_symlink():
        raise ValueError("diagnostic_exact_built_artifact_unavailable")
    # The original installed probe remains an independent retained failure.
    original_path = evidence_dir / "aggregate/installed-ollama.json"
    if original_path.exists():
        original = json.loads(original_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
        if original["identity"]["build_sha"] != CANDIDATE_SHA or original["identity"]["wheel_sha256"] != digest:
            raise ValueError("diagnostic_original_artifact_identity_rejected")
    return python, wheels[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    destination = args.evidence_dir / "aggregate/installed-ollama-open-cause-diagnostic.json"
    probe_output = destination.with_name("installed-ollama-open-cause-probe.json")
    if destination.exists() or probe_output.exists():
        raise ValueError("diagnostic_output_already_exists")
    # Always leave a separate outcome, including when the original build failed.
    result: dict[str, object] = {
        "schema": "hol-guard.installed-ollama-cause-diagnostic.v1",
        "passed": False,
        "qualification": False,
        "headline_timing_eligible": False,
    }
    try:
        python, wheel = select_artifacts(args.candidate.resolve(), args.evidence_dir.resolve())
        wheel_before = hashlib.sha256(wheel.read_bytes()).hexdigest()
        original_path = args.evidence_dir / "aggregate/installed-ollama.json"
        original_before = hashlib.sha256(original_path.read_bytes()).hexdigest() if original_path.exists() else None
        # This setup-Python parent never imports the runtime package. The
        # original verifier retains its existing isolated child owners/gates.
        completed = subprocess.run(
            [
                str(python),
                str(_ROOT / "scripts/ci/verify_native_ollama_install.py"),
                "--python",
                str(python),
                "--wheel",
                str(wheel),
                "--source-root",
                str(args.candidate.resolve()),
                "--source-sha",
                CANDIDATE_SHA,
                "--output",
                str(probe_output.resolve()),
            ],
            check=False,
        )
        probe = json.loads(probe_output.read_text(encoding="utf-8"))
        original_after = hashlib.sha256(original_path.read_bytes()).hexdigest() if original_path.exists() else None
        unchanged = original_before == original_after and hashlib.sha256(wheel.read_bytes()).hexdigest() == wheel_before
        result.update(
            probe=probe,
            verifier_return_code=completed.returncode,
            original_probe_sha256=original_before,
            wheel_sha256=wheel_before,
            original_probe_and_wheel_unchanged=unchanged,
            passed=completed.returncode == 0 and probe.get("passed") is True and unchanged,
        )
    except (OSError, ValueError, KeyError, TypeError):
        result["reason"] = "diagnostic_exact_installed_artifact_unavailable"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
