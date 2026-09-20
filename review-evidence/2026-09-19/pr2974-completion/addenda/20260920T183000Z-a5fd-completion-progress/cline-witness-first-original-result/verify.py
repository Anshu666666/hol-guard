"""Data-only verification of original Cline diagnostic artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).parent
SOURCE = ROOT.parent / "cline-witness-e440"
SOURCE_SHA = "95744afcf6e58681360f0709e13f2c387aba55f9"
DRIVER_SHA = "739e85d959e7dbf0689cec7351613b8e51d4dedd"


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def read(folder: Path, name: str) -> dict:
    return json.loads((folder / "raw" / name).read_bytes())


def verify(folder: Path) -> dict:
    metadata = json.loads((folder / "metadata.json").read_bytes())
    archive = (folder / "artifact.zip").read_bytes()
    assert len(archive) == metadata["size_in_bytes"]
    assert "sha256:" + digest(archive) == metadata["digest"]
    members = []
    with zipfile.ZipFile(folder / "artifact.zip") as zipped:
        assert len(zipped.namelist()) == len(set(zipped.namelist()))
        for name in zipped.namelist():
            original = zipped.read(name)
            assert original == (folder / "raw" / name).read_bytes()
            members.append({"path": name, "bytes": len(original), "sha256": digest(original)})
    before, after = read(folder, "before.json"), read(folder, "after.json")
    assert before["passed"] is True and after["passed"] is True
    assert before["binding"] == after["binding"]
    binding = before["binding"]
    assert binding["candidate_source"] == SOURCE_SHA
    assert binding["driver_source"] == DRIVER_SHA
    for name, identity in binding["candidate_files"].items():
        body = (SOURCE / name).read_bytes()
        assert identity == {"bytes": len(body), "sha256": digest(body)}
    cases = list(ET.parse(folder / "raw" / "source-controls.xml").iter("testcase"))
    identities = [(case.get("classname"), case.get("name")) for case in cases]
    assert len(identities) == len(set(identities)) == 101
    assert not any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped"))
    types = read(folder, "types.json")["summary"]
    assert types["errorCount"] == 0
    provision, run = read(folder, "provision.json"), read(folder, "run.json")
    assert provision["passed"] is True
    assert provision["installed_before"] == provision["installed_after"]
    assert run["installed_before"] == run["installed_after"]
    assert run["installation_unchanged"] is True and run["passed"] is False
    assert provision["installed_after"] == run["installed_before"]
    result = read(folder, "cline-witness/result.json")
    terminal = read(folder, "cline-witness-terminal.json")
    assert len(result["attempts"]) == 1 and result["passed"] is False
    attempt = result["attempts"][0]
    assert attempt["case_id"] == "cline/PreToolUse/benign/small"
    assert attempt["original_delivery"] == {"exit_checked": True, "stdout_checked": True}
    assert attempt["original_setup_validated"] is True
    child, worker = read(folder, "cline-witness/case-0/child.json"), read(folder, "cline-witness/case-0/worker.json")
    assert child == attempt["child"] and worker == attempt["worker"]
    assert child["parent_pid"] == worker["pid"]
    assert child["configuration_sha256"] == worker["configuration_sha256"] == attempt["observer_installation"]["configuration_sha256"]
    assert child["isolated"] is True and child["no_user_site"] is True
    assert worker["isolated"] is True and worker["no_user_site"] is True
    assert child["faults"] == ["callback_limit"]
    assert child["callbacks"] == 2_000_001 and set(child["counts"].values()) == {0}
    assert child["profile_restored"] is True and child["open_frames"] == 0
    assert child["observation_complete"] is False and child["validation_fault"] is True
    assert attempt["cleanup_faults"] == [] and attempt["owned_sidecars_retained"] is False
    assert terminal["return_code"] == 1 and terminal["returned"] is True
    assert terminal["timed_out"] is False and terminal["containment_failed"] is False
    assert terminal["output_limit_exceeded"] is False
    for name, descriptor in (("cline-witness/result.json", terminal["report"]), ("cline-witness.stdout", terminal["stdout"]), ("cline-witness.stderr", terminal["stderr"])):
        body = (folder / "raw" / name).read_bytes()
        assert descriptor == {"bytes": len(body), "sha256": digest(body)}
    return {
        "cell": binding["cell"], "artifact_id": metadata["id"],
        "archive_bytes": len(archive), "archive_sha256": digest(archive), "members": members,
        "source_and_installed_bindings_unchanged": True, "eight_source_members_rehashed": True,
        "controls": {"passed": 101, "failed": 0, "skipped": 0}, "types": types,
        "original_cases_offered": 1, "original_cases_declared": 4,
        "first_original_delivery_and_setup_validated": True,
        "observer": child, "worker": worker, "invocation_preflight": result["invocation_preflight"],
        "original_selected_edge_observed": False, "native_route_proved": False,
        "profile_and_owned_sidecars_cleaned": True, "outer_timeout_or_containment_failure": False,
        "original_failure_preserved": True, "performance_qualified": False,
    }


if __name__ == "__main__":
    rows = [verify(path) for path in sorted(ROOT.iterdir()) if (path / "artifact.zip").is_file()]
    report = {
        "schema": "pr2974.cline-child-witness-result.v1", "run_id": 35525771987,
        "source": SOURCE_SHA, "driver": DRIVER_SHA, "cells": rows,
        "finding": "Global profile callback cap consumed before the selected child edge; original route remains unproved.",
        "limits": ["Diagnostic failure, not a proven product route failure.", "Original first-case stdout/exit and setup pass separately from missing native oracle evidence.", "No replay or budget change was performed by this data-only reader.", "Prior alias failures remain failed and are not reclassified."]}
    (ROOT / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cells": [{"cell": r["cell"], "artifact_id": r["artifact_id"], "controls": r["controls"], "callbacks": r["observer"]["callbacks"]} for r in rows]}))
