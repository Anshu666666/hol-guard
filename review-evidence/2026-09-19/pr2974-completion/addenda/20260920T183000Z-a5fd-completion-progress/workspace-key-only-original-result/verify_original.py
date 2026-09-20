"""Data-only reconciliation of the single key-rotation diagnostic, without harness imports."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent


def digest(body):
    return hashlib.sha256(body).hexdigest()


def verify():
    archive = ROOT / "artifact.zip"
    body = archive.read_bytes()
    assert len(body) == 8853185
    assert digest(body) == "5aa4ac22661969366239c7659ee3e17d2548aaf7e1173e0cf2ca7a4e7f76fb7a"
    raw = ROOT / "archive"
    members = []
    with zipfile.ZipFile(archive) as opened:
        names = opened.namelist()
        assert len(names) == len(set(names)) == 41
        for name in names:
            assert not name.startswith("/") and ".." not in Path(name).parts
            content = opened.read(name)
            assert (raw / name).read_bytes() == content
            members.append({"path": name, "bytes": len(content), "sha256": digest(content)})
    read = lambda name: json.loads((raw / name).read_bytes())
    summary = read("workspace-lifecycle.json")
    ledger_bytes = (raw / "workspace-lifecycle.jsonl").read_bytes()
    ledger = [json.loads(line) for line in ledger_bytes.splitlines()]
    assert summary["ledger"] == {"bytes": len(ledger_bytes), "records": len(ledger), "sha256": digest(ledger_bytes)}
    assert len(ledger) == 12 and len(summary["cells"]) == 1
    cell = summary["cells"][0]
    assert ledger[0] == {"kind": "lifecycle_cell_offer", "registered_workspaces": 100, "scenario": "key_rotation"}
    parts = ledger[1:]
    assert [part["part"] for part in parts] == list(range(11))
    assert all(part["kind"] == "lifecycle_cell_terminal_part" and part["parts"] == 11 for part in parts)
    terminal = "".join(part["content"] for part in parts).encode()
    assert len(terminal) == cell["evidence"]["bytes"]
    assert digest(terminal) == cell["evidence"]["sha256"]
    assert all(part["result_sha256"] == digest(terminal) for part in parts)
    decoded = json.loads(terminal)
    assert decoded["summary"] == {k: v for k, v in cell.items() if k != "evidence"}
    assert not (decoded["proof"].keys() & decoded["summary"].keys())
    reconstructed = [{**decoded["summary"], **decoded["proof"]}]
    assert reconstructed == read("reconstructed-cells.json")
    assert cell["passed"] and cell["accept_to_ack_ms"] == 330.9404919999963
    assert cell["readiness_deadline_ms"] == 400.0 and cell["publisher_contained"] and cell["writer_drained"]
    controls = read("reader-controls-result.json")
    assert controls["collected"] == controls["executed"] and len(set(controls["collected"])) == 84
    assert controls["passed"] == 84 and controls["skipped"] == 0
    cases = ET.parse(raw / "reader-controls.xml").findall(".//testcase")
    assert len(cases) == 84 and all(len(case) == 0 for case in cases)
    expected = [node.replace("/", ".").replace(".py::", ".", 1) for node in controls["collected"]]
    assert [case.attrib["classname"] + "." + case.attrib["name"] for case in cases] == expected
    assert (raw / "binding-before.json").read_bytes() == (raw / "binding-after.json").read_bytes()
    assert (raw / "installed-before.json").read_bytes() == (raw / "installed-after.json").read_bytes()
    invocation = read("original-invocation.json")
    assert invocation["original_main_calls"] == 1 and invocation["original_main_return"] == 1
    assert invocation["counts"] == [100] and invocation["scenarios"] == ["key_rotation"]
    assert invocation["original_readiness_ms"] == 400
    assert invocation["workload_retries"] == invocation["additional_probes"] == 0
    validation = read("validation-result.json")
    assert validation["passed"] and validation["failure"] is None
    assert validation["original_exit"] == 1 and not validation["original_full_matrix_passed"]
    assert validation["source_driver_installed_preserved"]
    assert all(command["returncode"] == (1 if command["name"] == "original-key-rotation" else 0) for command in validation["commands"])
    admission = read("predicate-admission.json")
    assert admission["diagnostic_complete"] and admission["original_all_selected_passed"]
    report = read("predicates/00.json")
    observation = report["observation"]
    rows = observation["rows"]
    assert report["scenario"] == "key_rotation" and report["original_dispatch_calls"] == 1
    assert report["hooks_restored"] and report["dispatch_patch_restored"]
    assert report["original_result_flags"]["publisher_contained"]
    assert not observation["lost"] and observation["observation_complete"]
    assert not observation["overflow"] and observation["active_calls"] == 0
    assert len(rows) == 143 and [row["id"] for row in rows] == list(range(143))
    assert all(row["site"] != "unknown" for row in rows)
    assert all(row.get(key, "absent") is not None for row in rows for key in ("before", "after"))
    assert observation["await_calls"] == 2
    projected = []
    for path in sorted((ROOT / "projection").rglob("*")):
        if path.is_file() and path.name != "projection-index.json":
            relative = path.relative_to(ROOT / "projection")
            assert path.read_bytes() == (raw / relative).read_bytes()
            projected.append(str(relative))
    assert len(projected) == 33
    return {"schema": "pr2974.key-predicate.original-result.v1", "run_id": 35525001764,
            "job_id": 106115511984, "driver_commit": "680f1c018743d3b51b6b9481f9774a46255fcdd4",
            "source_commit": "e44008445630aad28ccc291ec234f55a14892e6d",
            "archive": {"artifact_id": 10609990369, "bytes": len(body), "sha256": digest(body), "members": members},
            "verified_original_text_members": 40, "log_projected_original_files_equal_archive": len(projected),
            "controls_passed": 84, "controls_skipped": 0, "original_main_calls": 1, "original_exit": 1,
            "cell_passes": 1, "cell_failures": 0, "cells": summary["cells"],
            "observation": {"rows": 143, "unknown_sites": 0, "lost": False, "overflow": False,
                            "active_calls": 0, "null_private_state_samples": 0, "complete": True, "await_calls": 2},
            "complete_ledger_reconstruction": True, "source_driver_installed_before_after_equal": True,
            "diagnostic_admitted": True, "original_readiness_ms": 400, "registered_workspaces": 100,
            "qualification_complete": False,
            "scope": ["Only the original key-rotation cell ran once; lost-metadata-hint was not replayed.",
                      "Original CLI exit one and full 15-cell matrix false remain; this single cell and its additional capture passed.",
                      "Private-state rows denote read intervals, not commit instants; clock origins remain separate.",
                      "Instrumentation overhead is inclusive and preactivation calls remain outside capture.",
                      "This passing successor does not retrospectively explain or admit the prior incomplete failure.",
                      "Exact default wheel build remains be612/ad9d; current source equality does not relabel it.",
                      "No full matrix, cross-platform, performance, or full descendant cleanup qualification."]}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
