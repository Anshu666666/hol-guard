"""Read-only verification of the one retained predicate run; no harness imports."""
import hashlib
import json
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent


def digest(body):
    return hashlib.sha256(body).hexdigest()


def verify():
    archive = ROOT / "artifact.zip"
    body = archive.read_bytes()
    assert len(body) == 8863541
    assert digest(body) == "abcd2ce1ad75e1bfe1ca2d7a7eb8dba433013e3719653e29fb8bd6690f118985"
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
    assert len(ledger) == 16
    reconstructed = []
    for offset, cell in zip((0, 8), summary["cells"], strict=True):
        offer, parts = ledger[offset], ledger[offset + 1:offset + 8]
        assert offer == {"kind": "lifecycle_cell_offer", "registered_workspaces": 100, "scenario": cell["scenario"]}
        assert [part["part"] for part in parts] == list(range(7))
        assert all(part["kind"] == "lifecycle_cell_terminal_part" and part["parts"] == 7 for part in parts)
        terminal = "".join(part["content"] for part in parts).encode()
        assert len(terminal) == cell["evidence"]["bytes"]
        assert digest(terminal) == cell["evidence"]["sha256"]
        assert all(part["result_sha256"] == digest(terminal) for part in parts)
        decoded = json.loads(terminal)
        assert decoded["summary"] == {k: v for k, v in cell.items() if k != "evidence"}
        assert not (decoded["proof"].keys() & decoded["summary"].keys())
        reconstructed.append({**decoded["summary"], **decoded["proof"]})
    assert reconstructed == read("reconstructed-cells.json")
    assert [cell["passed"] for cell in reconstructed] == [True, False]
    assert reconstructed[0]["accept_to_ack_ms"] == 239.2303219999974
    assert reconstructed[1]["failure"] and reconstructed[1]["receipt_witness"]["native_receipts"] == 0
    controls = read("reader-controls-result.json")
    assert controls["collected"] == controls["executed"] and len(controls["collected"]) == 58
    assert controls["passed"] == 58 and controls["skipped"] == 0
    cases = ET.parse(raw / "reader-controls.xml").findall(".//testcase")
    assert len(cases) == 58 and all(len(case) == 0 for case in cases)
    assert (raw / "binding-before.json").read_bytes() == (raw / "binding-after.json").read_bytes()
    assert (raw / "installed-before.json").read_bytes() == (raw / "installed-after.json").read_bytes()
    invocation = read("original-invocation.json")
    assert invocation["original_main_calls"] == 1 and invocation["original_main_return"] == 1
    assert invocation["counts"] == [100] and invocation["original_readiness_ms"] == 400
    assert invocation["workload_retries"] == invocation["additional_probes"] == 0
    validation = read("validation-result.json")
    assert validation["passed"] is False and validation["failure"]["stage"] == "admit-original"
    assert validation["original_full_matrix_passed"] is False and validation["source_driver_installed_preserved"] is True
    assert "ValueError: observation_incomplete" in (raw / "commands/admit-original.stderr").read_text()
    observations = []
    for index, cell in enumerate(reconstructed):
        report = read(f"predicates/{index:02d}.json")
        observation = report["observation"]
        rows = observation["rows"]
        assert report["scenario"] == cell["scenario"] and report["original_dispatch_calls"] == 1
        assert report["hooks_restored"] and report["dispatch_patch_restored"]
        assert report["original_result_flags"]["publisher_contained"]
        assert observation["lost"] and not observation["observation_complete"]
        assert not observation["overflow"] and observation["active_calls"] == 0
        assert all(row.get(key, "absent") is not None for row in rows for key in ("before", "after"))
        unknown = [{"id": row["id"], "stage": row["stage"]} for row in rows if row["site"] == "unknown"]
        observations.append({"scenario": cell["scenario"], "rows": len(rows), "unknown_sites": unknown,
                             "lost": True, "overflow": False, "active_calls": 0,
                             "null_private_state_samples": 0, "observation_complete": False})
    assert [x["rows"] for x in observations] == [221, 115]
    assert [x["unknown_sites"] for x in observations] == [[{"id": 201, "stage": "prepare"}],
        [{"id": 8, "stage": "compiled_policy"}, {"id": 25, "stage": "compiled_policy"},
         {"id": 40, "stage": "prepare"}, {"id": 71, "stage": "last_error"}]]
    projected = []
    for path in sorted((ROOT / "raw").rglob("*")):
        if path.is_file() and path.name != "projection-index.json":
            relative = path.relative_to(ROOT / "raw")
            assert path.read_bytes() == (raw / relative).read_bytes()
            projected.append(str(relative))
    assert len(projected) == 33
    return {"schema": "hol-guard.workspace-predicate-original-result.v1", "run_id": 35522495563,
            "job_id": 106108875358, "driver_commit": "cfa843cc6d42e2c8cb0baca4443e014bc13f964d",
            "source_commit": "e44008445630aad28ccc291ec234f55a14892e6d",
            "archive": {"artifact_id": 10608282357, "bytes": len(body), "sha256": digest(body), "members": members},
            "verified_original_text_members": 40, "log_projected_original_files_equal_archive": len(projected),
            "controls_passed": 58, "controls_skipped": 0, "original_main_calls": 1, "original_exit": 1,
            "cell_passes": 1, "cell_failures": 1, "cells": summary["cells"], "observations": observations,
            "complete_ledger_reconstruction": True, "source_driver_installed_before_after_equal": True,
            "diagnostic_admitted": False, "admission_failure": "observation_incomplete",
            "original_readiness_ms": 400, "registered_workspaces": 100, "qualification_complete": False,
            "scope": ["Original one-pass two-cell outcomes retained despite incomplete additional capture.",
                      "No replay or retrospective admission of unknown-site rows.",
                      "Private state rows denote read intervals, not commit instants; clock origins stay separate.",
                      "Instrumentation overhead is inclusive; calls entered before activation are outside capture.",
                      "Lost-metadata-hint success does not explain its earlier failure; no cause-specific repair inferred.",
                      "Retained default wheel build remains be612/ad9d, with exact product equality to current e440.",
                      "No full 15-cell, cross-platform, performance, or full descendant cleanup qualification."]}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
