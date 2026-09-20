"""Read only the original failed driver's archives and source-control records."""
import hashlib
import io
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).parent
IDS = {"linux-x64": 10615446092, "mac-arm64": 10615306431, "mac-x64": 10615161907}


def verify():
    metadata = json.loads((ROOT / "artifacts.json").read_text())
    jobs = json.loads((ROOT / "jobs.json").read_text())["jobs"]
    output = []
    first_roster = None
    for cell, identifier in IDS.items():
        artifact = next(x for x in metadata["artifacts"] if x["id"] == identifier)
        archive = (ROOT / str(identifier) / "artifact.zip").read_bytes()
        assert len(archive) == artifact["size_in_bytes"]
        assert "sha256:" + hashlib.sha256(archive).hexdigest() == artifact["digest"]
        job = next(x for x in jobs if "(" + cell + "," in x["name"])
        assert job["status"] == "completed" and job["conclusion"] == "failure"
        assert job["head_sha"] == "94d35ef56f6c76e5c8fd75de68ec79dbf5d6f179"
        controls = next(x for x in job["steps"] if x["number"] == 10)
        assert controls["conclusion"] == "failure"
        assert all(next(x for x in job["steps"] if x["number"] == n)["conclusion"] == "skipped" for n in (11, 12, 13))
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            assert set(z.namelist()) == {"before.json", "after.json", "input-contract.json", "source-controls.txt", "source-controls.xml", "wheel-requirements.txt"}
            members = []
            for info in z.infolist():
                body = z.read(info)
                assert body == (ROOT / str(identifier) / "raw" / info.filename).read_bytes()
                members.append({"path": info.filename, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
            before, after = (json.loads(z.read(n)) for n in ("before.json", "after.json"))
            assert before["passed"] is after["passed"] is True
            assert before["binding"] == after["binding"]
            binding = before["binding"]
            assert binding["candidate_source"] == "3d99b884a73568c2278e829fe53a103880fa69da"
            assert binding["product_source"] == "a1d509404b0803a91031cb51f4b0c919408bfeba"
            assert binding["artifact_source"]["build_source"] == "9f511875b236c12e5f23c783e958a536ac0360ba"
            assert binding["cell"] == cell
            rows = ET.fromstring(z.read("source-controls.xml")).findall(".//testcase")
            assert len(rows) == 288 and len({(x.get("classname"), x.get("name")) for x in rows}) == 288
            assert not any(x.find(k) is not None for x in rows for k in ("error", "skipped"))
            failures = [x for x in rows if x.find("failure") is not None]
            assert len(failures) == 32
            assert {x.get("classname") for x in failures} == {"tests.test_managed_aliases_installed_driver"}
            expected = "[Errno 13] Permission denied" if cell == "linux-x64" else "[Errno 30] Read-only file system"
            assert all(expected in x.find("failure").text and "/modeled-population-control" in x.find("failure").text for x in failures)
            roster = [(x.get("classname"), x.get("name"), x.find("failure") is not None) for x in rows]
            if first_roster is None:
                first_roster = roster
            assert roster == first_roster
            output.append({"cell": cell, "job_id": job["id"], "artifact_id": identifier, "archive_bytes": len(archive), "archive_sha256": hashlib.sha256(archive).hexdigest(), "members": members, "collected": 288, "passed": 256, "failed": 32, "errors": 0, "skipped_controls": 0, "installed_calls": 0, "installation_provision_cohort_steps": "skipped", "source_before_after_equal": True, "failure_family": expected, "failed_nodes": [x.get("name") for x in failures], "original_failure": True})
    return {"run_id": 35541914157, "overall": "failure", "cells": output, "equal_ordered_control_rosters": True, "scope": "Actual driver controls failed before installation, provisioning or registered cohort; no product or installed correctness outcome was produced."}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
