"""Data-only readback of the distinct remaining-route installed run."""
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
ORDER = ["priority-approval", "registered-aliases", "pi-sources", "ollama"]


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def verify(metadata):
    artifact_id = metadata["id"]
    directory = ROOT / str(artifact_id)
    raw = directory / "raw"
    archive = (directory / "artifact.zip").read_bytes()
    assert identity(archive) == {"bytes": metadata["size_in_bytes"], "sha256": metadata["digest"].removeprefix("sha256:")}
    members = {}
    with zipfile.ZipFile(directory / "artifact.zip") as zipped:
        infos = zipped.infolist()
        assert len(infos) == len({row.filename for row in infos}) < 100
        for member in infos:
            body = zipped.read(member)
            assert body == (raw / member.filename).read_bytes()
            members[member.filename] = identity(body)
    result = json.loads((raw / "run.json").read_bytes())
    binding = result["binding"]
    assert binding["driver_source"] == "3ca2d94fae01bad98299508d14d5fcd96d69c471"
    assert binding["driver_tree"] == "083adb856fe6d9e9f24779ef105ae1635ffbab61"
    assert binding["candidate_source"] == "d9eb624ddca258db53dc42583d1c8654825cb55b"
    assert binding["candidate_tree"] == "b463e98c0705363b56ce435578840a1dfa179f42"
    assert binding["product_source"] == "f8f190a286159b46bf14a624a62ba52b5d2371a3"
    assert binding["artifact_source"]["build_source"] == "be612a3e562a2041b3732a33c158eeae4f1dad40"
    for name in ("before", "provision", "after"):
        value = json.loads((raw / (name + ".json")).read_bytes())
        assert value["passed"] is True and value["binding"] == binding
    assert result["installation_unchanged"] is True
    assert result["installed_before"] == result["installed_after"]
    labels = [stage["label"] for stage in result["stages"]]
    assert labels == ORDER[:len(labels)] and len(labels) > 0
    assert not (raw / "priority-controls-offered.json").exists()
    assert not any((raw / (label + "-offered.json")).exists() for label in ORDER[len(labels):])
    cohorts = {}
    for stage in result["stages"]:
        label = stage["label"]
        assert stage["report"] == members[label + ".json"]
        for stream in ("stdout", "stderr"):
            assert stage[stream] == members[label + "." + stream]
        assert stage == json.loads((raw / (label + "-terminal.json")).read_bytes())
        report = json.loads((raw / (label + ".json")).read_bytes())
        cohort = {"passed": report["passed"], "stage": stage, "failure": report.get("failure"), "result": report.get("result")}
        if "case_ledger_sha256" in report:
            body = (raw / (label + ".jsonl")).read_bytes()
            assert identity(body) == {"bytes": report["case_ledger_bytes"], "sha256": report["case_ledger_sha256"]}
            ledger = [json.loads(line) for line in body.splitlines()]
            cohort.update(
                offered_rows=sum(row.get("status") == "offered" for row in ledger),
                validated_rows=sum(row.get("status") == "validated" for row in ledger),
                failed_rows=sum(row.get("status") == "failed" for row in ledger),
                ledger=ledger,
            )
        cohorts[label] = cohort
    assert all(stage["passed"] for stage in result["stages"][:-1])
    cases = list(ET.parse(raw / "source-controls.xml").iter("testcase"))
    assert len(cases) == 121 and not any(row.find(k) is not None for row in cases for k in ("failure", "error", "skipped"))
    return {
        "artifact_id": artifact_id, "archive": identity(archive), "members": members,
        "cell": binding["cell"], "passed": result["passed"], "source_controls_passed": len(cases),
        "installation_unchanged": True, "cohorts": cohorts, "unoffered_cohorts": ORDER[len(labels):],
        "completed_62_cohort_repeated": False,
        "scope": "Original byte-bound report readback only; no test, application import or native workload rerun.",
    }


if __name__ == "__main__":
    metadata = json.loads((ROOT / "artifact-metadata.json").read_bytes())
    result = [verify(item) for item in metadata["artifacts"]]
    (ROOT / "verified-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    for row in result:
        print(json.dumps({key: value for key, value in row.items() if key not in {"members", "cohorts"}}))
