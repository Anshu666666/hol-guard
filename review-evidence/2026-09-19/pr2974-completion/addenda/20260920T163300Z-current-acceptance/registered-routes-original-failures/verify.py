"""Data-only verification of retained RSP136 original reports."""
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
ARCHIVES = {
    10607987701: (33001, "138e8b7694bbc4293ab3580b952c4b7768dc9b1e875a54c37b750da3bd593f7f"),
    10607728301: (33446, "07109921b84140906fa499aa62e03f8831b57388a4c1496c42060bb9e0602894"),
    10607963145: (33442, "0e9c5ff5e7a4844898444777eb3497bea293482ff12d9c3a44e8b1f7a6697fd4"),
}


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def verify(artifact_id, expected):
    directory = ROOT / str(artifact_id)
    raw = directory / "raw"
    archive = (directory / "artifact.zip").read_bytes()
    assert (len(archive), hashlib.sha256(archive).hexdigest()) == expected
    members = {}
    with zipfile.ZipFile(directory / "artifact.zip") as zipped:
        infos = zipped.infolist()
        assert len(infos) == len({row.filename for row in infos})
        for member in infos:
            body = zipped.read(member)
            assert body == (raw / member.filename).read_bytes()
            members[member.filename] = identity(body)
    result = json.loads((raw / "run.json").read_bytes())
    assert result["binding"]["driver_source"] == "e690a2ecf8fe6cb60905e76684b0daecddb778e8"
    assert result["binding"]["candidate_source"] == "af2a317203ca103a0b202c88dddf88c91aa850a7"
    assert result["binding"]["product_source"] == "f8f190a286159b46bf14a624a62ba52b5d2371a3"
    assert result["binding"]["artifact_source"]["build_source"] == "be612a3e562a2041b3732a33c158eeae4f1dad40"
    assert result["installation_unchanged"] is True
    assert result["installed_before"] == result["installed_after"]
    assert [stage["label"] for stage in result["stages"]] == ["priority-controls", "priority-approval"]
    assert not any((raw / (label + "-offered.json")).exists() for label in ("registered-aliases", "pi-sources", "ollama"))
    for stage in result["stages"]:
        label = stage["label"]
        assert stage["report"] == members[label + ".json"]
        for stream in ("stdout", "stderr"):
            assert stage[stream] == members[label + "." + stream]
        assert stage == json.loads((raw / (label + "-terminal.json")).read_bytes())
        assert not any(stage[key] for key in ("timed_out", "containment_failed", "output_limit_exceeded"))
    rows = list(ET.parse(raw / "source-controls.xml").iter("testcase"))
    assert len(rows) == 88 and not any(row.find(k) is not None for row in rows for k in ("failure", "error", "skipped"))
    cohorts = {}
    for name in ("priority-controls", "priority-approval"):
        report = json.loads((raw / (name + ".json")).read_bytes())
        body = (raw / (name + ".jsonl")).read_bytes()
        assert identity(body) == {"bytes": report["case_ledger_bytes"], "sha256": report["case_ledger_sha256"]}
        ledger = [json.loads(line) for line in body.splitlines()]
        cohorts[name] = {
            "passed": report["passed"],
            "offered_rows": sum(row.get("status") == "offered" for row in ledger),
            "validated_rows": sum(row.get("status") == "validated" for row in ledger),
            "failed_rows": sum(row.get("status") == "failed" for row in ledger),
            "failure": report.get("failure"),
            "result": report.get("result"),
        }
    return {
        "artifact_id": artifact_id,
        "archive": identity(archive),
        "members": members,
        "cell": result["binding"]["cell"],
        "passed": result["passed"],
        "source_controls_passed": 88,
        "installation_unchanged": True,
        "cohorts": cohorts,
        "later_cohorts_offered": False,
        "scope": "Original data-only readback; no rerun, source tests, native calls or altered verdicts.",
    }


if __name__ == "__main__":
    result = [verify(key, value) for key, value in ARCHIVES.items()]
    (ROOT / "verified-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    for row in result:
        print(json.dumps({key: value for key, value in row.items() if key not in ("members", "cohorts")}))
