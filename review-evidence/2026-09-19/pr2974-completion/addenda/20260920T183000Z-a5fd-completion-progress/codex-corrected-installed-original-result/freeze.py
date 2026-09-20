"""Package original text evidence and its data-only readback without product execution."""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).parent
OUT = ROOT / "packet"
OUT.mkdir(exist_ok=True)


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()}


for name in ("metadata.json", "jobs.json", "run-api.json", "verify.py", "verified-result.json", "verify.stdout", "verify.stderr", "download.py", "download.log", "download-intel.log"):
    shutil.copyfile(ROOT / name, OUT / name)
for aid in (10609873805, 10609364746, 10610582284):
    dest = OUT / str(aid)
    dest.mkdir(exist_ok=True)
    shutil.copytree(ROOT / str(aid) / "raw", dest / "raw", dirs_exist_ok=True)
    shutil.copyfile(ROOT / str(aid) / "verification.json", dest / "verification.json")
result = json.loads((ROOT / "verified-result.json").read_bytes())
index = {
    "schema": "rsp136.corrected-codex-terminal-index.v1", "run_id": 35528764054,
    "source_commit": result["source_commit"], "source_tree": "676dd7eefa8cb7c3d4b42e06b9113d3f9cfb0d15",
    "driver_commit": result["driver_commit"], "driver_tree": "4f33133c9eb72cfb3d1143b7c315c2dbaf62e00a",
    "product_source": "a5fdde302aba2a06265c2e6e934b6ac9b76750df",
    "actual_native_build": "d7f30a0ad61d72d96d1a9e7970943404c4cc19dc",
    "product_and_build_tree": "ee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9",
    "launch_packet": "15e3598d01f06df05ffc549cba3dcd376b59a399",
    "source_peer": "1c2bcc30a8896a2f5acfaf21f7da314b50c524f7",
    "operational_peer": "53991f2a9e672a733791b70ab91e954436abbec0",
    "fresh_normal_artifact_admission": "b77c5ee27b4c30d91c9c92c6a56e86c0b11bd7c1",
    "first_attempts": True, "run_attempt": 1,
    "cells": [{k: row[k] for k in ("artifact_id", "cell", "archive", "source_controls_passed", "original_offered", "original_validated", "native_evaluations", "fresh_completed_allow", "continuation_status", "delivery", "installation_unchanged", "ledger_sha256")} for row in result["cells"]],
    "original_raw_members": 51, "no_tests_or_workload_repeated_by_readback": True,
    "archive_retention": "Authentic original ZIPs remain local and at the recorded GitHub artifacts. Every unmodified text member and its archive/member hashes are retained here; ZIP bytes are not duplicated into Git.",
    "scope": result["scope"], "limits": result["limits"],
    "prior_failures": "Earlier git exclusion, Codex request-digest mismatch, Cline witness and Pi encrypted/authority failures remain unchanged in their original packets. This packet establishes only the corrected Codex population.",
}
(OUT / "INDEX.json").write_text(json.dumps(index, sort_keys=True, indent=2) + "\n")
shutil.copyfile(__file__, OUT / "freeze.py")
rows = [{"path": p.relative_to(OUT).as_posix(), **identity(p.read_bytes())}
        for p in sorted(OUT.rglob("*")) if p.is_file() and p.name != "MANIFEST.json"]
(OUT / "MANIFEST.json").write_text(json.dumps({"files": rows}, sort_keys=True, indent=2) + "\n")
print(json.dumps({"files": len(rows) + 1, "original_raw_members": 51, "original_offers": 3, "original_validated": 3}))
