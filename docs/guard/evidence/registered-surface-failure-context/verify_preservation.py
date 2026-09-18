"""Verify the diagnostic additions against the exact hosted590 source."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
BASE = "590ce01334a7724f3f1349b2ab252110a5a268f5"


def original(relative: str) -> str:
    return subprocess.check_output(["git", "show", f"{BASE}:{relative}"], cwd=REPO).decode()


def digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


records = []
input_relative = "scripts/native_slo_launcher_input.py"
old = original(input_relative)
new = (REPO / input_relative).read_text()
begin = new.index("    try:\n        _validate_witness(case, evidence, route)\n")
end = new.index("    approval = _block_resolution", begin)
restored = new[:begin] + "    _validate_witness(case, evidence, route)\n" + new[end:]
restored = restored.replace(
    "    after = route_counts(snapshot)\n    route = witnessed_route(before, after)\n",
    "    route = witnessed_route(before, route_counts(snapshot))\n",
    1,
)
assert restored == old
records.append(
    {
        "relative_path": input_relative,
        "original_digest": digest(old),
        "changed_digest": digest(new),
        "only_validation_envelope_and_existing_counter_alias_changed": True,
    }
)

surface_relative = "scripts/native_slo_registered_surfaces_run.py"
old = original(surface_relative)
new = (REPO / surface_relative).read_text()
old_begin = old.index("                    if route != case.expected_route:\n")
old_end = old.index('                    attempt.stage = "complete"\n', old_begin)
old_block = old[old_begin:old_end]
begin = new.index("                    evidence: Mapping[str, object] | None = None\n")
body_begin = new.index("                        if route != case.expected_route:\n", begin)
body_end = new.index("                    except Exception as error:\n", body_begin)
end = new.index('                    attempt.stage = "complete"\n', body_end)
new_block = new[body_begin:body_end]
assert ast.dump(ast.parse(textwrap.dedent(new_block))) == ast.dump(ast.parse(textwrap.dedent(old_block)))
assert new[:begin] + old_block + new[end:] == old
records.append(
    {
        "relative_path": surface_relative,
        "original_digest": digest(old),
        "changed_digest": digest(new),
        "original_validation_block_ast_identical": True,
        "remaining_module_bytes_identical": True,
    }
)

unchanged = (
    "scripts/native_slo_workloads.py",
    "scripts/native_slo_contract.py",
    "scripts/native_slo_failure.py",
    "scripts/native_slo_observation_failure.py",
    "scripts/native_slo_registered_surfaces.py",
    "scripts/native_slo_registered_surfaces_evidence.py",
    "scripts/native_slo_priority_launchers.py",
    "scripts/native_slo_qualification_scenarios.py",
    ".github/workflows/native-performance-qualification.yml",
)
for relative in unchanged:
    old = original(relative)
    new = (REPO / relative).read_text()
    assert old == new
    records.append({"relative_path": relative, "sha256": digest(old), "unchanged_from_hosted_source": True})

report = {
    "schema": "hol-guard.surface-failure-source-preservation.v1",
    "mapped_commit_sha": BASE,
    "records": records,
    "qualification_replayed": False,
}
output = HERE / "source-preservation.json"
output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"records": len(records), "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))
