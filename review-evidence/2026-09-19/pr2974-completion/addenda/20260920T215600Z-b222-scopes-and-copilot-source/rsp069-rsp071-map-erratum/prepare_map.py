"""Reconcile retained data and exact Git source; never import or run product code."""

from pathlib import Path
import ast
import hashlib
import json
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent / "normalb222-posix/source.git"
OLD = "2433a8ce570f34f5ad3dbf23f3d7367267aad461"
NEW = "b222318cca2811ac7ae90c7364e2ec6d0a10651f"
BUILD = "6aa63accf753de56aef380bdf59710a031973bfa"


def git(*args):
    return subprocess.check_output(["git", "--git-dir=" + str(REPO), *args])


def digest(b):
    return hashlib.sha256(b).hexdigest()


def blob(b):
    return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()


def save(name, obj):
    (ROOT / name).write_bytes((json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


for name in [".github/workflows/ci.yml", "scripts/ci/pytest_duration_report.py"]:
    p = ROOT / "source" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(git("show", NEW + ":" + name))

bindings = []
for p in sorted((ROOT / "source").rglob("*")):
    if not p.is_file():
        continue
    relative = p.relative_to(ROOT / "source").as_posix()
    b = p.read_bytes()
    assert b == git("show", NEW + ":" + relative)
    old = git("show", OLD + ":" + relative)
    bindings.append({"path": relative, "bytes": len(b), "git_blob": blob(b),
                     "sha256": digest(b), "old_blob": blob(old), "identical": old == b})
save("SOURCE-BINDINGS.json", {"old_source": OLD, "current_source": NEW,
                             "current_tree": git("rev-parse", NEW + "^{tree}").decode().strip(),
                             "actual_build": BUILD,
                             "actual_build_tree": git("rev-parse", BUILD + "^{tree}").decode().strip(),
                             "rows": bindings})

source_nodes = {}
for p in (ROOT / "source/tests").glob("*.py"):
    tree = ast.parse(p.read_bytes())
    source_nodes[p.name] = [{"name": n.name, "line": n.lineno}
                            for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
save("DECLARED-SOURCE-TESTS.json", source_nodes)

raw = ROOT / "actual-ci"
plan = json.loads((raw / "selected-plan.json").read_bytes())
archive = raw / "plan.zip"
assert archive.stat().st_size == 553874
assert digest(archive.read_bytes()) == "f76c4c10ad6205dbc080dc0cb14417bb867936cfcf1f6bf441c7c99061178b5c"
with zipfile.ZipFile(archive) as z:
    roster = []
    for n in z.namelist():
        b = z.read(n)
        roster.append({"name": n, "bytes": len(b), "sha256": digest(b)})
    for row in plan:
        assert (raw / row["shard"]).read_bytes() == z.read(row["shard"])
save("actual-ci/PLAN-VERIFICATION.json", {"artifact_id": 10612049735,
     "archive_bytes": archive.stat().st_size, "archive_sha256": digest(archive.read_bytes()),
     "all_member_hashes": roster, "selected_files": [x["shard"] for x in plan],
     "binary_archive_local_only": True})

jobs = {1: 106142047959, 28: 106142048030, 29: 106142048106, 49: 106142048102}
outcomes = []
for row in plan:
    shard = int(row["shard"][6:8])
    log = (raw / f"job-shard-{shard}.log").read_bytes()
    lines = log.decode().splitlines()
    assert BUILD in log.decode()
    assert f'"{shard}")' in log.decode()  # Retained shell formats this exact selected index.
    collection = [x for x in lines if re.search(r"collected \d+ items", x)]
    summary = [x for x in lines if re.search(r"=+ \d+ passed", x)]
    assert len(collection) == len(summary) == 1
    expected_count = len((raw / row["shard"]).read_text().splitlines())
    assert f"collected {expected_count} items" in collection[0]
    module = row["selected"][0].split("::")[0]
    at = next(i for i, line in enumerate(lines) if module + " " in line)
    progress = [lines[at]]
    after = lines[at + 1].split("Z ", 1)[-1]
    if after.startswith("."):
        progress.append(lines[at + 1])
    dots = sum(len(re.search(r"(\.+)\s+\[", x).group(1)) for x in progress)
    assert dots == len(row["selected"])
    assert len(set(row["selected"])) == len(row["selected"])
    outcomes.append({"shard": shard, "job_id": jobs[shard], "selected_module": module,
                     "selected_nodes": row["selected"], "selected_pass_dots": dots,
                     "selected_skips_or_failures": 0, "shard_collected": expected_count,
                     "collection_line": collection[0], "summary_line": summary[0],
                     "module_progress_lines": progress, "log_bytes": len(log), "log_sha256": digest(log),
                     "source_claim": "Original exact-build CI source tests; no installed-wheel claim"})
save("actual-ci/SELECTED-OUTCOMES.json", {"run_id": 35534837377, "head_sha": NEW,
     "build_sha": BUILD, "outcomes": outcomes, "selected_total": sum(x["selected_pass_dots"] for x in outcomes),
     "archive_selected_pass": 72, "secrets_cli_selected_pass": 15,
     "unrelated_shard28_skip": "Retained in full log and shard summary; not attributed to either selected archive module",
     "method": "Exact uploaded shard argv roster + original collection count + complete module progress dots + terminal shard summary; no raw JUnit exists in this workflow"})

old_reports = {}
for cell in ["linux", "mac-arm", "mac-intel", "windows"]:
    p = ROOT / "historical" / (cell + ".json")
    b = p.read_bytes()
    d = json.loads(b)
    assert d["run_complete"] and d["status"] == "passed" and len(d["cases"]) == 28
    assert len({x["case"] for x in d["cases"]}) == 28 and all(x["status"] == "passed" for x in d["cases"])
    assert d["identity"]["source_sha"] == OLD
    old_reports[cell] = {"blob": blob(b), "bytes": len(b), "sha256": digest(b),
                         "platform": d["platform"], "machine": d["machine"], "python": d["python"],
                         "wheel_sha256": d["identity"]["wheel_sha256"], "case_count": 28,
                         "source_sha": OLD, "native_detector_active": False,
                         "cases": [{k: x[k] for k in ["case", "status", "exit_code", "files", "findings", "defaults"] if k in x} for x in d["cases"]]}
save("HISTORICAL-OUTCOMES.json", old_reports)

joined = json.loads((ROOT / "HISTORICAL-JOINS.json").read_bytes())
assert all(len(x["joins"]) == 12 and all(y["matches"] for y in x["joins"]) for x in joined.values())
save("RECONCILIATION.json", {"read_only_review": True, "product_tests_executed_by_this_review": 0,
     "installed_workloads_executed_by_this_review": 0, "source_mutations": 0,
     "ref_mutations": 0, "historical_installed_pass": 112, "current_selected_source_pass": 87,
     "unchanged_reported_providers_per_platform": 12, "source_binding_count": len(bindings),
     "changed_reviewed_paths": [x["path"] for x in bindings if not x["identical"]],
     "do_not_sum_scopes": True,
     "archive_historical_timing_claim": "Archived ledger assertion only: raw 17x30 report not recovered; no new validation credit",
     "archive_current_functional_evidence": "72 actual b222 Linux source/isolated-worker controls from existing main CI",
     "installed_receipt_limit": "Reports retain public-output hashes/counts and successful full-oracle assertions, not every original stdout body or independent new wheel download"})
print(json.dumps({"source_bindings": len(bindings), "historical_pass": 112, "current_source_selected_pass": 87}))
