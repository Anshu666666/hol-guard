"""Read and reconcile retained cbd Linux originals, then freeze a text packet."""
import base64
import gzip
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "terminal-packet"
SOURCE = "cbd9399e39adc4fe338bff468807656ebab3af13"
BUILD = "ef40a5833b75109593755ca3a4e74f9b2a193caa"
TREE = "3c59e6f81f531e7b4496ae49a278c9ddf3961380"
RUN = 35541550524
ARTIFACT = 10615690920

def ident(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}

def read(name):
    return json.loads((ROOT / name).read_bytes())

def put(name, raw):
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)

def dump(name, value):
    put(name, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())

def merkle(rows, prefix=""):
    children = {}
    for path, row in rows.items():
        if not path.startswith(prefix):
            continue
        tail = path[len(prefix):]
        first, sep, rest = tail.partition("/")
        if sep:
            children[first + "/"] = ("40000", merkle(rows, prefix + first + "/"))
        else:
            children[first] = (row["mode"], row["sha"])
    body = b"".join(mode.encode() + b" " + name.rstrip("/").encode() + b"\0" + bytes.fromhex(sha) for name, (mode, sha) in sorted(children.items()))
    return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()

def main():
    originals = [p for p in ROOT.rglob("*") if p.is_file() and "terminal-packet" not in p.parts and p.name != "download-private.json"]
    before = {str(p.relative_to(ROOT)): ident(p.read_bytes()) for p in originals}
    metadata = read("metadata.json")
    jobs = read("terminal-jobs.json")["jobs"]
    assert len(jobs) == 5 and all(j["status"] == "completed" and j["head_sha"] == SOURCE for j in jobs)
    expected = {106160019435: "success", 106160019580: "success", 106160019603: "failure", 106160019613: "success", 106164478702: "skipped"}
    assert {j["id"]: j["conclusion"] for j in jobs} == expected
    assert read("run.json")["head_sha"] == SOURCE
    meta = next(a for a in metadata["artifacts"] if a["id"] == ARTIFACT)
    assert meta["workflow_run"]["head_sha"] == SOURCE and meta["workflow_run"]["id"] == RUN
    assert not any(a["name"] in ("hol-guard-native-wheel-windows-x64", "hol-guard-native-artifact-matrix") for a in metadata["artifacts"])
    archive = ROOT / str(ARTIFACT) / "artifact.zip"
    archive_identity = ident(archive.read_bytes())
    assert archive_identity["bytes"] == meta["size_in_bytes"] and "sha256:" + archive_identity["sha256"] == meta["digest"]
    verification = read(f"{ARTIFACT}/verification.json")
    with zipfile.ZipFile(archive) as z:
        members = verification["members"]
        assert len(members) == len(z.namelist()) == 9 and {m["path"] for m in members} == set(z.namelist())
        for m in members:
            data = z.read(m["path"])
            assert len(data) == m["bytes"] and hashlib.sha256(data).hexdigest() == m["sha256"]
            assert data == (ROOT / str(ARTIFACT) / "raw" / m["path"]).read_bytes()
    census = read("source-tree.json")
    leaves = {r["path"]: r for r in census["tree"] if r["type"] == "blob"}
    assert len(leaves) == 4802 and census["sha"] == TREE and census["truncated"] is False and merkle(leaves) == TREE
    assert read("source-commit.json")["sha"] == SOURCE and read("source-commit.json")["tree"]["sha"] == TREE
    assert read("build-commit.json")["sha"] == BUILD and read("build-commit.json")["tree"]["sha"] == TREE
    assert SOURCE in [r["sha"] for r in read("build-commit.json")["parents"]]
    for path in (ROOT / "source").rglob("*"):
        if path.is_file():
            assert ident(path.read_bytes())["git_blob"] == leaves[str(path.relative_to(ROOT / "source"))]["sha"]
    wheels = read("wheel-verification.json")
    assert wheels["source_sha"] == SOURCE and wheels["build_sha"] == BUILD and wheels["same_tree"] == TREE
    assert len(wheels["wheels"]) == 2 and all(w["packaged_python_bytes_match_source"] == 1433 for w in wheels["wheels"])
    native = next(w for w in wheels["wheels"] if "runtime_manifest" in w)
    runtime = native["runtime_manifest"]
    raw = ROOT / str(ARTIFACT) / "raw"
    slo = json.loads((raw / "native-installed-slo.json").read_bytes())
    soak = json.loads((raw / "native-soak.json").read_bytes())
    default = json.loads((raw / "native-default-auto.json").read_bytes())
    identity = json.loads((raw / "native-installed-identity.json").read_bytes())
    pi = json.loads((raw / "installed-pi-output.json").read_bytes())
    evidence = json.loads((raw / "native-artifact-evidence.json").read_bytes())
    stop = json.loads((raw / "native-stop-diagnostic.json").read_bytes())
    for report in (slo["runtime"], identity, pi["runtime"]):
        assert report["build_sha"] == runtime["source_sha"] == BUILD and report["runtime_sha256"] == runtime["runtime_sha256"]
    assert identity["manifest_sha256"] == native["runtime_manifest_sha256"] and identity["runtime_size"] == runtime["runtime_size"]
    assert slo["runtime"]["rule_digest"] == evidence["rule_digest"] == runtime["rule_digest"]
    assert evidence["source_sha"] == BUILD
    assert len(evidence["artifacts"]) == 2
    for row in evidence["artifacts"]:
        data = (raw / "native-dist" / row["name"]).read_bytes()
        assert len(data) == row["size"] and hashlib.sha256(data).hexdigest() == row["sha256"]
    with zipfile.ZipFile(native["path"]) as z:
        package_digest = hashlib.sha256()
        for name in sorted(n for n in z.namelist() if n.startswith("codex_plugin_scanner/") and not n.endswith(("/", ".pyc")) and "/__pycache__/" not in n):
            package_digest.update(name.encode() + b"\0" + hashlib.sha256(z.read(name)).digest())
        assert package_digest.hexdigest() == slo["runtime"]["installed_package_sha256"]
    assert len(slo["gates"]) == 14 and all(v is True for v in slo["gates"].values()) and slo["passed"] is True and slo["qualification_complete"] is False
    assert default["resident_decisions"] == default["corpus_decisions"] == default["receipt_metrics"]["accepted"] == default["receipt_metrics"]["processed"] == 21
    assert len(default["route_receipts"]) == 21 and len({(r["event"], r["harness"]) for r in default["route_receipts"]}) == 21 and all(r["route"] == "native_resident" for r in default["route_receipts"])
    assert default["evidence_failure_diagnostics"] == {"all_evidence": {}, "native_receipts": {}}
    assert soak["passed"] is soak["soak_passed"] is soak["pid_stable"] is True
    assert soak["requests"] == soak["responses"] == 100000 and soak["receipts"] == 250000 and soak["errors"] == soak["health_failures"] == 0
    assert len(identity["cases"]) == 17 and len({r["case"] for r in identity["cases"]}) == 17 and all(r["result"] == ("replaced" if r["case"] == "live_replacement" else "passed") for r in identity["cases"])
    assert pi["native_route_metrics"] == {"native_resident": 4} and len(pi["generated_extension"]["real_cases"]) == 4 and len(pi["generated_extension"]["malformed_result_cases"]) == 7
    assert stop["status"] == "contained" and all(stop[k] == "verified" for k in ("acknowledged", "authenticated", "generation_present", "owner_lock", "marker_lock", "endpoint", "serving_shutdown"))
    log = (ROOT / "linux-job.log").read_text()
    assert '100000' in log and '250000' in log and str(ARTIFACT) in log and BUILD in log
    OUT.mkdir(exist_ok=False)
    summary = {"schema": "pr2974.cbd-linux-original-admission.v1", "source": SOURCE, "actual_build": BUILD, "same_tree": TREE, "run": RUN, "linux_job": 106160019580, "linux_conclusion": "success", "collector_job": 106164478702, "collector_conclusion": "skipped", "windows_job": 106160019603, "windows_conclusion": "failure", "strict_quartet_admitted": False, "archive": {"artifact_id": ARTIFACT, **archive_identity, "all_original_members_verified": 9}, "runtime": runtime, "whole_record_entries_verified": sum(w["record_entries_verified"] for w in wheels["wheels"]), "python_bytes_match_source_per_wheel": 1433, "source_python_paths": 1434, "configured_legacy_exclusion": wheels["wheels"][0]["configured_legacy_exclusion"], "installed_package_digest_join": package_digest.hexdigest(), "identity_cases": 17, "default_auto_routes_and_receipts": 21, "evidence_failure_maps": default["evidence_failure_diagnostics"], "generated_omp_real_cases": 4, "generated_omp_malformed_cases": 7, "ordinary_slo_gates": slo["gates"], "qualification_complete": False, "ordinary_soak": soak, "concurrency": slo["concurrency"], "warm": slo["latency"]["warm_all_harnesses"], "resident_recovery": slo["latency"]["resident_recovery"], "stop": stop, "limits": ["Current Windows original failure prevented the strict collector; no current Windows native wheel or current quartet is admitted. Prior a1 quartet remains a separate subject.", "Normal smoke/soak passed, not full qualification. Actual c16 p99 636.225 ms exceeds the original 200 ms qualification target but is inside normal 1000 ms gate; c64 has 32 engine_bypassed/32 native routes and no latency ceiling.", "Original 100000 request/250000 receipt count-bounded soak has 4500 ms hook ceiling. No campaign was rerun or imported by this data reader.", "This receipt does not admit registered-launcher minima, full lifetime CPU/private-resource accounting, 100-workspace first-admission, release/signing, updater or cross-version rollback.", "Original installed RECORD digest is preserved as an observed installed value; package content digest, wheel RECORD, runtime and manifest are independently rejoined. Installed RECORD includes installer changes and is not relabeled as raw wheel RECORD.", "Raw ZIP and both binary wheels are local and hash-bound; this Git packet preserves exact text originals and reversible inventories/source census, not binary copies."]}
    dump("SUMMARY.json", summary)
    for name in ("metadata.json", "terminal-jobs.json", "run.json", "source-commit.json", "build-commit.json", "pyproject.toml", "verify_packages.py", "wheel-verification.json", "download.py", "download.log", "download.stderr", "linux-job.log", "LOG-PRESERVATION.json"):
        put(name, (ROOT / name).read_bytes())
    put(f"{ARTIFACT}/verification.json", (ROOT / str(ARTIFACT) / "verification.json").read_bytes())
    for p in sorted(raw.glob("*.json")):
        put(f"{ARTIFACT}/raw/{p.name}", p.read_bytes())
    for p in (ROOT / "source").rglob("*"):
        if p.is_file():
            put("source/" + p.relative_to(ROOT / "source").as_posix(), p.read_bytes())
    encodings = []
    for name in ("source-tree.json", "wheel-member-inventory.json"):
        data = (ROOT / name).read_bytes(); compressed = gzip.compress(data, mtime=0); encoded = base64.b64encode(compressed); parts = []
        for offset in range(0, len(encoded), 64000):
            part = f"reversible/{name}.part-{offset // 64000:03d}.b64"; put(part, encoded[offset:offset + 64000]); parts.append(part)
        assert gzip.decompress(base64.b64decode(b"".join((OUT / p).read_bytes() for p in parts))) == data
        encodings.append({"original_path": name, "original": ident(data), "gzip": ident(compressed), "ordered_parts": parts})
    dump("ORIGINALS.json", {"encodings": encodings})
    assert before == {str(p.relative_to(ROOT)): ident(p.read_bytes()) for p in originals}
    dump("INPUT-PRESERVATION.json", {"all_original_inputs_unchanged": True, "files": before})
    put("freeze_terminal.py", Path(__file__).read_bytes())
    files = [{"path": str(p.relative_to(OUT)), **ident(p.read_bytes())} for p in sorted(OUT.rglob("*")) if p.is_file()]
    dump("MANIFEST.json", {"files": files})
    print(json.dumps({"files": len(files) + 1, "summary": ident((OUT / "SUMMARY.json").read_bytes()), "unchanged_inputs": len(before)}))

if __name__ == "__main__":
    main()
