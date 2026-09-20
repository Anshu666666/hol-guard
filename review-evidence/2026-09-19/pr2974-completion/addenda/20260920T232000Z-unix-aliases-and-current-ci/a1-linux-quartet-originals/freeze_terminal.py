"""Data-only retained current Linux/quartet join and immutable text packet."""
import base64
import gzip
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "terminal-packet"
SOURCE = "a1d509404b0803a91031cb51f4b0c919408bfeba"
BUILD = "9f511875b236c12e5f23c783e958a536ac0360ba"
TREE = "e60dfd218cd7cc9f29c9f2cd66223c866ea86c80"
RUN = 35539716189


def ident(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def put(name, raw):
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(raw)


def dump(name, obj):
    put(name, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


def main():
    OUT.mkdir(exist_ok=False)
    metadata = json.loads((ROOT / "metadata.json").read_bytes())
    jobs = json.loads((ROOT / "terminal-jobs.json").read_bytes())["jobs"]
    assert len(jobs) == 5 and all(j["status"] == "completed" and j["conclusion"] == "success" and j["head_sha"] == SOURCE for j in jobs)
    by_name = {row["name"]: row for row in metadata["artifacts"]}
    locations = json.loads((ROOT / "peer-artifact-locations.json").read_bytes())
    directories = {"hol-guard-native-wheel-linux-x64": str(ROOT / "10615025870"), **locations["directories"]}
    matrix = json.loads((ROOT / "10615435093/raw/native-matrix-evidence.json").read_bytes())
    assert matrix["passed"] is True and len(matrix["collected"]) == 7
    validation = matrix["validation"]
    assert validation["source_sha"] == BUILD and validation["package_version"] == "3.0.1" and validation["windows_waiver"] is None
    assert set(validation["platforms"]) == {"manylinux_2_17_x86_64", "macosx_11_0_arm64", "macosx_13_0_x86_64", "win_amd64"}
    archives, joined, seen, pure = [], [], {}, []
    for name, location in directories.items():
        directory = Path(location)
        meta = by_name[name]
        raw = (directory / "artifact.zip").read_bytes()
        identity = ident(raw)
        assert identity["bytes"] == meta["size_in_bytes"] and "sha256:" + identity["sha256"] == meta["digest"]
        assert meta["workflow_run"]["head_sha"] == SOURCE and meta["workflow_run"]["id"] == RUN
        original = json.loads((directory / "verification.json").read_bytes())
        original_members = original.get("members", original.get("files"))
        assert original_members is not None
        with zipfile.ZipFile(directory / "artifact.zip") as archive:
            entries = {row["path"]: row for row in original_members}
            assert set(entries) == set(archive.namelist()) and len(entries) == len(archive.namelist())
            for member, descriptor in entries.items():
                data = archive.read(member)
                assert len(data) == descriptor["bytes"] and hashlib.sha256(data).hexdigest() == descriptor["sha256"]
                assert (directory / "raw" / member).read_bytes() == data
        archives.append({"artifact_id": meta["id"], "name": name, **identity, "original_members_rehashed": len(original_members)})
        put(f'quartet/{meta["id"]}-verification.json', (directory / "verification.json").read_bytes())
        expected = [row for row in matrix["collected"] if row["artifact"] == name]
        assert {p.name for p in (directory / "raw/native-dist").glob("*.whl")} == {Path(row["member"]).name for row in expected}
        for row in expected:
            path = directory / "raw" / row["member"]
            data = path.read_bytes()
            assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
            assert row["identical_duplicate"] is (path.name in seen)
            if path.name.endswith("-any.whl"):
                pure.append(data)
            if path.name in seen:
                assert seen[path.name] == data
            seen[path.name] = data
            joined.append({"artifact_id": meta["id"], **row})
    assert len(pure) == 3 and pure[0] == pure[1] == pure[2] and len(seen) == 5
    assert len(validation["artifacts"]) == 5
    for row in validation["artifacts"]:
        data = seen[row["name"]]
        assert len(data) == row["size"] and hashlib.sha256(data).hexdigest() == row["sha256"]
    dump("QUARTET-JOIN.json", {"source": SOURCE, "actual_build": BUILD, "tree": TREE, "archives": archives, "seven_rows": joined, "three_pure_wheels_byte_equal": True, "five_admitted_artifacts_joined": True, "windows_waiver": None, "mac_packet": locations["mac_packet"], "windows_packet": locations["windows_packet"], "windows_peer": locations["windows_peer"], "scope": "Retained authentic original archive/member bytes and original strict hosted collector joined. No installed or validator workload repeated."})
    linux = ROOT / "10615025870/raw"
    slo = json.loads((linux / "native-installed-slo.json").read_bytes())
    soak = json.loads((linux / "native-soak.json").read_bytes())
    default = json.loads((linux / "native-default-auto.json").read_bytes())
    wheels = json.loads((ROOT / "wheel-verification.json").read_bytes())
    runtime = next(r["runtime_manifest"] for r in wheels["wheels"] if "runtime_manifest" in r)
    assert slo["runtime"]["build_sha"] == runtime["source_sha"] == BUILD
    assert slo["runtime"]["runtime_sha256"] == runtime["runtime_sha256"]
    assert slo["runtime"]["rule_digest"] == runtime["rule_digest"] == validation["rule_digest"]
    assert len(slo["gates"]) == 14 and all(v is True for v in slo["gates"].values()) and slo["qualification_complete"] is False
    assert default["resident_decisions"] == default["corpus_decisions"] == default["receipt_metrics"]["accepted"] == default["receipt_metrics"]["processed"] == 21
    assert default["evidence_failure_diagnostics"] == {"all_evidence": {}, "native_receipts": {}}
    assert soak["passed"] is soak["soak_passed"] is soak["pid_stable"] is True
    assert soak["requests"] == soak["responses"] == 100000 and soak["receipts"] == 250000 and soak["errors"] == 0
    summary = {"schema": "pr2974.a1-linux-strict-quartet.v1", "run": RUN, "source": SOURCE, "actual_build": BUILD, "same_tree": TREE, "linux_job": 106155073066, "collector_job": 106159454781, "all_five_original_jobs": "success", "new_artifacts": [10615025870, 10615435093], "runtime": runtime, "linux_record_rows": sum(w["record_entries_verified"] for w in wheels["wheels"]), "source_python": 1434, "packaged_python_per_wheel": 1433, "configured_legacy_exclusion": "src/codex_plugin_scanner/guard/native_runtime_resident.py", "linux_slo_gates": slo["gates"], "qualification_complete": False, "linux_default_auto_native_and_receipt_count": 21, "linux_evidence_failure_maps": default["evidence_failure_diagnostics"], "linux_soak": soak, "linux_concurrency": slo["concurrency"], "linux_warm": slo["latency"]["warm_all_harnesses"], "strict_quartet": validation, "limits": ["Normal original count-bounded100000 requests/250000 receipts; not an additional qualification campaign.", "Normal c16 deadline1000ms and soak4500ms gates remain distinct. Actual Linux c16p99517.75ms exceeds the original200ms qualification target; c64 has26 engine_bypassed and38 native routes with no latency ceiling.", "No full-performance, lifetimeCPU/private-memory, canary, release/signing or updater/downgrade qualification.", "Five unique admitted wheels include four native targets plus one pure wheel; no source distribution or six-file signed release is established.", "Windows separate original packet retains command_activity_persistence/sqlite_busy1 even though its ordinary21 native/receipt routes pass. Linux empty failure maps cannot erase it.", "Ordinary normalized ingress, recovery and inline installed controls do not replace registered launcher, encrypted post, approval continuation, or100-workspace first-admission populations.", "Binary archives/wheels remain locally retained/hash-bound. This Git packet preserves original text and lossless member inventory, not binary archive copies."]}
    dump("SUMMARY.json", summary)
    for name in ("metadata.json", "terminal-jobs.json", "download.py", "download.log", "download.stderr", "verify_packages.py", "wheel-verification.json", "wheel-verification.stdout", "wheel-verification.stderr", "original-job.log", "aggregate-job.log", "LOG-PRESERVATION.json", "source-commit.json", "build-commit.json", "pyproject.toml"):
        put(name, (ROOT / name).read_bytes())
    for aid in (10615025870, 10615435093):
        folder = ROOT / str(aid)
        put(f"{aid}/verification.json", (folder / "verification.json").read_bytes())
        for path in sorted((folder / "raw").glob("*.json")):
            put(f"{aid}/raw/{path.name}", path.read_bytes())
    for path in (ROOT / "source").rglob("*"):
        if path.is_file():
            put("source/" + path.relative_to(ROOT / "source").as_posix(), path.read_bytes())
    inventory = (ROOT / "wheel-member-inventory.json").read_bytes()
    compressed = gzip.compress(inventory, mtime=0)
    encoded = base64.b64encode(compressed)
    parts = []
    for offset in range(0, len(encoded), 64000):
        name = f"wheel-member-inventory.part-{offset // 64000:03d}.b64"
        put(name, encoded[offset:offset + 64000])
        parts.append(name)
    assert gzip.decompress(base64.b64decode(b"".join((OUT / name).read_bytes() for name in parts))) == inventory
    dump("INVENTORY-ENCODING.json", {"original": ident(inventory), "gzip": ident(compressed), "ordered_parts": parts})
    put("freeze_terminal.py", Path(__file__).read_bytes())
    manifest = [{"path": p.relative_to(OUT).as_posix(), **ident(p.read_bytes())} for p in sorted(OUT.rglob("*")) if p.is_file()]
    dump("MANIFEST.json", {"files": manifest})
    print(json.dumps({"files": len(manifest) + 1, "bytes": sum(r["bytes"] for r in manifest), "archives": len(archives), "rows": len(joined)}))


if __name__ == "__main__":
    main()
