"""Data-only exact current-source wheel and RECORD verifier; no package imports."""

import base64
import csv
import hashlib
import io
import json
import resource
import sys
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
ROOT = Path(__file__).resolve().parent
SOURCE = "a1d509404b0803a91031cb51f4b0c919408bfeba"
BUILD = "9f511875b236c12e5f23c783e958a536ac0360ba"
TREE = "e60dfd218cd7cc9f29c9f2cd66223c866ea86c80"
EXCLUDED = "src/codex_plugin_scanner/guard/native_runtime_resident.py"


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    source = json.loads((ROOT / "source-commit.json").read_text())
    build = json.loads((ROOT / "build-commit.json").read_text())
    census = json.loads((ROOT / "source-tree.json").read_text())
    assert source["sha"] == SOURCE and source["tree"]["sha"] == TREE
    assert build["sha"] == BUILD and build["tree"]["sha"] == TREE
    assert SOURCE in [item["sha"] for item in build["parents"]]
    assert census["sha"] == TREE and census["truncated"] is False
    leaves = {row["path"]: row for row in census["tree"] if row["type"] == "blob"}
    config_raw = (ROOT / "pyproject.toml").read_bytes()
    assert blob(config_raw) == leaves["pyproject.toml"]["sha"]
    config = tomllib.loads(config_raw.decode())
    assert [p for p in config["tool"]["hatch"]["build"]["exclude"] if p.startswith("src/codex_plugin_scanner/")] == [EXCLUDED]
    source_py = {p[4:]: row["sha"] for p, row in leaves.items() if p.startswith("src/codex_plugin_scanner/") and p.endswith(".py")}
    assert EXCLUDED[4:] in source_py
    expected = {p: sha for p, sha in source_py.items() if p != EXCLUDED[4:]}
    wheels = []
    inventory = []
    for argument in sys.argv[1:]:
        wheel = Path(argument).resolve(strict=True)
        assert wheel.stat().st_size < 64 * 1024 * 1024
        raw = wheel.read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = archive.namelist()
            assert 0 < len(infos) < 4096 and len(names) == len(set(names))
            assert sum(row.file_size for row in infos) < 100 * 1024 * 1024
            for row in infos:
                path = PurePosixPath(row.filename)
                assert not path.is_absolute() and ".." not in path.parts and "\\" not in row.filename and not row.is_dir()
                assert (row.external_attr >> 16) & 0o170000 != 0o120000
            record = [name for name in names if name.endswith(".dist-info/RECORD")]
            assert len(record) == 1
            rows = list(csv.reader(io.StringIO(archive.read(record[0]).decode())))
            assert all(len(row) == 3 for row in rows)
            assert len({row[0] for row in rows}) == len(rows) and {row[0] for row in rows} == set(names)
            members = []
            for name, digest, size in rows:
                data = archive.read(name)
                sha = hashlib.sha256(data).hexdigest()
                if name == record[0]:
                    assert digest == size == ""
                else:
                    assert digest == "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                    assert size == str(len(data))
                members.append({"path": name, "bytes": len(data), "sha256": sha, "git_blob": blob(data)})
            py = {name for name in names if name.startswith("codex_plugin_scanner/") and name.endswith(".py")}
            assert py == set(expected)
            assert all(blob(archive.read(name)) == expected[name] for name in py)
            result = {"path": str(wheel), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "record_entries_verified": len(rows), "nonself_record_entries_verified": len(rows) - 1, "packaged_python_bytes_match_source": len(py), "configured_legacy_exclusion": EXCLUDED}
            manifest_name = "codex_plugin_scanner/_native/runtime-manifest.json"
            if manifest_name in names:
                manifest_raw = archive.read(manifest_name)
                manifest = json.loads(manifest_raw)
                native = archive.read("codex_plugin_scanner/_native/hol-guard-runtime")
                assert manifest["source_sha"] == BUILD
                assert manifest["runtime_size"] == len(native)
                assert manifest["runtime_sha256"] == hashlib.sha256(native).hexdigest()
                result.update(runtime_manifest=manifest, runtime_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(), runtime_bytes_verified=True)
            wheels.append(result)
            inventory.append({"wheel": result["sha256"], "members": members})
    assert len(wheels) == 2 and sum("runtime_manifest" in row for row in wheels) == 1
    result = {"source_sha": SOURCE, "build_sha": BUILD, "same_tree": TREE, "source_leaves": len(leaves), "source_python_paths": len(source_py), "wheels": wheels, "scope": "Data-only authentic wheel whole RECORD, all packaged Python source blobs and runtime byte identity; no installation, application import, build or workload."}
    (ROOT / "wheel-verification.json").write_text(json.dumps(result, indent=2) + "\n")
    (ROOT / "wheel-member-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
