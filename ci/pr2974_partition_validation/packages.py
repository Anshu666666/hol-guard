"""Build new ordinary packages and verify every artifact member against the candidate."""

from __future__ import annotations

import base64
import csv
import email
import fnmatch
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tomllib
import zipfile

from common import CONFIG, HARNESS, HERE, REPORT, SCRATCH, SOURCE, Run, write_json


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    assert name and not name.startswith("/") and ".." not in path.parts and "." not in path.parts, name
    assert "\\" not in name and "\0" not in name, name
    return name


def file_record(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def verify_packages(run: Run, wheel: Path, sdist: Path) -> None:
    source_files = run.before["files"]
    current_harness_directory = HERE.relative_to(HARNESS).as_posix() + "/"
    project = tomllib.loads((SOURCE / "pyproject.toml").read_text())
    build = project["tool"]["hatch"]["build"]
    excluded = build.get("exclude", [])
    expected = {}
    for path in source_files:
        if path.startswith("src/codex_plugin_scanner/") and not any(fnmatch.fnmatchcase(path, p) for p in excluded):
            expected[path.removeprefix("src/")] = [path]
    forced = build["targets"]["wheel"].get("force-include", {})
    for origin, destination in forced.items():
        assert origin in source_files, origin
        expected.setdefault(destination, [])
        if origin not in expected[destination]:
            expected[destination].append(origin)
    assert expected
    wheel_members = {}
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        assert len({info.filename for info in infos}) == len(infos), "Duplicate wheel member"
        assert not archive.testzip(), "Wheel CRC mismatch"
        payloads = {}
        for info in infos:
            safe_name(info.filename)
            assert not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16), info.filename
            assert info.file_size <= 128 * 1024 * 1024, info.filename
            payload = archive.read(info)
            payloads[info.filename] = payload
            wheel_members[info.filename] = file_record(payload)
        records = [name for name in payloads if name.endswith(".dist-info/RECORD")]
        assert len(records) == 1, records
        record_name = records[0]
        metadata_root = record_name.rsplit("/", 1)[0] + "/"
        actual_package = {name for name in payloads if name.startswith("codex_plugin_scanner/")}
        assert actual_package == set(expected), {
            "missing": sorted(set(expected) - actual_package),
            "extra": sorted(actual_package - set(expected)),
        }
        for name, origins in expected.items():
            for origin in origins:
                assert wheel_members[name]["sha256"] == source_files[origin]["sha256"], (name, origin)
            wheel_members[name]["source_paths"] = origins
        for name in set(payloads) - actual_package:
            assert name.startswith(metadata_root), name
            wheel_members[name]["generated_dist_info"] = True
        for name in payloads:
            if name.startswith(metadata_root + "licenses/"):
                origin = name.removeprefix(metadata_root + "licenses/")
                assert origin in source_files, name
                assert wheel_members[name]["sha256"] == source_files[origin]["sha256"], name
                wheel_members[name]["source_paths"] = [origin]
        rows = list(csv.reader(io.StringIO(payloads[record_name].decode("utf-8"))))
        assert all(len(row) == 3 for row in rows)
        assert len({row[0] for row in rows}) == len(rows), "Duplicate RECORD row"
        assert {row[0] for row in rows} == set(payloads), "RECORD member coverage mismatch"
        for name, digest, size in rows:
            if name == record_name:
                assert digest == "" and size == ""
                continue
            expected_digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(payloads[name]).digest()).decode().rstrip("=")
            assert digest == expected_digest and size == str(len(payloads[name])), name
        metadata = email.message_from_bytes(payloads[metadata_root + "METADATA"])
        assert metadata["Name"] == project["project"]["name"]
        assert metadata["Version"] == project["project"]["version"]
    sdist_members = {}
    included_sources = set()
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        assert len({member.name for member in members}) == len(members), "Duplicate sdist member"
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        assert len(roots) == 1, roots
        prefix = next(iter(roots)) + "/"
        for member in members:
            safe_name(member.name)
            if member.isdir():
                sdist_members[member.name] = {"directory": True}
                continue
            assert member.isfile() and member.size <= 128 * 1024 * 1024, member.name
            stream = archive.extractfile(member)
            assert stream is not None
            data = stream.read()
            relative = member.name.removeprefix(prefix)
            assert member.name.startswith(prefix), member.name
            row = file_record(data)
            if relative == "PKG-INFO":
                metadata = email.message_from_bytes(data)
                assert metadata["Name"] == project["project"]["name"]
                assert metadata["Version"] == project["project"]["version"]
                row["generated_metadata"] = True
            else:
                assert relative in source_files, relative
                assert row["sha256"] == source_files[relative]["sha256"], relative
                included_sources.add(relative)
                row["source_path"] = relative
            assert not relative.startswith("ci/pr2974_source_validation/")
            assert not relative.startswith(current_harness_directory)
            assert relative != ".github/workflows/pr2974-source-validation.yml"
            sdist_members[member.name] = row
    required_sources = {origin for origins in expected.values() for origin in origins} | set(CONFIG["fixed_files"])
    assert required_sources <= included_sources, sorted(required_sources - included_sources)
    write_json(REPORT / "package-members.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "wheel": {"name": wheel.name, **file_record(wheel.read_bytes()), "members": wheel_members,
                  "record_rows": len(rows), "source_mapped_members": len(expected)},
        "sdist": {"name": sdist.name, **file_record(sdist.read_bytes()), "members": sdist_members,
                  "source_mapped_members": len(included_sources)},
        "force_includes": forced, "sdist_required_repaired_tests": sorted(CONFIG["fixed_files"]),
        "sdist_omitted_tracked_source_paths": sorted(set(source_files) - included_sources),
        "all_wheel_record_rows_verified": True,
        "all_actual_members_verified": True, "harness_in_artifacts": False, "qualification_complete": False,
    })


def run_packages(run: Run, env: dict[str, str], primary: Path, create_venv) -> None:
    backend = create_venv("build-environment")
    backend_env = dict(env, VALIDATION_BUILD_VENV=str(backend))
    uv = os.environ["VALIDATION_UV"]
    assert run.command("build-backend-install", [
        uv, "--no-config", "pip", "install", "--python", str(backend / "bin/python"),
        "build==1.5.0", "hatchling==1.30.1", "packaging==26.0", "pyproject-hooks==1.2.0", "pluggy==1.6.0",
        "pathspec==1.1.1", "trove-classifiers==2026.6.1.19",
    ], timeout=300, env=backend_env), "Build backend installation failed"
    assert run.command("build-backend-compatibility", [
        uv, "--no-config", "pip", "check", "--python", str(backend / "bin/python")
    ], env=backend_env), "Backend dependency check failed"
    assert run.command("build-backend-inventory", [
        str(backend / "bin/python"), "-I", str(HERE / "environment.py"),
        str(REPORT / "build-environment.json"), "--backend",
    ], env=backend_env), "Build backend identity failed"
    dist = SCRATCH / "dist"
    dist.mkdir()
    assert run.command("build-wheel-and-sdist", [
        str(backend / "bin/python"), "-m", "build", "--no-isolation", "--outdir", str(dist), str(SOURCE),
    ], timeout=420, env=backend_env), "Real package build failed"
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1, (wheels, sdists)
    assert len(list(dist.iterdir())) == 2, "Unexpected build outputs"
    for label, artifact in (("wheel", wheels[0]), ("sdist", sdists[0])):
        run.command("capability-artifact-gate-" + label, [
            str(primary), str(SOURCE / "scripts/ci/python_capability_cleanup_gate.py"),
            "--root", str(SOURCE), "--artifact", str(artifact),
            "--json", str(REPORT / ("capability-artifact-" + label + ".json")),
        ], timeout=180, env=env)
    verify_packages(run, wheels[0], sdists[0])
