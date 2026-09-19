"""Independently inspect original wheel/sdist bytes; never build or import a package."""

from __future__ import annotations

import base64
import csv
import email
import fnmatch
import hashlib
import io
import stat
import tarfile
import tomllib
import zipfile
from pathlib import PurePosixPath

from common import CONFIG, ORIGINAL, REPORT, SOURCE, digest, safe_name, write_json
from reports import parsed


def audit_packages(distributions: dict[str, bytes], payloads: dict[str, bytes],
                   report: dict[str, object], witness: dict[str, object]) -> dict[str, object]:
    wheels = [name for name in distributions if name.endswith(".whl")]
    sdists = [name for name in distributions if name.endswith(".tar.gz")]
    assert len(distributions) == 2 and len(wheels) == len(sdists) == 1
    wheel_name, sdist_name = wheels[0], sdists[0]
    assert "/" not in wheel_name and "/" not in sdist_name
    wheel_data, sdist_data = distributions[wheel_name], distributions[sdist_name]
    source_files = witness["files"]
    project = tomllib.loads((SOURCE / "pyproject.toml").read_text())
    build = project["tool"]["hatch"]["build"]
    excluded = build.get("exclude", [])
    expected = {}
    for path in source_files:
        if path.startswith("src/codex_plugin_scanner/") and not any(fnmatch.fnmatchcase(path, p) for p in excluded):
            expected[path.removeprefix("src/")] = [path]
    forced = build["targets"]["wheel"].get("force-include", {})
    assert len(forced) == 16
    for origin, destination in forced.items():
        assert origin in source_files
        expected.setdefault(destination, [])
        if origin not in expected[destination]:
            expected[destination].append(origin)
    wheel_members = {}
    with zipfile.ZipFile(io.BytesIO(wheel_data)) as archive:
        infos = archive.infolist()
        assert len({info.filename for info in infos}) == len(infos)
        assert sum(info.file_size for info in infos) <= 512 * 1024 * 1024
        contents = {}
        for info in infos:
            safe_name(info.filename)
            assert not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16)
            assert stat.S_IFMT(info.external_attr >> 16) in {0, stat.S_IFREG}
            assert not info.flag_bits & 1 and info.file_size <= 128 * 1024 * 1024
            data = archive.read(info)
            assert len(data) == info.file_size
            contents[info.filename] = data
            wheel_members[info.filename] = digest(data)
        records = [name for name in contents if name.endswith(".dist-info/RECORD")]
        assert len(records) == 1
        record_name = records[0]
        metadata_root = record_name.rsplit("/", 1)[0] + "/"
        actual_package = {name for name in contents if name.startswith("codex_plugin_scanner/")}
        assert actual_package == set(expected), "Wheel package membership mismatch"
        for name, origins in expected.items():
            for origin in origins:
                assert wheel_members[name]["sha256"] == source_files[origin]["sha256"]
            wheel_members[name]["source_paths"] = origins
        for name in set(contents) - actual_package:
            assert name.startswith(metadata_root)
            wheel_members[name]["generated_dist_info"] = True
        for name in contents:
            if name.startswith(metadata_root + "licenses/"):
                origin = name.removeprefix(metadata_root + "licenses/")
                assert origin in source_files and wheel_members[name]["sha256"] == source_files[origin]["sha256"]
                wheel_members[name]["source_paths"] = [origin]
        rows = list(csv.reader(io.StringIO(contents[record_name].decode())))
        assert all(len(row) == 3 for row in rows)
        assert len({row[0] for row in rows}) == len(rows)
        assert {row[0] for row in rows} == set(contents)
        for name, hashed, size in rows:
            if name == record_name:
                assert hashed == size == ""
            else:
                encoded = base64.urlsafe_b64encode(hashlib.sha256(contents[name]).digest()).decode().rstrip("=")
                assert hashed == "sha256=" + encoded and size == str(len(contents[name])), name
        metadata = email.message_from_bytes(contents[metadata_root + "METADATA"])
        assert metadata["Name"] == project["project"]["name"] and metadata["Version"] == project["project"]["version"]
    sdist_members = {}
    included = set()
    with tarfile.open(fileobj=io.BytesIO(sdist_data), mode="r:gz") as archive:
        members = archive.getmembers()
        assert 0 < len(members) <= 20000 and len({member.name for member in members}) == len(members)
        assert sum(member.size for member in members) <= 512 * 1024 * 1024
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        assert len(roots) == 1
        prefix = next(iter(roots)) + "/"
        for member in members:
            safe_name(member.name)
            if member.isdir():
                sdist_members[member.name] = {"directory": True}
                continue
            assert member.isfile() and not member.issparse() and member.size <= 128 * 1024 * 1024
            stream = archive.extractfile(member)
            assert stream is not None
            data = stream.read()
            assert len(data) == member.size and member.name.startswith(prefix)
            relative = member.name.removeprefix(prefix)
            row = digest(data)
            if relative == "PKG-INFO":
                metadata = email.message_from_bytes(data)
                assert metadata["Name"] == project["project"]["name"]
                assert metadata["Version"] == project["project"]["version"]
                row["generated_metadata"] = True
            else:
                assert relative in source_files and row["sha256"] == source_files[relative]["sha256"], relative
                included.add(relative)
                row["source_path"] = relative
            assert not relative.startswith("ci/pr2974_source_validation/")
            assert not relative.startswith("ci/pr2974_artifact_audit/")
            assert relative not in {CONFIG["original_workflow_path"], CONFIG["workflow_path"]}
            sdist_members[member.name] = row
    required = {origin for origins in expected.values() for origin in origins} | set(ORIGINAL["fixed_files"])
    assert required <= included
    reconstructed = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "wheel": {"name": wheel_name, **digest(wheel_data), "members": wheel_members,
                  "record_rows": len(rows), "source_mapped_members": len(expected)},
        "sdist": {"name": sdist_name, **digest(sdist_data), "members": sdist_members,
                  "source_mapped_members": len(included)},
        "force_includes": forced, "sdist_required_repaired_tests": sorted(ORIGINAL["fixed_files"]),
        "sdist_omitted_tracked_source_paths": sorted(set(source_files) - included),
        "all_wheel_record_rows_verified": True, "all_actual_members_verified": True,
        "harness_in_artifacts": False, "qualification_complete": False}
    original = parsed(payloads, "package-members.json")
    assert reconstructed == original, "Independently reconstructed package report differs"
    write_json(REPORT / "reconstructed-package-members.json", reconstructed)
    steps = report["commands"]
    build_command = steps["build-wheel-and-sdist"]["command"]
    assert build_command[1:5] == ["-m", "build", "--no-isolation", "--outdir"]
    assert len(build_command) == 7 and build_command[-1] == steps["build-wheel-and-sdist"]["cwd"]
    contract = parsed({"contract": (SOURCE / "docs/guard/contracts/python-capability-ownership.v1.json").read_bytes()}, "contract")
    excluded_candidates = contract["package_excluded_candidates"]
    gates = {}
    for label, name in (("wheel", wheel_name), ("sdist", sdist_name)):
        gate = parsed(payloads, "capability-artifact-" + label + ".json")
        assert gate["status"] == "passed" and gate["dynamic_import_unbounded"] == []
        assert gate["dynamic_import_destinations_checked"] is True
        assert gate["package_exclusions"] == [path for path in excluded_candidates if path in excluded]
        fixture = (SOURCE / contract["parity_fixture"]).read_bytes()
        assert gate["fixture"]["sha256"] == digest(fixture)["sha256"]
        command = steps["capability-artifact-gate-" + label]["command"]
        source_cwd = steps["capability-artifact-gate-" + label]["cwd"]
        assert command[1:5] == [source_cwd + "/scripts/ci/python_capability_cleanup_gate.py", "--root",
                                source_cwd, "--artifact"]
        assert command[5] == build_command[5] + "/" + name and command[6] == "--json"
        assert command[7].endswith("/capability-artifact-" + label + ".json") and len(command) == 8
        for candidate in excluded_candidates:
            package_path = candidate.removeprefix("src/")
            assert package_path not in wheel_members
            assert not any(path == package_path or path.endswith("/" + package_path) for path in sdist_members)
        gates[label] = {"status": gate["status"], "package_exclusions": gate["package_exclusions"],
                        "scope_files": gate["scope_files"], "dynamic_import_count": gate["dynamic_import_count"]}
    summary = {
        "wheel": {"name": wheel_name, **digest(wheel_data), "members": len(wheel_members),
                  "record_rows": len(rows), "source_mapped_members": len(expected)},
        "sdist": {"name": sdist_name, **digest(sdist_data), "members": len(sdist_members),
                  "source_mapped_members": len(included), "omitted_tracked_sources": len(set(source_files) - included)},
        "forced_includes": len(forced), "repaired_tests_in_sdist": sorted(ORIGINAL["fixed_files"]),
        "all_member_source_and_record_hashes_verified": True, "original_package_report_recomputed_equal": True,
        "original_capability_gates": gates, "no_package_import_or_build_reexecuted": True}
    write_json(REPORT / "package-audit.json", summary)
    return summary
