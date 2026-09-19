"""Read the one original failed Intel artifact; verify bytes before installation."""

from __future__ import annotations

import base64
import csv
import io
import json
from pathlib import PurePosixPath
import stat
import tomllib
import zipfile

from common import CONFIG, INPUTS, REPORT, SOURCE, digest, safe_name, write_json
from download import api, download, read_zip


def original_inputs():
    pin = CONFIG["artifact"]
    run = api("/actions/runs/" + str(CONFIG["original_run_id"]))
    assert run["id"] == CONFIG["original_run_id"] and run["head_sha"] == CONFIG["source_sha"]
    assert run["run_attempt"] == 1 and run["event"] == "pull_request"
    assert run["status"] == "completed" and run["conclusion"] == "failure"
    job = api("/actions/jobs/" + str(CONFIG["original_job_id"]))
    assert job["run_id"] == run["id"] and job["id"] == CONFIG["original_job_id"]
    assert job["status"] == "completed" and job["conclusion"] == "failure"
    failing = [step["name"] for step in job["steps"] if step["conclusion"] == "failure"]
    assert failing == ["Measure installed adapter-to-decision SLOs"], failing
    metadata = api("/actions/artifacts/" + str(pin["id"]))
    assert metadata["name"] == pin["name"] and metadata["size_in_bytes"] == pin["bytes"]
    assert metadata["digest"] == "sha256:" + pin["sha256"] and not metadata["expired"]
    assert metadata["workflow_run"]["id"] == run["id"]
    assert metadata["workflow_run"]["head_sha"] == CONFIG["source_sha"]
    merge = api("/git/commits/" + CONFIG["original_build_sha"])
    assert merge["tree"]["sha"] == CONFIG["source_tree"]
    assert [row["sha"] for row in merge["parents"]] == [CONFIG["release_base"], CONFIG["source_sha"]]
    values = read_zip(download(pin), "original-intel")
    wheels = [name for name in values if name.endswith(".whl")]
    assert len(wheels) == 1
    wheel_name = PurePosixPath(wheels[0]).name
    assert wheel_name == "hol_guard-3.0.1-py3-none-macosx_13_0_x86_64.whl"
    original_json = {}
    for name, data in values.items():
        if name in wheels:
            continue
        assert name.endswith(".json"), name
        basename = PurePosixPath(name).name
        assert basename not in original_json
        original_json[basename] = json.loads(data)
        destination = REPORT / "original" / basename
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    assert original_json["native-installed-slo.json"] == CONFIG["original_slo"]
    assert original_json["native-installed-identity.json"] == CONFIG["original_identity"]
    wheel_path = INPUTS / wheel_name
    wheel_path.write_bytes(values[wheels[0]])
    verify_wheel(wheel_path)
    return wheel_path


def verify_wheel(path):
    members = {}
    raw = {}
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= 16384 and len({i.filename for i in infos}) == len(infos)
        assert sum(i.file_size for i in infos) <= 128 * 1024 * 1024
        for info in infos:
            safe_name(info.filename)
            assert not info.flag_bits & 1 and info.file_size <= 64 * 1024 * 1024
            kind = stat.S_IFMT(info.external_attr >> 16)
            assert kind in {0, stat.S_IFREG, stat.S_IFDIR}
            if info.is_dir():
                assert info.file_size == 0
                continue
            assert kind != stat.S_IFDIR
            data = archive.read(info)
            assert len(data) == info.file_size
            raw[info.filename] = data
            members[info.filename] = {**digest(data), "crc32": info.CRC,
                                      "mode": (info.external_attr >> 16) & 0o777}
    records = [name for name in raw if name.endswith(".dist-info/RECORD")]
    assert len(records) == 1
    record_name = records[0]
    rows = list(csv.reader(io.StringIO(raw[record_name].decode())))
    assert all(len(row) == 3 for row in rows)
    assert len({row[0] for row in rows}) == len(rows)
    assert {row[0] for row in rows} == set(raw)
    for name, hashed, size in rows:
        if name == record_name:
            assert hashed == size == ""
        else:
            expected = base64.urlsafe_b64encode(bytes.fromhex(members[name]["sha256"])).decode().rstrip("=")
            assert hashed == "sha256=" + expected and size == str(len(raw[name])), name
    runtime_name = "codex_plugin_scanner/_native/hol-guard-runtime"
    manifest_name = "codex_plugin_scanner/_native/runtime-manifest.json"
    identity = CONFIG["original_identity"]
    assert members[runtime_name]["sha256"] == identity["runtime_sha256"]
    assert members[runtime_name]["bytes"] == identity["runtime_size"]
    assert members[runtime_name]["mode"] & 0o111
    assert members[manifest_name]["sha256"] == identity["manifest_sha256"]
    source_matches, other_members = {}, []
    for name, data in raw.items():
        source = SOURCE / "src" / name
        if name.startswith("codex_plugin_scanner/") and source.is_file():
            assert source.read_bytes() == data, name
            source_matches[name] = members[name]["sha256"]
        else:
            other_members.append(name)
    forced = tomllib.loads((SOURCE / "pyproject.toml").read_text())["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for origin, destination in forced.items():
        assert destination in raw and (SOURCE / origin).read_bytes() == raw[destination], destination
        source_matches[destination] = members[destination]["sha256"]
        if destination in other_members:
            other_members.remove(destination)
    assert source_matches
    assert all(name in source_matches for name in raw
               if name.startswith("codex_plugin_scanner/") and name.endswith(".py"))
    write_json(REPORT / "wheel-verification.json", {
        "wheel": digest(path.read_bytes()), "wheel_path": str(path), "members": members,
        "record": record_name, "record_complete_and_all_hashes_verified": True,
        "runtime_member": runtime_name, "runtime_manifest_member": manifest_name,
        "mapped_source_members": source_matches,
        "members_without_direct_src_mapping": other_members,
        "original_installation_record_hash_is_informational": True,
        "installation_may_regenerate_RECORD_and_direct_url_metadata": True,
        "qualification_complete": False})
