"""Read the two original Mac phase archives; execute no inspected-source workload."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common
from common import CONFIG, HARNESS, INPUTS, OUTPUT, REPORT, SOURCE, digest, failure, frame, git, headers, parsed, safe_name, write_json
from download import api, download, read_zip


def file_bytes(path: Path, *, maximum: int) -> bytes:
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), "Refuse nonregular reader input"
    assert before.st_uid == os.getuid(), "Reader input owner differs"
    assert 0 <= before.st_size <= maximum, "Reader input exceeds byte limit"
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                            value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    assert fields(before) == fields(opened) == fields(after) == fields(path.lstat()), "Reader input changed"
    assert len(data) == before.st_size
    return data


def checkout(root: Path, commit: str, tree: str | None, parents: list[str]) -> dict[str, object]:
    assert root.is_dir() and not root.is_symlink()
    assert git("rev-parse", "HEAD", cwd=root).decode().strip() == commit, "Checkout head mismatch"
    identity = headers(commit, root)
    assert identity["parents"] == parents, "Checkout parent mismatch"
    if tree is not None:
        assert identity["tree"] == tree, "Checkout tree mismatch"
    status = git("status", "--porcelain=v1", "--untracked-files=all", cwd=root)
    assert status == b"", "Checkout is not clean"
    entries = git("ls-tree", "-r", "-z", "--full-tree", commit, cwd=root)
    records = {}
    total = 0
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        name = safe_name(raw_path.decode("utf-8"))
        assert name not in records and kind == "blob" and mode in {"100644", "100755"}
        path = root / name
        assert path.resolve().is_relative_to(root), "Checkout input leaves root"
        data = file_bytes(path, maximum=4 * 1024 * 1024)
        actual_mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        assert actual_mode == mode
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual_blob == blob, "Tracked bytes do not match Git blob: " + name
        records[name] = {"mode": mode, "git_blob": blob, **digest(data)}
        total += len(data)
        assert total <= 64 * 1024 * 1024 and len(records) <= 5000, "Checkout inventory cap"
    return {"root": str(root), "head": commit, **identity, "files": records,
            "file_count": len(records), "total_bytes": total, "clean": True}


def witnesses() -> dict[str, object]:
    source = checkout(SOURCE, CONFIG["source_commit"], CONFIG["source_tree"], [CONFIG["source_parent"]])
    harness = checkout(HARNESS, os.environ["GITHUB_SHA"], None, [CONFIG["source_commit"]])
    assert source["file_count"] == CONFIG["source_file_count"]
    assert source["total_bytes"] == CONFIG["source_bytes"]
    assert set(harness["files"]) - set(source["files"]) == set(CONFIG["additions"])
    assert set(source["files"]).issubset(harness["files"])
    assert all(harness["files"][name] == row for name, row in source["files"].items())
    for name, expected in CONFIG["source_sha256"].items():
        assert source["files"][name]["sha256"] == expected, "Critical source hash mismatch"
    for filename, key in (("common.py", "common_sha256"), ("download.py", "download_sha256")):
        assert digest(file_bytes(HERE / filename, maximum=64 * 1024))["sha256"] == CONFIG["inherited_helpers"][key]
    return {"source": source, "harness": harness, "all_source_leaves_unchanged_in_harness": True}


def runtime() -> dict[str, object]:
    executable = Path(sys.executable).resolve(strict=True)
    value = {"python_version": platform.python_version(), "executable": str(executable),
             "executable_identity": digest(executable.read_bytes()), "platform": sys.platform,
             "uid": os.getuid(), "euid": os.geteuid(), "isolated": sys.flags.isolated,
             "dont_write_bytecode": sys.dont_write_bytecode,
             "complete_environment_certificate": False}
    assert value["python_version"] == CONFIG["python_version"]
    assert value["platform"] == "linux" and value["uid"] != 0 and value["uid"] == value["euid"]
    assert value["isolated"] == 1 and value["dont_write_bytecode"] is True
    return value


def metadata() -> dict[str, object]:
    run_pin = CONFIG["original_run"]
    run = api("/actions/runs/" + str(run_pin["id"]))
    assert all(run.get(key) == expected for key, expected in run_pin.items()), "Original run metadata differs"
    assert run["repository"]["full_name"] == CONFIG["repository"]
    assert run["head_repository"]["full_name"] == CONFIG["repository"]
    jobs_response = api("/actions/runs/" + str(run_pin["id"]) + "/attempts/1/jobs?per_page=100")
    jobs = jobs_response["jobs"]
    assert jobs_response["total_count"] == len(jobs) == len(CONFIG["original_jobs"]) == 2
    assert len({job["id"] for job in jobs}) == 2
    for pin in CONFIG["original_jobs"]:
        job = next(job for job in jobs if job["id"] == pin["id"])
        assert all(job.get(key) == expected for key, expected in pin.items() if key != "steps")
        projection = [{key: step[key] for key in ("number", "name", "status", "conclusion")} for step in job["steps"]]
        assert projection == pin["steps"], "Original step outcomes differ"
    artifacts_response = api("/actions/runs/" + str(run_pin["id"]) + "/artifacts?per_page=100")
    artifacts = artifacts_response["artifacts"]
    assert artifacts_response["total_count"] == len(artifacts) == len(CONFIG["artifacts"]) == 2
    assert len({artifact["id"] for artifact in artifacts}) == 2
    for pin in CONFIG["artifacts"]:
        artifact = next(artifact for artifact in artifacts if artifact["id"] == pin["id"])
        assert artifact["name"] == pin["name"] and artifact["size_in_bytes"] == pin["bytes"]
        assert artifact["digest"] == "sha256:" + pin["sha256"] and artifact["expired"] is False
        bound = artifact["workflow_run"]
        assert bound["id"] == run_pin["id"] and bound["head_sha"] == CONFIG["source_commit"]
        assert bound["head_branch"] == run_pin["head_branch"]
        expected_name = "macos-resolver-path-" + pin["label"] + "-" + CONFIG["source_commit"] + "-" + str(run_pin["id"]) + "-1"
        assert artifact["name"] == expected_name
        assert any(job["id"] == pin["job_id"] and job["name"].endswith(pin["label"] + ")") for job in jobs)
    return {"original_run": run, "original_jobs": jobs, "original_artifacts": artifacts,
            "artifact_architecture_binding": "exact_original_workflow_name_template_and_run_job_matrix_label",
            "original_run_and_jobs_remain_failed": True}


def inspect_archive(pin: dict[str, object], source: dict[str, object]) -> dict[str, object]:
    path = download(pin)
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= CONFIG["limits"]["zip_members"], "Native archive member cap"
        assert sum(info.file_size for info in infos) <= CONFIG["limits"]["zip_content_bytes"], "Native archive raw cap"
        assert all(info.file_size <= CONFIG["limits"]["member_bytes"] for info in infos), "Native member byte cap"
    payloads = read_zip(path, pin["label"])
    original = OUTPUT / "original-json" / pin["label"]
    original.mkdir(parents=True, exist_ok=False)
    # Preserve and emit every audited original byte before asserting report semantics.
    for name, data in sorted(payloads.items()):
        assert "/" not in name and name.endswith(".json"), "Unexpected normalized report path"
        data.decode("utf-8")
        (original / name).write_bytes(data)
        frame("native/" + pin["label"] + "/" + name, data, limit=CONFIG["limits"]["member_bytes"])
    assert sorted(payloads) == CONFIG["expected_members"], "Original normalized report population differs"
    reports = {name: parsed(payloads, name) for name in payloads}
    run = CONFIG["original_run"]
    for name, value in reports.items():
        assert isinstance(value, dict)
        assert value["workflow_commit"] == CONFIG["source_commit"]
        assert value["qualification_pass"] is False
        run_key, attempt_key = ("run", "attempt") if name == "job-outcome.json" else ("workflow_run", "workflow_attempt")
        assert value[run_key] == str(run["id"]) and value[attempt_key] == str(run["run_attempt"])
    prepared_source = reports["prepared.json"]["source"]
    expected_source = {"head": CONFIG["source_commit"],
                       "sha256": {name: source["files"][name]["sha256"] for name in CONFIG["native_report_source_paths"]}}
    assert prepared_source == expected_source, "Prepared report source binding differs"
    for name, value in reports.items():
        for key in ("source", "source_before", "source_after"):
            if key in value:
                assert value[key] == expected_source, "Original report source identity differs: " + name
    report_names = {"prepared": "prepared.json", "original": "resolver-path.json",
                    "python": "python-resolver-path.json", "dnssd": "dnssd-python-path.json"}
    prior_bindings = {}
    for name, value in reports.items():
        matched = {}
        for label, prior_name in report_names.items():
            key = label + "_report_sha256"
            if key in value:
                expected = digest(payloads[prior_name])["sha256"]
                assert value[key] == expected, "Original predecessor report digest differs: " + name
                matched[key] = expected
        if name in {"phase-admission.json", "dnssd-phase-path.json"}:
            assert len(matched) == 4, "Phase report lacks one preceding report binding"
        prior_bindings[name] = matched
    phase = reports["dnssd-phase-path.json"]
    return {"artifact_id": pin["id"], "architecture": pin["label"], "archive": digest(path.read_bytes()),
            "actual_members": {name: digest(data) for name, data in sorted(payloads.items())},
            "all_actual_zip_members_crc_and_sha256_verified": True,
            "all_normalized_original_json_bytes_emitted": True, "source_and_run_bound": True,
            "preceding_report_hash_bindings": prior_bindings,
            "original_report_outcomes": {name: {key: value.get(key) for key in
                ("schema", "status", "stage", "diagnostic_passed", "observation_complete", "qualification_pass")}
                for name, value in reports.items()},
            "phase_rows": phase.get("rows"), "phase_error_type": phase.get("error_type"),
            "original_job_outcome": reports["job-outcome.json"],
            "native_diagnostic_success_required_for_artifact_integrity": False}


def emit_report(path: Path, *, limit: int) -> None:
    frame("audit/" + path.name, path.read_bytes(), limit=limit)


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    result = {"schema": CONFIG["schema"], "audit_passed": False, "status": "started",
              "source_commit": CONFIG["source_commit"], "harness_commit": os.environ.get("GITHUB_SHA"),
              "observer_run_id": os.environ.get("GITHUB_RUN_ID"),
              "observer_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "qualification_complete": False, "original_run_and_jobs_remain_failed": True,
              "workload_executed": False, "artifact_results": [], "errors": []}
    before = None
    runtime_before = None
    try:
        assert os.environ.get("GITHUB_REPOSITORY") == CONFIG["repository"]
        assert os.environ.get("GITHUB_EVENT_NAME") == "push"
        assert os.environ.get("GITHUB_REF") == "refs/heads/" + CONFIG["branch"]
        assert os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        assert SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE)
        assert not OUTPUT.is_relative_to(SOURCE) and not OUTPUT.is_relative_to(HARNESS)
        assert HERE == HARNESS / "ci/pr2974_macos_phase_artifact_audit"
        runtime_before = runtime()
        write_json(REPORT / "runtime-before.json", runtime_before)
        before = witnesses()
        write_json(REPORT / "source-before.json", before)
        actual_metadata = metadata()
        write_json(REPORT / "original-metadata.json", actual_metadata)
        for pin in CONFIG["artifacts"]:
            try:
                audited = inspect_archive(pin, before["source"])
                write_json(REPORT / (pin["label"] + "-audit.json"), audited)
                result["artifact_results"].append({"artifact_id": pin["id"], "architecture": pin["label"], "passed": True})
            except BaseException as error:
                detail = {"artifact_id": pin["id"], "architecture": pin["label"], "passed": False, "error": failure(error)}
                result["artifact_results"].append(detail)
                write_json(REPORT / (pin["label"] + "-audit-failure.json"), detail)
    except BaseException as error:
        result["errors"].append({"stage": "admission_or_metadata", "error": failure(error)})
    finally:
        try:
            after = witnesses()
            write_json(REPORT / "source-after.json", after)
            result["source_and_harness_unchanged"] = before is not None and after == before
            runtime_after = runtime()
            write_json(REPORT / "runtime-after.json", runtime_after)
            result["reader_runtime_unchanged"] = runtime_before is not None and runtime_after == runtime_before
        except BaseException as error:
            result["errors"].append({"stage": "final_witness", "error": failure(error)})
        try:
            for path in sorted(REPORT.glob("*.json")):
                if path.name == "readout-outcome.json":
                    continue
                limit = CONFIG["limits"]["source_map_frame_bytes"] if path.name.startswith("source-") else CONFIG["limits"]["small_report_frame_bytes"]
                emit_report(path, limit=limit)
        except BaseException as error:
            result["errors"].append({"stage": "audit_report_framing", "error": failure(error)})
        result["loaded_inspected_source_modules"] = [
            {"module": name, "file": str(Path(module.__file__).resolve())}
            for name, module in sorted(sys.modules.items())
            if isinstance(getattr(module, "__file__", None), str)
            and Path(module.__file__).resolve().is_relative_to(SOURCE)
        ]
        result["audit_passed"] = (
            not result["errors"] and len(result["artifact_results"]) == 2
            and all(item["passed"] for item in result["artifact_results"])
            and result.get("source_and_harness_unchanged") is True
            and result.get("reader_runtime_unchanged") is True
            and not result["loaded_inspected_source_modules"]
        )
        result["status"] = "completed" if result["audit_passed"] else "audit_failed"
        result["prior_frame_count"] = len(common.EMITTED)
        result["prior_raw_frame_bytes"] = common.EMITTED_RAW
        result["prior_gzip_frame_bytes"] = common.EMITTED_COMPRESSED
        write_json(REPORT / "readout-outcome.json", result)
        try:
            emit_report(REPORT / "readout-outcome.json", limit=CONFIG["limits"]["small_report_frame_bytes"])
        except BaseException as error:
            result["audit_passed"] = False
            result["status"] = "outcome_framing_failed"
            result["errors"].append({"stage": "outcome_framing", "error": failure(error)})
            write_json(REPORT / "readout-outcome.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
