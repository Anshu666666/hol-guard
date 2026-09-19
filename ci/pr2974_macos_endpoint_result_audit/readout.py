"""Read original ARM results and Intel admission failure; execute no inspected-source workload."""

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
        expected_name = "macos-endpoint-" + pin["label"] + "-" + CONFIG["source_commit"] + "-" + str(run_pin["id"]) + "-1"
        assert artifact["name"] == expected_name
        assert any(job["id"] == pin["job_id"] and job["name"].endswith(pin["label"] + ")") for job in jobs)
    return {"original_run": run, "original_jobs": jobs, "original_artifacts": artifacts,
            "artifact_architecture_binding": "exact_original_workflow_name_template_and_run_job_matrix_label",
            "original_run_and_jobs_remain_failed": True}


def finite_cases(payloads: dict[str, bytes]) -> dict[str, object]:
    from xml.etree import ElementTree
    data = payloads["finite-junit.xml"]
    assert len(data) <= 256 * 1024 and b"<!DOCTYPE" not in data and b"<!ENTITY" not in data
    xml = ElementTree.fromstring(data)
    assert xml.tag == "testsuites" and len(xml) == 1 and xml[0].tag == "testsuite"
    suite = xml[0]
    assert {key: int(suite.attrib[key]) for key in ("tests", "failures", "errors", "skipped")} == {
        "tests": 83, "failures": 0, "errors": 0, "skipped": 0}
    cases = list(suite)
    assert len(cases) == 83 and all(case.tag == "testcase" for case in cases)
    keys = [(case.attrib["classname"], case.attrib["name"]) for case in cases]
    assert len(set(keys)) == 83 and all(not list(case) for case in cases)
    expected = [(row["classname"], row["function"]) for row in CONFIG["finite_functions"] for _ in range(row["cases"])]
    assert [(owner, name.split("[", 1)[0]) for owner, name in keys] == expected, "Ordered source-function/JUnit population differs"
    text = payloads["finite.log"].decode("utf-8", errors="strict")
    import re
    summaries = re.findall(r"(?m)^83 passed in [0-9]+(?:\.[0-9]+)?s\s*$", text)
    assert len(summaries) == 1 and not re.search(r"(?m)^(?:FAILED |ERROR |SKIPPED |XFAIL |XPASS )", text)
    return {"passed": 83, "failed": 0, "errors": 0, "skipped": 0, "ordered_junit_keys": keys,
            "source_function_counts_checked": True, "actual_parameter_names_retained": True,
            "independent_collection_or_fixture_phase_observer_claimed": False,
            "compiler_controls_within_these_cases": 9, "old475_replayed": False}


def lookup_cases(value: dict[str, object], prepared: dict[str, object]) -> dict[str, object]:
    assert value["schema"] == prepared["schema"]
    for key in ("workflow_commit", "workflow_run", "workflow_attempt"):
        assert value[key] == prepared[key], "Lookup run binding"
    for key in ("qualification_pass", "cause_proved", "same_OFD_claimed", "daemon_acceptance_claimed",
                "internal_library_thread_census_claimed", "prior_children_replayed",
                "current_runtime_equal_to_historical_claimed"):
        assert value[key] is False
    assert value["prepared_report_unchanged"] is True
    controls = [(context, mode) for context in ("standalone", "native_dlopen", "python")
                for mode in ("dns_simple", "dns_shared")]
    rows = value["rows"]
    assert isinstance(rows, list) and 0 <= len(rows) <= 6
    assert [(row["context"], row["mode"]) for row in rows] == controls[:len(rows)]
    pids = []
    for index, row in enumerate(rows):
        capture, metadata = row["capture"], row["metadata"]
        assert capture["deadline_seconds"] == 5.0
        assert capture["descendant_retirement_verified"] is False and capture["service_quiescence_verified"] is False
        pid = capture["pid"]
        assert pid is None or (type(pid) is int and 0 < pid < 2**31)
        if pid is not None:
            pids.append(pid)
            if index + 1 < len(rows):
                assert capture["direct_child_reaped"] is True, "Later child after unproved retirement"
        for channel in ("stdout", "stderr"):
            assert type(capture[channel + "_bytes"]) is int and 0 <= capture[channel + "_bytes"] <= 16385
        clean = (capture.get("status") == "completed" and capture.get("return_code") == 0
                 and capture.get("direct_child_reaped") is True and capture.get("termination_attempted") is False
                 and capture.get("stderr_bytes") == 0
                 and not any(key in capture for key in ("cleanup_error", "kill_errno", "output_limit", "error_type")))
        assert type(metadata["valid"]) is bool and type(metadata["complete"]) is bool
        assert type(metadata["loopback_label"]) is bool
        assert row["lookup_passed"] == (clean and metadata["complete"] and metadata["loopback_label"])
        if metadata["valid"]:
            assert metadata["raw_endpoint_exported"] is False
            assert isinstance(metadata["records"], list) and len(metadata["records"]) <= 61
            endpoint = metadata["endpoint"]
            assert isinstance(endpoint, dict) and endpoint["pid"] == pid
            assert endpoint["context"] == {"standalone": 0, "native_dlopen": 1, "python": 2}[row["context"]]
            for key in ("atomic_fd_snapshot_claimed", "same_OFD_claimed", "daemon_acceptance_claimed",
                        "mapped_executable_bytes_hashed", "internal_thread_census_claimed"):
                assert endpoint[key] is False
            assert all("hex" not in endpoint[key] for key in ("local", "peer"))
    # PID reuse is possible after reaping; retain the observed IDs without inventing an all-run PID guarantee.
    bindings = {}
    for key in ("source", "tools", "runtime", "historical", "images"):
        if key + "_before" in value and key != "images":
            assert value[key + "_before"] == prepared[key]
        if key + "_unchanged" in value:
            equal = value[key + "_before"] == value[key + "_after"]
            assert value[key + "_unchanged"] == equal
            bindings[key] = equal
    if value["status"] == "experiment_finished":
        assert len(rows) == 6 and set(bindings) == {"source", "tools", "runtime", "historical", "images"}
        complete = all(bindings.values()) and all(
            row["capture"]["direct_child_reaped"]
            and row["capture"].get("status") in ("completed", "deadline_exceeded")
            and row["capture"].get("stderr_bytes") == 0
            and not any(key in row["capture"] for key in ("cleanup_error", "kill_errno", "output_limit", "error_type"))
            and row["metadata"]["valid"] and not row["metadata"].get("partial_line")
            and not row["metadata"].get("trace_overflow")
            and (row["capture"]["status"] != "completed" or row["metadata"]["complete"])
            and row["metadata"]["endpoint"]["observation_complete"] for row in rows)
        assert value["observation_complete"] == complete
        assert value["diagnostic_passed"] == (complete and all(row["lookup_passed"] for row in rows))
    return {"status": value["status"], "stage": value["stage"], "diagnostic_passed": value["diagnostic_passed"],
            "observation_complete": value["observation_complete"], "observed_children": len(rows),
            "ordered_controls": [(row["context"], row["mode"]) for row in rows], "observed_pids": pids,
            "passed_lookup_count": sum(row["lookup_passed"] for row in rows), "rows": rows,
            "images_before": value.get("images_before"), "images_after": value.get("images_after"),
            "bindings": bindings, "comparison": value.get("comparison"), "cause_proved": False,
            "raw_stdout_or_native_protocol_reparse_claimed": False}


def inspect_archive(pin: dict[str, object], source: dict[str, object]) -> dict[str, object]:
    path = download(pin)
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= CONFIG["limits"]["zip_members"], "Endpoint archive member cap"
        assert sum(info.file_size for info in infos) <= CONFIG["limits"]["zip_content_bytes"], "Endpoint archive raw cap"
        assert all(info.file_size <= CONFIG["limits"]["member_bytes"] for info in infos), "Endpoint member byte cap"
    payloads = read_zip(path, pin["label"])
    original = OUTPUT / "original-json" / pin["label"]
    original.mkdir(parents=True, exist_ok=False)
    # Every original JSON, JUnit and log member is retained before any interpretation or pass assertion.
    for name, data in sorted(payloads.items()):
        destination = original / safe_name(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        frame("native/" + pin["label"] + "/" + name, data, limit=CONFIG["limits"]["member_bytes"])
    assert sorted(payloads) == pin["expected_members"], "Original endpoint report population differs"
    reports = {name: parsed(payloads, name) for name in payloads if name.endswith(".json")}
    assert all(isinstance(value, dict) for value in reports.values())
    run = CONFIG["original_run"]
    for name in ("prepared.json", "final-witness.json", "job-outcome.json"):
        value = reports[name]
        assert value["workflow_commit"] == CONFIG["source_commit"] and value["qualification_pass"] is False
        run_key, attempt_key = ("run", "attempt") if name == "job-outcome.json" else ("workflow_run", "workflow_attempt")
        assert value[run_key] == str(run["id"]) and value[attempt_key] == str(run["run_attempt"])
    prepared, final, outcome = (reports[name] for name in ("prepared.json", "final-witness.json", "job-outcome.json"))
    assert prepared["schema"] == "hol-guard.macos-dnssd-endpoint-context.v1"
    assert final["schema"] == "hol-guard.macos-endpoint-final-witness.v1"
    assert outcome["status"] == "finished" and outcome["prior_children_replayed"] is False
    assert outcome["steps"] == pin["normalized_steps"] and outcome["cause_proved"] is False
    assert outcome["final_witness_retained"] is True
    assert outcome["final_witness_file"] == digest(payloads["final-witness.json"])
    expected_source = {
        "head": CONFIG["source_commit"],
        "historical_files": {name: source["files"][name]["sha256"] for name in CONFIG["historical_source_paths"]},
        "added_files": {name: source["files"][name]["sha256"] for name in CONFIG["endpoint_source_paths"]},
    }
    assert prepared["source"] == expected_source, "Prepared source binding differs"
    before, after = reports["environment-before.json"], reports["environment-after.json"]
    assert before == after and before["schema"] == "hol-guard.macos-endpoint-validation-environment.v1"
    assert before["python_version"].split()[0] == "3.12.10"
    assert before["expected_versions"] == CONFIG["expected_native_versions"]
    assert before["qualification_pass"] is False and before["scope"] == "fixed_nine_distribution_files_and_interpreter"
    environment_source = "scripts/ci/native_macos_dnssd_endpoint_environment.py"
    assert before["observer_source"] == {
        "sha256": source["files"][environment_source]["sha256"], "bytes": source["files"][environment_source]["bytes"]}
    assert isinstance(before["files"], dict) and 0 < len(before["files"]) <= 30000
    for name, identity in before["files"].items():
        assert isinstance(name, str) and name.startswith("/") and set(identity) == {"bytes", "sha256"}
        assert type(identity["bytes"]) is int and 0 <= identity["bytes"] <= 256 * 1024 * 1024
        assert isinstance(identity["sha256"], str) and len(identity["sha256"]) == 64
        assert all(letter in "0123456789abcdef" for letter in identity["sha256"])
    lookups = reports.get("endpoint-context.json", {})
    for key, filename in (("prepared", "prepared.json"), ("lookups", "endpoint-context.json")):
        row = final["inputs"][key]
        if filename in payloads:
            assert row["observed"] is True
            value = row["value"]
            assert value["sha256"] == digest(payloads[filename])["sha256"]
            assert value["current_run"] is True and value["report"] == reports[filename]
        else:
            assert row["observed"] is False
    expected_pin = (lookups.get("prepared_report_sha256") == digest(payloads["prepared.json"])["sha256"]
                    if isinstance(lookups.get("prepared_report_sha256"), str) else None)
    assert final["prepared_report_unchanged"] is expected_pin
    assert final["diagnostic_outcome_replaced"] is False and final["cause_proved"] is False
    assert final["original_status"] == {"prepared": prepared.get("status"), "lookups": lookups.get("status")}
    assert final["original_diagnostic_passed"] == lookups.get("diagnostic_passed")
    assert set(final["bindings"]) == {"source", "historical", "runtime", "tools"}
    assert set(final["images"]) == {"standalone", "native_dlopen", "bridge"}
    def comparison(after: dict[str, object], baseline: object) -> dict[str, object]:
        if after["observed"] is not True:
            return {"baseline_available": baseline is not None, "unchanged": False, "status": "final_observation_failed"}
        if baseline is None:
            return {"baseline_available": False, "unchanged": None, "status": "baseline_unavailable"}
        equal = after["value"] == baseline
        return {"baseline_available": True, "unchanged": equal, "status": "unchanged" if equal else "changed"}
    for name, row in final["bindings"].items():
        assert row["comparison"] == comparison(row["after"], lookups.get(name + "_before", prepared.get(name)))
        if name == "source" and row["after"]["observed"] is True:
            assert row["after"]["value"] == expected_source
    for name, image in final["images"].items():
        consistent = (image["file"]["observed"] and image["macho"]["observed"]
                      and image["file"]["value"]["sha256"] == image["macho"]["value"]["sha256"])
        assert image["file_and_macho_hashes_match"] == consistent
        assert image["comparison"] == comparison(image["macho"], lookups.get("images_before", {}).get(name))
        assert image["separate_snapshot_race_exclusion_claimed"] is False
    unchanged = (expected_pin is True and all(row["comparison"]["unchanged"] is True for row in final["bindings"].values())
                 and all(row["comparison"]["unchanged"] is True and row["file_and_macho_hashes_match"]
                         for row in final["images"].values()))
    assert final["all_unchanged"] == unchanged
    assert final["status"] == ("witness_complete" if unchanged else "witness_incomplete")
    assert (outcome["steps"]["final_witness"] == "success") == unchanged
    if pin["label"] == "arm64":
        assert prepared["status"] == "prepared" and prepared["stage"] == "complete"
        assert set(outcome["compiler"]) == {prefix + "." + channel for prefix in ("direct", "bridge", "host")
                                           for channel in ("stdout", "stderr")}
        finite, observed = finite_cases(payloads), lookup_cases(lookups, prepared)
    else:
        assert prepared["status"] == "admission_failed" and outcome["compiler"] == {} and not lookups
        finite, observed = {"executed": 0, "reason": "original_prepare_failed"}, {"observed_children": 0}
    return {
        "artifact_id": pin["id"], "architecture": pin["label"], "archive": digest(path.read_bytes()),
        "actual_members": {name: digest(data) for name, data in sorted(payloads.items())},
        "all_actual_zip_members_crc_and_sha256_verified": True,
        "all_original_report_bytes_emitted_before_semantic_checks": True,
        "source_and_run_bound": True, "original_native_environment_observations_equal": True,
        "native_environment_observed_file_count": len(before["files"]),
        "native_environment_file_bytes_reobserved_by_reader": False,
        "prepared_status": {key: prepared.get(key) for key in
                            ("schema", "status", "stage", "error_type", "identity_command_failure")},
        "final_status": {key: final.get(key) for key in ("schema", "status", "stage", "all_unchanged")},
        "final_images": final["images"], "final_bindings": final["bindings"], "original_job_outcome": outcome,
        "finite": finite, "lookup_observations": observed, "original_run_and_jobs_remain_failed": True,
        "failure_cause_not_inferred_from_missing_reports": True, "native_success_required_for_artifact_integrity": False,
    }

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
        assert HERE == HARNESS / "ci/pr2974_macos_endpoint_result_audit"
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
