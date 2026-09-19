"""Audit original immutable source, environment, command and failure records as data."""

from __future__ import annotations

import ast
import base64
import io
import json
import re
import tokenize
import tomllib
from pathlib import PurePosixPath

from common import CONFIG, EVIDENCE, ORIGINAL, REPORT, SOURCE, digest, frame, git, parsed, write_json


def original_log() -> dict:
    data = EVIDENCE["log"].encode("utf-8")
    assert digest(data) == EVIDENCE["log_utf8"] == CONFIG["original_log"]
    commands = []
    retained = []
    active = None
    records = {}
    failures = []
    for line in EVIDENCE["log"].splitlines():
        match = re.search(r"MACOS_FINITE_COMMAND (\{.*\})$", line)
        if match:
            commands.append(json.loads(match[1]))
        match = re.search(r"MACOS_FINITE_FILE_BEGIN (\{.*\})$", line)
        if match:
            assert active is None
            meta = json.loads(match[1])
            assert meta["kind"] not in records
            active = {"meta": meta, "chunks": []}
        match = re.search(r"MACOS_FINITE_FILE_CHUNK (\S+) (\d+)/(\d+) ([A-Za-z0-9+/=]+)$", line)
        if match:
            assert active is not None and match[1] == active["meta"]["kind"]
            assert int(match[2]) == len(active["chunks"]) + 1
            assert int(match[3]) == active["meta"]["chunks"]
            assert len(match[4]) <= active["meta"]["chunk_characters"] == 1024
            active["chunks"].append(match[4])
        match = re.search(r"MACOS_FINITE_FILE_END (\S+)$", line)
        if match:
            assert active is not None and match[1] == active["meta"]["kind"]
            assert len(active["chunks"]) == active["meta"]["chunks"]
            raw = base64.b64decode("".join(active["chunks"]), validate=True)
            assert digest(raw) == {key: active["meta"][key] for key in ("bytes", "sha256")}
            records[match[1]] = raw
            active = None
        if 'Z {"actual_finite_results": ' in line:
            retained.append(json.loads(line.split("Z ", 1)[1]))
        if "AssertionError:" in line:
            failures.append(line.split("Z ", 1)[-1])
    assert active is None and set(records) == {"finite-results.json"}
    assert commands == EVIDENCE["actual_commands"] and len(commands) == 15
    assert retained == [EVIDENCE["original_retained_workflow_outcome"]]
    expected_failure = ("AssertionError: ('/home/runner/work/_temp/pr2974-macos-phase-finite/"
                        "report/finite-junit-log-copy.json', 1208096, 262144)")
    assert failures == [expected_failure]
    assert digest(records["finite-results.json"]) == CONFIG["finite_frame"]
    assert json.loads(records["finite-results.json"]) == retained[0]["actual_finite_results"]
    result = {"log": digest(data), "original_command_records": 15, "complete_frames": ["finite-results.json"],
              "actual_framing_failure": failures[0], "original_driver_outcome": "failure",
              "original_workflow_conclusion": "failure", "original_failure_preserved": True}
    write_json(REPORT / "original-log-audit.json", result)
    return result


def audit_reports(payloads: dict[str, bytes], witness: dict) -> dict:
    manifest = parsed(payloads, "artifact-manifest.json")
    assert digest(payloads["artifact-manifest.json"])["sha256"] == CONFIG["artifact_manifest_sha256"]
    assert len(manifest) == 114 and len(payloads) == 115
    assert set(payloads) == set(manifest) | {"artifact-manifest.json"}
    for name, expected in manifest.items():
        assert digest(payloads[name]) == expected, name
    before, after = parsed(payloads, "source-before.json"), parsed(payloads, "source-after.json")
    assert before == after == witness
    assert payloads["source-before.json"] == payloads["source-after.json"]
    outcome = parsed(payloads, "job-outcome.json")
    assert outcome == EVIDENCE["original_retained_workflow_outcome"]
    assert outcome["source_sha"] == CONFIG["source_sha"] and outcome["source_tree"] == CONFIG["source_tree"]
    assert outcome["harness_sha"] == CONFIG["original_harness_sha"]
    assert outcome["run_id"] == str(CONFIG["original_run_id"]) and outcome["run_attempt"] == "1"
    assert outcome["status"] == "finished" and outcome["passed"] is True and outcome["errors"] == []
    assert outcome["source_unchanged"] is True and outcome["environment_unchanged"] is True
    assert outcome["finite_execution_credit"] is True  # Retained pre-framing driver field, not observer credit.
    assert outcome["pre_upload_gate_passed"] is False
    assert outcome["workflow_step_outcomes"] == {
        "HARNESS_CHECKOUT": "success", "SOURCE_CHECKOUT": "success", "PYTHON_SETUP": "success",
        "UV_SETUP": "success", "DRIVER_OUTCOME": "failure"}
    for name in ("native_qualification_credit", "installed_qualification_credit", "qualification_complete"):
        assert outcome[name] is False
    steps = parsed(payloads, "steps.json")
    assert steps == outcome["steps"] == EVIDENCE["actual_commands"]
    assert len({row["name"] for row in steps}) == len(steps) == 15
    for row in steps:
        assert row["passed"] is True and row["returncode"] == 0
        assert row["timed_out"] is False and row["log_limit_exceeded"] is False
        assert "error" not in row and "cleanup_error" not in row
        assert digest(payloads[row["name"] + ".log"]) == {
            "sha256": row["log_sha256"], "bytes": row["log_bytes"]}
    identity = parsed(payloads, "identity-summary.json")
    expected_names = {"source-before.json", "source-after.json", "environment-before.json",
                      "environment-after.json", "pytest-capture.json", "finite-junit.xml"}
    assert set(identity) == expected_names
    for name, expected in identity.items():
        assert digest(payloads[name]) == expected, name
    harness = parsed(payloads, "harness.json")
    assert harness == {"sha": CONFIG["original_harness_sha"], "tree": CONFIG["original_harness_tree"],
                       "parents": [CONFIG["source_sha"]], "files": CONFIG["original_files"]}
    summary = parsed(payloads, "finite-results.json")
    assert digest(payloads["finite-results.json"]) == CONFIG["finite_frame"]
    assert summary == outcome["actual_finite_results"]
    result = {"all_115_original_members_hash_verified": True, "original_command_count": 15,
              "all_original_commands_passed": True, "source_files": len(witness["files"]),
              "source_maps_equal_current_immutable_git_bytes": True,
              "original_pre_framing_driver_passed_field": True,
              "original_pre_upload_gate_passed": False, "original_workflow_failure_preserved": True,
              "original_outcome": digest(payloads["job-outcome.json"])}
    write_json(REPORT / "original-reports-audit.json", result)
    return result


def audit_syntax_and_admission(payloads: dict[str, bytes]) -> dict:
    before, after = parsed(payloads, "syntax-before.json"), parsed(payloads, "syntax-after.json")
    assert before == after and set(before) == set(ORIGINAL["python_files"])
    for path, row in before.items():
        data = (SOURCE / path).read_bytes()
        tree = ast.parse(data, filename=path)
        expected_ast = (ast.dump(tree, include_attributes=False, indent=2) + "\n").encode()
        constants = [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                     if isinstance(node, ast.Constant)]
        tokens = [{"type": token.type, "name": tokenize.tok_name[token.type], "string": token.string,
                   "start": list(token.start), "end": list(token.end), "line": token.line}
                  for token in tokenize.tokenize(io.BytesIO(data).readline)]
        assert row["source_sha256"] == digest(data)["sha256"]
        for suffix, field in ((".ast.txt", "ast_sha256"), (".normalized-ast.txt", "import_normalized_ast_sha256"),
                              (".tokens.json", "tokens_sha256"), (".literals.json", "literals_sha256")):
            a = "syntax/before/" + str(PurePosixPath(path).with_suffix(suffix))
            b = "syntax/after/" + str(PurePosixPath(path).with_suffix(suffix))
            assert payloads[a] == payloads[b] and digest(payloads[a])["sha256"] == row[field], a
        assert payloads["syntax/before/" + str(PurePosixPath(path).with_suffix(".ast.txt"))] == expected_ast
        assert parsed(payloads, "syntax/before/" + str(PurePosixPath(path).with_suffix(".tokens.json"))) == tokens
        assert parsed(payloads, "syntax/before/" + str(PurePosixPath(path).with_suffix(".literals.json"))) == constants
    bridge = parsed(payloads, "format-equivalence.json")
    assert set(bridge["files"]) == set(before)
    expected_fields = {"raw_ast_identical", "import_normalized_ast_identical", "literal_values_identical",
                       "token_records_identical", "source_bytes_identical"}
    assert all(set(row) == expected_fields and all(value is True for value in row.values())
               for row in bridge["files"].values())
    assert bridge["semantic_equivalence_claim"] is False
    admission = parsed(payloads, "original-admission-preserved.json")
    assert admission == CONFIG["admission_expected"]
    assert admission["public_parent"] == CONFIG["source_parent"]
    driver = "scripts/ci/native_macos_resolver_path.py"
    prior = git("show", CONFIG["source_parent"] + ":" + driver)
    current = (SOURCE / driver).read_bytes()
    assert digest(prior)["sha256"] == admission["original_driver_sha256"]
    assert digest(current)["sha256"] == admission["driver_sha256"]
    def closure(data):
        tree = ast.parse(data)
        matches = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "SOURCES" for target in node.targets)]
        assert len(matches) == 1
        paths = ast.literal_eval(matches[0].value)
        tree.body.remove(matches[0])
        return ast.dump(tree, include_attributes=False), paths
    old_ast, old_paths = closure(prior)
    new_ast, new_paths = closure(current)
    assert old_ast == new_ast and list(new_paths) == admission["source_closure"]
    additions = [path for path in new_paths if path not in old_paths]
    assert len(additions) == 9 and tuple(path for path in new_paths if path not in additions) == old_paths
    restored = current
    for path in additions:
        line = ('    "' + path + '",\n').encode()
        assert restored.count(line) == 1
        restored = restored.replace(line, b"")
    assert restored == prior
    for path, expected in ORIGINAL["preserved_files"].items():
        assert (SOURCE / path).read_bytes() == git("show", CONFIG["source_parent"] + ":" + path)
        assert digest((SOURCE / path).read_bytes())["sha256"] == expected
    assert len(admission["original_steps"]) == 17 and len(admission["added_steps"]) == 4
    assert admission["original_steps_preserved_except_explicit_additions"] is True
    assert digest((SOURCE / ".github/workflows/native-macos-resolver-path.yml").read_bytes())["sha256"] == (
        admission["workflow_sha256"])
    result = {"nine_source_ast_token_literal_snapshots_reconstructed": True,
              "all_original_before_after_snapshot_bytes_identical": True,
              "original_driver_reconstructed_byte_for_byte": True, "original_closure_additions": 9,
              "unchanged_original_files": len(ORIGINAL["preserved_files"]),
              "prior_reviewed_admission_record_rebound_to_actual_source": True,
              "broad_semantic_equivalence_claim": False}
    write_json(REPORT / "source-and-admission-audit.json", result)
    return result


def audit_environment(payloads: dict[str, bytes]) -> dict:
    before, after = parsed(payloads, "environment-before.json"), parsed(payloads, "environment-after.json")
    assert before == after and payloads["environment-before.json"] == payloads["environment-after.json"]
    assert before["installed_versions"] == ORIGINAL["installed_versions"]
    assert set(before["distribution_metadata_sha256"]) == set(ORIGINAL["installed_versions"])
    assert len(before["installed_versions"]) == 9
    host = parsed(payloads, "host.json")
    assert before["python_version"] == host["python_version"]
    assert before["python_version"].split(" ", 1)[0] == CONFIG["python_version"]
    assert before["image"] == host["image"]
    assert host["uname"][0] == "Linux" and host["uname"][-1] == "x86_64"
    assert set(before["launchers"]) == {"python", "python3", "python3.12"}
    for name, row in before["launchers"].items():
        assert row == {"sha256": host["python_sha256"], "mode": "0755", "uid": host["uid"]}
        assert before["files"]["bin/" + name]["sha256"] == row["sha256"]
        assert before["files"]["bin/" + name]["mode"] == "0o755"
    assert set(before["runtime_extensions"]) == {"_socket", "_ctypes"}
    hashes = [row["sha256"] for row in before["runtime_extensions"].values()]
    hashes += list(before["distribution_metadata_sha256"].values())
    hashes += [before["process_environment_sha256"], host["python_sha256"]]
    assert all(re.fullmatch("[0-9a-f]{64}", value) for value in hashes)
    assert before["files"]
    for path, row in before["files"].items():
        assert not path.startswith("/") and ".." not in PurePosixPath(path).parts
        if "link" in row:
            assert set(row) == {"link"} and isinstance(row["link"], str)
        else:
            assert set(row) == {"sha256", "bytes", "mode"}
            assert re.fullmatch("[0-9a-f]{64}", row["sha256"]) and row["bytes"] >= 0
            assert re.fullmatch("0o[0-7]+", row["mode"])
    lock_data = (SOURCE / "uv.lock").read_bytes()
    lock = tomllib.loads(lock_data.decode())
    selected, lines = {}, []
    for name, version in sorted(ORIGINAL["installed_versions"].items()):
        matches = [package for package in lock["package"] if package["name"] == name and package["version"] == version]
        assert len(matches) == 1
        hashes = sorted({wheel["hash"] for wheel in matches[0]["wheels"]})
        assert hashes and all(re.fullmatch("sha256:[0-9a-f]{64}", value) for value in hashes)
        selected[name] = {"version": version, "wheel_hashes": hashes}
        lines.append(name + "==" + version + "".join(" --hash=" + value for value in hashes))
    assert payloads["requirements.txt"] == ("\n".join(lines) + "\n").encode()
    assert parsed(payloads, "dependency-inputs.json") == {
        "source_lock_sha256": digest(lock_data)["sha256"], "selected_packages": selected,
        "requirements_sha256": digest(payloads["requirements.txt"])["sha256"], "project_install_requested": False}
    for name in ("native_qualification_credit", "installed_qualification_credit", "qualification_complete"):
        assert before[name] is False
    result = {"original_environment_full_file_maps_identical": True, "original_environment_files": len(before["files"]),
              "nine_exact_locked_distributions": before["installed_versions"],
              "launchers_bound_to_original_host_sha256": host["python_sha256"],
              "original_runtime_extensions": before["runtime_extensions"],
              "observer_recreated_or_executed_environment": False}
    write_json(REPORT / "original-environment-audit.json", result)
    return result


def emit_original(payloads: dict[str, bytes]) -> dict:
    catalog = {}
    for name, data in sorted(payloads.items()):
        limit = 2 * 1024 * 1024 if name in {"finite-junit.xml", "finite-junit-log-copy.json"} else 16 * 1024 * 1024
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            # The existing independent frame decoder returns UTF-8 text.
            # Retain every original binary byte through an explicit lossless envelope.
            envelope = {"encoding": "base64", "original": digest(data),
                        "base64": base64.b64encode(data).decode("ascii")}
            encoded = (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode()
            label = "original-binary/" + name + ".json"
            frame(label, encoded, limit=16 * 1024 * 1024)
            transfer = {"label": label, "encoding": "base64-json-envelope", "envelope": digest(encoded)}
        else:
            label = "original/" + name
            frame(label, data, limit=limit)
            transfer = {"label": label, "encoding": "original-utf8"}
        catalog[name] = {**digest(data), "full_original_bytes_emitted": True, "transfer": transfer}
    write_json(REPORT / "original-emitted-catalog.json", catalog)
    return {"full_original_files_emitted": len(catalog)}
