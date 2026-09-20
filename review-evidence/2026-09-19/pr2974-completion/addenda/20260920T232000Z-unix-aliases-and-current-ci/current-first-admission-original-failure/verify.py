"""Pure-data original current-artifact first-admission verifier; no product imports."""
import base64
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "10614508539/raw"
SOURCE = ROOT / "source"


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read(name):
    return decode((RAW / name).read_bytes())


def verify():
    manifest_raw = (SOURCE / "MANIFEST.json").read_bytes()
    assert identity(manifest_raw)["sha256"] == "3a71f6cd7c96cef86bbf18816dff4286a331ef8ac23d589b49c49395de9ae55d"
    manifest = decode(manifest_raw)
    archive = decode((ROOT / "10614508539/verification.json").read_bytes())
    metadata = decode((ROOT / "artifacts.json").read_bytes())["artifacts"]
    assert len(metadata) == 1 and metadata[0]["id"] == archive["artifact_id"] == 10614508539
    original_zip = ROOT / "10614508539/artifact.zip"
    zip_identity = identity(original_zip.read_bytes())
    assert zip_identity["bytes"] == archive["archive_bytes"] == metadata[0]["size_in_bytes"] == 8850838
    assert zip_identity["sha256"] == archive["archive_sha256"] == metadata[0]["digest"].removeprefix("sha256:")
    with zipfile.ZipFile(original_zip) as z:
        assert len(z.namelist()) == len(set(z.namelist())) == len(archive["members"])
        assert set(z.namelist()) == {r["path"] for r in archive["members"]}
        for row in archive["members"]:
            raw = z.read(row["path"])
            assert raw == (RAW / row["path"]).read_bytes()
            assert all(identity(raw)[k] == row[k] for k in ("bytes", "sha256"))
    groups = {}
    marker = "HG_CURRENT_FIRST_ADMISSION_FILE_V1 "
    frames = 0
    for line in (ROOT / "job.log").read_text().splitlines():
        if marker not in line:
            continue
        row = decode(line.split(marker, 1)[1])
        assert row["kind"] == "part"
        groups.setdefault(row["path"], []).append(row)
        frames += 1
    assert frames == 45 and len(groups) == 31
    bodies = {}
    for name, rows in groups.items():
        first = rows[0]
        assert [r["part"] for r in rows] == list(range(first["parts"]))
        assert all(all(r[k] == first[k] for k in ("parts", "bytes", "path", "sha256", "git_blob")) for r in rows)
        raw = b"".join(base64.b64decode(r["base64"], validate=True) for r in rows)
        assert all(identity(raw)[k] == first[k] for k in ("bytes", "sha256", "git_blob"))
        assert raw == (ROOT / "projected" / name).read_bytes()
        if name != "projection-index.json":
            assert raw == (RAW / name).read_bytes()
        bodies[name] = raw
    index = decode(bodies["projection-index.json"])
    assert {r["path"] for r in index["admitted"]} == set(bodies) - {"projection-index.json"}
    assert index["unavailable"] == [{"path": "first-admission.json", "status": "missing"}]
    assert index["total_source_bytes"] == sum(len(bodies[r["path"]]) for r in index["admitted"])
    for row in index["admitted"]:
        assert row == {"path": row["path"], **identity(bodies[row["path"]])}
    before, after = read("binding-before.json"), read("binding-after.json")
    assert before == after
    assert before["source"]["head"] == manifest["source_sha"] == "a1d509404b0803a91031cb51f4b0c919408bfeba"
    assert before["source"]["tree"] == manifest["source_tree"] == "e60dfd218cd7cc9f29c9f2cd66223c866ea86c80"
    assert before["driver"]["head"] == "72874536975292f865a3c6633ad1bd20f08b50bd"
    assert before["driver"]["tree"] == "3f45cb15f359eb511f73f1b54268fb23a9b9ead3"
    assert before["files"] == manifest["driver_files"] and before["source_files"] == manifest["source_files"]
    installed = read("installed-before.json")
    assert installed == read("installed-after.json")
    assert installed["noneditable"] is True and installed["interpreter"]["owned_venv"] is True
    wheel = manifest["retained_wheel"]
    assert all(identity((RAW / wheel["wheel_name"]).read_bytes())[k] == wheel["wheel_identity"][k] for k in ("bytes", "sha256"))
    expected = read("expected-installed.json")
    assert expected["runtime_manifest"] == installed["runtime"] == wheel["runtime_manifest"]
    with zipfile.ZipFile(RAW / wheel["wheel_name"]) as z:
        names = {n for n in z.namelist() if n.startswith("codex_plugin_scanner/") and not n.endswith("/")}
        assert names == set(expected["package_entries"])
        for name in names:
            assert {k: identity(z.read(name))[k] for k in ("bytes", "sha256")} == expected["package_entries"][name]
    control = read("reader-controls-result.json")
    nodes = manifest["expected_reader_nodes"]
    assert control["collected"] == control["executed"] == nodes and len(nodes) == len(set(nodes)) == control["passed"] == 41 and control["skipped"] == 0
    cases = list(ET.parse(RAW / "reader-controls.xml").getroot().iter("testcase"))
    assert [c.attrib["classname"].replace(".", "/") + ".py::" + c.attrib["name"] for c in cases] == nodes
    assert not any(list(c.iter(kind)) for c in cases for kind in ("failure", "error", "skipped"))
    result = read("validation-result.json")
    assert result["original_command_attempts"] == result["original_exit"] == 1
    assert result["source_driver_installed_preserved"] is True and result["passed"] is False
    assert result["failure"] == {"stage": "admit-original", "type": "RuntimeError"}
    commands = read("commands.json")
    assert commands == result["commands"]
    assert [(r["name"], r["returncode"]) for r in commands] == [("sync",0),("uninstall",0),("install",0),("ruff",0),("format",0),("types",0),("reader-collect",0),("reader-controls",0),("installed-before",0),("original-first-admission",1),("admit-original",1),("installed-after",0)]
    for row in commands:
        assert row["timed_out"] is False and row["direct_child_exited"] is True
        for stream in ("stdout", "stderr"):
            assert {k: identity((RAW / "commands" / (row["name"] + "." + stream)).read_bytes())[k] for k in ("bytes", "sha256")} == row[stream]
    report = read("workspace-lifecycle.json")
    ledger = (RAW / "workspace-lifecycle.jsonl").read_bytes()
    assert ledger.endswith(b"\n") and report["ledger"] == {"bytes": len(ledger), "records": 2, "sha256": identity(ledger)["sha256"]}
    offer, part = [decode(line) for line in ledger.splitlines()]
    assert offer == {"kind": "lifecycle_cell_offer", "registered_workspaces": 100, "scenario": "first_admission_fault"}
    assert part["part"] == 0 and part["parts"] == 1 and part["kind"] == "lifecycle_cell_terminal_part"
    encoded = part["content"].encode("ascii")
    cell_envelope = decode(encoded)
    summary = report["cells"][0]
    assert len(report["cells"]) == 1 and summary["evidence"]["sha256"] == part["result_sha256"] == identity(encoded)["sha256"]
    assert summary["evidence"]["bytes"] == len(encoded) and summary["evidence"]["parts"] == 1
    assert cell_envelope["summary"] == {k:v for k,v in summary.items() if k != "evidence"}
    assert not set(cell_envelope["summary"]) & set(cell_envelope["proof"])
    cell = {**cell_envelope["summary"], **cell_envelope["proof"]}
    assert [cell] == read("reconstructed-cells.json")
    assert cell["failure"]["origin"] == "native_slo_workspace_lifecycle.await_ack" and cell["failure"]["line"] == 73
    assert cell["failure"]["diagnostic_digest"] == hashlib.sha256(b"workspace lifecycle authenticated acknowledgment deadline").hexdigest()
    assert cell["passed"] is False and cell["publisher_contained"] is True and cell["publication_events"] == 0
    assert cell["lifecycle_clocks"]["boundaries_ms"] == {} and cell["readiness_deadline_ms"] == 400
    assert not any(k in cell for k in ("service_replacement", "fault", "requests", "accepted_ms", "binding", "cleanup_failures", "fixture_cleanup_failure"))
    assert report["counts"] == [100] and report["scenarios"] == ["first_admission_fault"] and report["declared_cells_visited"] is True
    assert report["complete_lifecycle_matrix_visited"] is report["implemented_checks_passed"] is report["headline_timing_eligible"] is report["full_rsp_128_129_qualification"] is False
    for key, value in (("build_sha", wheel["runtime_manifest"]["source_sha"]), ("runtime_sha256", wheel["runtime_identity"]["sha256"]), ("rule_digest", wheel["runtime_manifest"]["rule_digest"])):
        assert report["runtime"][key] == value
    for path in ("scripts/native_slo_workspace_lifecycle.py", "scripts/native_slo_workspace_lifecycle_runner.py"):
        raw = (SOURCE / path).read_bytes()
        expected_row = next(r for r in manifest["source_files"] if r["path"] == path)
        assert {"path": path, **identity(raw)} == expected_row
    return {"schema":"pr2974.current-first-admission-original-result.v1","run":35541994314,"job":106161204439,"artifact":10614508539,"archive":zip_identity,"original_members":len(archive["members"]),"projection_frames":frames,"projection_files":len(groups),"projection_unavailable":index["unavailable"],"source":manifest["source_sha"],"source_tree":manifest["source_tree"],"driver":before["driver"]["head"],"driver_tree":before["driver"]["tree"],"artifact_build":wheel["artifact_build_source"],"wheel":wheel["wheel_identity"],"runtime":wheel["runtime_manifest"],"all_source_driver_installed_bindings_preserved":True,"reader_controls":{"passed":41,"skipped":0},"style_types_preparation_passed":True,"original_cli_invocations":1,"original_exit":1,"original_cell":cell,"first_admission_fault_offered":False,"service_replacement_offered":False,"recovered_request_offered":False,"original_initial_setup_deadline_ms":400,"timed_cold_registration_acceptance_reached":False,"strict_single_cell_admission":False,"full15_matrix_visited":False,"current_source_fix_established":False,"limits":["Fresh actual currenta1/build9f511 original initial-readiness refusal; not a repeat of oldbe612 subject and not evidence that lazy imports repair or cause it.","Initial await_ack follows original strict overlay write and request_publish, and uses a new now+400ms deadline. Replacement, cold registration acceptance and reply fault occur only after its successful return.","Publication observer is not yet installed at this failure. publication_events0 is an unobserved/default cell projection, not proof no publication happened or evidence of capture loss.","No original local clock values, publisher last_error, generation, prepared result, current snapshot, authenticated readback or exact failed predicate survive. Line73 establishes deadline refusal, not a specific leaf cause or exact duration.","Final publisher_contained true is original cleanup observation; it does not establish earlier readiness or complete descendant reaping. No cleanup failure is retained.","installed_runtime_matches false is a cell binding check with absent successful binding; independent before/after package/runtime identity passes.","Only declared cell was visited. The first-reply discard/retry/ACK/recovered native+SQL receipt requirement remains unexercised in this run; no full15, cross-platform or performance qualification.","Verifier reads original records only; it does not rerun the application, native process, original schema writer or tests. Original hosted reader did execute its exact source-bound producer roundtrip before rejecting the failed cell."]}


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
