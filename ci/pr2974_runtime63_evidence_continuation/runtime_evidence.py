"""Retain only source-selected original artifacts and logs; do not rerun tests."""

from __future__ import annotations

import base64
import json
import zipfile

from common import HERE, OUTPUT, REPORT, digest, parsed, write_json
from download import download, read_zip
from runtime_job_logs import job_log


def collect_evidence(config, emit, jobs):
    limits = config["limits"]
    pins = config["artifacts"]
    assert len(pins) == limits["artifacts"] == 98
    assert sum(pin["bytes"] for pin in pins) == limits["pinned_zip_total_bytes"]
    assert limits["all_zip_expanded_bytes"] == 100663296
    downloaded = []
    expanded = 0
    retained = config["retained_plan"]
    container = (HERE / retained["path"]).read_bytes()
    assert digest(container) == {"bytes": retained["bytes"], "sha256": retained["sha256"]}
    envelope = json.loads(container)
    plan_pin = next(pin for pin in pins if pin["label"] == "pytest-shard-plan")
    assert envelope["artifact_id"] == plan_pin["id"] == 10581946352
    assert envelope["encoding"] == "base64"
    raw_zip = base64.b64decode(envelope["content"], validate=True)
    assert digest(raw_zip) == {"bytes": plan_pin["bytes"], "sha256": plan_pin["sha256"]}
    output_zip = OUTPUT / "original-zips" / (str(plan_pin["id"]) + ".zip")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    output_zip.write_bytes(raw_zip)
    emit("retained-original-plan-zip", envelope)
    expected_members = {row["name"]: row for row in retained["members"]}
    assert len(expected_members) == 97
    with zipfile.ZipFile(output_zip) as archive:
        infos = archive.infolist()
        assert len(infos) == len({info.filename for info in infos}) == 97
        assert {info.filename for info in infos} == set(expected_members)
        expanded = sum(info.file_size for info in infos)
        assert expanded == retained["expanded_bytes"] == 27514674
        assert expanded <= limits["all_zip_expanded_bytes"]
        for info in infos:
            pin = expected_members[info.filename]
            assert (info.file_size, info.compress_size, info.CRC, info.flag_bits,
                    info.external_attr, info.header_offset, info.compress_type) == (
                pin["bytes"], pin["compressed_bytes"], pin["crc32"], pin["flags"],
                pin["external_attributes"], pin["local_offset"], pin["method"])
    plan_payloads = read_zip(output_zip, "retained-original-plan")
    for name, pin in expected_members.items():
        assert digest(plan_payloads[name]) == {"bytes": pin["bytes"], "sha256": pin["sha256"]}
    assert set(plan_payloads) == {"plan.json"} | {f"shard-{index:02d}.txt" for index in range(96)}
    plan = parsed(plan_payloads, "plan.json")
    assert plan["schema_version"] == 1 and plan["shard_count"] == 96 and plan["node_count"] == 22611
    shards = {}
    giant_nodes = []
    for index in range(96):
        nodes = plan_payloads[f"shard-{index:02d}.txt"].decode("utf-8").splitlines()
        assert nodes == sorted(nodes) and len(nodes) == plan["node_counts"][index]
        assert len(nodes) == len(set(nodes)) and all("::" in node for node in nodes)
        assert len({node.split("::", 1)[0] for node in nodes}) == plan["file_counts"][index]
        for node in nodes:
            if len(node.encode()) > 524288:
                giant_nodes.append({"shard_index": index, "node_utf8_bytes": len(node.encode()),
                    "node_sha256": digest(node.encode())["sha256"],
                    "json_quoted_utf8_bytes": len(json.dumps(node, ensure_ascii=True).encode())})
        shards[index] = nodes
    flattened = [node for nodes in shards.values() for node in nodes]
    assert len(flattened) == len(set(flattened)) == plan["node_count"]
    assert giant_nodes == retained["giant_nodes"]
    emit("retained-plan-verification", {
        "artifact_id": plan_pin["id"], "members": retained["members"],
        "expanded_bytes": expanded, "all_crc_length_and_sha256_verified": True,
        "all_original_counts_order_and_uniqueness_verified": True,
        "giant_nodes": giant_nodes, "plan_downloaded": False,
        "original_failed_reader_limits_unchanged": True})

    prior_pin = next(pin for pin in pins if pin["label"] == "prior-exact-runtime-collection")
    prior_path = download(prior_pin)
    downloaded.append(prior_pin["id"])
    prior_zip = prior_path.read_bytes()
    emit("original-zip-" + str(prior_pin["id"]), {
        "artifact_id": prior_pin["id"], "label": prior_pin["label"], "encoding": "base64",
        "content": base64.b64encode(prior_zip).decode("ascii"), **digest(prior_zip)})
    with zipfile.ZipFile(prior_path) as archive:
        infos = archive.infolist()
        prior_expanded = sum(info.file_size for info in infos)
        emit("prior-collection-bounds", {
            "members": len(infos), "expanded_bytes": prior_expanded,
            "member_sizes": {info.filename: info.file_size for info in infos},
            "aggregate_expanded_bytes": expanded + prior_expanded})
        assert 0 < len(infos) <= limits["prior_report_members"]
        assert len({info.filename for info in infos}) == len(infos)
        assert all(0 <= info.file_size <= limits["prior_member_bytes"] for info in infos)
        assert prior_expanded <= limits["prior_total_bytes"]
        expanded += prior_expanded
        assert expanded <= limits["all_zip_expanded_bytes"]
    payloads = read_zip(prior_path, "original-prior-runtime-collection")
    manifest = parsed(payloads, "artifact-manifest.json")
    assert set(manifest) == set(payloads) - {"artifact-manifest.json", "job-outcome.json"}
    for name, pin in manifest.items():
        assert digest(payloads[name]) == pin, name
    source = parsed(payloads, "source-before.json")
    assert source["source_sha"] == config["source_sha"] and source["source_tree"] == config["source_tree"]
    selected = parsed(payloads, "runtime-selected-files.json")
    assert selected == sorted(config["source_files"])
    for path in selected:
        assert source["files"][path]["git_blob"] == config["source_files"][path]["git_blob"]
    collection = parsed(payloads, "runtime-collection.json")
    assert collection["pytest_exit_code"] == 0 and collection["error"] is None
    expected = collection["nodeids"]
    assert len(expected) == len(set(expected)) == config["expected_original_collection"] == 718
    runtime = set(config["source_files"])
    assert all(node.split("::", 1)[0] in runtime for node in expected)
    indices = [index for index in range(96)
               if any(node.split("::", 1)[0] in runtime for node in shards[index])]
    assert indices == config["selected_shards"] and len(indices) == 46
    natural = {node for index in indices for node in shards[index] if node.split("::", 1)[0] in runtime}
    assert natural == set(expected), "Exact original718 collection/plan equality before any log"
    for name in ("artifact-manifest.json", "source-before.json",
                 "runtime-selected-files.json", "runtime-collection.json"):
        emit("prior-" + name.removesuffix(".json"), {
            "original_path": name, "encoding": "utf-8", "content": payloads[name].decode(),
            **digest(payloads[name])})
    emit("exact-original-plan-collection", {
        "selected_shards": indices, "prior718": expected, "natural_runtime_plan": sorted(natural),
        "exact_original_collection_equality": True, "all_prior_internal_manifest_hashes_verified": True,
        "source_files": config["source_files"], "source_sha": config["source_sha"],
        "source_tree": config["source_tree"], "new_runtime_pass_credit": 0})

    reuse_pin = config["reused_shard11_receipt"]
    raw = (HERE / reuse_pin["path"]).read_bytes()
    assert digest(raw) == {"bytes": reuse_pin["bytes"], "sha256": reuse_pin["sha256"]}
    reused = json.loads(raw)
    evidence = reused["separate_retained_data_inflation"]
    status = evidence["original_shard11_status"]
    assert reused["original_failed_sweep"]["run_id"] == 35438843603
    assert status["original_run_id"] == config["run_id"] and status["call_partition_complete"] is True
    assert status["call_count"] == 236
    rows = evidence["selected20_runtime_calls"]
    assert len(rows) == reuse_pin["runtime_calls"] == 20
    assert {row["node"] for row in rows} == {
        node for node in shards[11] if node.split("::", 1)[0] in runtime}
    assert all(row["status"] == "passed" and row["shard_index"] == 11
               and row["job_id"] == jobs[11]["id"] for row in rows)
    emit("reused-shard11-evidence", reused)

    duration_indices = [index for index in indices if index != 11]
    assert duration_indices == config["duration_shards"] and len(duration_indices) == 45
    opaque = []
    for index in duration_indices:
        pin = next(pin for pin in pins if pin["label"] == "pytest-durations-" + str(index))
        path = download(pin)
        downloaded.append(pin["id"])
        raw = path.read_bytes()
        emit("original-zip-" + str(pin["id"]), {
            "artifact_id": pin["id"], "label": pin["label"], "shard_index": index,
            "encoding": "base64", "content": base64.b64encode(raw).decode("ascii"), **digest(raw)})
        opaque.append({"shard_index": index, "artifact_id": pin["id"],
                       **digest(raw), "members_not_decompressed": True})
    logs = []
    for index in duration_indices:
        value = job_log(jobs[index]["id"], limits["job_log_bytes"], limits["all_job_log_bytes"])
        raw = value.encode()
        emit("original-job-" + str(jobs[index]["id"]) + "-full-log", {
            "job_id": jobs[index]["id"], "shard_index": index,
            "encoding": "utf-8", "content": value, **digest(raw)})
        logs.append({"job_id": jobs[index]["id"], "shard_index": index, **digest(raw)})
    assert len(opaque) == len(logs) == 45
    result = {"exact_prior718_plan_equality": True, "selected_shards": indices,
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "prior_collection_nodes": expected, "prior_collection_artifact_id": prior_pin["id"],
        "downloaded_original_artifact_ids": downloaded, "plan_downloaded": False,
        "opaque_duration_archives": opaque, "original_job_logs": logs,
        "previously_verified_runtime_calls_reused": 20, "reused_shard": 11,
        "known_expanded_bytes": expanded, "unchanged_aggregate_cap": limits["all_zip_expanded_bytes"],
        "opaque_duration_expansion_and_status_audit_pending": True,
        "no_irrelevant_duration_or_log_downloads": True, "all98_archive_sweep_repeated": False,
        "new_runtime_pass_credit": 0, "qualification_complete": False}
    write_json(REPORT / "retained-input-transport.json", result)
    return result
