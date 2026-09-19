"""Read pinned plan/prior reports before downloading only relevant shard evidence."""

from __future__ import annotations

import base64
import json
import math
import zipfile

from common import HERE, REPORT, digest, parsed, write_json
from download import download, read_zip

EXPANDED = 0


def archives(config, emit):
    global EXPANDED
    limits = config["limits"]
    pins = config["artifacts"]
    assert len(pins) == limits["artifacts"] == 98
    assert sum(pin["bytes"] for pin in pins) == limits["pinned_zip_total_bytes"]
    oversized = config["known_oversized_node"]
    extra = oversized["node_utf8_bytes"] + 1
    assert oversized["shard_index"] == 11 and extra == 8388761
    assert oversized["original_plan_exception_remainder_cap_bytes"] == limits["plan_member_bytes"] == 524288
    assert limits["all_zip_expanded_bytes"] == 100663296
    downloads = []

    def bounded(pin):
        global EXPANDED
        path = download(pin)
        label = pin["label"]
        downloads.append(pin["id"])
        original_zip = path.read_bytes()
        emit("original-zip-" + str(pin["id"]), {
            "artifact_id": pin["id"], "label": label, "encoding": "base64",
            "content": base64.b64encode(original_zip).decode("ascii"), **digest(original_zip)})
        is_plan = label == "pytest-shard-plan"
        is_prior = label == "prior-exact-runtime-collection"
        members = limits["plan_members"] if is_plan else limits["prior_report_members"] if is_prior else 1
        member_limit = limits["plan_member_bytes"] if is_plan else limits["prior_member_bytes"] if is_prior else limits["duration_member_bytes"]
        total_limit = limits["plan_total_bytes"] + extra if is_plan else limits["prior_total_bytes"] if is_prior else member_limit
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            expanded = sum(info.file_size for info in infos)
            EXPANDED += expanded
            sizes = {info.filename: info.file_size for info in infos}
            emit(label + "-targeted-bounds", {
                "artifact_id": pin["id"], "members": len(infos), "expanded_bytes": expanded,
                "member_sizes": sizes, "aggregate_expanded_bytes": EXPANDED,
                "central_directory": [{"name": item.filename, "bytes": item.file_size,
                    "compressed_bytes": item.compress_size, "crc32": item.CRC,
                    "flags": item.flag_bits, "external_attributes": item.external_attr} for item in infos],
                "ordinary_member_limit": member_limit, "total_limit": total_limit,
                "known_shard11_plan_extra": extra if is_plan else 0,
                "original_aggregate_limit_unchanged": limits["all_zip_expanded_bytes"]})
            assert 0 < len(infos) <= members and len(sizes) == len(infos)
            assert expanded <= total_limit and EXPANDED <= limits["all_zip_expanded_bytes"]
            assert all(0 <= info.file_size <= member_limit + (
                extra if is_plan and info.filename == "shard-11.txt" else 0) for info in infos)
        payloads = read_zip(path, "targeted-" + label)
        return payloads

    plan_pin = next(pin for pin in pins if pin["label"] == "pytest-shard-plan")
    plan_payloads = bounded(plan_pin)
    assert set(plan_payloads) == {"plan.json"} | {f"shard-{index:02d}.txt" for index in range(96)}
    plan = parsed(plan_payloads, "plan.json")
    assert plan["schema_version"] == 1 and plan["shard_count"] == 96
    shards = {}
    giant = None
    for index in range(96):
        raw = plan_payloads[f"shard-{index:02d}.txt"]
        nodes = raw.decode("utf-8").splitlines()
        assert nodes == sorted(nodes) and len(nodes) == plan["node_counts"][index]
        assert len(nodes) == len(set(nodes)) and all("::" in node for node in nodes)
        if index == 11:
            matches = [node for node in nodes if len(node.encode()) == oversized["node_utf8_bytes"]
                       and digest(node.encode())["sha256"] == oversized["node_sha256"]]
            assert len(matches) == 1, "Exact known oversized node is required"
            giant = matches[0]
            assert raw.count((giant + "\n").encode()) == 1
            assert len(raw) - extra <= limits["plan_member_bytes"]
        else:
            assert len(raw) <= limits["plan_member_bytes"]
        shards[index] = nodes
    flattened = [node for nodes in shards.values() for node in nodes]
    assert len(flattened) == len(set(flattened)) == plan["node_count"]
    assert giant is not None and sum(map(len, plan_payloads.values())) - extra <= limits["plan_total_bytes"]

    prior_pin = next(pin for pin in pins if pin["label"] == "prior-exact-runtime-collection")
    payloads = bounded(prior_pin)
    manifest = parsed(payloads, "artifact-manifest.json")
    assert set(manifest) == set(payloads) - {"artifact-manifest.json", "job-outcome.json"}
    for name, expected_digest in manifest.items():
        assert digest(payloads[name]) == expected_digest, name
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
    natural = {node for index in indices for node in shards[index] if node.split("::", 1)[0] in runtime}
    assert natural == set(expected), "Exact original718 collection/plan equality required"
    write_json(REPORT / "targeted-original-plan-selection.json", {
        "selected_shards": indices, "prior718": expected, "natural_runtime_plan": sorted(natural),
        "known_oversized_node": oversized, "all_other_original_plan_bounds_preserved": True})

    pin = config["reused_shard11_receipt"]
    raw = (HERE / pin["path"]).read_bytes()
    assert digest(raw) == {"bytes": pin["bytes"], "sha256": pin["sha256"]}
    reused = json.loads(raw)
    evidence = reused["separate_retained_data_inflation"]
    assert reused["original_failed_sweep"]["run_id"] == 35438843603
    assert evidence["original_shard11_status"]["original_run_id"] == config["run_id"]
    assert evidence["original_shard11_status"]["call_partition_complete"] is True
    assert evidence["original_shard11_status"]["call_count"] == 236
    rows = evidence["selected20_runtime_calls"]
    assert len(rows) == pin["runtime_calls"] == 20
    assert {row["node"] for row in rows} == {
        node for node in shards[11] if node.split("::", 1)[0] in runtime}
    assert all(row["status"] == "passed" and row["shard_index"] == 11 for row in rows)
    emit("reused-shard11-evidence", reused)

    durations = {}
    for index in indices:
        if index == 11:
            continue
        pin = next(pin for pin in pins if pin["label"] == "pytest-durations-" + str(index))
        payloads = bounded(pin)
        assert set(payloads) == {"pytest-durations.json"}
        report = parsed(payloads, "pytest-durations.json")
        assert report["schema_version"] == 1 and isinstance(report["node_durations_seconds"], dict)
        values = report["node_durations_seconds"]
        assert all(isinstance(node, str) and node for node in values)
        assert all(isinstance(value, (int, float)) and not isinstance(value, bool)
                   and math.isfinite(value) and value >= 0 for value in values.values())
        assert set(values) <= set(shards[index])
        durations[index] = values
    assert set(durations) == set(indices) - {11}
    write_json(REPORT / "targeted-download-population.json", {
        "downloaded_original_artifact_ids": downloads, "selected_shards": indices,
        "reused_shards": [11], "all98_sweep_repeated": False,
        "expanded_bytes": EXPANDED, "unchanged_aggregate_limit": limits["all_zip_expanded_bytes"]})
    return shards, durations, expected, reused, indices
