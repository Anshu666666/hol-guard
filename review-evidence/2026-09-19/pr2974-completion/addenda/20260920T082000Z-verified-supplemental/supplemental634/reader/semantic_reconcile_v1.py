"""Bounded, read-only reconciliation of the original 634 control records.

This reader imports no candidate or harness module and runs no original tests.
"""
from __future__ import annotations

import resource
resource.setrlimit(resource.RLIMIT_AS, (99614720, 99614720))
resource.setrlimit(resource.RLIMIT_CPU, (90, 90))

import ast
import gc
import hashlib
import json
import math
from pathlib import Path
import signal
import sys
import time
import traceback
import xml.etree.ElementTree as ET

LIMIT = 8 * 1024 * 1024
ROOT = Path("/home/user/pr2974-corrective634-decode-asnf")
MEMBERS = ROOT / "members-v1"
PREP = Path("/home/user/pr2974-corrective634-parser-prep")
OUTPUT = ROOT / "semantic-v1"
SOURCE = "4d10758e2cb44e5afa72a08aa631a02541dad534"
TREE = "fbc00caa3788eb422158a2263a578e83ac626183"
DRIVER = "b05127dd2cec4f02eb97d715138179c741e52ec0"
BOOT = "c6aba711-75f6-4cbb-90b1-d991ba91b54e"
SOURCE_CENSUS = "771ecf5d159d0739b451abf9e1f37a9d4281f0048044e526972f4bd4172bfaea"
SCHEDULE = [
    ("oauth_fingerprint_original", 13, 600),
    ("secret_promotion", 13, 60),
    ("incoming_python_additions", 112, 600),
    ("workspace-pure", 62, 300),
    ("workspace-forward", 16, 300),
    ("workspace-lifecycle", 10, 300),
    ("incoming_ed731_python", 253, 600),
    ("incoming_2433_python", 94, 600),
    ("incoming_017_python", 20, 60),
    ("incoming_8f15_python", 41, 60),
]
GROUPS = [
    ("oauth_fingerprint_original", ["oauth_fingerprint_original"], 13),
    ("secret_promotion", ["secret_promotion"], 13),
    ("incoming_python_additions", ["incoming_python_additions"], 112),
    ("workspace_original88", ["workspace-pure", "workspace-forward", "workspace-lifecycle"], 88),
    ("incoming_ed731_python", ["incoming_ed731_python"], 253),
    ("incoming_2433_python", ["incoming_2433_python"], 94),
    ("incoming_017_python", ["incoming_017_python"], 20),
    ("incoming_8f15_python", ["incoming_8f15_python"], 41),
]


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def parse(raw):
    require(len(raw) <= LIMIT, "semantic value exceeds fixed 8 MiB")
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path, reference=None):
    before = path.stat()
    require(path.is_file() and not path.is_symlink() and before.st_size <= LIMIT, "bounded regular input")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "input changed while read")
    require(len(raw) == before.st_size, "input size")
    if reference is not None:
        require(len(raw) == reference["bytes"] and digest(raw) == reference["sha256"], "input reference")
    return raw


def selection_matches(node, selector):
    if "::" not in selector:
        return node.startswith(selector + "::")
    return node == selector or ("[" not in selector and node.startswith(selector + "["))


def definition_nodes(node, prefix=""):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        qualified = prefix + node.name
        yield qualified, node
        prefix = qualified + ".<locals>."
    elif isinstance(node, ast.ClassDef):
        prefix += node.name + "."
    for child in ast.iter_child_nodes(node):
        yield from definition_nodes(child, prefix)


def walk(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def properties(case):
    return [[row.attrib["name"], row.attrib["value"]] for row in case.findall("properties/property")]


def xml(raw):
    require(b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw, "XML entity declaration")
    root = ET.fromstring(raw)
    require(root.tag in {"testsuite", "testsuites"}, "XML root")
    suites = [root] if root.tag == "testsuite" else list(root)
    require(all(s.tag == "testsuite" for s in suites), "XML suite shape")
    cases = [case for suite in suites for case in suite.findall("testcase")]
    require(sum(int(s.attrib["tests"]) for s in suites) == len(cases), "XML declared case count")
    require(all(int(s.attrib.get(k, "0")) == 0 for s in suites for k in ("errors", "failures", "skipped")),
            "XML nonpass aggregate")
    return cases


def phase_join(nodes, phases, items, cases):
    require([(p["nodeid"], p["when"]) for p in phases] ==
            [(n, when) for n in nodes for when in ("setup", "call", "teardown")], "phase order")
    require(all(p["outcome"] == "passed" and p["wasxfail"] is None and
                p["failure_file"] is None and p["longrepr_bytes"] == 0 and
                p["longrepr_sha256"] == digest(b"") for p in phases), "phase outcome")
    require(all(type(p["duration_seconds"]) in (int, float) and math.isfinite(p["duration_seconds"]) and
                p["duration_seconds"] >= 0 for p in phases), "phase duration")
    expected = [(r["junit"]["classname"], r["junit"]["name"]) for r in items]
    actual = [(r.attrib["classname"], r.attrib["name"]) for r in cases]
    require(actual == expected and len(actual) == len(set(actual)), "JUnit bijection")
    retained = []
    for index, (node, case) in enumerate(zip(nodes, cases, strict=True)):
        require(all(case.find(k) is None for k in ("failure", "error", "skipped")), "JUnit nonpass case")
        props = properties(case)
        require(props == phases[index * 3 + 2]["user_properties"], "ordered duplicate JUnit properties")
        retained.append({"nodeid": node, "user_properties": props})
    return retained


def synthetic_controls():
    passed = []
    for raw in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}'):
        try:
            parse(raw)
        except (AssertionError, ValueError):
            passed.append("duplicate_or_nonfinite_refusal")
        else:
            raise AssertionError("synthetic JSON accepted")
    case = ET.fromstring('<testcase classname="m" name="n"><properties>'
                         '<property name="duplicate" value="first"/><property name="duplicate" value="second"/>'
                         '</properties></testcase>')
    nodes = ["p.py::n"]
    items = [{"junit": {"classname": "m", "name": "n"}}]
    phases = [{"nodeid": nodes[0], "when": when, "outcome": "passed", "wasxfail": None,
               "failure_file": None, "longrepr_bytes": 0, "longrepr_sha256": digest(b""),
               "duration_seconds": 0.0, "user_properties": []}
              for when in ("setup", "call", "teardown")]
    phases[-1]["user_properties"] = [["duplicate", "first"], ["duplicate", "second"]]
    phase_join(nodes, phases, items, [case])
    passed.append("ordered_duplicate_properties_preserved")
    phases[-1]["user_properties"].reverse()
    try:
        phase_join(nodes, phases, items, [case])
    except AssertionError:
        passed.append("ordered_duplicate_properties_mismatch_refused")
    else:
        raise AssertionError("synthetic property reordering accepted")
    phases[-1]["user_properties"].reverse()
    try:
        phase_join(nodes, list(reversed(phases)), items, [case])
    except AssertionError:
        passed.append("phase_reordering_refused")
    else:
        raise AssertionError("synthetic phase order accepted")
    return passed


def file_reference(name, index):
    return {"path": name, **index[name]}


def load_member(name, index):
    raw = read(MEMBERS / name, index[name])
    return parse(raw)


def source_identity(row, source_files):
    require(row["origin"] in {"candidate", "owned_dependency"}, "unscoped source origin")
    if row["origin"] == "candidate":
        pin = source_files[row["path"]]
        require(pin["bytes"] == row["bytes"] and pin["sha256"] == row["sha256"],
                "candidate source identity")
    return row["origin"] + "/" + row["path"]


def check_origins(origins, source_files):
    for record in origins.values():
        if "namespace_paths" in record:
            require(set(record) == {"namespace_paths"}, "namespace origin keys")
            for path in record["namespace_paths"]:
                require(type(path) is str and path and not path.startswith("/") and
                        ".." not in Path(path).parts and
                        any(name.startswith(path + "/") for name in source_files), "namespace source path")
        else:
            require(record["origin"] == "candidate", "module outside candidate")
            source_identity(record, source_files)


def provenance(contract, snapshots, source_files, expected_inputs):
    providers = contract["providers"]
    provider_rows, functions, definition_refs = [], {}, set()
    for key, row in providers.items():
        require(key == source_identity(row, source_files), "provider key")
        raw = row["content"].encode()
        require(len(raw) == row["bytes"] and digest(raw) == row["sha256"], "provider original bytes")
        item = {k: v for k, v in row.items() if k != "content"}
        if row["origin"] == "candidate":
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                                usedforsecurity=False).hexdigest()
            require(blob == source_files[row["path"]]["git_blob"], "provider exact Git blob")
            item["git_blob"] = blob
        provider_rows.append(item)
    for key, value in contract["definitions"].items():
        require(type(value) is str and digest(value.encode()) == key, "definition byte digest")
    for value in walk(contract["collection"]):
        if isinstance(value, dict) and {"definition_ast_sha256", "code_qualname", "signature_ast"} <= value.keys():
            key = source_identity(value, source_files)
            require(key in providers, "function provider missing")
            provider = providers[key]
            require((value["sha256"], value["bytes"]) == (provider["sha256"], provider["bytes"]),
                    "function source versus provider")
            definition_refs.add(value["definition_ast_sha256"])
            require(value["definition_ast_sha256"] in contract["definitions"], "function definition absent")
            token = digest(encode(value))
            functions[token] = value
        elif isinstance(value, dict) and {"origin", "path", "sha256", "bytes"} <= value.keys():
            source_identity(value, source_files)
    by_provider = {}
    for function in functions.values():
        by_provider.setdefault(function["origin"] + "/" + function["path"], []).append(function)
    for key, records in by_provider.items():
        parsed = ast.parse(providers[key]["content"], type_comments=True)
        definitions = list(definition_nodes(parsed))
        for record in records:
            matches = [node for qualified, node in definitions
                       if qualified == record["code_qualname"] and
                       min([node.lineno, *(d.lineno for d in node.decorator_list)]) <= record["first_line"] <= node.lineno]
            require(len(matches) == 1, "unique source AST definition")
            node = matches[0]
            require(ast.dump(node, include_attributes=False) == contract["definitions"][record["definition_ast_sha256"]],
                    "source AST definition bytes")
            require(ast.dump(node.args, include_attributes=False) == record["signature_ast"] and
                    node.end_lineno == record["definition_end_line"], "source AST signature and end line")
        del parsed, definitions, matches, node
    check_origins(contract["module_origins"], source_files)
    require(contract["conftests"] == ["conftest.py", "tests/conftest.py"], "original conftests")
    for snapshot in snapshots:
        require(snapshot["source_inputs_after"] == expected_inputs, "273 source input after identities")
        check_origins(snapshot["source_origins_after"], source_files)
        require(snapshot["binaries_after"] == contract["binaries"], "binary before after scope")
    require(contract["binaries"] == {
        "build_manifest_present": False, "build_manifest_sha256": None,
        "scope": "native_binaries_not_required_or_qualified_for_python_controls"}, "Python binary scope")
    return {
        "providers": provider_rows,
        "unique_function_records": [{"record_sha256": key, **value} for key, value in sorted(functions.items())],
        "definition_digests": sorted(contract["definitions"]),
        "referenced_definition_digests": sorted(definition_refs),
        "candidate_provider_git_blobs_verified": sum(r["origin"] == "candidate" for r in provider_rows),
        "owned_dependency_provider_contents_verified": sum(r["origin"] == "owned_dependency" for r in provider_rows),
        "candidate_module_origins": len(contract["module_origins"]),
        "source_inputs_after_verified_per_snapshot": len(expected_inputs),
        "ast_python_reader_version": sys.version.split()[0],
        "original_observer_python_version": "3.12.13",
        "original_definition_ast_exactly_recomputed": True,
        "owned_dependency_bytes_are_not_candidate_Git_blobs": True,
    }


def admit_snapshot(snapshot, expected, mode, contract, index):
    name = expected["name"]
    require(snapshot["schema"] == "hol-guard-native-controls-observation.v1", "capture schema")
    require(snapshot["source_sha"] == SOURCE and snapshot["source_tree"] == TREE, "capture source")
    require(snapshot["cohort"] == name and snapshot["mode"] == mode, "capture cohort/mode")
    require(snapshot["pytest_exit_code"] == 0 and snapshot["error"] is None and
            snapshot["evidence_error"] is None, "capture completion")
    require(all(snapshot[k] is True for k in ("source_unchanged", "binary_unchanged", "collection_admitted")),
            "capture admission")
    require(snapshot["qualification_complete"] is False and snapshot["contract"] is None and
            snapshot["reports"] == [], "split snapshot state")
    require(snapshot["execution_collection_matches_prior"] is (mode == "run"), "fresh collection equality")
    observation = snapshot["collection_observation"]
    require(observation["admitted"] is True and observation["complete"] is True and
            observation["collection_definitions_providers_conftests_and_origins"] == "contract",
            "collection observation")
    expected_observation = [{k: row[k] for k in ("nodeid", "fixture_names", "autouse_names")}
                            for row in contract["collection"]]
    require(observation["item_observations"] == expected_observation, "ordered observed fixture population")
    retention = snapshot["capture_retention"]
    require(set(retention) == {"schema", "complete", "contract", "phases", "aggregate_limit_bytes"} and
            retention["schema"] == "pr2974-control-capture-retention.v1" and
            retention["complete"] is True and retention["aggregate_limit_bytes"] == 16 * 1024 * 1024,
            "capture retention")
    total = index["controls/" + name + "/" + mode + ".json"]["bytes"]
    for kind, suffix, keys in (("contract", ".contract.json", {"file", "bytes", "sha256"}),
                               ("phases", ".phases.jsonl", {"file", "bytes", "sha256", "records"})):
        row = retention[kind]
        require(set(row) == keys and row["file"] == mode + suffix, "capture reference shape")
        pin = index["controls/" + name + "/" + row["file"]]
        require((pin["bytes"], pin["sha256"]) == (row["bytes"], row["sha256"]), "capture reference identity")
        total += row["bytes"]
    require(total <= retention["aggregate_limit_bytes"], "original aggregate limit")
    require(retention["phases"]["records"] == (0 if mode == "collect" else 3 * expected["expected_cases"]),
            "declared phase count")
    argv = snapshot["pytest_argv"]
    require(argv[-len(expected["selectors"]):] == expected["selectors"], "actual selector argv order")
    require(("--collect-only" in argv) is (mode == "collect"), "actual collect-only argv")
    require(argv[:3] == ["--strict-markers", "-m", "not slow"] and
            ["-m", ""] == argv[argv.index("no:cacheprovider") + 1:argv.index("no:cacheprovider") + 3],
            "original explicit marker clearing")


def write_exclusive(path, value):
    raw = encode(value)
    require(len(raw) <= LIMIT, "derived semantic output limit")
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": path.name, "bytes": len(raw), "sha256": digest(raw)}


def main():
    signal.alarm(120)
    require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == BOOT, "replacement environment changed")
    require(resource.getrlimit(resource.RLIMIT_AS) == (99614720, 99614720), "address-space bound")
    started = time.monotonic()
    created = False
    result = {
        "schema": "hol-guard.pr2974.corrective634-independent-semantic-reconciliation.v1",
        "source_sha": SOURCE, "source_tree": TREE, "driver_sha": DRIVER,
        "run_id": 35494533524, "job_id": 106035074778, "memory_limit_bytes": 99614720,
        "maximum_materialized_json_value_bytes": LIMIT, "passed": False, "cohorts": [],
        "native_or_original_workload_executed": False, "qualification_complete": False,
    }
    try:
        OUTPUT.mkdir(exist_ok=False)
        created = True
        result["synthetic_reader_controls"] = synthetic_controls()
        config_raw = read(PREP / "trusted-manifest.json")
        require(digest(config_raw) == "3cb6875fabc6a64ce88a8831556385721b02c74a3f7a8f51979bac634a687d22",
                "exact driver manifest")
        config = parse(config_raw)
        refs = parse(read(PREP / "trusted-harness-refs.json"))
        extraction = parse(read(ROOT / "content-extraction-v1.json"))
        require(extraction["passed"] is True and extraction["all_named_member_hashes_and_content_references_verified"] is True,
                "prior streaming extraction")
        index = extraction["files"]
        result["content_extraction_reference"] = {
            "bytes": (ROOT / "content-extraction-v1.json").stat().st_size,
            "sha256": digest(read(ROOT / "content-extraction-v1.json")),
            "named_files": len(index), "unique_contents": len(extraction["contents"])}
        before = load_member("source-before.json", index)
        after_ref = index["source-after.json"]
        require(index["source-before.json"]["sha256"] == after_ref["sha256"], "source before/after byte identity")
        read(MEMBERS / "source-after.json", after_ref)
        require((before["source_sha"], before["source_tree"], before["harness_sha"]) == (SOURCE, TREE, DRIVER),
                "source snapshot binding")
        source_files = before["files"]
        census = [[path, value["git_blob"], value["mode"]] for path, value in sorted(source_files.items())]
        raw_census = json.dumps(census, sort_keys=True, separators=(",", ":")).encode()
        require(len(census) == 4751 and len(raw_census) == 505588 and digest(raw_census) == SOURCE_CENSUS,
                "independent complete Git tree census")
        require(sorted([[path, row["git_blob"]] for path, row in before["harness_files"].items()]) == refs,
                "37 driver Git blob references")
        for path, hash_value in config["source_inputs"].items():
            require(source_files[path]["sha256"] == hash_value, "manifest source input snapshot join")
        result["source_binding"] = {
            "candidate_git_tree_rows": len(census), "candidate_git_census_sha256": SOURCE_CENSUS,
            "candidate_inline_provider_bytes_independently_checked_below": True,
            "all_other_recorded_source_sha256_values_not_independently_downloaded": True,
            "harness_git_blob_references": len(refs), "source_before_after_identical": True,
            "before": file_reference("source-before.json", index),
            "after": file_reference("source-after.json", index),
            "manifest_sha256": digest(config_raw)}
        expected = config["python_cohorts"]
        require([(r["name"], r["expected_cases"], r["timeout"]) for r in expected] == SCHEDULE, "original schedule")
        selectors = [s for r in expected for s in r["selectors"]]
        require(len(selectors) == len(set(selectors)) == 298, "selector population")
        for i, left in enumerate(selectors):
            require(not any(selection_matches(left, right) or selection_matches(right, left)
                            for right in selectors[i + 1:]), "overlapping selectors")
        finite = load_member("finite-controls.json", index)
        require(finite["source_sha"] == SOURCE and finite["source_tree"] == TREE and
                finite["passed"] is True and finite["actual_passed_cases"] == 634, "finite aggregate scope")
        require([r["cohort"] for r in finite["cohorts"]] == [r[0] for r in SCHEDULE], "finite cohort order")
        all_nodes, all_properties, all_definitions, all_providers = [], [], set(), set()
        for planned, reported in zip(expected, finite["cohorts"], strict=True):
            name = planned["name"]
            result["current_cohort"] = name
            prefix = "controls/" + name + "/"
            collect_contract_ref, run_contract_ref = index[prefix + "collect.contract.json"], index[prefix + "run.contract.json"]
            require((collect_contract_ref["bytes"], collect_contract_ref["sha256"]) ==
                    (run_contract_ref["bytes"], run_contract_ref["sha256"]), "fresh contract exact bytes")
            read(MEMBERS / (prefix + "collect.contract.json"), collect_contract_ref)
            contract_raw = read(MEMBERS / (prefix + "run.contract.json"), run_contract_ref)
            contract = parse(contract_raw)
            require(encode(contract) == contract_raw, "canonical immutable contract")
            del contract_raw
            require((contract["source_sha"], contract["source_tree"], contract["cohort"]) == (SOURCE, TREE, name),
                    "contract source and cohort")
            require(contract["selectors"] == planned["selectors"], "contract selectors")
            prior, actual = load_member(prefix + "collect.json", index), load_member(prefix + "run.json", index)
            admit_snapshot(prior, planned, "collect", contract, index)
            admit_snapshot(actual, planned, "run", contract, index)
            items = contract["collection"]
            nodes = [r["nodeid"] for r in items]
            require(len(nodes) == len(set(nodes)) == planned["expected_cases"], "collection case count")
            require([r["junit"]["name"] for r in items] == [n.rsplit("::", 1)[1] for n in nodes], "collection JUnit names")
            covered = []
            require([r["selector"] for r in planned["selection_counts"]] == planned["selectors"], "manifest selection order")
            for selection in planned["selection_counts"]:
                matches = [n for n in nodes if selection_matches(n, selection["selector"])]
                require(len(matches) == selection["expected_cases"], "selector count")
                covered.extend(matches)
            require(covered == nodes, "ordered selector coverage")
            require(read(MEMBERS / (prefix + "collect.phases.jsonl"), index[prefix + "collect.phases.jsonl"]) == b"",
                    "collect phases empty")
            require(xml(read(MEMBERS / (prefix + "collect.xml"), index[prefix + "collect.xml"])) == [],
                    "collect JUnit empty")
            phases_raw = read(MEMBERS / (prefix + "run.phases.jsonl"), index[prefix + "run.phases.jsonl"])
            require(phases_raw.endswith(b"\n"), "final phase newline")
            phases = []
            for line in phases_raw.splitlines():
                phase = parse(line)
                require(encode(phase) == line + b"\n", "canonical original phase")
                phases.append(phase)
            del phases_raw
            cases = xml(read(MEMBERS / (prefix + "run.xml"), index[prefix + "run.xml"]))
            retained_properties = phase_join(nodes, phases, items, cases)
            prov = provenance(contract, (prior, actual), source_files, config["source_inputs"])
            require(reported["passed"] is True and reported["collection_command_passed"] is True and
                    reported["body_command_attempted"] is True and reported["error"] is None, "finite command flags")
            require(reported["collection_sha256"] == index[prefix + "collect.json"]["sha256"] and
                    reported["execution_sha256"] == index[prefix + "run.json"]["sha256"], "finite snapshot references")
            rec = reported["reconciliation"]
            require(rec["ordered_duplicate_user_properties"] == retained_properties and
                    rec["cases_passed"] == len(nodes) and rec["phases_passed"] == len(phases) and
                    rec["junit_cases"] == len(cases), "finite aggregate agrees with actual rows")
            require(all(rec[k] is True for k in ("ordered_collection_equal", "ordered_phase_and_junit_bijection")) and
                    rec["skipped"] == 0 and rec["xfail_or_xpass"] == 0, "finite outcome scope")
            projection = {
                "source_sha": SOURCE, "source_tree": TREE, "cohort": name,
                "selectors": planned["selectors"], "selection_counts": planned["selection_counts"],
                "source_contract": file_reference(prefix + "run.contract.json", index),
                "complete_collection_rows_sha256": digest(encode(items)),
                "ordered_cases": [
                    {"nodeid": row["nodeid"], "junit": row["junit"], "param_id": row["param_id"],
                     "original_collection_row_sha256": digest(encode(row)),
                     "function_record_sha256": digest(encode(row["function"])),
                     "definition_ast_sha256": row["function"]["definition_ast_sha256"],
                     "fixtures": {key: [digest(encode(f["function"])) for f in value]
                                  for key, value in row["fixtures"].items()},
                     "fixture_names": row["fixture_names"], "autouse_names": row["autouse_names"],
                     "parameters_sha256": digest(encode(row["parameters"])),
                     "marks_sha256": digest(encode(row["marks"])),
                     "parameter_scopes": row["parameter_scopes"],
                     "collecting_source": row["collecting_source"],
                     "exact_parameter_admission_sha256": digest(encode(row.get("exact_parameter_admission")))}
                    for row in items],
                "provenance": prov, "ordered_duplicate_user_properties": retained_properties,
                "incoming_c_fixtures": contract["incoming_c_fixtures"],
                "incoming_2433_c_fixtures": contract["incoming_2433_c_fixtures"],
                "original_cases_reexecuted": False, "qualification_complete": False,
            }
            projection_ref = write_exclusive(OUTPUT / (name + ".json"), projection)
            summary = {
                "cohort": name, "cases": len(nodes), "phases": len(phases), "junit_cases": len(cases),
                "selectors": len(planned["selectors"]), "skipped": 0, "xfail_or_xpass": 0,
                "collection_and_body_timeout_seconds_each": planned["timeout"],
                "original_phase_duration_seconds_total": sum(r["duration_seconds"] for r in phases),
                "complete_raw_collect_run_phase_junit_source_joins": True,
                "ordered_duplicate_properties": sum(len(r["user_properties"]) for r in retained_properties),
                "unique_definitions_in_contract": len(contract["definitions"]),
                "unique_providers_in_contract": len(contract["providers"]),
                "projection": projection_ref,
                "original_files": [file_reference(prefix + mode + suffix, index) for mode in ("collect", "run")
                                   for suffix in (".json", ".contract.json", ".phases.jsonl", ".xml")],
            }
            result["cohorts"].append(summary)
            all_nodes.extend(nodes)
            all_properties.extend(retained_properties)
            all_definitions.update(contract["definitions"])
            all_providers.update((r["origin"], r["path"], r["sha256"]) for r in contract["providers"].values())
            del prior, actual, items, nodes, cases, phases, contract, projection, prov, retained_properties
            gc.collect()
        require(len(all_nodes) == len(set(all_nodes)) == 634, "cross-cohort node uniqueness")
        groups = load_member("supplemental-groups.json", index)
        require(groups["passed"] is True and groups["source_sha"] == SOURCE and groups["source_tree"] == TREE and
                groups["planned_cases"] == 634 and groups["planned_phases"] == 1902 and
                groups["planned_selection_entries"] == 298, "reported logical scope")
        require([r["cohort"] for r in groups["physical_cohorts"]] == [r[0] for r in SCHEDULE], "physical group order")
        require([n for r in groups["physical_cohorts"] for n in r["reconciled_nodeids"]] == all_nodes,
                "logical report raw node joins")
        by_name = {r["cohort"]: r for r in result["cohorts"]}
        logical = []
        for (name, members, count), original in zip(GROUPS, groups["logical_groups"], strict=True):
            require(original["group"] == name and original["physical_cohorts"] == members and
                    original["passed"] is True and original["admitted_cases"] == count and
                    original["admitted_phases"] == 3 * count, "logical group membership")
            require(sum(by_name[n]["cases"] for n in members) == count, "actual logical case total")
            logical.append({"group": name, "cohorts": members, "cases": count, "phases": 3 * count})
        result.update({
            "passed": True, "current_cohort": None, "actual_cases": len(all_nodes),
            "actual_phases": sum(r["phases"] for r in result["cohorts"]),
            "actual_junit_cases": sum(r["junit_cases"] for r in result["cohorts"]),
            "selectors": len(selectors), "physical_cohorts": 10, "logical_groups": logical,
            "original593_cases": sum(r["cases"] for r in result["cohorts"][:-1]),
            "separate_incoming41_cases": result["cohorts"][-1]["cases"],
            "unique_definition_digests": len(all_definitions), "unique_provider_identities": len(all_providers),
            "all_original_run_phases_passed": True, "collect_phase_rows": 0, "collect_junit_cases": 0,
            "ordered_duplicate_properties": sum(len(r["user_properties"]) for r in all_properties),
            "skips": 0, "xfail_or_xpass": 0,
            "source_readers_imported_or_original_tests_run": False,
            "native_phase_workload_or_installed_performance_validation": False,
            "complete_descendant_retirement_claimed": False,
            "oversized_unparsed_noncohort_member": {
                "path": "formatter-proposals.json", **index["formatter-proposals.json"],
                "bytes_verified": True, "semantic_materialization_refused_above_8MiB": True},
        })
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)[:512],
                           "traceback": traceback.format_exc(limit=8)}
    finally:
        result["elapsed_data_processing_seconds"] = time.monotonic() - started
        result["maximum_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        result["reader_sha256"] = digest(read(Path(__file__)))
        if created:
            ref = write_exclusive(OUTPUT / "result.json", result)
            print(json.dumps({**result, "result_reference": ref}, sort_keys=True))
        else:
            print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
