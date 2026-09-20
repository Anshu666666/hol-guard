"""Independently join retained original phase-control records without executing controls."""
import ast
import hashlib
import json
import pathlib
import xml.etree.ElementTree as ET

ROOT = pathlib.Path("/workspace/scratch/745337b67ff9/qualification-recovered/phase-untimed-35511122796")
SOURCE = pathlib.Path("/workspace/scratch/745337b67ff9/qualification-recovered/phase-repo")

def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value

def read(name):
    return json.loads((ROOT / name).read_bytes(), object_pairs_hook=pairs)

rb = read("READBACK.json")
assert rb["complete"] and len(rb["members"]) == 23
for member in rb["members"]:
    data = (ROOT / member["name"]).read_bytes()
    assert len(data) == member["bytes"] and hashlib.sha256(data).hexdigest() == member["sha256"]
stages = {}
for name in ("ruff", "format", "types", "collect", "controls"):
    record = read(name + "-result.json")
    assert record["returncode"] == 0 and record["capture_complete"] and record["timed_out"] is False
    for suffix, member in record["streams"].items():
        data = (ROOT / (name + "." + suffix)).read_bytes()
        assert len(data) == member["bytes"] == member["retained_bytes"]
        assert hashlib.sha256(data).hexdigest() == member["sha256"] and not member["overflow"]
    stages[name] = {"returncode": 0, "capture_complete": True}
assert (ROOT / "source-bind.json").read_bytes() == (ROOT / "control-source-before.json").read_bytes() == (ROOT / "source-after.json").read_bytes()
binding = read("source-bind.json")
assert binding["source"]["sha"] == "65956a96b932f2233749ce044980129d0205755b"
assert binding["source"]["tree"] == "4c26fc53ce20944be56ec26a58115c95857fe8ea"
assert binding["driver"]["sha"] == "3945934e5aa683237cfa05ddbefed3140b73a102"
assert binding["driver"]["tree"] == "2b1abb4c5a537072092dad153cf1fda5c85e6c2a"
assert len(binding["inputs"]) == 18
for name, member in binding["inputs"].items():
    data = (SOURCE / name).read_bytes()
    assert len(data) == member["bytes"] and hashlib.sha256(data).hexdigest() == member["sha256"]
    assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == member["git_blob"]
declared = read("declared-controls.json")
count = 0
for name in declared["tests"]:
    tree = ast.parse((SOURCE / name).read_text())
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        cases = 1
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "parametrize":
                assert len(decorator.args) >= 2 and isinstance(decorator.args[1], (ast.List, ast.Tuple))
                cases *= len(decorator.args[1].elts)
        count += cases
selectors = [line for line in (ROOT / "collect.stdout").read_text().splitlines() if line.startswith("tests/") and "::" in line]
assert count == declared["declared_cases"] == len(set(selectors)) == len(selectors) == 61
assert selectors == read("collected-selectors.json")
xml = (ROOT / "controls.xml").read_bytes()
assert b"<!DOCTYPE" not in xml and b"<!ENTITY" not in xml
cases = []
for case in ET.fromstring(xml).iter("testcase"):
    assert case.find("failure") is None and case.find("error") is None and case.find("skipped") is None
    cases.append({"selector": case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"], "status": "passed"})
admission = read("control-admission.json")
assert [case["selector"] for case in cases] == selectors and admission["cases"] == cases and admission["passed"] is True
assert admission["declared_cases"] == admission["collected"] == admission["executed"] == 61
assert admission["original_88_calls_executed"] is False
types = read("types.stdout")
assert types["summary"]["errorCount"] == 0 and not [row for row in types["generalDiagnostics"] if row["severity"] == "error"]
result = {
    "schema": "priority-phase-hosted-untimed-v2-verified.v1",
    "run": 35511122796, "job": 106079100401, "artifact": 10605491806,
    "archive_bytes": rb["archive_bytes"], "archive_sha256": rb["archive_sha256"], "members": 23,
    "source": binding["source"], "driver": binding["driver"],
    "all18_source_inputs_match_exact_published_bytes": True, "source_before_after_byte_identical": True,
    "stages": stages, "interpreter": read("interpreter.json"), "types_summary": types["summary"],
    "declared_collected_executed_passed": 61, "skipped": 0, "ordered_cases": cases,
    "all_stream_hash_size_overflow_joins": True, "original88_calls_executed": False,
    "native_build_or_workload": False, "qualification_eligible": False,
    "reader_revision": "Outer literal-list/tuple AST cardinality; parameter expressions are never evaluated.",
    "scope": "Untimed Mac ARM source controls. Native installed behavior and original88-call diagnostic remain unexecuted."
}
with (ROOT / "VERIFIED-RESULT.json").open("x") as stream:
    json.dump(result, stream, indent=2)
    stream.write("\n")
print(json.dumps({key: value for key, value in result.items() if key != "ordered_cases"}))
