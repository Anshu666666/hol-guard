"""Synthetic controls for the bounded worker-retirement reader delta only."""
import resource
resource.setrlimit(resource.RLIMIT_AS, (99614720, 99614720))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
import ast
import hashlib
import io
import json
import pathlib
import signal
signal.alarm(60)
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == "c6aba711-75f6-4cbb-90b1-d991ba91b54e"
ROOT = pathlib.Path("/home/user/pr2974-worker-retirement-parser-prep")
PINS = {
    "decode_log_stream.py": "745496184e5cb9690a45477a48da1d1866bbb370c04632463bf9b5a4fbf89dcf",
    "extract_packet_members.py": "9f890da2097e978b40bfb30999f7a4a9ce41bbc67c4c9e9a75be4a61c68c8512",
    "previous-decode_log_stream.py": "e88df94287c51e56e59a308800c236d1e29da73b75b6646705dbd8b2750c2f4b",
}
parsed = {}
for name, expected in PINS.items():
    source = (ROOT / name).read_bytes()
    assert len(source) <= 32768 and hashlib.sha256(source).hexdigest() == expected
    parsed[name] = ast.parse(source)
checks = []
def passed(name):
    checks.append({"name": name, "passed": True})
def execute(nodes, namespace):
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, "<selected-decoder-control-fragments>", "exec"), namespace)
def refuses(action, exception, name):
    try:
        action()
    except exception:
        passed(name)
    else:
        raise AssertionError(name)
space = {"json": json, "hashlib": hashlib}
execute([node for node in parsed["extract_packet_members.py"].body
         if isinstance(node, (ast.FunctionDef, ast.ClassDef))], space)
for name, raw in (
    ("duplicate_member_metadata", b'{"bytes":1,"bytes":2}'),
    ("nested_duplicate_metadata", b'{"outer":{"sha256":"a","sha256":"b"}}'),
    ("nonfinite_metadata", b'{"bytes":NaN}'),
):
    refuses(lambda raw=raw: space["strict_loads"](raw), ValueError, name)
assert space["strict_loads"](b'{"bytes":0,"encoding":"utf-8"}') == {"bytes": 0, "encoding": "utf-8"}
passed("distinct_metadata_retained")
for cap in (3, 4, 8):
    reader = space["Reader"](io.BytesIO(b'"abc"'))
    value = reader.value(cap)
    assert value["bytes"] == 5 and value["sha256"] == hashlib.sha256(b'"abc"').hexdigest()
    assert value["raw"] == (b'"abc"' if cap >= 5 else None)
    passed("original_encoded_value_boundary_" + str(cap))
# Compile the actual new filename assertion, not a duplicate predicate.
name_asserts = [node for node in ast.walk(parsed["extract_packet_members.py"])
                if isinstance(node, ast.Assert) and "p.as_posix()" in ast.unparse(node.test)]
assert len(name_asserts) == 1
def admit_name(name):
    execute(name_asserts, {"name": name, "p": pathlib.PurePosixPath(name)})
admit_name("controls/python/run.json")
passed("canonical_relative_name")
for name in ("a//b", "a/./b", "../a", "/a", "a\\b"):
    refuses(lambda name=name: admit_name(name), AssertionError, "unsafe_name_" + repr(name))
top_asserts = [node for node in ast.walk(parsed["extract_packet_members.py"])
               if isinstance(node, ast.Assert) and "key not in top_seen" in ast.unparse(node.test)]
assert len(top_asserts) == 1
execute(top_asserts, {"key": "files", "top_seen": set()})
passed("first_files_key")
refuses(lambda: execute(top_asserts, {"key": "files", "top_seen": {"files"}}),
        AssertionError, "duplicate_files_key")
class FakePath:
    def __init__(self, owner, name):
        self.owner, self.name = owner, name
    def write_text(self, value):
        self.owner.data[self.name] = value
    def open(self, mode):
        assert mode == "x"
        if self.name in self.owner.data:
            raise FileExistsError(self.name)
        raise AssertionError("This synthetic control never creates a real file")
class FakeRoot:
    def __init__(self):
        self.data = {"stream-admission.json": "original-receipt"}
    def is_dir(self):
        return True
    def __truediv__(self, name):
        return FakePath(self, name)
def receipt_branch(tree, condition):
    found = [node for node in ast.walk(tree)
             if isinstance(node, ast.If) and ast.unparse(node.test) == condition]
    assert len(found) == 1
    return found
def receipt_space(fake, created):
    return {"ROOT": fake, "created_root": created, "state": {"passed": False},
            "json": json, "hashlib": hashlib}
old = FakeRoot()
execute(receipt_branch(parsed["previous-decode_log_stream.py"], "ROOT.is_dir()"), receipt_space(old, False))
assert old.data["stream-admission.json"] != "original-receipt"
passed("old_existing_root_overwrite_reproduced")
new = FakeRoot()
execute(receipt_branch(parsed["decode_log_stream.py"], "created_root"), receipt_space(new, False))
assert new.data["stream-admission.json"] == "original-receipt"
passed("new_existing_root_receipt_preserved")
new_exclusive = FakeRoot()
refuses(lambda: execute(receipt_branch(parsed["decode_log_stream.py"], "created_root"),
                        receipt_space(new_exclusive, True)), FileExistsError, "exclusive_receipt_refuses_overwrite")
assert new_exclusive.data["stream-admission.json"] == "original-receipt"
result = {"schema": "hol-guard.pr2974.worker-retirement-parser-controls.v1",
          "source_hashes": PINS, "checks": checks, "count": len(checks), "passed": True,
          "memory_limit_bytes": 99614720,
          "maximum_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
          "source_scope": "Parsed reader function/assert/guard fragments only, in-memory streams and fake roots",
          "original_log_decoded": False, "native_or_original_workload_executed": False}
print(json.dumps(result, sort_keys=True))
