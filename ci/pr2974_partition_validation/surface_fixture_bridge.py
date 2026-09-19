"""Verify only the eight approved Surface synthetic fixture literal substitutions."""
from __future__ import annotations

import ast
import hashlib
import importlib
import io
import tokenize
from pathlib import Path

from source_definition_contract import IGNORED_TOKENS, outer_units

SPEC = {
    "baseline_sha256": "aefc229d8cc717aecb100aa48f2f2a890349dd46bed8075ac1bf2d93e98f8ddf",
    "helper": {
        "path": "tests/guard_surface_fixture_support.py",
        "module": "tests.guard_surface_fixture_support",
        "name": "SYNTHETIC_DPOP_PRIVATE_KEY_PEM",
        "sha256": "296db67a4086ca7b9958a85883f5a373ceae4fe5d3996387afac7d5c786ccb5f"
    },
    "value_sha256": "ad46fa6e7bd524f2a35f4d8a32828cd31fda394ac70a2115e5adba4d7cd301c8",
    "files": {
        "tests/test_guard_surface_server_07_cloud_identity.py": {
            "before_sha256": "8941cee53538006ef14bf1c235e397ba4a8113c469c79d321b0b172c06f02fdf",
            "after_sha256": "bae3b9d83689715acafc3bac5716687f9224468d8e6d120f800452aee439e5d5",
            "names": [
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_uses_oauth_profile_without_legacy_credentials",
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_extracts_plan_id_from_oauth_credentials",
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_mirrors_oauth_repair_detail_in_pairing_state",
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_surfaces_first_sync_repair_consistently"
            ]
        },
        "tests/test_guard_surface_server_08_cloud_recovery.py": {
            "before_sha256": "aff97a78d70901f5db52ac1983a1d27bf6f1725ef1668161181952ad138f37dc",
            "after_sha256": "50a1be6a061603b379b0e29c19c6fd7e85ce1384175be3095ad07cd1b2ac500e",
            "names": [
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_softens_refresh_race_copy_when_local_protection_stays_active",
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_reports_post_sync_reauth_as_local_only",
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_keeps_failed_sync_copy_distinct_from_oauth_repair",
                "TestGuardSurfaceServer.test_guard_daemon_runtime_snapshot_prefers_active_sync_over_expired_connect_state"
            ]
        }
    }
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _offset(text, line, byte_column):
    lines = text.splitlines(keepends=True)
    prefix = lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8")
    return sum(map(len, lines[:line - 1])) + len(prefix)


def _bounds(text, node):
    return (_offset(text, node.lineno, node.col_offset),
            _offset(text, node.end_lineno, node.end_col_offset))


def _keyword(function, expected_name):
    found = []
    for call in ast.walk(function):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name) and call.func.value.id == "store"
                and call.func.attr == "set_oauth_local_credentials"):
            continue
        for keyword in call.keywords:
            if keyword.arg == "dpop_private_key_pem":
                found.append(keyword.value)
    assert len(found) == 1, ("Ambiguous approved setter keyword", expected_name)
    return found[0]


def _tokens(raw, node):
    start = min([node.lineno, *[item.lineno for item in node.decorator_list]])
    return [(token.type, token.string)
            for token in tokenize.tokenize(io.BytesIO(raw).readline)
            if token.type not in IGNORED_TOKENS
            and start <= token.start[0] and token.end[0] <= node.end_lineno]


class SurfaceFixtureBridge:
    """Source-bound candidate inverse; never constructed for baseline collection."""

    def __init__(self, root, baseline):
        self.root = Path(root).resolve(strict=True)
        self.baseline = baseline
        assert baseline.sha256 == SPEC["baseline_sha256"]
        original = dict(outer_units(baseline.tree))
        self.name = SPEC["helper"]["name"]
        helper_path = self.root / SPEC["helper"]["path"]
        helper_raw = helper_path.read_bytes()
        assert _sha(helper_raw) == SPEC["helper"]["sha256"]
        helper = ast.parse(helper_raw, filename=str(helper_path), type_comments=True)
        assert len(helper.body) == 2
        doc, assignment = helper.body
        assert isinstance(doc, ast.Expr) and isinstance(doc.value, ast.Constant)
        assert type(doc.value.value) is str
        assert isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
        assert isinstance(assignment.targets[0], ast.Name) and assignment.targets[0].id == self.name
        assert isinstance(assignment.value, ast.Constant) and type(assignment.value.value) is str
        self.value = assignment.value.value
        assert len(self.value.encode("utf-8")) == 74
        assert _sha(self.value.encode("utf-8")) == SPEC["value_sha256"]
        self.files = {}
        self.units = {}
        self.evidence = {
            "candidate_only": True, "baseline_modified": False,
            "helper": {"path": SPEC["helper"]["path"], "sha256": _sha(helper_raw), "bytes": len(helper_raw)},
            "value_sha256": SPEC["value_sha256"], "value_bytes": 74, "sites": [],
        }
        for path, pin in SPEC["files"].items():
            raw = (self.root / path).read_bytes()
            assert _sha(raw) == pin["after_sha256"], path
            text = raw.decode("utf-8")
            tree = ast.parse(text, filename=str(self.root / path), type_comments=True)
            current = dict(outer_units(tree))
            imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                       and node.module == SPEC["helper"]["module"]]
            assert len(imports) == 1
            imported = imports[0]
            assert imported.level == 0 and len(imported.names) == 1
            assert imported.names[0].name == self.name and imported.names[0].asname is None
            start, end = _bounds(text, imported)
            assert text[start:end] == "from " + SPEC["helper"]["module"] + " import " + self.name
            assert imported.col_offset == 0 and text[end:end + 1] == "\n"
            edits = [(start, end + 1, "")]
            for name in pin["names"]:
                before, after = original[name], current[name]
                old_value, new_value = _keyword(before, name), _keyword(after, name)
                assert isinstance(old_value, ast.Constant) and type(old_value.value) is str
                assert old_value.value == self.value
                assert isinstance(new_value, ast.Name) and new_value.id == self.name
                assert isinstance(new_value.ctx, ast.Load)
                all_added = [node for node in ast.walk(after)
                             if isinstance(node, ast.Name) and node.id == self.name]
                assert all_added == [new_value], name
                original_literal = ast.get_source_segment(baseline.text, old_value)
                assert original_literal is not None
                edits.append((*_bounds(text, new_value), original_literal))
                self.evidence["sites"].append({
                    "path": path, "qualname": name,
                    "keyword": "store.set_oauth_local_credentials:dpop_private_key_pem",
                    "candidate_name_line": new_value.lineno, "original_literal_line": old_value.lineno,
                    "raw_function_ast": ast.dump(after, include_attributes=False),
                    "original_function_ast": ast.dump(before, include_attributes=False),
                })
                self.units[(path, name)] = True
            edits.sort(reverse=True)
            previous = len(text)
            inverse = text
            for start, end, replacement in edits:
                assert 0 <= start < end <= previous
                inverse = inverse[:start] + replacement + inverse[end:]
                previous = start
            inverse_raw = inverse.encode("utf-8")
            assert _sha(inverse_raw) == pin["before_sha256"], ("Whole-file inverse differs", path)
            normalized = dict(outer_units(ast.parse(inverse, filename=str(self.root / path), type_comments=True)))
            for name in pin["names"]:
                assert ast.dump(normalized[name], include_attributes=False) == ast.dump(
                    original[name], include_attributes=False), name
            self.files[path] = {"raw": raw, "inverse_raw": inverse_raw, "units": normalized}
        assert len(self.units) == 8
        self.evidence["exact_whole_file_inverse"] = {
            path: {"raw_sha256": pin["after_sha256"], "inverse_sha256": pin["before_sha256"]}
            for path, pin in SPEC["files"].items()
        }

    def applies(self, path, name):
        return (path, name) in self.units

    def definition(self, path, name, node):
        return self.files[path]["units"][name] if self.applies(path, name) else node

    def tokens(self, path, name, source, node):
        if self.applies(path, name):
            return _tokens(self.files[path]["inverse_raw"], self.files[path]["units"][name])
        return source.tokens_for(node)

    def runtime_binding(self, path, name, function):
        assert self.applies(path, name)
        provider = importlib.import_module(SPEC["helper"]["module"])
        provider_path = Path(provider.__file__).resolve(strict=True)
        assert provider_path == self.root / SPEC["helper"]["path"]
        assert _sha(provider_path.read_bytes()) == SPEC["helper"]["sha256"]
        value = vars(provider)[self.name]
        assert type(value) is str and value == self.value
        assert function.__globals__[self.name] is value
        return {
            "helper_path": str(provider_path), "helper_sha256": SPEC["helper"]["sha256"],
            "module": provider.__name__, "name": self.name, "value_sha256": _sha(value.encode("utf-8")),
            "value_bytes": len(value.encode("utf-8")), "imported_object_is_provider_object": True,
            "imported_id_within_process": id(function.__globals__[self.name]),
            "provider_id_within_process": id(value),
        }
