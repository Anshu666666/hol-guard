"""Record actual collection, fixture bindings, phases and product origins."""

from __future__ import annotations

import ast
import enum
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import sys

ROOT = Path(os.environ["LSC_TEST_ROOT"]).resolve()
PRODUCT = Path(os.environ["LSC_PRODUCT_ROOT"]).resolve()
OUTPUT = Path(os.environ["LSC_TEST_REPORT"]).resolve()
PREFIX = Path(sys.prefix).resolve()
COLLECTION = os.environ["LSC_COLLECTION_ONLY"] == "1"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_definition_contract import callable_source


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def location(path: Path) -> str:
    path = path.resolve()
    for root, prefix in ((ROOT, "@tests/"), (PRODUCT, "@product/"), (PREFIX, "@environment/")):
        if path.is_relative_to(root):
            return prefix + str(path.relative_to(root))
    return str(path)


def function_record(value):
    if inspect.isbuiltin(value):
        return {"builtin": value.__module__ + "." + value.__qualname__}
    source, raw, definition = callable_source(value)
    return {"path": location(source.path), "name": raw.__qualname__,
            "first_line": raw.__code__.co_firstlineno,
            "function_ast_sha256": digest(ast.dump(definition["node"], include_attributes=False).encode()),
            "whole_file_sha256": source.sha256}


def value_record(value):
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        assert math.isfinite(value)
        return value
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if inspect.ismodule(value):
        return {"module": value.__name__}
    if inspect.isbuiltin(value):
        return {"builtin": value.__module__ + "." + value.__qualname__}
    if isinstance(value, Path):
        return {"path": location(value)}
    if isinstance(value, enum.Enum):
        return {"enum": type(value).__module__ + "." + type(value).__qualname__,
                "value": value_record(value.value)}
    if isinstance(value, (list, tuple)):
        return {"type": type(value).__name__, "items": [value_record(item) for item in value]}
    if isinstance(value, (set, frozenset)):
        items = [value_record(item) for item in value]
        return {"type": type(value).__name__, "items": sorted(items, key=lambda item: json.dumps(item, sort_keys=True))}
    if isinstance(value, dict):
        items = [[value_record(key), value_record(item)] for key, item in value.items()]
        return {"dict": sorted(items, key=lambda item: json.dumps(item[0], sort_keys=True))}
    if inspect.isfunction(value):
        return {"callable": function_record(value)}
    if inspect.isclass(value):
        return {"class": value.__module__ + "." + value.__qualname__}
    text = repr(value)
    assert not re.search(r"0x[0-9a-fA-F]+", text), (type(value).__qualname__, "Unstable parameter representation")
    return {"type": type(value).__module__ + "." + type(value).__qualname__, "repr": text}


class Capture:
    def __init__(self):
        self.cases = []
        self.reports = []
        self.collection_reports = []
        self.setups = 0
        self.calls = 0
        self.collection_bound = False

    def pytest_collection_finish(self, session):
        for item in session.items:
            fixtures = {}
            autouse = list(session._fixturemanager._getautousenames(item))
            for name, definitions in sorted(item._fixtureinfo.name2fixturedefs.items()):
                fixtures[name] = [{"argname": definition.argname, "scope": definition.scope,
                                   "baseid": definition.baseid, "argnames": list(definition.argnames),
                                   "params": value_record(definition.params), "ids": value_record(definition.ids),
                                   "autouse_for_item": name in autouse, "function": function_record(definition.func)}
                                  for definition in definitions]
            callspec = getattr(item, "callspec", None)
            self.cases.append({
                "nodeid": item.nodeid, "function": function_record(item.obj),
                "markers": [{"name": marker.name, "args": value_record(marker.args),
                             "kwargs": value_record(marker.kwargs)} for marker in item.iter_markers()],
                "fixture_order": list(item.fixturenames), "fixture_definitions": fixtures,
                "fixture_initialnames": list(item._fixtureinfo.initialnames), "autouse_names": autouse,
                "parameters": value_record(callspec.params) if callspec else None,
                "parameter_indices": callspec.indices if callspec else None,
                "parameter_id": callspec.id if callspec else None,
                "argument_scopes": {name: scope.value for name, scope in callspec._arg2scope.items()} if callspec else None})
        if not COLLECTION:
            prior = json.loads(Path(os.environ["LSC_PRIOR_COLLECTION"]).read_text())
            assert prior["pytest_exit_code"] == 0 and prior["error"] is None
            assert self.cases == prior["cases"], "Execution collection differs before any fixture setup"
        self.collection_bound = True

    def refuse_unbound_execution(self):
        assert not COLLECTION and self.collection_bound, "Unbound execution is refused"

    def pytest_runtest_protocol(self, item, nextitem):
        self.refuse_unbound_execution()

    def pytest_fixture_setup(self, fixturedef, request):
        self.refuse_unbound_execution()

    def pytest_pyfunc_call(self, pyfuncitem):
        self.refuse_unbound_execution()

    def pytest_runtest_setup(self, item):
        self.refuse_unbound_execution()
        self.setups += 1
        assert not COLLECTION, "A fixture setup was reached during collection-only validation"

    def pytest_runtest_call(self, item):
        self.refuse_unbound_execution()
        self.calls += 1
        assert not COLLECTION, "A test body was reached during collection-only validation"

    def pytest_collectreport(self, report):
        self.collection_reports.append({"nodeid": report.nodeid, "outcome": report.outcome,
                                        "longrepr": str(report.longrepr) if report.failed else None})

    def pytest_runtest_logreport(self, report):
        self.reports.append({
            "nodeid": report.nodeid, "when": report.when, "outcome": report.outcome,
            "duration_seconds": report.duration, "wasxfail": getattr(report, "wasxfail", None),
            "longrepr": str(report.longrepr) if report.longrepr is not None else None})


def main() -> int:
    # The test root may be the baseline/candidate checkout or an owned copy of the
    # unchanged seam file. The product root is explicitly supplied and checked.
    assert PRODUCT.is_dir() and ROOT.is_dir()
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(PRODUCT))
    import pytest
    for name in ("pytest_runtest_protocol", "pytest_fixture_setup", "pytest_pyfunc_call",
                 "pytest_runtest_setup", "pytest_runtest_call"):
        setattr(Capture, name, pytest.hookimpl(tryfirst=True)(getattr(Capture, name)))
    capture = Capture()
    code, error, origins = 99, None, {}
    try:
        code = int(pytest.main(sys.argv[1:], plugins=[capture]))
    except BaseException as caught:
        error = repr(caught)
    finally:
        try:
            assert len({case["nodeid"] for case in capture.cases}) == len(capture.cases)
            if COLLECTION:
                assert capture.setups == capture.calls == 0 and not capture.reports
            for name, module in sorted(sys.modules.copy().items()):
                if name != "codex_plugin_scanner" and not name.startswith("codex_plugin_scanner."):
                    continue
                filename = getattr(module, "__file__", None)
                if filename is None:
                    continue
                path = Path(filename).resolve()
                assert path.is_relative_to(PRODUCT), (name, str(path), str(PRODUCT))
                origins[name] = {"path": str(path.relative_to(PRODUCT)), "sha256": digest(path.read_bytes())}
            assert origins, "No product source origin was observed"
        except BaseException as caught:
            error = error or repr(caught)
            code = code or 98
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps({
            "pytest_exit_code": code, "error": error, "cases": capture.cases,
            "phase_reports": capture.reports, "collection_reports": capture.collection_reports, "fixture_setup_entries": capture.setups,
            "test_call_entries": capture.calls, "product_module_origins": origins,
            "collection_only": COLLECTION, "collection_bound_before_execution": capture.collection_bound,
            "qualification_complete": False},
            sort_keys=True, indent=2) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
