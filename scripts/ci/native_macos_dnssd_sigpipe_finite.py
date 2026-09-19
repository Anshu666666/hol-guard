"""Reconcile the exact new finite selection and its actual JUnit without replay."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TESTS = (
    ("tests/test_native_macos_dnssd_sigpipe.py", 27),
    ("tests/test_native_macos_dnssd_sigpipe_path.py", 8),
    ("tests/test_native_macos_dnssd_sigpipe_forwarding.py", 13),
)


def expected_population() -> tuple[list[tuple[str, str]], list[dict[str, Any]]]:
    population, inputs = [], []
    for name, expected in TESTS:
        raw = (ROOT / name).read_bytes()
        tree = ast.parse(raw.decode("utf-8"), filename=name, type_comments=True)
        functions = []
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
                continue
            count = 1
            parameters = []
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or ast.unparse(decorator.func) != "pytest.mark.parametrize":
                    raise ValueError("Unexpected new finite decorator")
                if len(decorator.args) != 2 or decorator.keywords:
                    raise ValueError("Unbounded new finite parameter form")
                values = ast.literal_eval(decorator.args[1])
                if not isinstance(values, (tuple, list)) or not values:
                    raise ValueError("New finite parameter population")
                count *= len(values)
                parameters.append({"names": ast.literal_eval(decorator.args[0]), "values": values})
            functions.append({"name": node.name, "cases": count, "parameters": parameters})
            population.extend([(name[:-3].replace("/", "."), node.name)] * count)
        if sum(row["cases"] for row in functions) != expected:
            raise ValueError("New finite source count changed")
        inputs.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "functions": functions})
    if len(population) != 48:
        raise ValueError("New finite total")
    return population, inputs


def main() -> int:
    directory = Path(sys.argv[1])
    result: dict[str, Any] = {
        "schema": "hol-guard.macos-sigpipe-finite-contract.v1", "passed": False,
        "qualification_pass": False, "old_83_or_475_replayed": False,
        "phase_observer_or_separate_collection_claimed": False, "cases": [],
    }
    try:
        expected, result["inputs"] = expected_population()
        path = directory / "finite-junit.xml"
        raw = path.read_bytes()
        if not 0 < len(raw) <= 512 * 1024:
            raise ValueError("Finite XML bound")
        result["junit"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        root = ET.fromstring(raw)
        cases = list(root.iter("testcase"))
        actual = []
        keys = []
        for case in cases:
            name, classname = case.attrib["name"], case.attrib["classname"]
            children = [item.tag for item in case]
            result["cases"].append({
                "classname": classname, "name": name, "seconds": case.attrib.get("time"),
                "outcome_elements": [tag for tag in children if tag in ("failure", "error", "skipped")],
            })
            keys.append((classname, name))
            actual.append((classname, name.split("[", 1)[0]))
        if actual != expected or len(keys) != len(set(keys)):
            raise ValueError("Ordered finite function population or unique parameter IDs")
        suites = list(root.iter("testsuite"))
        totals = {key: sum(int(suite.attrib.get(key, "0")) for suite in suites) for key in (
            "tests", "failures", "errors", "skipped"
        )}
        result["totals"] = totals
        if totals != {"tests": 48, "failures": 0, "errors": 0, "skipped": 0}:
            raise ValueError("Finite outcomes")
        if any(row["outcome_elements"] for row in result["cases"]):
            raise ValueError("Finite non-passing case")
        result["passed"] = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, ET.ParseError) as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        target = directory / "finite-contract.json"
        pending = target.with_suffix(".pending")
        pending.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(target)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
