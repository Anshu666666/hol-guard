"""Finite origin partition and encrypted-only residual function identities."""

from __future__ import annotations

import json
import sysconfig
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.package_benchmark_phases import phase_report, validate_phases
from scripts.package_benchmark_profile_origins import ORIGINS, private_top, roots
from tests.test_package_benchmark_phases import synthetic_phases


def code_at(path, qualname="example"):
    scope = {}
    exec(compile("def example(): pass", str(path), "exec"), scope)
    code = scope["example"].__code__
    field = "co_qualname" if hasattr(code, "co_qualname") else "co_name"
    return code.replace(**{field: qualname})


def entry(code, cpu=0.001):
    return SimpleNamespace(code=code, callcount=2, reccallcount=0, totaltime=cpu, inlinetime=cpu)


def test_exact_origin_partition_and_private_residual_cover_unselected_entries(tmp_path):
    paths = roots(tmp_path)
    library = paths["libraries"][0]
    code_origins = [
        (code_at(paths["guard"] / "other.py"), "guard_python"),
        (code_at(library / "pydantic/main.py"), "pydantic_python"),
        (code_at(library / "pydantic_fake/main.py"), "third_party_python"),
        (code_at(paths["stdlib"] / "json/encoder.py"), "json_python"),
        (code_at(paths["stdlib"] / "hmac.py"), "hash_python"),
        (code_at(paths["stdlib"] / "sqlite3/dbapi2.py"), "sqlite_python"),
        (code_at(paths["stdlib"] / "re/__init__.py"), "regex_python"),
        (code_at(paths["stdlib"] / "pathlib.py"), "stdlib_python"),
        (code_at(tmp_path / "PRIVATE_PATH/unknown.py"), "other_python"),
        (code_at("<PRIVATE_GENERATED>"), "other_python"),
        ("<method 'validate_python' of 'pydantic_core._pydantic_core.SchemaValidator' objects>", "pydantic_core"),
        ("<method 'validate_python' of 'other.SchemaValidator' objects>", "other_c"),
        ("<built-in method _json.encode_basestring_ascii>", "json_c"),
        ("<method 'update' of '_hashlib.HMAC' objects>", "hash_c"),
        ("<method 'lower' of 'str' objects>", "bytes_text_c"),
        ("<method 'execute' of 'sqlite3.Connection' objects>", "sqlite_c"),
        ("<method 'search' of 're.Pattern' objects>", "regex_c"),
        # A leaf name is insufficient to assert a module/implementation.
        ("<built-in function to_json>", "other_c"),
        ("PRIVATE_C_NAME", "other_c"),
    ]
    private = {}
    result = phase_report(
        SimpleNamespace(getstats=lambda: [entry(code) for code, _ in code_origins]),
        tmp_path,
        wall_ns=10**9,
        process_ns=10**9,
        private_details=private,
    )
    rows = result["origins"]["categories"]
    for category in ORIGINS:
        count = sum(label == category for _, label in code_origins)
        assert rows[category] == {
            "functions": count,
            "calls": count * 2,
            "recursive_calls": 0,
            "exclusive_thread_cpu_ns": count * 1_000_000,
        }
    assert sum(row["exclusive_thread_cpu_ns"] for row in rows.values()) == result["profiled_exclusive_thread_cpu_ns"]
    assert "PRIVATE" not in json.dumps(result) and str(tmp_path) not in json.dumps(result)
    assert private["eligible_functions"] == len(code_origins) - 1  # SQLite execute is already selected.
    assert "PRIVATE_C_NAME" in json.dumps(private)
    assert "PRIVATE_PATH" not in json.dumps(private) and "PRIVATE_GENERATED" not in json.dumps(private)
    validate_phases(result)


def test_private_selection_excludes_selected_spans_and_reports_omission(tmp_path):
    guard = roots(tmp_path)["guard"]
    selected = code_at(guard / "runtime/supply_chain_bundle_models.py", "SupplyChainBundleIndex.build")
    stats = [entry(selected, 1.0)] + [entry(f"private-{i}", i / 1000) for i in range(75)]
    private = {}
    result = phase_report(
        SimpleNamespace(getstats=lambda: stats), tmp_path, wall_ns=10**10, process_ns=10**10, private_details=private
    )
    assert result["functions"]["bundle_index"]["calls"] == 2
    assert private["eligible_functions"] == 75 and private["omitted_functions"] == 25
    assert len(private["functions"]) == 50
    assert private["functions"][0]["identity"] == "private-74"
    assert private["functions"][-1]["identity"] == "private-25"
    assert "SupplyChainBundleIndex" not in json.dumps(private)


def test_private_identity_is_bounded_and_has_full_identity_digest(tmp_path):
    import hashlib

    identity = "x" * 10000
    top = private_top([entry(identity)], tmp_path)["functions"][0]
    assert top["identity"] == "x" * 256 and top["identity_truncated"] is True
    assert top["identity_sha256"] == hashlib.sha256(identity.encode()).hexdigest()
    assert len(json.dumps(top)) < 1024


@pytest.mark.parametrize(
    "mutation", ("category", "field", "bool", "negative", "sum", "scope", "schema", "functions", "zero", "recursive")
)
def test_closed_public_origin_validation_rejects_unknowns_and_impossible_metrics(mutation):
    value = synthetic_phases()
    origins = value["origins"]
    row = origins["categories"]["other_c"]
    if mutation == "category":
        origins["categories"]["PRIVATE"] = {}
    elif mutation == "field":
        row["PRIVATE"] = 1
    elif mutation == "bool":
        row["functions"] = True
    elif mutation == "negative":
        row["calls"] = -1
    elif mutation == "sum":
        row.update(functions=1, calls=1, exclusive_thread_cpu_ns=1)
    elif mutation == "scope":
        origins["relationship"] = "inclusive"
    elif mutation == "schema":
        origins["schema"] = "unknown"
    elif mutation == "functions":
        row.update(functions=2, calls=1)
    elif mutation == "zero":
        row["calls"] = 1
    else:
        row.update(functions=1, calls=1, recursive_calls=2)
    with pytest.raises(ValueError, match="package_phase_origin"):
        validate_phases(value)


def test_library_paths_are_admitted_before_stdlib_parent(tmp_path):
    # Typical locked venv roots are nested under a Python lib path; explicit
    # third-party roots must not be mislabeled as standard-library work.
    from scripts.package_benchmark_profile_origins import python_origin

    stdlib = Path(sysconfig.get_path("stdlib"))
    libraries = (stdlib / "site-packages",)
    category, _ = python_origin(
        code_at(libraries[0] / "pydantic/main.py"), {"guard": tmp_path, "stdlib": stdlib, "libraries": libraries}
    )
    assert category == "pydantic_python"


def test_route_failure_retains_private_residual_without_completed_observation(tmp_path, monkeypatch):
    from scripts import package_benchmark_worker as worker
    from scripts.package_benchmark_corpus import Case
    from tests.test_package_benchmark_matrix import worker_case

    def fail(*_args):
        raise RuntimeError("synthetic_route_failure")

    monkeypatch.setattr(worker, "_run_route", fail)
    with pytest.raises(RuntimeError, match="synthetic_route_failure"):
        worker_case(Case("npm", 100, 100, "exact", "protect_dry_run"), tmp_path, monkeypatch, measurement="attribution")
    journal = [json.loads(line) for line in (tmp_path / "journal.jsonl").read_text().splitlines()]
    terminal = journal[-1]
    assert terminal["status"] == "attribution_finished"
    assert terminal["private_profile_residual"]["functions"]
    assert all(row["status"] != "completed" for row in journal)
    assert not (tmp_path / "semantic.json").exists()
    validate_phases(terminal["phases"])
