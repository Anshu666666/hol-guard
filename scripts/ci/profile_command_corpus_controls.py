"""Exercise diagnostic privacy and source-frame boundaries before profiling."""
from __future__ import annotations

import cProfile
import json
import sysconfig
import tempfile
from pathlib import Path


def _entries(function, *arguments):
    profiler = cProfile.Profile(builtins=False)
    try:
        result = profiler.runcall(function, *arguments)
    finally:
        profiler.disable()
    return result, profiler.getstats()


def _expect_source_failure(helper, entries, root, expected, wanted):
    try:
        helper.profile_rows(entries, root, expected)
    except ValueError as error:
        assert error.args == (wanted,)
        assert helper.exception_metadata(error) == {
            "class": "ValueError", "diagnosticCode": wanted,
        }
    else:
        raise AssertionError("source_boundary_refusal_missing")


def _privacy_controls(helper):
    assert helper.exception_metadata(ValueError("untracked_profile_source")) == {
        "class": "ValueError", "diagnosticCode": "untracked_profile_source",
    }

    class Unprintable:
        def __str__(self):
            raise AssertionError("exception_argument_stringified")

        def __repr__(self):
            raise AssertionError("exception_argument_rendered")

    errors = (
        ValueError("private-sentinel"),
        ValueError("untracked_profile_source\nprivate-sentinel"),
        ValueError("untracked_profile_source", "private-sentinel"),
        ValueError(Unprintable()),
    )
    for error in errors:
        metadata = helper.exception_metadata(error)
        assert metadata == {"class": "ValueError"}
        assert "private-sentinel" not in json.dumps(metadata)
    custom = type("CustomValueError", (ValueError,), {})("untracked_profile_source")
    assert helper.exception_metadata(custom) == {"class": "OtherException"}


def _repository_controls(helper):
    with tempfile.TemporaryDirectory(prefix="guard-profile-source-") as temporary:
        root = Path(temporary).resolve()
        path = root / "tracked.py"
        payload = b"def probe():\n    return 7\n"
        path.write_bytes(payload)
        namespace = {}
        exec(compile(payload, str(path), "exec"), namespace)
        result, entries = _entries(namespace["probe"])
        assert result == 7
        expected = {"tracked.py": helper.git_blob(payload)}
        rows, bindings, seen, count = helper.profile_rows(entries, root, expected)
        assert len(rows) == 1 and count == 1 and seen == {"tracked.py"}
        assert bindings == {helper.source_id("tracked.py"): expected["tracked.py"]}
        _expect_source_failure(helper, entries, root, {}, "untracked_profile_source")
        _expect_source_failure(
            helper, entries, root, {"tracked.py": "0" * 40}, "profile_source_changed",
        )


def _installed_dependency_control(helper):
    from packaging import version

    root = Path.cwd().resolve()
    expected = helper.frozen_source(root)
    dependency = Path(version.__file__).resolve()
    sites = {Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib")}
    if not dependency.is_relative_to(root):
        raise ValueError("dependency_probe_not_nested")
    if not any(dependency.is_relative_to(site) for site in sites):
        raise ValueError("dependency_probe_not_site_packages")
    assert str(dependency.relative_to(root)) not in expected
    result, entries = _entries(version.Version, "1.2.3")
    assert str(result) == "1.2.3"
    rows, bindings, seen, count = helper.profile_rows(entries, root, expected)
    assert rows == [] and bindings == {} and seen == set() and count == 0


def verify_profile_boundaries(helper):
    _privacy_controls(helper)
    _repository_controls(helper)
    _installed_dependency_control(helper)
    return 0
