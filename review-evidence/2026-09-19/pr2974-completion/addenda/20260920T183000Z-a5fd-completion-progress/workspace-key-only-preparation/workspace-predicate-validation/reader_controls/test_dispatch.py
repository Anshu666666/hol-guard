"""Owned child forwarding, setup/cleanup/export failures, and source refusal."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from predicate import child
from predicate.bindings import Registry
from predicate.parent import FixtureForwarding


def test_setup_failure_forwards_same_dispatch_once() -> None:
    fixture, request, result = object(), {"private": "sentinel"}, object()
    calls, reports = [], []

    def original(*args: Any) -> Any:
        calls.append(args)
        return result

    observed = child.observe_dispatch(
        original,
        fixture,
        "workspace_lifecycle",
        request,
        scenario="key_rotation",
        retain=reports.append,
        registry=Registry.__new__(Registry),
    )
    assert observed is result and calls == [(fixture, "workspace_lifecycle", request)]
    assert reports[0]["setup_failed"] is True and reports[0]["observation"] is None
    assert "sentinel" not in json.dumps(reports)


def test_retention_failure_does_not_mask_original_exception() -> None:
    error = ValueError("private")
    calls = []

    def original(*args: Any) -> Any:
        calls.append(args)
        raise error

    def failed_export(_value: Any) -> None:
        raise RuntimeError("export failed")

    with pytest.raises(ValueError) as caught:
        child.observe_dispatch(
            original,
            object(),
            "workspace_lifecycle",
            {},
            scenario="key_rotation",
            retain=failed_export,
            registry=Registry.__new__(Registry),
        )
    assert caught.value is error and len(calls) == 1


def test_restore_failure_keeps_original_result(monkeypatch: Any) -> None:
    result, reports = object(), []

    class Hooks:
        restored = False

        def __init__(self, *_args: Any) -> None:
            pass

        def __enter__(self) -> Any:
            return self

        def close(self) -> None:
            raise RuntimeError("cleanup")

    monkeypatch.setattr(child, "OwnedHooks", Hooks)
    monkeypatch.setattr(child, "Capture", lambda _session: object())
    fixture = SimpleNamespace(session=object(), workspaces=tuple(range(100)))
    request = {"op": "workspace_lifecycle", "scenario": "key_rotation", "receipt_profile": "candidate"}
    assert (
        child.observe_dispatch(
            lambda *_args: result,
            fixture,
            "workspace_lifecycle",
            request,
            scenario="key_rotation",
            retain=reports.append,
            registry=Registry.__new__(Registry),
        )
        is result
    )
    assert reports == []  # Missing report is explicit incomplete admission.


def test_exact_two_entrypoint_rewrites_preserve_all_original_args(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    script = tmp_path / "scripts/native_slo_daemon_fixture.py"
    script.write_text("# fixture")
    forwarding = FixtureForwarding(tmp_path, tmp_path)
    original = ("/owned/python", "-u", str(script), "--serve", "/owned/runtime", "none", "normal", "100")
    for index, scenario in enumerate(child.SCENARIOS):
        actual = forwarding.rewrite(original, index)
        assert actual[:2] == original[:2] and actual[-5:] == original[3:]
        assert actual[actual.index("--scenario") + 1] == scenario
    with pytest.raises(ValueError):
        forwarding.rewrite(original, 2)
    with pytest.raises(ValueError):
        forwarding.rewrite((*original[:-1], "1"), 0)


def test_stale_source_hash_refused_before_install(tmp_path: Path) -> None:
    from scripts import native_slo_workspace_lifecycle as lifecycle

    source = Path(lifecycle.__file__).resolve().parents[1]
    rows = json.loads((Path(__file__).resolve().parents[1] / "source-bindings.json").read_text())
    rows[0]["sha256"] = "0" * 64
    manifest = tmp_path / "bindings.json"
    manifest.write_text(json.dumps(rows))
    with pytest.raises(RuntimeError, match="source_identity"):
        Registry(source, manifest)
