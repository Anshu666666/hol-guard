from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import resolve_guard_home_for_user_home
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_numeric_journal import recover_numeric_journal
from scripts.native_slo_registered_surfaces import RegisteredSurface
from scripts.native_slo_registered_surfaces_run import surface_cases
from scripts.native_slo_surface_tail_contract import ROUTES, route_for
from scripts.native_slo_surface_tail_worker import collect
from scripts.native_slo_workloads import build_cases


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    workspace = tmp_path_factory.mktemp("surface-tail-corpus")
    return build_cases(workspace)


def surface(route, tmp_path):
    return RegisteredSurface(
        route.harness,
        route.event,
        route.scope,
        ("/synthetic/python",),
        (),
        tmp_path,
        tmp_path / "registration.json",
        "f" * 64,
    )


def test_all_exact_profiles_exist_in_frozen_corpus_and_fit_public_key_bound(corpus, tmp_path):
    for route in ROUTES:
        selected = surface_cases(corpus, surface(route, tmp_path))
        assert len(selected) == route.preflight_count
        ordinary = [case for case in selected if case.case_id == route.case_id]
        assert len(ordinary) == 1
        assert ordinary[0].size_class == route.size_class
        projection = {"measurements": {route.series: {"count": 200}}}
        assert len(route.series) <= 64 and assert_privacy_safe(projection) == projection


@pytest.mark.parametrize("mode,count", [("smoke", 2), ("qualification", 200)])
def test_actual_registered_collector_preflights_before_one_numeric_batch(tmp_path, monkeypatch, corpus, mode, count):
    from scripts import native_slo_surface_tail_worker as module

    route = ROUTES[0]
    entry = surface(route, tmp_path)
    monkeypatch.setattr(module, "install_registered_surface", lambda *args: (entry,))
    monkeypatch.setattr(module, "build_cases", lambda _: corpus)
    observed = []
    numeric = tmp_path / "raw-numeric.jsonl"

    def observation(session, registered, case, journal):
        assert registered is entry
        if len(observed) < route.preflight_count:
            assert not numeric.exists()
        observed.append(case.case_id)
        return 7.0

    monkeypatch.setattr(module, "observe", observation)
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path, guard_home=tmp_path / ".hol-guard")
    report = collect(session, route=route, mode=mode, raw_file=tmp_path / "raw.json")
    assert len(observed) == count + route.preflight_count
    assert observed[route.preflight_count :] == [route.case_id] * count
    recovered = recover_numeric_journal(numeric)
    assert recovered["collection_complete"] and recovered["series"][route.series] == [7.0] * count
    assert report["measurements"][route.series]["count"] == count
    assert report["qualification_complete"] is False


def test_failed_semantic_preflight_offers_no_timing_samples(tmp_path, monkeypatch, corpus):
    from scripts import native_slo_surface_tail_worker as module

    route = route_for("copilot.preToolUse.global")
    monkeypatch.setattr(module, "install_registered_surface", lambda *args: (surface(route, tmp_path),))
    monkeypatch.setattr(module, "build_cases", lambda _: corpus)

    def fails(*args):
        raise AssertionError("registered_surface_copilot_schema_mismatch")

    monkeypatch.setattr(module, "observe", fails)
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path, guard_home=tmp_path / ".hol-guard")
    with pytest.raises(AssertionError):
        collect(session, route=route, mode="qualification", raw_file=tmp_path / "raw.json")
    assert not (tmp_path / "raw.json").exists() and not (tmp_path / "raw-numeric.jsonl").exists()


def test_cline_fixture_home_contract_is_the_production_default(tmp_path):
    # AdapterSession selects this layout before DaemonFixture relays it. This
    # assertion validates the actual production home resolver, not host startup.
    context = HarnessContext(
        home_dir=tmp_path, workspace_dir=tmp_path / "workspace", guard_home=tmp_path / ".hol-guard"
    )
    assert context.guard_home == resolve_guard_home_for_user_home(context.home_dir)


def test_unavailable_platform_is_explicit_and_unknown_text_stays_private():
    from scripts.native_slo_registered_surfaces import SurfaceUnavailableError
    from scripts.native_slo_surface_tail_worker import failure_report

    known = failure_report(SurfaceUnavailableError("zcode_windows_shell_comment_unqualified"))
    assert known["availability_code"] == "zcode_windows_shell_comment_unqualified"
    assert assert_privacy_safe(known) == known
    unknown = failure_report(SurfaceUnavailableError("unexpected_sensitive_text"))
    assert "availability_code" not in unknown
    assert "unexpected_sensitive_text" not in str(unknown)
