from __future__ import annotations

import base64
import copy
import hashlib
import json
import runpy
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.launcher_campaign_result import finalize, read_controller, validate_export
from scripts.native_slo_qualification import sampling_plan


@pytest.fixture(scope="module")
def worker() -> dict[str, Any]:
    # Reuse the already reviewed pure-data full-population generator, not an
    # installed producer or a replay of measurements from any original run.
    helpers = runpy.run_path(str(Path(__file__).with_name("test_launcher_measurement_consumer.py")))
    block = helpers["block"](sampling_plan(runs=6, qualification=True))
    block.update(cleanup_confirmed=False, export_privacy_passed=False)
    identity = block["identity_before"]
    inventory = {
        "package_sha256": identity["installed_manifest_sha256"],
        "wheel_members": 1500,
        "record_sha256": "d" * 64,
        "record_members": 1502,
        "dependencies_sha256": "f" * 64,
        "scope": "original_wheel_members_and_RECORD_listed_files_not_unlisted_generated_caches",
    }
    return {
        "schema": "hol-guard.launcher-worker-intermediate.v1",
        "passed": True,
        "arm": {
            "schema": "hol-guard.launcher-arm-intermediate.v1",
            "admitted": True,
            "producer_offered": True,
            "producer_returned": True,
            "fixture_cleanup_confirmed": True,
            "boundary_closed": True,
            "failed_stages": [],
            "policy_before_sha256": identity["policy_fixture_sha256"],
            "policy_after_sha256": identity["policy_fixture_sha256"],
            "block": block,
        },
        "installed_inventories": [inventory, dict(inventory)],
    }


def controller(worker: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(worker, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    return {
        "schema": "hol-guard.launcher-host-controller.v1",
        "configuration_sha256": "c" * 64,
        "outer_wall_seconds": 4800,
        "worker_launched": True,
        "worker_exit": 0,
        "worker_reaped": True,
        "cleanup_complete": True,
        "group_empty_before_cleanup": True,
        "emergency_group_kill_used": False,
        "collection_failure": None,
        "fault": None,
        "stdout": {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()},
        "stderr": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
        "private_worker_stdout_base64": base64.b64encode(body).decode(),
    }


def result(subject: dict[str, Any], original: dict[str, Any]) -> dict[str, Any]:
    return finalize(subject, configuration_sha256="c" * 64, identity=original["arm"]["block"]["identity_before"])


def test_full_original_population_is_joined_after_cleanup_without_mutating_flags(worker: dict[str, Any]) -> None:
    original = copy.deepcopy(worker)
    output = result(controller(worker), worker)
    assert output["admitted"] is True and output["counts_and_identity_admitted"] is True
    assert output["joined"]["offered"] == output["joined"]["returned"] == 13_464
    assert output["block"]["cleanup_confirmed"] is output["block"]["export_privacy_passed"] is True
    assert output["worker_document"]["arm"]["block"]["cleanup_confirmed"] is False
    assert output["qualification_complete"] is False
    assert worker == original


@pytest.mark.parametrize(
    "key,value",
    [
        ("configuration_sha256", "a" * 64),
        ("outer_wall_seconds", 4801),
        ("worker_launched", False),
        ("worker_exit", True),
        ("worker_exit", 1),
        ("worker_reaped", False),
        ("cleanup_complete", False),
        ("group_empty_before_cleanup", False),
        ("emergency_group_kill_used", True),
        ("collection_failure", "wall_time"),
        ("fault", "os"),
    ],
)
def test_controller_failures_do_not_promote_safe_original(worker: dict[str, Any], key: str, value: Any) -> None:
    envelope = controller(worker)
    envelope[key] = value
    output = result(envelope, worker)
    assert output["admitted"] is False and output["block"] is None
    assert output["worker_document"] == worker


@pytest.mark.parametrize("kind", ["count", "record", "policy", "source", "premature", "metrics"])
def test_source_count_policy_inventory_and_metric_faults_remain_closed(worker: dict[str, Any], kind: str) -> None:
    mutated = copy.deepcopy(worker)
    if kind == "count":
        mutated["arm"]["block"]["offers"]["rows"].pop()
    elif kind == "record":
        mutated["installed_inventories"][1]["record_sha256"] = "a" * 64
    elif kind == "policy":
        mutated["arm"]["policy_after_sha256"] = "a" * 64
    elif kind == "source":
        mutated["arm"]["block"]["identity_after"]["runtime_rule_digest"] = "a" * 64
    elif kind == "premature":
        mutated["arm"]["block"]["cleanup_confirmed"] = True
    else:
        sampled = mutated["arm"]["block"]["resources"]["sampled_resources"]
        sampled["unavailable_samples"] = 1
    output = result(controller(mutated), worker)
    assert output["admitted"] is False
    assert output["counts_and_identity_admitted"] is (kind == "metrics")
    assert output["refusal"] == ("required_metrics_unavailable" if kind == "metrics" else "data_admission_failed")


@pytest.mark.parametrize(
    "value", ["/private/owned-home/config.toml", "cat .env", "PRIVATE-SCANNER-OUTPUT", "token-value"]
)
def test_private_text_is_withheld_not_sanitized(worker: dict[str, Any], value: str) -> None:
    mutated = copy.deepcopy(worker)
    mutated["arm"]["block"]["resources"]["scope"] = value
    output = result(controller(mutated), worker)
    assert output["worker_document"] is None and output["admitted"] is False
    assert value not in json.dumps(output)
    assert output["source_bytes"]["bytes"] > 0


def test_unknown_field_and_nonfinite_or_huge_number_are_refused() -> None:
    for value in ({"auth_token": "a" * 64}, {"samples": float("nan")}, {"samples": 10**1000}):
        with pytest.raises(ValueError):
            validate_export(value)


def test_duplicate_controller_keys_are_refused() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        read_controller(b'{"schema":1,"schema":2}')


def test_original_stdout_length_and_digest_are_independently_checked(worker: dict[str, Any]) -> None:
    envelope = controller(worker)
    envelope["stdout"]["sha256"] = "f" * 64
    output = result(envelope, worker)
    assert output["admitted"] is False and output["worker_document"] is None


def test_actual_source_resource_report_vocabulary_is_admitted(monkeypatch) -> None:
    from scripts import native_slo_launcher_resources as resource
    from scripts import native_slo_resources as samples
    from scripts.native_slo_lifetime_cpu import CpuSnapshot

    class Boundary:
        identity_sha256 = "a" * 64

        def __init__(self) -> None:
            self.reads = 0

        def snapshot(self) -> CpuSnapshot:
            self.reads += 1
            return CpuSnapshot(self.reads * 1000, self.reads * 600, self.reads * 400)

        def member_pids(self) -> tuple[int, ...]:
            return (1,)

    original = samples.ResourceSampler

    class Sampler:
        def __init__(self, **arguments: Any) -> None:
            self.actual = original(**arguments)

        def __enter__(self) -> Sampler:
            for _ in range(30):
                self.actual._sample()
            return self

        def __exit__(self, *_args: object) -> None:
            self.actual._sample()

        def report(self, *, attempted: int) -> dict[str, object]:
            return self.actual.report(attempted=attempted)

    def modeled(*_args: Any, **_kwargs: Any) -> samples.TreeResources:
        return samples.TreeResources(
            rss_bytes=2000,
            private_bytes=1000,
            cpu_seconds=1.0,
            processes=1,
            threads=1,
            descriptors=4,
            handles=None,
            unavailable={"handles": "platform_unsupported"},
            process_cpu={(1, 1.0): 1.0},
            cpu_includes_reaped=True,
        )

    monkeypatch.setattr(samples, "sample_process_tree", modeled)
    monkeypatch.setattr(resource, "ResourceSampler", Sampler)
    boundary: Any = Boundary()
    observation = resource.LauncherResourceObservation(lifetime_cpu=boundary, protected_live_members=True)
    marker = object()
    assert observation.run(lambda: marker) is marker
    validate_export(observation.report)
    assert observation.report["sampled_resources"]["samples"] == 31
