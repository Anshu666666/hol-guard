"""Use real resident platform labels with separately bound shipping targets."""

from __future__ import annotations

import pytest

from scripts.native_slo_pair_record import validate_runtime
from scripts.native_slo_qualification import sampling_plan
from tests.native_slo_pair_support import block_fixture, bundle_fixture

TARGET_PAIRS = (
    ("x86_64-unknown-linux-musl", "x86_64-linux"),
    ("x86_64-apple-darwin", "x86_64-macos"),
    ("aarch64-apple-darwin", "aarch64-macos"),
    ("x86_64-pc-windows-msvc", "x86_64-windows"),
)


@pytest.mark.parametrize("arm", ["baseline", "candidate"])
@pytest.mark.parametrize(("target", "runtime_target"), TARGET_PAIRS)
def test_actual_runtime_target_and_exact_artifact_identities_complete_validation(tmp_path, arm, target, runtime_target):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, arm, sampling_plan(runs=1, qualification=False))
    report["runtime"]["target"] = runtime_target
    validate_runtime(report, bundle["arms"][arm], target=target)
    assert report["runtime"]["target"] == runtime_target


@pytest.mark.parametrize(("target", "runtime_target"), TARGET_PAIRS)
def test_cargo_triple_is_not_accepted_as_a_resident_platform_label(tmp_path, target, runtime_target):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    report["runtime"]["target"] = target
    with pytest.raises(ValueError, match="pair_installed_runtime_context_invalid"):
        validate_runtime(report, bundle["arms"]["candidate"], target=target)


@pytest.mark.parametrize(
    ("target", "runtime_target"),
    [(target, other) for target, expected in TARGET_PAIRS for _, other in TARGET_PAIRS if other != expected],
)
def test_crossed_platform_or_architecture_never_completes_an_arm(tmp_path, target, runtime_target):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    report["runtime"]["target"] = runtime_target
    with pytest.raises(ValueError, match="pair_installed_runtime_context_invalid"):
        validate_runtime(report, bundle["arms"]["candidate"], target=target)


@pytest.mark.parametrize(
    "target", ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "x86_64-linux", "unknown"]
)
def test_unsupported_distribution_target_is_not_normalized_or_inferred(tmp_path, target):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    with pytest.raises(ValueError, match="pair_target_invalid"):
        validate_runtime(report, bundle["arms"]["candidate"], target=target)


@pytest.mark.parametrize(
    "field",
    [
        "build_sha",
        "runtime_sha256",
        "installed_package_sha256",
        "package_version",
        "python_version",
        "dependency_versions_sha256",
    ],
)
def test_correct_platform_label_does_not_bypass_immutable_artifact_binding(tmp_path, field):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    report["runtime"][field] = "changed"
    with pytest.raises(ValueError, match="pair_runtime_identity_mismatch"):
        validate_runtime(report, bundle["arms"]["candidate"], target=TARGET_PAIRS[0][0])


def test_correct_platform_label_does_not_bypass_wheel_binding(tmp_path):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block_fixture(bundle, "candidate", sampling_plan(runs=1, qualification=False))
    report["artifact_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="pair_wheel_identity_mismatch"):
        validate_runtime(report, bundle["arms"]["candidate"], target=TARGET_PAIRS[0][0])
