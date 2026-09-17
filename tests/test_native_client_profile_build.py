from __future__ import annotations

import json

import pytest

from scripts.ci import build_native_client_profile_wheel as builder

SHA = "a" * 40
DIGEST = "b" * 64


def _capabilities(target: str) -> dict:
    return {
        "build_sha": SHA,
        "target": builder.TARGETS[target][1],
        "rule_digest": DIGEST,
        "features": ["resident-stream-v1", builder.CAPABILITY],
    }


@pytest.mark.parametrize("target", tuple(builder.TARGETS))
def test_build_binds_source_target_feature_and_installed_private_interpreter(tmp_path, monkeypatch, target):
    destination = tmp_path / "build"
    python = tmp_path / "external-venv/python"
    commands = []
    prepared = []

    def prepare():
        prepared.append(True)
        return python

    def run(argv, *, environment=None):
        commands.append((argv, environment))
        if argv[:2] == ["git", "rev-parse"]:
            return SHA
        if "scripts/sync_repo_version.py" in argv:
            return "3.2.0"
        if "capabilities" in argv:
            return json.dumps(_capabilities(target))
        if "scripts/build_native_hol_guard_wheel.py" in argv:
            (destination / "native").mkdir()
            (destination / "native/hol_guard-3.2.0.whl").write_bytes(b"fixture")
        return ""

    monkeypatch.setattr(builder, "_prepare_build_interpreter", prepare)
    monkeypatch.setattr(builder, "_run", run)
    wheel = builder.build(
        target=target, platform_tag=builder.TARGETS[target][0], destination=destination, source_sha=SHA
    )
    assert prepared == [True]
    assert wheel == destination / "native/hol_guard-3.2.0.whl"
    cargo, environment = next(item for item in commands if item[0][0] == "cargo")
    assert cargo == [
        "cargo",
        "+1.88.0",
        "build",
        "--manifest-path",
        "rust/Cargo.toml",
        "--locked",
        "--release",
        "--target",
        target,
        "-p",
        "hol-guard-runtime",
        "--features",
        "diagnostic-native-client",
    ]
    assert environment["HOL_GUARD_BUILD_SHA"] == SHA
    assert environment["HOL_GUARD_PACKAGE_VERSION"] == "3.2.0"
    assemble = next(argv for argv, _ in commands if "scripts/build_native_hol_guard_wheel.py" in argv)
    assert assemble[assemble.index("--source-sha") + 1] == SHA
    assert assemble[assemble.index("--rule-digest") + 1] == DIGEST
    assert assemble[assemble.index("--target") + 1] == target
    assert all(argv[0] == str(python) for argv, _ in commands if "scripts/" in " ".join(argv))
    assert commands[-1][0] == [
        "uv",
        "pip",
        "install",
        "--python",
        str(python),
        "--no-deps",
        "--force-reinstall",
        str(wheel),
    ]


@pytest.mark.parametrize("failure", ["target", "tag", "source_format", "source_mismatch"])
def test_identity_rejection_precedes_interpreter_mutation_and_build(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(builder, "_prepare_build_interpreter", lambda: pytest.fail("must not mutate interpreter"))
    calls = []
    monkeypatch.setattr(builder, "_run", lambda argv: calls.append(argv) or "c" * 40)
    target = "unsupported" if failure == "target" else "x86_64-apple-darwin"
    tag = "macosx_11_0_x86_64" if failure == "tag" else "macosx_13_0_x86_64"
    sha = "main" if failure == "source_format" else SHA
    with pytest.raises(ValueError, match=r"native_client_profile_(target|source)"):
        builder.build(target=target, platform_tag=tag, destination=tmp_path / "never-created", source_sha=sha)
    assert len(calls) == (1 if failure == "source_mismatch" else 0)
    assert not (tmp_path / "never-created").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("build_sha", "c" * 40),
        ("target", "aarch64-macos"),
        ("rule_digest", "not-a-digest"),
        ("features", []),
        ("features", [builder.CAPABILITY, builder.CAPABILITY]),
        ("features", [builder.CAPABILITY, {}]),
        ("features", builder.CAPABILITY),
    ],
)
def test_native_capability_binding_rejects_mismatch(field, value):
    target = "x86_64-apple-darwin"
    capabilities = _capabilities(target)
    capabilities[field] = value
    with pytest.raises(ValueError, match="capability_mismatch"):
        builder._validate_capabilities(capabilities, SHA, target)


def test_explicit_opt_in_is_required_before_any_build(monkeypatch):
    monkeypatch.setattr(
        builder.sys,
        "argv",
        [
            "builder",
            "--target",
            "x86_64-apple-darwin",
            "--platform-tag",
            "macosx_13_0_x86_64",
            "--source-sha",
            SHA,
            "--destination",
            "unused",
        ],
    )
    monkeypatch.setattr(builder, "build", lambda **_: pytest.fail("must not build"))
    with pytest.raises(SystemExit) as error:
        builder.main()
    assert error.value.code == 2
