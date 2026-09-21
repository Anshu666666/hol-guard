"""The installed-style authoring CLI runs before Guard state or lifecycle setup."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import write_kit
from tests.extension_builder_support import cli_document, make_kit, repository_fixture


def invoke(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    result = cli.main(arguments)
    return result, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("program,prefix", [("hol-guard", []), ("plugin-scanner", ["guard"])])
def test_both_entrypoint_families_support_authoring_without_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    program: str,
    prefix: list[str],
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Authoring must not initialize policy, workspace, or GuardStore")

    monkeypatch.setattr(sys, "argv", [program])
    monkeypatch.setattr(commands_router, "resolve_guard_home", forbidden)
    monkeypatch.setattr(commands_router, "_resolve_guard_workspace", forbidden)
    monkeypatch.setattr(commands_router, "GuardStore", forbidden)
    monkeypatch.setattr(commands_router, "enforce_lifecycle_gate", forbidden)
    source = tmp_path / "surface.json"
    source.write_text(canonical_json(cli_document()), encoding="utf-8")
    output = tmp_path / "kit"
    arguments = [
        *prefix,
        "extensions",
        "generate",
        "--from",
        "cli",
        "--input",
        str(source),
        "--output",
        str(output),
        "--slug",
        "builder-demo",
        "--publisher",
        "community.example",
        "--homepage",
        "https://example.test/demo",
        "--executable",
        "builder-demo",
        "--json",
    ]
    status, generated = invoke(arguments, capsys)
    assert status == 0 and generated["generated"] is True
    assert generated["reviewedOperations"] == 0
    status, validated = invoke([*prefix, "extensions", "validate", str(output), "--json"], capsys)
    assert status == 0 and validated["validated"] is True
    assert not (tmp_path / ".hol-guard").exists()


def test_existing_inspection_parser_is_unchanged() -> None:
    parser = cli._build_parser("hol-guard", program_mode="hol-guard")
    arguments = parser.parse_args(["command", "extensions", "--json"])
    assert arguments.guard_command == "command"


def test_cli_domain_errors_are_json_and_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    status, error = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "cli",
            "--input",
            str(source),
            "--output",
            str(tmp_path / "kit"),
            "--json",
        ],
        capsys,
    )
    assert status == 2
    assert error["error"]["code"] == "missing_metadata"
    assert not (tmp_path / "kit").exists()
    status, error = invoke(["extensions", "validate", str(tmp_path / "absent"), "--json"], capsys)
    assert status == 2 and error["ok"] is False


def test_cli_replay_and_diff_exit_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    original = make_kit(tmp_path)
    reviewed = make_kit(tmp_path, reviewed=True)
    old = tmp_path / "original"
    changed = tmp_path / "reviewed"
    write_kit(original, old)
    write_kit(reviewed, changed)
    replay = tmp_path / "replay"
    status, _ = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(old / "discovery.json"),
            "--output",
            str(replay),
            "--json",
        ],
        capsys,
    )
    assert status == 0
    status, equal = invoke(["extensions", "diff", str(old), str(replay), "--json"], capsys)
    assert status == 0 and equal["changed"] is False
    status, different = invoke(["extensions", "diff", str(old), str(changed), "--json"], capsys)
    assert status == 1 and different["changed"] is True
    status, error = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(old / "discovery.json"),
            "--output",
            str(tmp_path / "invalid"),
            "--slug",
            "override",
            "--json",
        ],
        capsys,
    )
    assert status == 2 and error["error"]["code"] == "snapshot_override"


def test_cli_apply_is_plan_only_until_explicit_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    kit = make_kit(tmp_path)
    location = tmp_path / "kit"
    write_kit(kit, location)
    repository = repository_fixture(tmp_path)
    arguments = ["extensions", "apply", str(location), "--repo", str(repository), "--json"]
    status, plan = invoke(arguments, capsys)
    assert status == 0 and plan["written"] is False
    status, result = invoke([*arguments, "--write", "--expected-plan", plan["planDigest"]], capsys)
    assert status == 0 and result["written"] is True
    status, conflict = invoke([*arguments, "--write", "--expected-plan", plan["planDigest"]], capsys)
    assert status == 3 and conflict["error"]["code"] == "repository_conflict"


def test_cli_handoff_runs_the_complete_repository_preparation_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source = {
        "schema": "guard.command-extension-source.v1",
        "extension": {"extension_id": "command.demo"},
    }
    source_path = tmp_path / "contributions/command-sources/command.demo.json"
    fixture_path = tmp_path / "tests/fixtures/command-source-demo.v1.json"
    source_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    source_path.write_text(canonical_json(source), encoding="utf-8")
    fixture_path.write_text("{}", encoding="utf-8")
    script = tmp_path / "scripts/prepare_extension_contribution.py"
    script.write_text("# checked by the subprocess stub\n", encoding="utf-8")
    calls: list[tuple[list[str], Path]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs["cwd"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"ok": True, "checked": True, "targetCommandsExecuted": 0}),
            stderr="",
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.extension_builder_commands.subprocess.run",
        run,
    )
    arguments = [
        "extensions",
        "handoff",
        "--repo",
        str(tmp_path),
        "--source",
        str(source_path),
        "--fixture",
        str(fixture_path),
        "--json",
    ]
    status, result = invoke(arguments, capsys)
    assert status == 0
    assert result == {"contributionId": "command.demo", "readyForPullRequest": True, "targetCommandsExecuted": 0}
    assert calls == [
        (
            [
                sys.executable,
                str(script),
                "--check",
                "--source",
                str(source_path),
                "--fixture",
                str(fixture_path),
            ],
            tmp_path,
        )
    ]


def test_cli_handoff_rejects_noncanonical_paths_before_running_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source = {
        "schema": "guard.command-extension-source.v1",
        "extension": {"extension_id": "command.demo"},
    }
    source_path = tmp_path / "drafts/command.demo.json"
    fixture_path = tmp_path / "tests/fixtures/command-source-demo.v1.json"
    source_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    source_path.write_text(canonical_json(source), encoding="utf-8")
    fixture_path.write_text("{}", encoding="utf-8")
    status, error = invoke(
        [
            "extensions",
            "handoff",
            "--repo",
            str(tmp_path),
            "--source",
            str(source_path),
            "--fixture",
            str(fixture_path),
            "--json",
        ],
        capsys,
    )
    assert status == 2 and error["error"]["code"] == "canonical_paths"


def test_cli_handoff_fails_when_repository_preparation_rejects_the_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    source = {
        "schema": "guard.command-extension-source.v1",
        "extension": {"extension_id": "command.demo"},
    }
    source_path = tmp_path / "contributions/command-sources/command.demo.json"
    fixture_path = tmp_path / "tests/fixtures/command-source-demo.v1.json"
    source_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    source_path.write_text(canonical_json(source), encoding="utf-8")
    fixture_path.write_text("{}", encoding="utf-8")
    (tmp_path / "scripts/prepare_extension_contribution.py").write_text("# invoked by the stub\n", encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.extension_builder_commands.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 2, stdout="", stderr="invalid fixture"),
    )

    status, error = invoke(
        [
            "extensions",
            "handoff",
            "--repo",
            str(tmp_path),
            "--source",
            str(source_path),
            "--fixture",
            str(fixture_path),
            "--json",
        ],
        capsys,
    )
    assert status == 2 and error["error"]["code"] == "handoff_validation"


def test_cli_output_conflicts_have_dedicated_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    kit = make_kit(tmp_path)
    location = tmp_path / "kit"
    write_kit(kit, location)
    status, error = invoke(
        [
            "extensions",
            "generate",
            "--from",
            "snapshot",
            "--input",
            str(location / "discovery.json"),
            "--output",
            str(location),
            "--json",
        ],
        capsys,
    )
    assert status == 3 and error["error"]["code"] == "output_exists"
