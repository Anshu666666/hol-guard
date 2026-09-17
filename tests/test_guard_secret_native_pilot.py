"""The experimental boundary must preserve captures before finding semantics."""

from __future__ import annotations

import copy
import os
import random
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.secrets import secret_detection as detector

_scripts_path = str(Path(__file__).resolve().parents[1] / "scripts")
sys.path.insert(0, _scripts_path)
try:
    import secret_scan_native_pilot as pilot
    from bench_guard_secret_scans import _qualify_detector
    from secret_scan_benchmark_fixtures import WORKLOADS, _file_bytes, context_examples, provider_examples
finally:
    # Leaving scripts on the import path shadows the repository's ci namespace
    # with scripts/ci and prevents installed-probe tests from being collected.
    sys.path.remove(_scripts_path)


@pytest.fixture
def binary() -> Path:
    configured = os.environ.get("GUARD_OFFLINE_REGEX_PILOT_BINARY")
    if not configured:
        pytest.skip("build the explicit experimental binary and set GUARD_OFFLINE_REGEX_PILOT_BINARY")
    result = Path(configured)
    assert result.is_file(), "configured native pilot binary is missing"
    return result


@pytest.fixture
def client(binary):
    value = pilot.PilotClient(binary, detector)
    try:
        yield value
    finally:
        value.close()


def expected_captures(text):
    output = {}
    for rule in detector.SECRET_RULES:
        output[rule.rule_id] = [
            {"whole": list(match.span()), "secret": list(match.span("secret"))} for match in rule.pattern.finditer(text)
        ]
    output["credential-assignment"] = [
        {name: list(match.span(0 if name == "whole" else name)) for name in ("whole", "secret", "name", "quote")}
        for match in detector._ASSIGNMENT.finditer(text)
    ]
    return output


def test_all_catalog_and_context_captures_match_python(client):
    for example in (*provider_examples(), *context_examples()):
        if example.text.isascii():
            assert client.extract(example.text) == expected_captures(example.text), example.label


def test_ascii_assignment_edges_and_seeded_combinations(client):
    body = "8aQ2vF4zH6mL0sN3tR5xW7bD9kP1cE4uJ"
    cases = []
    for length in (11, 12, 255, 256, 257, 520):
        secret = (body * 20)[:length]
        for opening, closing in (("", ""), ('"', '"'), ("'", "'"), ('"', "'"), ("'", '"'), ('"', "")):
            for whitespace in ("", " ", "\t", "\r\n", "\x1c", "\x1d", "\x1e", "\x1f", "\v", "\f"):
                cases.append(f"API_SECRET{whitespace}={whitespace}{opening}{secret}{closing}\n")
    randomizer = random.Random(731)
    for _ in range(150):
        name = randomizer.choice(["x", "xy", "SECRET", "n" * 81, "n" * 82, "1SECRET", "a.b-c"])
        quote = randomizer.choice(['"', "'", ""])
        secret = randomizer.choice([body, body + '"' + body, body + "," + body, "${PAYMENT_SECRET}", "x" * 260])
        cases.append(f"{name}{randomizer.choice([':', '='])}{quote}{secret}{quote}")
    # Keep individual document boundaries; a previous prefix cannot affect a later suffix.
    for index, text in enumerate(cases):
        assert client.extract(text) == expected_captures(text), index


def test_dense_provider_spans_and_empty_file_reset(client):
    case = next(item for item in WORKLOADS if item.name == "working_provider_large")
    text = _file_bytes(case, 0, 0).decode()
    for value in (text, "", "ghp_", "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY", text):
        assert client.extract(value) == expected_captures(value)


def test_findings_hmac_unicode_fallback_and_per_file_limits(binary):
    expected_contract = _qualify_detector()
    examples = (*provider_examples(), *context_examples())
    expected = [detector.scan_secret_text(item.text, path=item.path, max_findings=1) for item in examples]
    installed = pilot.install(binary)
    try:
        assert _qualify_detector() == expected_contract
        actual = [detector.scan_secret_text(item.text, path=item.path, max_findings=1) for item in examples]
        assert actual == expected
        assert installed.client.stats["native_files"] > 0
        assert installed.client.stats["python_fallback_files"] == 2
        process = installed.client.process
    finally:
        installed.close()
    assert process is not None and process.poll() == 0
    assert _qualify_detector() == expected_contract


def test_oversized_text_uses_full_python_semantics(binary, monkeypatch):
    text = provider_examples()[0].text
    expected = detector.scan_secret_text(text, path="src/config.ts")
    monkeypatch.setattr(pilot, "_MAX_TEXT", 8)
    installed = pilot.install(binary)
    try:
        assert detector.scan_secret_text(text, path="src/config.ts") == expected
        assert installed.client.stats["python_fallback_files"] == 1
        assert installed.client.process is None
    finally:
        installed.close()


@pytest.mark.parametrize("text", ["雪", "a" * (4 * 1024 * 1024 + 1)], ids=["unicode", "oversized"])
def test_native_rejects_unsupported_direct_requests(client, text):
    with pytest.raises(pilot.PilotError):
        client.extract(text)
    assert client.process is None


def test_candidate_budget_aborts_and_reaps_child(client):
    # Each copy is a provider and generic candidate; exceed 100,000 captures
    # while remaining inside the 4 MiB logical-file byte bound.
    value = provider_examples()[2].text * 51_000
    assert len(value) < 4 * 1024 * 1024
    with pytest.raises(pilot.PilotError):
        client.extract(value)
    assert client.process is None


def valid_response(client):
    return {
        "schema": pilot._SCHEMA,
        "catalog": client.catalog,
        "id": 1,
        "complete": True,
        "rules": [{"id": spec["id"], "captures": []} for spec in client.patterns],
    }


@pytest.mark.parametrize(
    "corruption", ["id", "complete", "catalog", "order", "span", "overlap", "field", "boolean-span"]
)
def test_bad_protocol_never_becomes_clean_result(monkeypatch, corruption):
    client = pilot.PilotClient(Path("/not-launched"), detector)
    value = valid_response(client)
    if corruption == "id":
        value["id"] = True
    elif corruption == "complete":
        value["complete"] = False
    elif corruption == "catalog":
        value["catalog"] = "0" * 64
    elif corruption == "order":
        value["rules"].reverse()
    elif corruption in {"span", "overlap", "boolean-span"}:
        capture = {"whole": [0, 3], "secret": [0, 3]}
        if corruption == "span":
            capture["secret"][1] = 4
        if corruption == "boolean-span":
            capture["secret"][0] = False
        value["rules"][0]["captures"] = [capture]
        if corruption == "overlap":
            value["rules"][0]["captures"].append(copy.deepcopy(capture))
    else:
        value["extra"] = 0
    monkeypatch.setattr(client, "_start", lambda: None)
    monkeypatch.setattr(client, "_exchange", lambda _: value)
    with pytest.raises(pilot.PilotError):
        client.extract("abc")


@pytest.mark.parametrize("behavior", ["eof", "deadline", "unterminated", "invalid-json"])
@pytest.mark.skipif(sys.platform != "linux", reason="pilot pipe transport is a Linux-only experiment")
def test_transport_failure_is_bounded_and_reaped(tmp_path, behavior):
    script = tmp_path / "broken-child"
    code = {
        "eof": "pass",
        "deadline": "import time; time.sleep(20)",
        "unterminated": 'import sys; sys.stdout.write("{}"); sys.stdout.flush()',
        "invalid-json": 'print("invalid frame")',
    }[behavior]
    script.write_text(f"#!{sys.executable}\n" + code + "\n")
    script.chmod(0o700)
    client = pilot.PilotClient(script, detector, timeout=0.1)
    with pytest.raises(pilot.PilotError):
        client.extract("candidate text stays private")
    assert client.process is None


def test_duplicate_response_fields_are_rejected():
    import json

    with pytest.raises(pilot.PilotError, match="duplicate"):
        json.loads('{"complete":false,"complete":true}', object_pairs_hook=pilot._unique_object)


def test_assignment_catalog_drift_requires_requalification(monkeypatch):
    import re

    monkeypatch.setattr(detector, "_ASSIGNMENT", re.compile(r"changed(?P<secret>pattern)"))
    with pytest.raises(pilot.PilotError, match="requalification"):
        pilot.PilotClient(Path("/not-launched"), detector)


def test_installed_pilot_restores_repository_function(binary):
    from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository

    original = repository.scan_secret_text
    installed = pilot.install(binary)
    installed.close()
    assert repository.scan_secret_text is original


def test_full_cli_staged_divergence_includes_native_boundary(binary, tmp_path):
    from secret_scan_benchmark_fixtures import Workload, create_fixture

    from scripts.scanner_pilot_process import full_cli as _full_cli

    target = tmp_path / "repository"
    create_fixture(target, Workload("cli", "staged", 2, 512, content="providers", unstaged_change=True))
    root = Path(__file__).resolve().parents[1]
    options = {"extra_args": ("--fail-on-findings",), "expected_exit": 3}
    _, baseline = _full_cli(root, target, "staged", **options)
    sample, candidate = _full_cli(root, target, "staged", native_pilot_binary=binary, **options)
    assert candidate == baseline
    assert candidate["finding_count"] == 2 and not candidate["truncated"]
    assert sample["native_pilot_native_files"] == 2
    assert sample["native_pilot_python_fallback_files"] == 0
    assert sample["full_cli_process_tree_cpu_ms"] > 0


@pytest.mark.parametrize("case", ["invalid_working", "invalid_staged", "links_git", "links_filesystem"])
def test_full_cli_encoding_and_scanned_link_parity(binary, tmp_path, case):
    from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
    from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets
    from scripts.scanner_pilot_process import full_cli
    from tests.fixtures.guard_secret_working_inputs import CONTENT, SECRET, create

    workflow, paths, count = create(tmp_path / "repository", case)
    target = tmp_path / "repository"
    root = Path(__file__).resolve().parents[1]
    arguments = {"extra_args": ("--fail-on-findings",), "expected_exit": 3}
    _, expected = full_cli(root, target, workflow, **arguments)
    sample, actual = full_cli(root, target, workflow, native_pilot_binary=binary, **arguments)
    assert actual == expected
    assert [finding["path"] for finding in actual["findings"]] == list(paths)
    assert actual["files_scanned"] == count and actual["bytes_scanned"] == len(CONTENT) * len(paths)
    assert actual["errors"] == [] and not actual["truncated"]
    assert SECRET not in str(actual)
    assert sample["native_pilot_native_files"] == len(paths)
    # Malformed source bytes are omitted by the original decoder before regex;
    # do not misreport them as a valid Unicode Python fallback.
    assert sample["native_pilot_python_fallback_files"] == 0
    scan = scan_staged_secrets if workflow == "staged" else scan_repository_secrets
    before = scan(target)
    installed = pilot.install(binary)
    try:
        after = scan(target)
    finally:
        installed.close()
    assert before == after
    assert [f.to_public_dict(fingerprint_key=b"tenant-a") for f in before.findings] == [
        f.to_public_dict(fingerprint_key=b"tenant-a") for f in after.findings
    ]


def test_admitted_read_failure_preserves_native_partial_result_and_cli_exit(binary, tmp_path, monkeypatch, capsys):
    import json

    from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository
    from codex_plugin_scanner.guard.secrets import working_file_reader as reader
    from codex_plugin_scanner.guard.secrets.cli import main
    from tests.fixtures.guard_secret_working_inputs import CONTENT, SECRET

    (tmp_path / "a.env").write_bytes(CONTENT)
    target = tmp_path / "b.env"
    target.write_bytes(CONTENT)
    identity = target.stat().st_ino
    original_read = reader.os.read

    def fail_admitted_read(descriptor, size):
        if os.fstat(descriptor).st_ino == identity:
            raise OSError("synthetic private path detail")
        return original_read(descriptor, size)

    monkeypatch.setattr(reader, "os", SimpleNamespace(**(vars(os) | {"read": fail_admitted_read})))
    arguments = ["scan", str(tmp_path), "--json", "--fail-on-findings"]
    expected = repository.scan_repository_secrets(tmp_path)
    assert main(arguments) == 2
    expected_cli = capsys.readouterr()
    installed = pilot.install(binary)
    try:
        actual = repository.scan_repository_secrets(tmp_path)
        assert main(arguments) == 2
        actual_cli = capsys.readouterr()
    finally:
        installed.close()
    assert actual == expected
    assert actual_cli == expected_cli
    assert json.loads(actual_cli.out) == actual.to_public_dict()
    assert actual.errors == ("working_tree_file_unavailable_or_changed",) and actual.truncated
    assert [finding.path for finding in actual.findings] == ["a.env"]
    assert SECRET not in actual_cli.out and "private path" not in actual_cli.out
    assert installed.client.stats["native_files"] == 2 and installed.client.stats["python_fallback_files"] == 0
    assert actual.findings[0].fingerprint(b"tenant-a") == expected.findings[0].fingerprint(b"tenant-a")


def test_whitespace_translation_rejects_unsupported_context():
    assert pilot._translate_provider_pattern(r"[^\s/@]") == rf"[^{pilot._SPACE}/@]"
    assert pilot._translate_provider_pattern(r"literal\\s") == r"literal\\s"
    with pytest.raises(pilot.PilotError, match="requalification"):
        pilot._translate_provider_pattern(r"name\s+value")


def test_provider_length_and_ascii_word_boundaries(client):
    # Exercise each format at surrounding word/nonword boundaries and around
    # its maximum candidate length; compare capture spans before suppression.
    for example in provider_examples():
        value = example.text.split("=", 1)[1].strip().strip('"')
        for extra in (0, 1, 220, 255, 256):
            for left, right in (("", ""), ("_", "_"), ("x", "-"), ("-", "x"), ("\x1c", "\x1f")):
                text = left + value + "A" * extra + right
                assert client.extract(text) == expected_captures(text), (example.label, extra, left, right)


def test_cleanup_error_still_restores_all_four_patched_globals(monkeypatch):
    from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository

    original = (detector.scan_secret_text, detector.SECRET_RULES, detector._ASSIGNMENT, repository.scan_secret_text)
    installed = pilot.install(Path("/not-launched"))
    monkeypatch.setattr(installed.client, "close", lambda: (_ for _ in ()).throw(OSError("fixture close failed")))
    with pytest.raises(OSError):
        installed.close()
    assert (
        detector.scan_secret_text,
        detector.SECRET_RULES,
        detector._ASSIGNMENT,
        repository.scan_secret_text,
    ) == original


def test_cleanup_failure_does_not_replace_original_protocol_error(monkeypatch):
    client = pilot.PilotClient(Path("/not-launched"), detector)
    monkeypatch.setattr(client, "_start", lambda: (_ for _ in ()).throw(pilot.PilotError("original protocol failure")))
    monkeypatch.setattr(client, "close", lambda: (_ for _ in ()).throw(OSError("fixture cleanup failed")))
    with pytest.raises(pilot.PilotError, match="original protocol failure"):
        client.extract("private fixture")
    assert client.stats["cleanup_failures"] > 0


def test_unconfirmed_kill_retains_process_ownership(monkeypatch):
    import subprocess
    from types import SimpleNamespace

    child = SimpleNamespace(
        stdin=None,
        stdout=None,
        wait=lambda **_: (_ for _ in ()).throw(subprocess.TimeoutExpired("fixture", 1)),
        kill=lambda: (_ for _ in ()).throw(OSError("fixture kill failed")),
    )
    client = pilot.PilotClient(Path("/not-launched"), detector)
    client.process = child
    with pytest.raises(OSError):
        client.close()
    assert client.process is child and client.stats["cleanup_failures"] > 0


@pytest.mark.parametrize("diagnostic_error", [OSError, BrokenPipeError])
def test_cli_error_is_not_replaced_by_failure_diagnostic_io(monkeypatch, diagnostic_error):
    from types import SimpleNamespace

    from codex_plugin_scanner import cli

    original = RuntimeError("distinct originating CLI failure")

    def fail_main():
        raise original

    class FailedStderr:
        def write(self, _text):
            raise diagnostic_error("fixture diagnostic write failed")

    monkeypatch.setattr(cli, "main", fail_main)
    monkeypatch.setattr(
        pilot,
        "install",
        lambda _binary: SimpleNamespace(close=lambda: None, client=SimpleNamespace(stats={"cleanup_failures": 0})),
    )
    monkeypatch.setattr(sys, "stderr", FailedStderr())
    with pytest.raises(RuntimeError) as failure:
        pilot.cli_main(Path("/not-launched"))
    assert failure.value is original
