"""The experimental boundary must preserve captures before finding semantics."""

from __future__ import annotations

import copy
import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import secret_scan_native_pilot as pilot
from bench_guard_secret_scans import _qualify_detector
from secret_scan_benchmark_fixtures import WORKLOADS, _file_bytes, context_examples, provider_examples

from codex_plugin_scanner.guard.secrets import secret_detection as detector


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
    from bench_guard_secret_scans import _full_cli
    from secret_scan_benchmark_fixtures import Workload, create_fixture

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
