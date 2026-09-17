"""Frozen registry transport only; production decoding and resolution stay real."""

from __future__ import annotations

import hashlib
import io
import urllib.parse
from contextlib import contextmanager
from typing import Any

from scripts.package_benchmark_corpus import canonical, digest, package_name, registry_payload
from scripts.package_benchmark_oracle import require

REGISTRY_BYTES = canonical(registry_payload())
REGISTRY_HEADERS = {"accept": "application/vnd.npm.install-v1+json", "user-agent": "hol-guard-local"}


class RegistryTransport:
    def __init__(self, count: int) -> None:
        if type(count) is not int or not 1 <= count <= 100:
            raise ValueError("registry_fixture_count_invalid")
        self.expected = tuple(
            "https://registry.npmjs.org/" + urllib.parse.quote(package_name(i), safe="") for i in range(count)
        )
        self.observed: list[dict[str, object]] = []
        self.invalid = False

    @contextmanager
    def open(self, request: Any, *, timeout: object):
        headers = {key.lower(): value for key, value in request.header_items()}
        record = {"url": request.full_url, "method": request.get_method(), "headers": headers, "timeout": timeout}
        if (
            len(self.observed) >= len(self.expected)
            or request.full_url not in self.expected
            or request.get_method() != "GET"
            or request.data is not None
            or headers != REGISTRY_HEADERS
            or type(timeout) not in {int, float}
            or timeout != 1
        ):
            self.invalid = True
            raise AssertionError("registry_fixture_transport_contract_changed")
        self.observed.append(record)
        # The real managed retry/JSON code calls read().decode('utf-8').
        with io.BytesIO(REGISTRY_BYTES) as response:
            yield response

    def report(self) -> dict[str, object]:
        require(
            not self.invalid and sorted(str(item["url"]) for item in self.observed) == sorted(self.expected),
            "registry_calls",
        )
        return {
            "schema": "hol-guard.package-registry-fixture.v1",
            "boundary": "synthetic_transport_real_decoder_and_resolver",
            "calls": len(self.observed),
            "request_sha256": digest(sorted(self.observed, key=lambda item: str(item["url"]))),
            "response_sha256": hashlib.sha256(REGISTRY_BYTES).hexdigest(),
            "initial_timeout_seconds": 1,
            "retry_timeout_seconds": 1,
            "external_network_observed": False,
        }


@contextmanager
def registry_transport(case, evaluator):
    if case.mode != "registry-resolved":
        yield None
        return
    from codex_plugin_scanner.guard.runtime import runner

    require(evaluator._TIMEOUT_SECONDS == evaluator._RETRY_TIMEOUT_SECONDS == 1, "registry_deadline")
    fixture = RegistryTransport(case.dependencies)
    previous = runner.managed_urlopen
    runner.managed_urlopen = fixture.open
    try:
        yield fixture
    finally:
        runner.managed_urlopen = previous


def validate_registry(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "boundary",
        "calls",
        "request_sha256",
        "response_sha256",
        "initial_timeout_seconds",
        "retry_timeout_seconds",
        "external_network_observed",
    }:
        raise ValueError("package_registry_schema_invalid")
    expected = RegistryTransport(100)
    expected.observed = [
        {"url": url, "method": "GET", "headers": REGISTRY_HEADERS, "timeout": 1} for url in expected.expected
    ]
    if (
        value["external_network_observed"] is not False
        or value != expected.report()
        or any(type(value[key]) is not int for key in ("calls", "initial_timeout_seconds", "retry_timeout_seconds"))
    ):
        raise ValueError("package_registry_commitment_invalid")
