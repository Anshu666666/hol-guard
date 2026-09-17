"""Real loopback fixture I/O and exact bounded response attribution."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from scripts.mcp_rebaseline_network import NETWORK_TRACE, validate_network
from scripts.mcp_rebaseline_trace import CHILD, TRACES, digest, messages, trace_identity, validate_tool_response


def test_network_child_roundtrip_preserves_request_and_measures_real_service():
    trace = next(trace for trace in TRACES if trace.name == NETWORK_TRACE)
    inputs = messages(trace, 2)
    observed = subprocess.run(
        [sys.executable, "-u", "-c", CHILD, str(trace.catalog_size), "0", "0", "1"],
        input="".join(json.dumps(message) + "\n" for message in inputs),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if "PermissionError" in observed.stderr and not observed.stdout:
        pytest.skip("runner prohibits binding a loopback fixture socket")
    assert observed.returncode == 0, observed.stderr
    responses = [json.loads(line) for line in observed.stdout.splitlines()]
    assert len(responses) == len(inputs)
    for request, response in zip(inputs[2:], responses[2:], strict=True):
        row = validate_tool_response(request, response, {"decision": "policy-warn", "policy_action": "warn"}, trace)
        assert row["request_sha256"] == digest(request)
        assert row["network_roundtrip_wall_ns"] >= row["network_service_wall_ns"] >= 10_000_000
        assert row["network_request_bytes"] == 65


@pytest.mark.parametrize(
    "mutation", ["missing", "unknown", "external", "count", "negative", "boolean", "wire", "boundary"]
)
def test_network_oracle_rejects_missing_or_unbound_observations(mutation):
    proof = {
        "child_wall_ns": 30_000_000,
        "network": {
            "requests": 1,
            "loopback": True,
            "network_roundtrip_wall_ns": 20_000_000,
            "network_client_thread_cpu_ns": 10,
            "network_service_wall_ns": 10_000_000,
            "network_service_thread_cpu_ns": 10,
            "network_request_bytes": 65,
            "network_response_bytes": 180,
        },
    }
    network = proof["network"]
    if mutation == "missing":
        proof.pop("network")
    elif mutation == "unknown":
        network["endpoint"] = "PRIVATE_SENTINEL"
    elif mutation == "external":
        network["loopback"] = False
    elif mutation == "count":
        network["requests"] = 2
    elif mutation == "negative":
        network["network_client_thread_cpu_ns"] = -1
    elif mutation == "boolean":
        network["network_client_thread_cpu_ns"] = True
    elif mutation == "wire":
        network["network_request_bytes"] = 66
    elif mutation == "boundary":
        network["network_service_wall_ns"] = 21_000_000
    with pytest.raises(ValueError):
        validate_network(proof, expected=True)


def test_original_seven_trace_requests_remain_frozen():
    expected = ORIGINAL_TRACES
    assert {trace.name: trace_identity(trace, 13)["sha256"] for trace in TRACES[:7]} == expected


ORIGINAL_TRACES = {
    "catalog10": "55235cd7867f4639e7b518d51b88d625ae792f994f653e3498b6f99e9c7efa51",
    "catalog100": "55235cd7867f4639e7b518d51b88d625ae792f994f653e3498b6f99e9c7efa51",
    "catalog1000": "55235cd7867f4639e7b518d51b88d625ae792f994f653e3498b6f99e9c7efa51",
    "payload16k": "c6e2ad5c7604577778f588ebf47cbd328d0287a149356468175fb28ab9baafd8",
    "catalog_refresh": "e425b195f921fb7df62003db9a528c2a55e0ea5cd9b455f3e52f951d20fc5da8",
    "child_delay10ms": "55235cd7867f4639e7b518d51b88d625ae792f994f653e3498b6f99e9c7efa51",
    "inline_approval10ms": "f81e820ca606a24eb9ccb8c1a77579e82dbc1ce7f00b6838277614cd2e273bbf",
}
