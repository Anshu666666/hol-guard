"""Frozen synthetic stdio inputs and exact forwarding oracles; no server I/O."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from scripts.mcp_rebaseline_network import NETWORK_CHILD, NETWORK_TRACE, validate_network

PLAIN_CALLS = 13
RESOURCE_CALLS = 100


def calls_for_mode(mode: str, calls: int = PLAIN_CALLS) -> int:
    return RESOURCE_CALLS if mode == "resources" else calls


@dataclass(frozen=True)
class Trace:
    name: str
    catalog_size: int
    payload_bytes: int = 128
    child_delay_ms: int = 0
    approval_delay_ms: int = 0
    refresh: bool = False


TRACES = (
    Trace("catalog10", 10),
    Trace("catalog100", 100),
    Trace("catalog1000", 1000),
    Trace("payload16k", 100, 16384),
    Trace("catalog_refresh", 100, refresh=True),
    Trace("child_delay10ms", 100, child_delay_ms=10),
    Trace("inline_approval10ms", 10, approval_delay_ms=10),
    Trace(NETWORK_TRACE, 100),
)


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def messages(trace: Trace, calls: int) -> list[dict[str, Any]]:
    if not 1 <= calls <= 100:
        raise ValueError("calls outside 1..100")
    result: list[dict[str, Any]] = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"elicitation": {}}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    for index in range(calls):
        if trace.refresh and index == calls // 2:
            result.append({"jsonrpc": "2.0", "id": "refresh", "method": "tools/list", "params": {}})
        arguments = {"text": ("routine fixture value " * (trace.payload_bytes // 22 + 1))[: trace.payload_bytes]}
        if trace.approval_delay_ms:
            arguments["target"] = f"synthetic-item-{index}.txt"
        result.append(
            {
                "jsonrpc": "2.0",
                "id": index + 3,
                "method": "tools/call",
                "params": {
                    "name": "dangerous_delete" if trace.approval_delay_ms else "echo_0",
                    "arguments": arguments,
                },
            }
        )
    return result


def trace_identity(trace: Trace, calls: int) -> dict[str, object]:
    data = messages(trace, calls)
    return {"trace": asdict(trace), "calls": calls, "sha256": digest(data), "canonical_bytes": len(encoded(data))}


def catalog_result(trace: Trace, generation: int) -> dict[str, object]:
    return {
        "tools": [
            {
                "name": "dangerous_delete" if trace.approval_delay_ms and index == 0 else f"echo_{index}",
                "description": f"Synthetic routine fixture generation {generation}",
                "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                "outputSchema": {"type": "object"},
                "annotations": {"readOnlyHint": True},
            }
            for index in range(trace.catalog_size)
        ]
    }


def validate_tool_response(message: dict[str, Any], response: object, event: object, trace: Trace) -> dict[str, object]:
    expected_decision = "inline-approved" if trace.approval_delay_ms else "policy-warn"
    expected_action = "allow" if trace.approval_delay_ms else "warn"
    if not isinstance(response, dict) or response.get("id") != message["id"] or response.get("jsonrpc") != "2.0":
        raise ValueError("response identity mismatch")
    result = response.get("result")
    if not isinstance(result, dict) or result.get("content") != [{"type": "text", "text": "ok"}]:
        raise ValueError("request did not reach synthetic child")
    proof = result.get("_fixture")
    if not isinstance(proof, dict) or proof.get("request_sha256") != digest(message):
        raise ValueError("child saw a different request")
    if (
        not isinstance(event, dict)
        or event.get("decision") != expected_decision
        or event.get("policy_action") != expected_action
    ):
        raise ValueError("unexpected Guard decision or route")
    if not isinstance(proof.get("child_wall_ns"), int) or not isinstance(proof.get("child_cpu_ns"), int):
        raise ValueError("missing child work observation")
    if not isinstance(proof.get("wire_bytes"), int) or not 1 <= proof["wire_bytes"] <= 4 * 1024 * 1024:
        raise ValueError("missing bounded child wire-byte observation")
    return {
        "request_id": message["id"],
        "request_sha256": proof["request_sha256"],
        "decision": event["decision"],
        "policy_action": event["policy_action"],
        "child_wall_ns": proof["child_wall_ns"],
        "child_cpu_ns": proof["child_cpu_ns"],
        "wire_bytes": proof["wire_bytes"],
        **validate_network(proof, expected=trace.name == NETWORK_TRACE),
    }


# Ordinary traces perform no service I/O. The additional trace performs an
# actual bounded TCP request to its own fixed loopback-only service.
CHILD = (
    r"""
import hashlib, json, sys, time
catalog_size, delay_ms, dangerous, network_enabled = map(int, sys.argv[1:])
"""
    + NETWORK_CHILD
    + r"""
generation = 0
for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    if method == 'tools/list':
        generation += 1
        result = {'tools': [{'name': 'dangerous_delete' if dangerous and i == 0 else 'echo_' + str(i),
                  'description': 'Synthetic routine fixture generation ' + str(generation),
                  'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string'}}},
                  'outputSchema': {'type': 'object'}, 'annotations': {'readOnlyHint': True}}
                 for i in range(catalog_size)]}
    elif method == 'tools/call':
        started, cpu = time.perf_counter_ns(), time.process_time_ns()
        if delay_ms:
            time.sleep(delay_ms / 1000)
        identity = hashlib.sha256(json.dumps(message, sort_keys=True, separators=(',', ':'),
                                             ensure_ascii=True, allow_nan=False).encode()).hexdigest()
        network = network_call(identity) if network_enabled else None
        result = {'content': [{'type': 'text', 'text': 'ok'}], '_fixture': {
            'request_sha256': identity, 'wire_bytes': len(line.encode('utf-8')),
            'child_wall_ns': time.perf_counter_ns() - started,
            'child_cpu_ns': time.process_time_ns() - cpu}}
        if network is not None:
            result['_fixture']['network'] = network
    else:
        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'synthetic', 'version': '1'}}
    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}), flush=True)
if network_enabled:
    network_stop.set()
    network_thread.join(timeout=1)
    network_listener.close()
    if network_thread.is_alive() or network_errors:
        raise ValueError('loopback fixture service cleanup incomplete')
"""
)
