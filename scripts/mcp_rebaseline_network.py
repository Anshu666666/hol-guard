"""Finite loopback-only fixture service embedded in the synthetic MCP child."""

from __future__ import annotations

from typing import Any

NETWORK_TRACE = "loopback_tcp10ms"
NETWORK_METRICS = (
    "network_roundtrip_wall_ns",
    "network_client_thread_cpu_ns",
    "network_service_wall_ns",
    "network_service_thread_cpu_ns",
    "network_request_bytes",
    "network_response_bytes",
)


def validate_network(proof: dict[str, Any], *, expected: bool) -> dict[str, int]:
    value = proof.get("network")
    if not expected:
        if value is not None:
            raise ValueError("unexpected network fixture observation")
        return {}
    if not isinstance(value, dict) or set(value) != {*NETWORK_METRICS, "requests", "loopback"}:
        raise ValueError("missing exact loopback network observation")
    if value["requests"] != 1 or type(value["requests"]) is not int or value["loopback"] is not True:
        raise ValueError("unexpected loopback request count or route")
    if any(type(value[key]) is not int or not 0 < value[key] <= 10**10 for key in NETWORK_METRICS):
        raise ValueError("invalid bounded network metrics")
    if value["network_request_bytes"] != 65 or not 1 <= value["network_response_bytes"] <= 512:
        raise ValueError("unexpected bounded loopback wire length")
    if (
        not 10_000_000
        <= value["network_service_wall_ns"]
        <= value["network_roundtrip_wall_ns"]
        <= proof["child_wall_ns"]
    ):
        raise ValueError("network service and round-trip boundaries disagree")
    return {key: value[key] for key in NETWORK_METRICS}


# Only the synthetic child executes this code. It binds a numeric loopback
# address, never performs DNS or accepts a configurable destination. The service
# runs in a child-owned thread; thread CPU separates it from the client thread.
NETWORK_CHILD = r"""
import socket, threading
network_listener = None
network_thread = None
network_stop = threading.Event()
network_errors = []

def read_limited(stream, maximum):
    data = bytearray()
    while not data.endswith(b'\n'):
        piece = stream.recv(min(128, maximum + 1 - len(data)))
        if not piece:
            raise ValueError('loopback fixture incomplete frame')
        data.extend(piece)
        if len(data) > maximum:
            raise ValueError('loopback fixture frame limit')
    return bytes(data)

def serve_network():
    try:
        while not network_stop.is_set():
            try:
                connection, peer = network_listener.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(1)
                if peer[0] != '127.0.0.1':
                    raise ValueError('loopback fixture unexpected peer')
                request = read_limited(connection, 65)
                if len(request) != 65 or any(byte not in b'0123456789abcdef' for byte in request[:-1]):
                    raise ValueError('loopback fixture unexpected commitment')
                service_begin, service_cpu = time.perf_counter_ns(), time.thread_time_ns()
                time.sleep(0.010)
                response = {'request_sha256': request[:-1].decode('ascii'),
                            'service_wall_ns': time.perf_counter_ns() - service_begin,
                            'service_thread_cpu_ns': time.thread_time_ns() - service_cpu}
                connection.sendall(json.dumps(response, separators=(',', ':')).encode('ascii') + b'\n')
    except BaseException as error:
        network_errors.append(type(error).__name__)

if network_enabled:
    network_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    network_listener.bind(('127.0.0.1', 0))
    network_listener.listen(1)
    network_listener.settimeout(0.1)
    network_port = network_listener.getsockname()[1]
    network_thread = threading.Thread(target=serve_network, name='synthetic-loopback', daemon=True)
    network_thread.start()

def network_call(identity):
    begin, used = time.perf_counter_ns(), time.thread_time_ns()
    request = identity.encode('ascii') + b'\n'
    with socket.create_connection(('127.0.0.1', network_port), timeout=1) as connection:
        connection.sendall(request)
        raw = read_limited(connection, 512)
    reply = json.loads(raw)
    if (set(reply) != {'request_sha256', 'service_wall_ns', 'service_thread_cpu_ns'}
            or reply['request_sha256'] != identity):
        raise ValueError('loopback fixture response commitment mismatch')
    if network_errors:
        raise ValueError('loopback fixture service failed')
    return {'requests': 1, 'loopback': True,
            'network_roundtrip_wall_ns': time.perf_counter_ns() - begin,
            'network_client_thread_cpu_ns': time.thread_time_ns() - used,
            'network_service_wall_ns': reply['service_wall_ns'],
            'network_service_thread_cpu_ns': reply['service_thread_cpu_ns'],
            'network_request_bytes': len(request), 'network_response_bytes': len(raw)}
"""
