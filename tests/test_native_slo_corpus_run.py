from __future__ import annotations

from io import BytesIO
from types import SimpleNamespace

import pytest

from scripts import native_slo_corpus_run as corpus


@pytest.mark.parametrize("encoded,status", [(b'{"hook_event_name":', 400), (b"x" * 1_000_001, 413)])
def test_transport_rejection_distinguishes_declared_length_from_delivered_malformed_bytes(
    monkeypatch: pytest.MonkeyPatch, encoded: bytes, status: int
) -> None:
    connections = []

    class Connection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.headers = {}
            self.sent = b""
            self.closed = False
            connections.append(self)

        def putrequest(self, *_args: object) -> None:
            pass

        def putheader(self, key: str, value: str) -> None:
            self.headers[key] = value

        def endheaders(self) -> None:
            pass

        def send(self, value: bytes) -> None:
            self.sent += value

        def getresponse(self) -> BytesIO:
            response = BytesIO(
                b'{"error":"request_body_too_large"}' if status == 413 else b'{"error":"invalid_request_body"}'
            )
            response.status = status
            return response

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(corpus, "HTTPConnection", Connection)
    session = SimpleNamespace(
        guard_home="synthetic",
        workspace="synthetic",
        daemon=SimpleNamespace(port=1234, _server=SimpleNamespace(auth_token="synthetic")),
    )
    response, observed_status = corpus._transport_boundary(session, "pi", encoded)
    connection = connections[0]
    assert observed_status == status
    assert response["error"] == ("request_body_too_large" if status == 413 else "invalid_request_body")
    assert int(connection.headers["Content-Length"]) == len(encoded)
    assert connection.sent == (b"" if status == 413 else encoded)
    assert connection.closed is True
