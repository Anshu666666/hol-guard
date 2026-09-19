"""Original legacy event upload cases with explicit source-bound consent."""

from tests.support.optional_uploads import seed_legacy_optional_uploads


def run_local_pain_signals(tmp_path, capsys, monkeypatch) -> None:
    from tests import test_guard_events as api

    home_dir = tmp_path / "home"
    store = api.GuardStore(home_dir)
    store.add_event(
        "changed_artifact_caught",
        {
            "harness": "codex",
            "artifact_id": "codex:project:secret_probe",
            "artifact_name": "secret_probe",
            "policy_action": "block",
            "changed_fields": ["command", "args"],
            "publisher": "hashgraph-online",
        },
        "2026-04-10T00:00:00Z",
    )
    api._SyncRequestHandler.requests = []
    api._SyncRequestHandler.signal_status = 200
    api._SyncRequestHandler.response_payload = {
        "syncedAt": "2026-04-10T00:00:00Z",
        "receiptsStored": 0,
        "inventoryStored": 0,
        "inventoryDiff": {"generatedAt": "2026-04-10T00:00:00Z", "items": []},
        "advisories": [],
        "exceptions": [],
    }

    server = api.HTTPServer(("127.0.0.1", 0), api._SyncRequestHandler)
    thread = api.threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        seed_legacy_optional_uploads(
            store,
            monkeypatch,
            issuer=f"http://127.0.0.1:{server.server_port}",
            sync_url=f"http://127.0.0.1:{server.server_port}/guard/receipts/sync",
            token="local-test-token",
            telemetry=True,
        )
        login_rc = 0

        sync_rc = api.main(["guard", "sync", "--home", str(home_dir), "--json"])
        output = api.json.loads(capsys.readouterr().out)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    signal_requests = [
        item for item in api._SyncRequestHandler.requests if item["path"].endswith("/guard/signals/pain")
    ]

    assert login_rc == 0
    assert sync_rc == 0
    assert output["pain_signals_uploaded"] == 1
    assert (
        signal_requests[0]["payload"]["items"][0]["signalId"]
        == "changed_artifact_caught:codex:codex:project:secret_probe"
    )


def run_noisy_incident_signals(tmp_path, capsys, monkeypatch) -> None:
    from tests import test_guard_events as api

    home_dir = tmp_path / "home"
    store = api.GuardStore(home_dir)
    store.add_event(
        "changed_artifact_caught",
        {
            "harness": "codex",
            "artifact_id": "codex:project:allowed_change",
            "artifact_name": "allowed_change",
            "policy_action": "allow",
            "changed_fields": ["command"],
        },
        "2026-04-10T00:00:00Z",
    )
    store.add_event(
        "changed_artifact_caught",
        {
            "harness": "codex",
            "artifact_id": "codex:project:blocked_change",
            "artifact_name": "blocked_change",
            "policy_action": "block",
            "changed_fields": ["command"],
        },
        "2026-04-10T00:01:00Z",
    )
    store.add_event(
        "install_time_warn",
        {
            "harness": "guard-cli",
            "artifact_id": "package:npm:left-pad",
            "artifact_name": "left-pad",
            "install_kind": "install",
            "risk_signals": ["suspicious package behavior"],
        },
        "2026-04-10T00:02:00Z",
    )
    store.add_event(
        "install_time_warn",
        {
            "harness": "guard-cli",
            "artifact_id": "package:npm:left-pad",
            "artifact_name": "left-pad",
            "install_kind": "install",
            "risk_signals": ["suspicious package behavior"],
        },
        "2026-04-10T00:03:00Z",
    )
    for index, action in enumerate(("require-reapproval", "sandbox-required"), start=4):
        store.add_event(
            f"install_time_{action}",
            {
                "harness": "guard-cli",
                "artifact_id": f"package:npm:{action}",
                "artifact_name": action,
                "install_kind": "install",
                "policy_action": action,
                "risk_signals": [f"install {action}"],
            },
            f"2026-04-10T00:0{index}:00Z",
        )
    store.add_event(
        "supply_chain_bundle_refresh_requested",
        {
            "artifact_id": "package:npm:left-pad",
            "artifact_name": "left-pad",
            "reason": "feed_stale",
        },
        "2026-04-10T00:06:00Z",
    )
    store.add_event(
        "approval_gate/remote_policy_sync_blocked",
        {"error": "gate_locked"},
        "2026-04-10T00:07:00Z",
    )
    api._SyncRequestHandler.requests = []
    api._SyncRequestHandler.signal_status = 200
    api._SyncRequestHandler.response_payload = {
        "syncedAt": "2026-04-10T00:00:00Z",
        "receiptsStored": 0,
        "inventoryStored": 0,
        "inventoryDiff": {"generatedAt": "2026-04-10T00:00:00Z", "items": []},
        "advisories": [],
        "exceptions": [],
    }

    server = api.HTTPServer(("127.0.0.1", 0), api._SyncRequestHandler)
    thread = api.threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        seed_legacy_optional_uploads(
            store,
            monkeypatch,
            issuer=f"http://127.0.0.1:{server.server_port}",
            sync_url=f"http://127.0.0.1:{server.server_port}/guard/receipts/sync",
            token="local-test-token",
            telemetry=True,
        )
        login_rc = 0

        sync_rc = api.main(["guard", "sync", "--home", str(home_dir), "--json"])
        output = api.json.loads(capsys.readouterr().out)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    signal_requests = [
        item for item in api._SyncRequestHandler.requests if item["path"].endswith("/guard/signals/pain")
    ]
    uploaded_items = [signal for request in signal_requests for signal in request["payload"].get("items", [])]
    uploaded_ids = {str(item.get("artifactId")) for item in uploaded_items}
    uploaded_names = {str(item.get("signalName")) for item in uploaded_items}

    assert login_rc == 0
    assert sync_rc == 0
    assert output["pain_signals_uploaded"] == 6
    assert "codex:project:allowed_change" not in uploaded_ids
    assert "codex:project:blocked_change" in uploaded_ids
    assert "package:npm:left-pad" in uploaded_ids
    assert "guard:policy:disable" in uploaded_ids
    assert "approval_gate/remote_policy_sync_blocked" in uploaded_names
    assert "supply_chain_bundle_refresh_requested" in uploaded_names
    assert "install_time_warn" in uploaded_names
    assert "install_time_require-reapproval" in uploaded_names
    assert "install_time_sandbox-required" in uploaded_names


def run_all_pain_signal_batches(tmp_path, capsys, monkeypatch) -> None:
    from tests import test_guard_events as api

    home_dir = tmp_path / "home"
    store = api.GuardStore(home_dir)
    for index in range(505):
        store.add_event(
            "changed_artifact_caught",
            {
                "harness": "codex",
                "artifact_id": f"codex:project:secret_probe_{index}",
                "artifact_name": f"secret_probe_{index}",
                "policy_action": "block",
                "changed_fields": ["command"],
            },
            "2026-04-10T00:00:00Z",
        )
    api._SyncRequestHandler.requests = []
    api._SyncRequestHandler.signal_status = 200
    api._SyncRequestHandler.response_payload = {
        "syncedAt": "2026-04-10T00:00:00Z",
        "receiptsStored": 0,
        "inventoryStored": 0,
        "inventoryDiff": {"generatedAt": "2026-04-10T00:00:00Z", "items": []},
        "advisories": [],
        "exceptions": [],
    }

    server = api.HTTPServer(("127.0.0.1", 0), api._SyncRequestHandler)
    thread = api.threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        seed_legacy_optional_uploads(
            store,
            monkeypatch,
            issuer=f"http://127.0.0.1:{server.server_port}",
            sync_url=f"http://127.0.0.1:{server.server_port}/guard/receipts/sync",
            token="local-test-token",
            telemetry=True,
        )
        login_rc = 0

        sync_rc = api.main(["guard", "sync", "--home", str(home_dir), "--json"])
        output = api.json.loads(capsys.readouterr().out)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    signal_requests = [
        item for item in api._SyncRequestHandler.requests if item["path"].endswith("/guard/signals/pain")
    ]
    total_uploaded = sum(len(item["payload"].get("items", [])) for item in signal_requests)
    latest_event_id = max(
        item["event_id"] for item in store.list_events(limit=600, event_name="changed_artifact_caught")
    )

    assert login_rc == 0
    assert sync_rc == 0
    assert output["pain_signals_uploaded"] == 505
    assert len(signal_requests) == 2
    assert total_uploaded == 505
    assert store.get_sync_payload("pain_signal_cursor") == {"event_id": latest_event_id}


def run_query_parameter_preservation(tmp_path, capsys, monkeypatch) -> None:
    from tests import test_guard_events as api

    home_dir = tmp_path / "home"
    store = api.GuardStore(home_dir)
    store.add_event(
        "changed_artifact_caught",
        {
            "harness": "codex",
            "artifact_id": "codex:project:secret_probe",
            "artifact_name": "secret_probe",
            "policy_action": "block",
            "changed_fields": ["command"],
        },
        "2026-04-10T00:00:00Z",
    )
    api._SyncRequestHandler.requests = []
    api._SyncRequestHandler.receipt_response_statuses = []
    api._SyncRequestHandler.signal_status = 200
    api._SyncRequestHandler.response_payload = {
        "syncedAt": "2026-04-09T00:00:00Z",
        "receiptsStored": 0,
        "inventoryStored": 0,
        "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
        "advisories": [],
        "exceptions": [],
    }

    server = api.HTTPServer(("127.0.0.1", 0), api._SyncRequestHandler)
    thread = api.threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        seed_legacy_optional_uploads(
            store,
            monkeypatch,
            issuer=f"http://127.0.0.1:{server.server_port}",
            sync_url=f"http://127.0.0.1:{server.server_port}/registry/api/v1?tenant=preview",
            token="local-test-token",
            telemetry=True,
        )
        sync_rc = api.main(["guard", "sync", "--home", str(home_dir), "--json"])
        output = api.json.loads(capsys.readouterr().out)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert sync_rc == 0
    assert output["synced_at"] == "2026-04-09T00:00:00Z"
    request_paths = [item["path"] for item in api._SyncRequestHandler.requests]
    assert request_paths.index("/registry/api/v1/guard/receipts/sync?tenant=preview") < request_paths.index(
        "/registry/api/v1/guard/signals/pain?tenant=preview"
    )
