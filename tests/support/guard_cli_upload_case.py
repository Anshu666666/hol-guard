"""Original CLI receipt upload journey with explicit source-bound consent."""

from tests.support.optional_uploads import seed_legacy_optional_uploads


def run_login_and_sync_posts_receipts(tmp_path, capsys, monkeypatch):
    from tests import test_guard_cli as api

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    api._build_stable_guard_fixture(home_dir, workspace_dir)
    api._write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
    api._SyncRequestHandler.response_payload = {
        "syncedAt": "2026-04-09T00:00:00Z",
        "receiptsStored": 1,
    }
    api._SyncRequestHandler.captured_bodies = []
    api._SyncRequestHandler.captured_paths = []

    server = api.HTTPServer(("127.0.0.1", 0), api._SyncRequestHandler)
    thread = api.threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config_path = home_dir / "config.toml"
        local_config = config_path.read_text(encoding="utf-8")
        seed_legacy_optional_uploads(
            api.GuardStore(home_dir),
            monkeypatch,
            issuer=f"http://127.0.0.1:{server.server_port}",
            sync_url=f"http://127.0.0.1:{server.server_port}/receipts",
            token="demo-token",
            telemetry=True,
        )
        with config_path.open("a", encoding="utf-8") as local_settings:
            local_settings.write(local_config)
        login_rc = 0

        run_rc = api.main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        api.json.loads(capsys.readouterr().out)

        sync_rc = api.main(
            [
                "guard",
                "sync",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        sync_output = api.json.loads(capsys.readouterr().out)
        status_rc = api.main(["guard", "status", "--home", str(home_dir), "--workspace", str(workspace_dir), "--json"])
        status_output = api.json.loads(capsys.readouterr().out)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert login_rc == 0
    assert run_rc == 0
    assert sync_rc == 0
    assert status_rc == 0
    assert sync_output["receipts_stored"] == 1
    assert sync_output["inventory"] == 0
    assert sync_output["inventory_tracked"] >= 1
    assert status_output["cloud_state"] == "paired_active"
    assert status_output["last_sync_at"] == "2026-04-09T00:00:00Z"
    assert api._SyncRequestHandler.captured_headers["authorization"] == "Bearer demo-token"
    receipt_body = next(
        body
        for body in api._SyncRequestHandler.captured_bodies
        if isinstance(body.get("receipts"), list) and len(body["receipts"]) >= 1
    )
    event_body = next(body for body in api._SyncRequestHandler.captured_bodies if "events" in body)
    assert len(receipt_body["receipts"]) >= 1
    assert "inventory" not in receipt_body
    assert len(event_body["events"]) >= 1
    first_receipt = receipt_body["receipts"][0]
    assert "artifactId" in first_receipt
    assert "artifact_id" not in first_receipt
    assert "receiptId" in first_receipt
    assert "artifactSlug" in first_receipt
    assert "artifactHash" in first_receipt
    assert "recommendation" in first_receipt
