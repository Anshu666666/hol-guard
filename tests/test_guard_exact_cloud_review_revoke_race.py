"""HGP-181: disable/revocation race with a leased exact decision."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_revoked_capability_cannot_commit_leased_decision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    first = review_request("applied-before-revoke")
    leased = review_request("leased-after-revoke")
    add_review_request(store, first)
    add_review_request(store, leased)
    enable_exact_cloud_review(store)
    applied = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, first.request_id, receipt_id="applied-before"),
    )
    approval = remote_approval(store, leased.request_id, receipt_id="leased-after")
    original = store.resolve_one_request_with_signed_remote_exact_result

    def _revoke_then_commit(request_id: str, **kwargs: Any) -> dict[str, object]:
        disable_exact_cloud_review(store)
        return original(request_id, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", _revoke_then_commit)
    with pytest.raises(ExactCloudReviewError, match=r"cloud_review_capability_revoked|remote_exact_capability_changed"):
        apply_exact_cloud_review(store, remote_approval=approval)
    history = store.get_approval_request(first.request_id)
    assert history is not None and history["status"] == "resolved"
    assert history["request_id"] == applied.request_id
    pending = store.get_approval_request(leased.request_id)
    assert pending is not None and pending["status"] == "pending"


def _apply_after_process_restart() -> None:
    import json
    import os
    import sys

    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(Path(sys.argv[1]))
    approval = json.loads(Path(sys.argv[2]).read_text())
    try:
        apply_exact_cloud_review(store, remote_approval=approval)
    except ExactCloudReviewError as error:
        print(json.dumps({"pid": os.getpid(), "error": error.code}))
    else:
        raise AssertionError("The earlier capability authorized another application")


@pytest.mark.parametrize("change", ["disable", "rotate", "oauth-revocation"])
def test_actual_commit_barrier_rechecks_persisted_authority_and_survives_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    import json
    import os
    import subprocess
    import sys
    import threading
    from datetime import datetime, timezone

    from codex_plugin_scanner.guard.runtime.exact_cloud_review import exact_cloud_review_status
    from codex_plugin_scanner.guard.store import GuardStore

    store = connected_exact_review_store(tmp_path)
    for request_id in ("earlier-valid", "paused-decision"):
        add_review_request(store, review_request(request_id))
    enable_exact_cloud_review(store)
    apply_exact_cloud_review(
        store, remote_approval=remote_approval(store, "earlier-valid", receipt_id="earlier-valid-receipt")
    )
    earlier = store.get_approval_request("earlier-valid")
    approval = remote_approval(store, "paused-decision", receipt_id="paused-receipt")
    original = store.resolve_one_request_with_signed_remote_exact_result
    entered = threading.Event()
    release = threading.Event()
    outcomes: list[str] = []

    def before_transaction(request_id: str, **kwargs: Any) -> dict[str, object]:
        # Signature, immutable request and original capability preflight have
        # completed. The unmodified Store transaction has not started yet.
        entered.set()
        assert release.wait(5)
        return original(request_id, **kwargs)

    def apply() -> None:
        try:
            apply_exact_cloud_review(store, remote_approval=approval)
        except ExactCloudReviewError as error:
            outcomes.append(error.code)
        except BaseException as error:
            outcomes.append(type(error).__name__)
        else:
            outcomes.append("unexpected-application")

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", before_transaction)
    thread = threading.Thread(target=apply)
    thread.start()
    try:
        assert entered.wait(5)
        other = GuardStore(store.guard_home)
        if change == "disable":
            disable_exact_cloud_review(other)
        elif change == "rotate":
            enable_exact_cloud_review(other)
        else:
            credentials = other.get_oauth_local_credentials(allow_primary=False)
            assert isinstance(credentials, dict)
            fields = (
                "issuer",
                "client_id",
                "refresh_token",
                "dpop_private_key_pem",
                "dpop_public_jwk",
                "dpop_public_jwk_thumbprint",
                "machine_id",
                "device_id",
                "workspace_id",
                "runtime_id",
                "access_token",
                "access_token_expires_at",
            )
            options: dict[str, Any] = {key: credentials[key] for key in fields if key in credentials}
            other.set_oauth_local_credentials(
                **options, grant_id="new-grant", now=datetime.now(timezone.utc).isoformat()
            )
            assert exact_cloud_review_status(other)["enabled"] is False
            assert other.get_sync_payload("guard_exact_cloud_review_revocation") is not None
        assert thread.is_alive() and outcomes == []
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert outcomes[0] in {
        "cloud_review_capability_revoked",
        "remote_exact_capability_changed",
        "remote_exact_oauth_changed",
    }
    assert store.get_approval_request("earlier-valid") == earlier
    paused = store.get_approval_request("paused-decision")
    assert paused is not None and paused["status"] == "pending"
    assert not store.has_exact_cloud_review_receipt("paused-receipt")
    approval_file = tmp_path / "synthetic-paused-approval.json"
    approval_file.write_text(json.dumps(approval))
    approval_file.chmod(0o600)
    checkout = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from tests.test_guard_exact_cloud_review_revoke_race import _apply_after_process_restart; "
            "_apply_after_process_restart()",
            str(store.guard_home),
            str(approval_file),
        ],
        cwd=checkout,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(checkout / "src"), str(checkout)))},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    observed = json.loads(result.stdout)
    assert observed["pid"] != os.getpid()
    assert observed["error"] in {
        "cloud_review_capability_revoked",
        "remote_exact_capability_mismatch",
        "cloud_review_capability_missing",
        "remote_exact_wrong_grant",
    }
    assert GuardStore(store.guard_home).get_approval_request("earlier-valid") == earlier
    assert not store.has_exact_cloud_review_receipt("paused-receipt")
