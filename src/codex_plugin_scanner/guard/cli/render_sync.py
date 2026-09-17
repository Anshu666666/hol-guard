"""Receipt and policy progress with separate optional telemetry status."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def render_sync_summary(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Synced at", str(payload.get("synced_at") or "unknown"))
    body.add_row("Receipts sent", str(payload.get("receipts") or 0))
    body.add_row("Inventory tracked", str(payload.get("inventory_tracked", payload.get("inventory")) or 0))
    body.add_row("Receipts stored", str(payload.get("receipts_stored") or 0))
    body.add_row("Advisories stored", str(payload.get("advisories_stored") or 0))
    remote_policies_stored = payload.get("remote_policies_stored")
    exceptions_stored = payload.get("exceptions_stored")
    pain_signals_uploaded = payload.get("pain_signals_uploaded")
    if remote_policies_stored is not None:
        body.add_row("Remote policies", str(remote_policies_stored or 0))
    if exceptions_stored is not None:
        body.add_row("Exceptions stored", str(exceptions_stored or 0))
    if pain_signals_uploaded is not None:
        body.add_row("Pain signals uploaded", str(pain_signals_uploaded or 0))
    if payload.get("receipt_upload_status") is not None:
        body.add_row("Receipt upload", str(payload.get("receipt_upload_status")))
    if payload.get("policy_validation_status") is not None:
        body.add_row("Policy validation", str(payload.get("policy_validation_status")))
    if payload.get("policy_application_status") is not None:
        body.add_row("Policy application", str(payload.get("policy_application_status")))
    if payload.get("policy_rejection_reason"):
        body.add_row("Policy rejection", str(payload.get("policy_rejection_reason")))
    degraded = payload.get("telemetry_status") == "degraded"
    if degraded:
        body.add_row("Telemetry", "uploads delayed")
    console.print(Panel(body, title="Guard sync complete", border_style="yellow" if degraded else "green"))
