"""Exact signed memory target projection for local matchers."""

from __future__ import annotations

from collections.abc import Mapping

from .review_oauth_binding import GuardReviewContractError, GuardReviewOAuthMetadata


def _text_ids(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise GuardReviewContractError("decision_memory_target_invalid")
    items = [str(item).strip() for item in value if isinstance(item, str) and str(item).strip()]
    if len(items) != len(value):
        raise GuardReviewContractError("decision_memory_target_invalid")
    return tuple(items)


def validate_exact_memory_target(
    target: Mapping[str, object],
    *,
    oauth: GuardReviewOAuthMetadata,
    project_identity: str | None = None,
) -> None:
    """Refuse sibling or partial multi-target projections before any row is written."""

    workspace_ids = _text_ids(target.get("workspaceIds"))
    machine_ids = _text_ids(target.get("machineIds"))
    project_ids = _text_ids(target.get("projectIds"))
    if not workspace_ids and not machine_ids and not project_ids:
        raise GuardReviewContractError("decision_memory_target_invalid")
    if len(workspace_ids) > 1 or len(machine_ids) > 1 or len(project_ids) > 1:
        raise GuardReviewContractError("decision_memory_target_partial")
    if workspace_ids and workspace_ids[0] != oauth.workspace_id:
        raise GuardReviewContractError("decision_memory_workspace_mismatch")
    if machine_ids and machine_ids[0] != oauth.installation_id:
        raise GuardReviewContractError("decision_memory_machine_mismatch")
    if project_ids and (project_identity is None or project_ids[0] != project_identity):
        raise GuardReviewContractError("decision_memory_project_mismatch")


def local_memory_match_fields(
    target: Mapping[str, object],
    *,
    oauth: GuardReviewOAuthMetadata,
    project_identity: str | None,
) -> tuple[str | None, str | None]:
    """Return exact (workspace, publisher) matcher fields for one accepted target."""

    workspace_ids = _text_ids(target.get("workspaceIds"))
    machine_ids = _text_ids(target.get("machineIds"))
    project_ids = _text_ids(target.get("projectIds"))
    parts: list[str] = []
    if workspace_ids:
        parts.append(workspace_ids[0])
    if machine_ids:
        parts.append(f"machine:{machine_ids[0]}")
    if project_ids:
        parts.append(f"project:{project_ids[0]}")
    if not parts:
        return oauth.workspace_id, None
    return "|".join(parts), None


__all__ = ["local_memory_match_fields", "validate_exact_memory_target"]
