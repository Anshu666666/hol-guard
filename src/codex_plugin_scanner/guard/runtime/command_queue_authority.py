"""Independent local authority sources advertised by the Cloud command queue."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ..review_contracts import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from .command_capability import AuthorizedCommandJob, CommandCapabilityError, authorize_command_job
from .exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    authorize_exact_cloud_review_job,
)
from .exact_cloud_review_transport import uses_exact_transport
from .native_review_delivery import (
    authorize_native_review_delivery,
    require_legacy_review_transport,
    uses_native_review_delivery,
)
from .runner import GuardSyncNotConfiguredError


def command_queue_oauth_target(store: GuardStore) -> tuple[str, str]:
    try:
        oauth = guard_review_oauth_metadata(store)
    except GuardReviewContractError as error:
        raise GuardSyncNotConfiguredError("Guard command queue requires a device-bound OAuth grant.") from error
    return oauth.device_id, oauth.workspace_id


def authorize_command_queue_job(
    store: GuardStore,
    job: dict[str, object],
    *,
    schema_versions: Mapping[str, int],
    now: str | None = None,
    authorize_generic: Callable[..., AuthorizedCommandJob] = authorize_command_job,
) -> AuthorizedCommandJob:
    if job.get("operation") == EXACT_CLOUD_REVIEW_OPERATION:
        if uses_native_review_delivery(job):
            return authorize_native_review_delivery(store, job, now=now)
        try:
            require_legacy_review_transport(store, job)
        except ValueError as error:
            raise CommandCapabilityError(str(error)) from error
        return authorize_exact_cloud_review_job(store, job, now=now)
    return authorize_generic(store, job, schema_versions=schema_versions, now=now)


def authorize_transport_command_queue_job(
    store: GuardStore,
    job: dict[str, object],
    *,
    schema_versions: Mapping[str, int],
    now: str | None = None,
    authorize_generic: Callable[..., AuthorizedCommandJob] | None = None,
) -> AuthorizedCommandJob:
    exact_transport = uses_exact_transport(job)
    exact_operation = job.get("operation") == EXACT_CLOUD_REVIEW_OPERATION
    if exact_transport and not exact_operation:
        raise CommandCapabilityError("remote_exact_job_operation_invalid")
    if exact_operation and not exact_transport:
        raise CommandCapabilityError("remote_exact_transport_required")
    return authorize_command_queue_job(
        store,
        job,
        schema_versions=schema_versions,
        now=now,
        authorize_generic=authorize_generic or authorize_command_job,
    )


__all__ = ["authorize_command_queue_job", "authorize_transport_command_queue_job", "command_queue_oauth_target"]
