"""Allowlisted public fixture companion; no private key or OAuth material."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.contracts.guard_cloud_review import validate_exact_command_result
from codex_plugin_scanner.guard.native_approval_v4_protocol import decode_native_approval_v4_proof

_JOB_KEYS = frozenset(
    [
        "id",
        "operation",
        "protocolVersion",
        "deviceId",
        "workspaceId",
        "nonce",
        "expiresAt",
        "idempotencyKey",
        "payload",
        "serverResolvedBinding",
    ]
)
_BINDING_KEYS = frozenset(
    [
        "actionDigest",
        "approvalId",
        "claimDigest",
        "capabilityId",
        "localRequestId",
        "localRequestVersion",
        "policyAction",
        "scope",
        "grantId",
        "machineId",
        "localMachineInstallationId",
        "runtimeId",
        "machineInstallationId",
        "runtimeGrantId",
        "reviewRequestId",
    ]
)
_RESULT_KEYS = frozenset(
    [
        "applicationReason",
        "applicationStatus",
        "applicationUpdatedAt",
        "continuationReason",
        "continuationStatus",
        "continuationUpdatedAt",
        "contractVersion",
        "correlationId",
        "localRequestId",
        "protocolVersion",
        "receiptId",
    ]
)


def _object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("synthetic_interoperability_fields_invalid")
    return cast(dict[str, object], value)


def synthetic_delivery_companion(
    *, job: dict[str, object], result: dict[str, object], source_claim: dict[str, object]
) -> dict[str, object]:
    """Retain the exact delivered assertion/result, excluding the local route marker."""
    marked = _object(job, _JOB_KEYS | {"_guardCommandTransport"})
    if marked["_guardCommandTransport"] != "cloud_review":
        raise ValueError("synthetic_interoperability_transport_invalid")
    queued = {key: value for key, value in marked.items() if key != "_guardCommandTransport"}
    payload = _object(queued["payload"], frozenset(["harness", "nativeApprovalContext", "nativeApprovalProof"]))
    context = _object(payload["nativeApprovalContext"], frozenset(["decision", "decisionReceiptId"]))
    binding = _object(queued["serverResolvedBinding"], _BINDING_KEYS)
    proof = decode_native_approval_v4_proof(payload["nativeApprovalProof"])
    if proof is None or proof["challenge"] != source_claim.get("nativeApprovalChallenge"):
        raise ValueError("synthetic_interoperability_proof_invalid")
    for key, value in queued.items():
        if key in {"payload", "serverResolvedBinding", "protocolVersion"}:
            continue
        if not isinstance(value, str) or not value or len(value) > 1024:
            raise ValueError("synthetic_interoperability_scalar_invalid")
    for key, value in binding.items():
        if key == "localRequestVersion":
            if type(value) is not int or value < 1:
                raise ValueError("synthetic_interoperability_version_invalid")
        elif not isinstance(value, str) or not value or len(value) > 1024:
            raise ValueError("synthetic_interoperability_scalar_invalid")
    waiting = _object(result, _RESULT_KEYS)
    validate_exact_command_result(waiting)
    if (
        type(queued["protocolVersion"]) is not int
        or queued["protocolVersion"] != 2
        or queued["operation"] != "guard.review.resolveExact"
        or context["decision"] != "allow_once"
        or payload["harness"] != source_claim.get("harnessId")
        or binding["claimDigest"] != source_claim.get("claimHash")
        or binding["localRequestId"] != source_claim.get("localRequestId")
        or waiting["correlationId"] != queued["id"]
        or waiting["localRequestId"] != binding["localRequestId"]
        or waiting["receiptId"] != context["decisionReceiptId"]
        or waiting["applicationStatus"] != "failed_retryable"
        or waiting["applicationReason"] != "native_approval_waiting_for_hook"
        or waiting["continuationStatus"] != "waiting"
    ):
        raise ValueError("synthetic_interoperability_binding_invalid")
    # JSON detaches nested assertion bytes; the helper never accepts a store,
    # signing key, credential object, or enrollment record as an input.
    return cast(
        dict[str, object], json.loads(json.dumps({"queuedCommand": queued, "deliveryResult": waiting}, allow_nan=False))
    )


def fixture_build_provenance(repository: Path) -> dict[str, str]:
    """Report actual checked-out source; external workflow metadata must verify it."""
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True, timeout=10).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repository, text=True, timeout=10).strip()
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"[0-9a-f]{40}", tree)
        or os.environ.get("GITHUB_SHA") != commit
        or not re.fullmatch(r"[1-9][0-9]*", run_id)
    ):
        raise ValueError("synthetic_interoperability_build_binding_invalid")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=repository, check=True, timeout=10)
    return {"sourceCommit": commit, "sourceTree": tree, "buildRunId": run_id}
