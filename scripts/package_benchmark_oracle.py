"""Frozen package outcomes plus explicit normalization of per-attempt identities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scripts.package_benchmark_corpus import FORMAT_BY_NAME, Case, digest, package_name

_IDENTITIES = frozenset(
    {
        "package_intent_hash",
        "workspace_fingerprint",
        "repo_fingerprint",
        "evidence_id",
        "evidence_ids",
        "action_id",
        "request_id",
    }
)
_VOLATILE = frozenset({"lockfileParseElapsedMs"})


class OracleMismatchError(ValueError):
    pass


def require(value: object, field: str) -> None:
    if not value:
        raise OracleMismatchError("package_matrix_mismatch:" + field)


def normalized(value: object) -> object:
    """Preserve all values except declared per-attempt IDs and elapsed diagnostics.

    Identity correspondence is checked separately; parser version, completeness,
    reasons, severity, evidence details and unknown fields remain comparable.
    """
    if isinstance(value, Mapping):
        return {str(key): normalized(item) for key, item in value.items() if key not in _IDENTITIES | _VOLATILE}
    if isinstance(value, (tuple, list)):
        return [normalized(item) for item in value]
    return value


def expected_names(case: Case) -> set[str]:
    if case.mode == "unresolved":
        return {package_name(i) for i in range(case.dependencies)}
    matches = 0 if case.mode == "absent" else min(case.dependencies, case.bundle_size - 1)
    return {"bench-anchor", *(package_name(i) for i in range(matches))}


def private_projection(evaluation: Mapping[str, object], evidence: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Bound raw retention while committing to every unprojected value."""
    packages = evaluation.get("packages")
    sample = list(packages[:8]) + list(packages[-8:]) if isinstance(packages, (tuple, list)) else []
    return {
        "evaluation_sha256": digest(evaluation),
        "evidence_sha256": digest(evidence),
        "evidence_rows": len(evidence),
        "package_count": len(packages) if isinstance(packages, (tuple, list)) else None,
        "decision": evaluation.get("decision"),
        "policy_action": evaluation.get("policy_action"),
        "enforcement": evaluation.get("enforcement"),
        "cache_status": evaluation.get("cache_status"),
        "package_sample": [
            {
                key: item.get(key)
                for key in ("name", "namespace", "ecosystem", "direct", "resolvedVersion", "decision", "reasons")
            }
            for item in sample
            if isinstance(item, Mapping)
        ],
        "raw_command_retained": False,
    }


def validate_evaluation(
    case: Case, evaluation: Mapping[str, object], evidence: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    require(case.route != "bundle_kernel", "wrong_boundary")
    require(evaluation.get("decision") == "block" and evaluation.get("policy_action") == "block", "decision")
    packages = evaluation.get("packages")
    require(isinstance(packages, (tuple, list)), "packages_shape")
    assert isinstance(packages, (tuple, list))
    require(all(isinstance(item, Mapping) for item in packages), "package_shape")
    require(len(packages) == len(expected_names(case)), "package_count")
    require({item.get("name") for item in packages} == expected_names(case), "package_names")
    fmt = FORMAT_BY_NAME[case.format]
    for item in packages:
        require(item.get("decision") == "block", "package_decision")
        require(item.get("ecosystem") == fmt.ecosystem, "ecosystem")
        require(item.get("namespace") == ("bench" if fmt.ecosystem == "packagist" else None), "namespace")
        require(item.get("lockfileParseComplete") is not False, "completeness")
        require(item.get("resolvedVersion") == (None if case.mode == "unresolved" else "1.0.0"), "resolved_version")
        reasons = item.get("reasons")
        require(isinstance(reasons, (list, tuple)) and reasons, "package_reasons")
        require(
            all(
                isinstance(reason, Mapping) and reason.get("code") != "lockfile_parse_incomplete" for reason in reasons
            ),
            "complete_reasons",
        )
        if case.mode == "unresolved":
            require({reason.get("code") for reason in reasons} == {"cloud_auth_error"}, "unresolved_fallback")
            require(item.get("direct") is True, "unresolved_direct")
        elif item.get("name") != "bench-anchor":
            require(item.get("direct") is False, "transitive_identity")
            code = (
                "known_malware"
                if case.mode == "deny" and item.get("name") == package_name(0)
                else "transitive_lockfile_match"
            )
            require(any(reason.get("code") == code for reason in reasons), "transitive_reason")
    require(len(evidence) == len(packages), "evidence_count")
    if case.mode == "unresolved":
        require(
            evaluation.get("enforcement") == "premium_cloud" and evaluation.get("cache_status") == "cloud-error",
            "unresolved_route",
        )
    evidence_ids = evaluation.get("evidence_ids")
    require(isinstance(evidence_ids, (tuple, list)), "evidence_id_binding")
    assert isinstance(evidence_ids, (tuple, list))
    require({row.get("evidence_id") for row in evidence} == set(evidence_ids), "evidence_id_binding")
    seen: list[object] = []
    package_digests = {digest(item) for item in packages}
    harness = "guard-cli" if case.route == "protect_dry_run" else "hol-guard"
    for row in evidence:
        require(row.get("category") == "supply-chain" and row.get("signal_id") == "block", "evidence_classification")
        require(row.get("request_id") == evaluation.get("package_intent_hash"), "evidence_request_binding")
        require(
            row.get("harness") == harness
            and row.get("action_id")
            == harness + ":project:package-request:" + str(evaluation.get("package_intent_hash")),
            "evidence_action_binding",
        )
        details = row.get("details")
        require(isinstance(details, Mapping), "evidence_details")
        assert isinstance(details, Mapping)
        require(
            details.get("workspace_fingerprint")
            == details.get("repo_fingerprint")
            == evaluation.get("workspace_fingerprint"),
            "evidence_input_binding",
        )
        package = details.get("package")
        require(digest(package) in package_digests, "evidence_package_binding")
        seen.append(package)
    require(sorted(digest(item) for item in seen) == sorted(digest(item) for item in packages), "evidence_coverage")
    return {
        "packages": len(packages),
        "evidence_rows": len(evidence),
        "decision": "block",
        "semantic_sha256": digest(normalized(evaluation)),
        "evidence_sha256": digest(sorted((normalized(row) for row in evidence), key=digest)),
        "complete": True,
    }


def validate_kernel(case: Case, decisions: Sequence[Mapping[str, object]]) -> dict[str, object]:
    require(case.route == "bundle_kernel" and len(decisions) == case.dependencies, "kernel_boundary")
    matched = min(case.dependencies, case.bundle_size // 2)
    for index, item in enumerate(decisions):
        require(item.get("action") == ("block" if index < matched else "monitor"), "kernel_action")
        require(item.get("stale") is False and item.get("emergency_deny") is False, "kernel_state")
        require(
            item.get("reason") == ("known_malware_or_kev" if index < matched else "no_cached_match"), "kernel_reason"
        )
    return {"lookups": len(decisions), "matched": matched, "semantic_sha256": digest(decisions), "complete": True}
