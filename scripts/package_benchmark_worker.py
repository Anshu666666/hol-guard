"""One isolated package invocation; full source route, not an installed launcher."""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import os
import shlex
import socket
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from types import CodeType
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(_ROOT))

from scripts.package_benchmark_corpus import (  # noqa: E402
    FORMAT_BY_NAME,
    NOW,
    NOW_SECONDS,
    WORKSPACE_ID,
    Case,
    digest,
    fixture,
    package_name,
)
from scripts.package_benchmark_evidence import (  # noqa: E402
    environment_identity,
    harness_identity,
    load_object,
    source_identity,
    write_private,
)
from scripts.package_benchmark_oracle import (  # noqa: E402
    normalized,
    private_projection,
    require,
    validate_evaluation,
    validate_kernel,
)
from scripts.package_benchmark_protocol import MISMATCH_FIELDS  # noqa: E402


def _cpu() -> float:
    import resource

    return sum(
        value.ru_utime + value.ru_stime
        for value in (resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN))
    )


def _profile_counts(profile: cProfile.Profile) -> dict[str, int]:
    watched = {
        ("lockfile_parse_result", "parse_lockfile_text"),
        ("lockfile_parse_result", "_validate_lockfile_structure"),
        ("lockfile_parse_result", "_validate_text_lockfile"),
        ("text_lockfile_parse", "parse_text_lockfile"),
        ("workspace_path_guard", "read_bytes_within_workspace"),
        ("workspace_path_guard", "read_text_within_workspace"),
        ("store_evidence_facade", "add_evidence"),
        ("store_evidence_facade", "add_evidence_batch"),
    }
    result: dict[str, int] = {}
    for entry in profile.getstats():
        if not isinstance(entry.code, CodeType):
            continue
        identity = (Path(entry.code.co_filename).stem, entry.code.co_name)
        if identity in watched:
            result[".".join(identity)] = entry.callcount
    return result


def _evidence(store: Any) -> list[dict[str, object]]:
    with store._connect() as connection:
        rows = [dict(row) for row in connection.execute("select * from guard_evidence order by evidence_id")]
    for row in rows:
        row["details"] = json.loads(row.pop("details_json"))
    return rows


def _run_route(
    case: Case, value: dict[str, Any], store: Any, workspace: Path, response: Any
) -> tuple[dict[str, Any], object | None]:
    from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
    from codex_plugin_scanner.guard.runtime.package_intent_common import build_package_request_artifact
    from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
    from codex_plugin_scanner.guard.runtime.supply_chain_bundle import evaluate_cached_supply_chain_bundle
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact

    if case.route == "bundle_kernel":
        decisions = [
            asdict(
                evaluate_cached_supply_chain_bundle(
                    response, package_name=package_name(i), package_version=None, ecosystem="npm", now=NOW_SECONDS
                )
            )
            for i in range(case.dependencies)
        ]
        return {"decisions": decisions}, None
    if case.route == "protect_dry_run":
        protected = build_package_protect_payload(
            command=value["command"],
            store=store,
            workspace_dir=workspace,
            dry_run=True,
            now=NOW,
            config=None,
            unsafe_raw_output=False,
            timeout_seconds=30,
        )
        require(protected is not None, "protect_unsupported")
        assert protected is not None
        payload, exit_code = protected
        require(payload.get("executed") is False and payload.get("dry_run") is True, "protect_executed")
        require(exit_code != 0, "protect_exit")
        projected = payload["supply_chain_evaluation"]
        assert isinstance(projected, dict)
        return projected, {
            "exit_code": exit_code,
            "verdict": payload["verdict"],
            "executed": payload["executed"],
        }
    intent = parse_package_intent(shlex.join(value["command"]), workspace=workspace, environment=os.environ)
    require(intent is not None, "intent_unsupported")
    assert intent is not None
    artifact = build_package_request_artifact("hol-guard", intent, config_path="hol-guard.toml", source_scope="project")
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace, now=NOW)
    return result.to_dict(), None


def run(args: argparse.Namespace) -> dict[str, object]:
    if not sys.platform.startswith("linux"):
        raise ValueError("package_matrix_platform_not_qualified")
    root = args.source_root.resolve(strict=True)
    source_before = source_identity(root)
    environment = environment_identity()
    supplied = cast("dict[str, Any]", load_object(args.fixture))
    value = supplied["fixture"]
    case_data = value["case"]
    case = Case(**{key: case_data[key] for key in ("format", "dependencies", "bundle_size", "mode", "route")})
    require(value == fixture(case), "frozen_fixture")
    require(supplied["response"]["bundle"] == value["bundle"], "signed_bundle_fixture")
    report: dict[str, object] = {
        "schema": "hol-guard.package-attempt.v2",
        "case_id": case.id,
        "source": source_before,
        "fixture_sha256": digest(value),
        "signed_response_sha256": digest(supplied["response"]),
        "environment": environment,
        "harness_sha256": harness_identity(_ROOT),
        "measurement": args.measurement,
        "status": "setup_started",
        "installed_artifact": False,
        "cpu_scope": "self_plus_waited_children",
        "native_activation_authorized": False,
        "worker_address_space_limit": 4 * 1024**3,
        "worker_file_size_limit": 64 * 1024**2,
    }
    write_private(args.journal, report, append=True)
    sys.path.insert(0, str(root / "src"))
    from codex_plugin_scanner.guard import local_supply_chain as _local_supply_chain
    from codex_plugin_scanner.guard import store as store_module
    from codex_plugin_scanner.guard.runtime import package_intent_parser as _package_intent_parser
    from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
    from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
        load_supply_chain_bundle_response,
        verify_supply_chain_bundle_response,
    )

    for imported in (store_module, _local_supply_chain, _package_intent_parser):
        assert imported.__file__ is not None
        require(Path(imported.__file__).resolve().is_relative_to(root / "src"), "source_import")
    network_attempts: list[bool] = []

    def no_network(*_args: object, **_kwargs: object) -> Any:
        network_attempts.append(True)
        raise RuntimeError("package_matrix_network_forbidden")

    socket.create_connection = no_network
    socket.socket.connect = no_network
    socket.socket.connect_ex = no_network
    response = load_supply_chain_bundle_response(supplied["response"])
    require(
        len(response.verification_keys) == 1
        and response.verification_keys[0].fingerprint_sha256 == supplied["trusted_fingerprint"],
        "fixture_trust_anchor",
    )
    verify_supply_chain_bundle_response(response, trusted_keys=response.verification_keys, now=NOW_SECONDS)
    profile = cProfile.Profile() if args.measurement == "attribution" else None
    with tempfile.TemporaryDirectory(prefix="package-matrix-", dir=args.temporary_root) as temporary:
        home = Path(temporary)
        workspace = home / "workspace"
        workspace.mkdir()
        guard_home = home / "guard"
        guard_home.mkdir(mode=0o700)
        (guard_home / "config.toml").write_text('security_level = "strict"\n')
        for name, content in value["files"].items():
            (workspace / name).write_bytes(content.encode())
        store = store_module.GuardStore(guard_home)
        store.get_cloud_workspace_id = lambda: WORKSPACE_ID
        store.cache_supply_chain_bundle(WORKSPACE_ID, supplied["response"], NOW)
        # Explicit reset makes this boundary uncached even if setup changes.
        with store._connect() as connection:
            connection.execute("delete from guard_supply_chain_eval_cache")
        write_private(args.journal, {**report, "status": "measurement_started"}, append=True)
        if profile is not None:
            profile.enable()
        cpu_started = _cpu() if args.measurement == "timing" else None
        wall_started = time.perf_counter_ns() if args.measurement == "timing" else None
        evaluation, protection = _run_route(case, value, store, workspace, response)
        wall_ended = time.perf_counter_ns() if args.measurement == "timing" else None
        cpu_ended = _cpu() if args.measurement == "timing" else None
        if profile is not None:
            profile.disable()
        if args.measurement == "timing":
            assert (
                wall_started is not None
                and wall_ended is not None
                and cpu_started is not None
                and cpu_ended is not None
            )
            report.update(wall_ms=(wall_ended - wall_started) / 1_000_000, cpu_ms=(cpu_ended - cpu_started) * 1000)
        write_private(args.journal, {**report, "status": "measurement_finished"}, append=True)
        # Only post-boundary inspection below: output, DB and parse coverage.
        require(not network_attempts, "network_attempted")
        if case.route == "bundle_kernel":
            report.update(validate_kernel(case, evaluation["decisions"]))
        else:
            rows = _evidence(store)
            write_private(args.semantic, {**private_projection(evaluation, rows), "protection": protection})
            report.update(validate_evaluation(case, evaluation, rows))
            report["protect_sha256"] = digest(normalized(protection))
        if value["files"]:
            fmt = FORMAT_BY_NAME[case.format]
            captured = (workspace / fmt.filename).read_bytes()
            require(captured == value["files"][fmt.filename].encode(), "source_changed")
            parsed = evaluator._parse_lockfile_text_result(fmt.filename, captured)
            require(parsed.complete and len(parsed.entries) == case.dependencies, "parser_coverage")
            report.update(
                parser_version=parsed.parser_version,
                entry_sha256=digest([asdict(item) for item in parsed.entries]),
                input_sha256=hashlib.sha256(captured).hexdigest(),
                input_bytes=len(captured),
                entries=len(parsed.entries),
            )
        if profile is not None:
            report["operation_counts"] = _profile_counts(profile)
        require(source_identity(root) == source_before, "source_identity_changed")
        report["status"] = "completed"
        write_private(args.journal, report, append=True)
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--semantic", type=Path, required=True)
    parser.add_argument("--temporary-root", type=Path, required=True)
    parser.add_argument("--measurement", choices=("validation", "timing", "attribution"), required=True)
    args = parser.parse_args()
    if sys.platform.startswith("linux"):
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    try:
        report = run(args)
    except Exception as error:
        report = {
            "schema": "hol-guard.package-attempt.v2",
            "status": "failed",
            "category": type(error).__name__,
            "failure_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
        }
        message = str(error)
        if message.startswith("package_matrix_mismatch:") and message.split(":", 1)[1] in MISMATCH_FIELDS:
            report["mismatch"] = message.split(":", 1)[1]
        write_private(args.journal, report, append=True)
        print(json.dumps(report), flush=True)
        return 1
    print(json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
