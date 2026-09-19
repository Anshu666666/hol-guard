"""Source preservation, admission and collector accounting; no hosted timing claims."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import shlex
import sys

import pytest

from scripts.ci import native_macos_dnssd_python_path as collector
from tests.test_native_macos_dnssd_python import BRIDGE, RUNTIME, records, wire


def reports(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    base = collector.original._base()
    source = {
        "head": "a" * 40,
        "sha256": {str(collector.CHILD.relative_to(collector.original.ROOT)): RUNTIME["dnssd_child_source_sha256"]},
    }
    tools = {"python_sha256": RUNTIME["python_sha256"], "python_socket_module_sha256": RUNTIME["socket_sha256"]}
    prepared = base | {"status": "prepared", "source": source, "tools": tools}
    prior = base | {
        "status": "experiment_finished",
        "stage": "complete",
        "source_before": source,
        "tools_before": tools,
        "source_unchanged": True,
        "tools_unchanged": True,
        "binary_unchanged": True,
        "rows": [
            {"mode": mode, "capture": {"pid": 100 + i, "direct_child_reaped": True}, "lookup_passed": False}
            for i, mode in enumerate(collector.original.MODES)
        ],
    }
    current = base | {
        "status": "experiment_finished",
        "stage": "complete",
        "source_before": source,
        "tools_before": tools,
        "source_unchanged": True,
        "tools_unchanged": True,
        "runtime_unchanged": True,
        "bridge_unchanged": True,
        "original_report_unchanged": True,
        "original_report_sha256": "f" * 64,
        "loaded_images_consistent": False,
        "runtime_before": {k: v for k, v in RUNTIME.items() if k != "dnssd_child_source_sha256"},
        "rows": [
            {"mode": mode, "capture": {"pid": 200 + i, "direct_child_reaped": True}, "lookup_passed": False}
            for i, mode in enumerate(collector.PREVIOUS_MODES)
        ],
    }
    return prepared, prior, current


def test_failed_prior_lookups_can_only_admit_when_bound_and_retired(monkeypatch):
    prepared, prior, current = reports(monkeypatch)
    assert collector.previous_admission(prepared, prior, current, "f" * 64) is None
    assert not current["diagnostic_passed"] and not prior["diagnostic_passed"]
    assert not current["loaded_images_consistent"]


@pytest.mark.parametrize(
    "target,key,value",
    [
        ("current", "workflow_commit", "b" * 40),
        ("current", "workflow_run", "456"),
        ("current", "workflow_attempt", "2"),
        ("current", "source_before", {}),
        ("current", "tools_before", {}),
        ("current", "original_report_sha256", "a" * 64),
        ("current", "status", "diagnostic_failed"),
        ("current", "stage", "additional_controls"),
        ("current", "source_unchanged", False),
        ("current", "tools_unchanged", False),
        ("current", "runtime_unchanged", False),
        ("current", "bridge_unchanged", False),
        ("current", "original_report_unchanged", False),
        ("current", "rows", []),
        ("prior", "binary_unchanged", False),
        ("prior", "stage", "additional_controls"),
    ],
)
def test_mismatched_or_incomplete_previous_evidence_is_refused(monkeypatch, target, key, value):
    prepared, prior, current = reports(monkeypatch)
    assert collector.previous_admission(prepared, prior, current, "f" * 64) is None
    (prior if target == "prior" else current)[key] = value
    assert collector.previous_admission(prepared, prior, current, "f" * 64) is not None


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("mutation", [{"pid": True}, {"pid": 0}, {"direct_child_reaped": False}])
def test_every_previous_child_requires_its_own_valid_retirement(monkeypatch, index, mutation):
    prepared, prior, current = reports(monkeypatch)
    assert collector.previous_admission(prepared, prior, current, "f" * 64) is None
    current["rows"][index]["capture"].update(mutation)
    assert collector.previous_admission(prepared, prior, current, "f" * 64) == "previous_child_retirement_unproved"


def bound_collector(monkeypatch):
    prepared, prior, current = reports(monkeypatch)
    monkeypatch.setattr(collector.original, "_eligible", lambda: True)
    monkeypatch.setattr(collector.original, "source_identity", lambda: prepared["source"])
    monkeypatch.setattr(collector.original, "tool_identity", lambda: prepared["tools"])
    monkeypatch.setattr(collector, "runtime_identity", lambda: RUNTIME)
    monkeypatch.setattr(collector, "bridge_identity", lambda _: BRIDGE)
    return prepared, prior, current


def capture(success=True, reaped=True):
    return {
        "pid": 123,
        "status": "completed" if success else "deadline_exceeded",
        "return_code": 0 if success else -9,
        "direct_child_reaped": reaped,
        "termination_attempted": not success,
        "stderr_bytes": 0,
    }


def test_real_collection_forwards_exact_two_modes_and_preserves_failed_prefix(monkeypatch, tmp_path):
    prepared, _, current = bound_collector(monkeypatch)
    calls, saved = [], []

    def lookup(argv):
        calls.append(argv)
        mode = argv[argv.index("--mode") + 1]
        return (capture(False), wire(records(mode)[:7])) if mode == "dns_simple" else (capture(), wire(records(mode)))

    monkeypatch.setattr(collector, "run_lookup", lookup)
    bridge = tmp_path / "bridge"
    report = collector.collect(prepared, bridge, current, lambda r: saved.append(copy.deepcopy(r)))
    assert len(calls) == 2
    for argv, mode in zip(calls, collector.MODES, strict=True):
        assert argv == (
            sys.executable,
            "-I",
            str(collector.CHILD),
            "--mode",
            mode,
            "--bridge",
            str(bridge),
            "--bridge-sha256",
            BRIDGE["sha256"],
        )
    assert report["status"] == "experiment_finished" and not report["diagnostic_passed"]
    assert [row["lookup_passed"] for row in report["rows"]] == [False, True]
    assert report["rows"][0]["metadata"]["valid"] and not report["rows"][0]["metadata"]["complete"]
    assert not report["loaded_images_consistent"] and len(saved) == 3


def test_unreaped_child_stops_without_evaluating_suffix(monkeypatch, tmp_path):
    prepared, _, current = bound_collector(monkeypatch)
    calls = []
    monkeypatch.setattr(
        collector, "run_lookup", lambda argv: (calls.append(argv) or capture(False, False), wire(records()[:5]))
    )
    report = collector.collect(prepared, tmp_path / "bridge", current, lambda _: None)
    assert len(calls) == 1 and len(report["rows"]) == 1
    assert report["status"] == "direct_child_cleanup_unproved" and not report["diagnostic_passed"]


def test_success_needs_both_actual_bound_sequences(monkeypatch, tmp_path):
    prepared, _, current = bound_collector(monkeypatch)
    monkeypatch.setattr(
        collector, "run_lookup", lambda argv: (capture(), wire(records(argv[argv.index("--mode") + 1])))
    )
    report = collector.collect(prepared, tmp_path / "bridge", current, lambda _: None)
    assert report["diagnostic_passed"] and report["loaded_images_consistent"] and not report["qualification_pass"]


@pytest.mark.parametrize("binding", ["source_identity", "tool_identity", "runtime_identity", "bridge_identity"])
def test_final_identity_change_cannot_pass(monkeypatch, tmp_path, binding):
    prepared, _, current = bound_collector(monkeypatch)
    monkeypatch.setattr(
        collector, "run_lookup", lambda argv: (capture(), wire(records(argv[argv.index("--mode") + 1])))
    )
    owner = collector.original if binding in {"source_identity", "tool_identity"} else collector
    real = getattr(owner, binding)
    count = []

    def changed(*args):
        count.append(True)
        return real(*args) if len(count) == 1 else {}

    monkeypatch.setattr(owner, binding, changed)
    report = collector.collect(prepared, tmp_path / "bridge", current, lambda _: None)
    assert not report["diagnostic_passed"]


def test_actual_cli_admission_keeps_failed_previous_results(tmp_path, monkeypatch):
    prepared, prior, current = reports(monkeypatch)
    prior_path = tmp_path / "original.json"
    prior_path.write_text(json.dumps(prior))
    current["original_report_sha256"] = hashlib.sha256(prior_path.read_bytes()).hexdigest()
    prepared_path = tmp_path / "prepared.json"
    prepared_path.write_text(json.dumps(prepared))
    current_path = tmp_path / "python.json"
    current_path.write_text(json.dumps(current))
    output = tmp_path / "admission.json"
    monkeypatch.setattr(collector.original, "_eligible", lambda: True)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collector",
            "--prepared",
            str(prepared_path),
            "--original-report",
            str(prior_path),
            "--python-report",
            str(current_path),
            "--output",
            str(output),
            "--admit-previous",
        ],
    )
    assert collector.main() == 0
    report = json.loads(output.read_bytes())
    assert report["status"] == "admitted" and not report["qualification_pass"]
    assert report["python_report_sha256"] == hashlib.sha256(current_path.read_bytes()).hexdigest()
    assert not json.loads(current_path.read_bytes())["diagnostic_passed"]
    current["rows"][3]["capture"]["direct_child_reaped"] = False
    current_path.write_text(json.dumps(current))
    assert collector.main() == 1
    assert json.loads(output.read_bytes())["reason"] == "previous_child_retirement_unproved"


def test_workflow_preserves_bounds_and_compile_arguments():
    root = collector.original.ROOT
    workflow = (root / ".github/workflows/native-macos-resolver-path.yml").read_text()
    assert "timeout-minutes: 8" in workflow and "cancel-in-progress: false" in workflow
    start = workflow.index("scripts/ci/native_macos_dnssd_python_bridge.c")
    command_start = workflow.rfind("/usr/bin/xcrun", 0, start)
    command_end = workflow.index("\n      - name:", start)
    tokens = shlex.split(workflow[command_start:command_end].replace("\\\n", " "))
    assert tokens[:4] == ["/usr/bin/xcrun", "--sdk", "macosx", "clang"]
    assert tokens[4:10] == list(collector.BRIDGE_FLAGS)
    assert tokens[10:] == [
        "scripts/ci/native_macos_dnssd_python_bridge.c",
        "-o",
        "$RUNNER_TEMP/macos-resolver-path-build/dnssd-bridge.dylib",
        ">",
        "$RUNNER_TEMP/macos-resolver-path-build/dnssd-bridge.stdout",
        "2>",
        "$RUNNER_TEMP/macos-resolver-path-build/dnssd-bridge.stderr",
    ]
    assert (
        workflow.index("id: python_lookups")
        < workflow.index("id: dnssd_admission")
        < workflow.index("id: dnssd_bridge")
        < workflow.index("id: dnssd_lookups")
    )
    for name in (
        "scripts/__init__.py",
        "scripts/ci/__init__.py",
        "scripts/ci/native_macos_dnssd_python_child.py",
        "scripts/ci/native_macos_dnssd_python_evidence.py",
        "scripts/ci/native_macos_dnssd_python_path.py",
        "scripts/ci/native_macos_dnssd_python_bridge.c",
        "tests/test_native_macos_dnssd_python.py",
        "tests/test_native_macos_dnssd_python_path.py",
    ):
        assert name in collector.original.SOURCES
    tree = ast.parse((root / "scripts/ci/native_macos_dnssd_python_child.py").read_text())
    assert any(isinstance(n, ast.Attribute) and n.attr == "CDLL" for n in ast.walk(tree))
    assert not any(
        isinstance(n, ast.Attribute) and n.attr in {"PyDLL", "Thread", "fork", "Popen"} for n in ast.walk(tree)
    )


ORIGINAL_PINS = dict(
    [
        (
            "scripts/ci/native_macos_resolver_probe.c",
            "e63cb7724237e94ad130c0a65d0144b60a1a6bbb6e67f7fa89964aa42fd39cfe",
        ),
        (
            "scripts/ci/native_macos_resolver_capture.py",
            "6e230917586b746dd91b9f6f1be522ee15f163500077ca64bf03a11b9589bbb9",
        ),
        (
            "scripts/ci/native_macos_resolver_evidence.py",
            "0fe548288ec83334486f6b13316fab6dd1f24619585bf051e2f08bd7bdfee8a2",
        ),
        (
            "scripts/ci/native_macos_resolver_tool_capture.py",
            "f840e7307366032c645ab56ede14933e72d26150cf1e4c36aee6734efe90dd2f",
        ),
        (
            "scripts/ci/native_macos_service_identity.py",
            "965bfd5f7495986612a01c20e7d61597ac255271b1c4d2640948422ed0dd24a8",
        ),
        (
            "scripts/ci/native_macos_python_resolver_bridge.c",
            "5110383fd4dc4f0c0c5674b448ec164e5a5579e401402f24a3a1b7cf71ee2fa0",
        ),
        (
            "scripts/ci/native_macos_python_resolver_child.py",
            "07aed31b0122812327b555c573080f072bfd3c78989572192b1586ce058777a1",
        ),
        (
            "scripts/ci/native_macos_python_resolver_evidence.py",
            "14c32d421fde7999d3c23dcf178eed1811d5f699161ea33c67a63cb59f91654b",
        ),
        (
            "scripts/ci/native_macos_python_resolver_path.py",
            "5e17d78ea0f070fd81ca78bd3675dd5a3cdfe24a1b4451223e2550549ddb6bc4",
        ),
        (
            "tests/test_native_macos_python_resolver.py",
            "2af41807ec6d4fcf2a6bafb98b079672c1c59a2c70dbe16f1294a91a777241a1",
        ),
        (
            "tests/test_native_macos_python_resolver_binding.py",
            "d23c4daad9217e79728fb348bfc2dc2caa5ca191a04992e0e250818269e77d1b",
        ),
        (
            "tests/test_native_macos_resolver_capture.py",
            "69c3917fb86b38681c6fc0c3e4e2aee4b5587aca4e01db0513cb019c8b4bc128",
        ),
        (
            "tests/test_native_macos_resolver_evidence.py",
            "e2f143816e170d01fd89a1fec25483d73e7d85d054c5d63571eac9207d95d573",
        ),
        (
            "tests/test_native_macos_resolver_path.py",
            "2982578cc4ce35af7da13035fcaf8331160106607738446310f795ffc637e5ab",
        ),
        (
            "tests/test_native_macos_resolver_tool_capture.py",
            "82e32e929af031124b2ea51bfaac330e5f981e8fbd7cab65651322e7363519f9",
        ),
    ]
)


@pytest.mark.parametrize("name,expected", ORIGINAL_PINS.items())
def test_all_previous_implementation_and_control_bytes_remain_exact(name, expected):
    assert hashlib.sha256((collector.original.ROOT / name).read_bytes()).hexdigest() == expected


def test_original_driver_only_expands_its_source_manifest():
    tree = ast.parse((collector.original.ROOT / "scripts/ci/native_macos_resolver_path.py").read_bytes())
    tree.body = [
        node
        for node in tree.body
        if not (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SOURCES" for target in node.targets)
        )
    ]
    assert (
        hashlib.sha256(ast.dump(tree).encode()).hexdigest()
        == "e317f6518d4798d8ea1b84858960dd0af1ecee69f6f3d57f3476e2657b5e2048"
    )


def test_separate_bridge_invokes_original_dns_modes_only():
    source = (collector.original.ROOT / "scripts/ci/native_macos_dnssd_python_bridge.c").read_text()
    assert '#include "native_macos_python_resolver_bridge.c"' in source
    assert "if (operation > 1) return 64;" in source
    assert 'operation ? "dns_shared" : "dns_simple"' in source
    assert "return hol_guard_original_resolver_main(2, arguments);" in source
