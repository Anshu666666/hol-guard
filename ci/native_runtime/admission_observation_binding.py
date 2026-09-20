"""Exact source and installed-artifact guards for the original 400 Windows corpus."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

SOURCE_SHA = "4001185e4f39cad51fd5eab314bf02b86b8a1674"
SOURCE_TREE = "7a328609488ffefecd3cdd12a9c7adba6a591e97"
GUARDS: dict[str, str] = {
    "ci/native_runtime/probe_native_default_auto.py": (
        "552db3dc5699068cd849d4ba9201cc7f5d293ffc6d57ae576d55364f3907e316"
    ),
    "ci/native_runtime/default_auto_routes.py": "7252251bb86cccc89ebe59e8287752a5b1b9cd2165abbcdeff50dff031c26b12",
    "ci/native_runtime/default_auto_failure.py": "fb810dfa664b801305b0989195e55e2f8f615ac3f8813a81ed45066e2358f227",
    "ci/native_runtime/default_auto_startup_failure.py": (
        "cf314a32689b55531ffb5554ac797da6f675ec6f1587ac96e0fd6331df23b176"
    ),
    "ci/native_runtime/installed_hook_client.py": "99b5e18cb50cea08a271c2a1e681fd89f5f7e5aa2c5dd423aabe48be7e710ba1",
    "scripts/native_probe_receipts.py": "deef72aee9b5171d9898d04fc6a8ed393a142464b1a333383511e4c0c4169562",
    "scripts/native_slo_adapter.py": "e76d4e5ee20009a4469911ce398d823cd892f8788e879b4e464cbc5d2a118554",
    "scripts/native_slo_contract.py": "1d49fb3e23a794eab1d2afff02ec39b2b106847ab338836567dea9d560bb473e",
    "docs/guard/contracts/hook-data-plane-ownership.v2.json": (
        "e0ba91cb30398b39424e7cf42fca98704823c6bae4c84f760827728800a0dfa1"
    ),
    "pyproject.toml": "f6538a00756a7604c72127732774267f8549cace4b6b29468a4e6d18fc6511cb",
    "uv.lock": "e3b9190128f06c6743ac3c49446b5d6b312b2ea1d15a7f99f7b83991837b4d78",
    "src/codex_plugin_scanner/guard/daemon/hook_metrics.py": (
        "255407e00d7973d5d87516a51e24060de202ab2d3af62f72138533975bde88cc"
    ),
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_scheduler.py": (
        "bda8332b1bc5664f52d9b030e456c346cd07b37aca7b02d2380aba16ee78dc0e"
    ),
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_scheduler_contracts.py": (
        "c51035aad6664746a18fdb9e98e3628d39cc28bd586e8af01fdd67e1b278d428"
    ),
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_scheduler_types.py": (
        "32f2ccb6c3d17a9dc8c65a3154271f24c2ee12b7e8d81604d5766d4ede7bb44b"
    ),
    "src/codex_plugin_scanner/guard/daemon/server.py": (
        "9cc4cbd5e7506606ccaff1c375a802dfbdb686f72a9a8884839c8fa49f3f4348"
    ),
    "src/codex_plugin_scanner/guard/daemon/server_handler_hook_admission.py": (
        "1136578ff934cbebc76424121ff46008e15b31c0cfdbaca36b74531389204020"
    ),
    "src/codex_plugin_scanner/guard/daemon/server_handler_hook_execution.py": (
        "42ec3cdcd335bb1146ace3fdfb556fa26ea179599301920063446274ab99a3e2"
    ),
    "src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py": (
        "417478d3c6fc7adacaf8207bbd9ef363b7b111f39fb8380ffcc32a4fd439a4f0"
    ),
    "src/codex_plugin_scanner/guard/daemon/hook_worker.py": (
        "cc68db1ab6d11d40f9c0c08781aa61592451997c5c4e8805029450ecee66f786"
    ),
    "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py": (
        "a9c490155992d36830ad839a528cc1323b387b39124887470772e9bfcf044005"
    ),
    "src/codex_plugin_scanner/guard/daemon/hook_worker_responses.py": (
        "29e4b0c00581ee33b4044702580f08789d267287c0e990c5bf79eaa859d72700"
    ),
}


def source_binding(package: Path, fixture: Path) -> list[dict[str, object]]:
    result = []
    for name, wanted in GUARDS.items():
        prefix = "src/codex_plugin_scanner/"
        path = package / name.removeprefix(prefix) if name.startswith(prefix) else fixture / name
        raw = path.read_bytes()
        if hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() != wanted:
            raise RuntimeError("admission_source_bytes_changed")
        result.append(
            {"source": name, "lf_sha256": wanted, "actual_sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        )
        if name.startswith(prefix) and name.endswith(".py"):
            module_name = name.removeprefix("src/").removesuffix(".py").replace("/", ".")
            module = sys.modules.get(module_name)
            if module is not None and Path(str(module.__file__)).resolve() != path.resolve():
                raise RuntimeError("admission_module_origin_changed")
    return result


def installed_origin(package: Path, fixture: Path, prefix: Path) -> None:
    if package.is_relative_to(fixture / "src") or not package.is_relative_to(prefix):
        raise RuntimeError("admission_installed_package_required")


def wheel_binding(wheel: Path, package: Path) -> dict[str, Any]:
    """Join the retained newly built wheel to exact installed native members."""
    if wheel.stat().st_size > 128 * 1024 * 1024:
        raise RuntimeError("admission_wheel_size_invalid")
    raw = wheel.read_bytes()
    members = []
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("admission_wheel_duplicate_members")
        for leaf in ("_native/hol-guard-runtime.exe", "_native/runtime-manifest.json"):
            member = "codex_plugin_scanner/" + leaf
            if archive.getinfo(member).file_size > 64 * 1024 * 1024:
                raise RuntimeError("admission_native_member_size_invalid")
            original = archive.read(member)
            actual = (package / leaf).read_bytes()
            if actual != original:
                raise RuntimeError("admission_installed_member_changed")
            members.append({"member": member, "bytes": len(actual), "sha256": hashlib.sha256(actual).hexdigest()})
        manifest = json.loads((package / "_native/runtime-manifest.json").read_bytes())
        if manifest["source_sha"] != SOURCE_SHA or manifest["target"] != "x86_64-pc-windows-msvc":
            raise RuntimeError("admission_native_build_source_changed")
    return {
        "wheel_name": wheel.name,
        "wheel_bytes": len(raw),
        "wheel_sha256": hashlib.sha256(raw).hexdigest(),
        "native_members": members,
        "build_source": SOURCE_SHA,
        "historical_failed_executable": False,
        "new_isolated_build": True,
    }
