"""Temporary startup observer in one private venv, outside the product roster."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from scripts.ci.cline_witness.process_observation import binding as process_binding

PROFILE_NAME = "_hol_guard_cline_profile"
NESTED_NAME = "_hol_guard_cline_nested_run"
PROCESS_NAME = "_hol_guard_cline_process_observation"
METHOD_NAME = "_hol_guard_cline_methods"
CONFIG_NAME = "_hol_guard_cline_config.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def owned(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("child_observer_path_admission")


def code_frames(path: Path, names: set[str], label: str) -> list[dict[str, Any]]:
    """Bind real Python code identities, including decorators and nested names."""
    body = path.read_bytes()
    if len(body) > 1_048_576:
        raise ValueError("child_observer_source_limit")
    tree = ast.parse(body, filename=str(path))
    rows: list[dict[str, Any]] = []

    def visit(node: ast.AST, prefix: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                if name in names:
                    line = min([child.lineno, *(item.lineno for item in child.decorator_list)])
                    rows.append({"file": str(path), "qualname": name, "line": line, "id": label + ":" + name})
                suffix = "." if isinstance(child, ast.ClassDef) else ".<locals>."
                visit(child, name + suffix)
            else:
                visit(child, prefix)

    visit(tree)
    if {row["qualname"] for row in rows} != names:
        raise ValueError("child_observer_frame_not_found")
    return rows


def bootstrap(config: dict[str, Any], configuration_sha: str, profile_sha: str) -> bytes:
    # Exact generated-worker and nested attested-CLI forms only. The worker
    # records its actual PID before its original body; the CLI checks that
    # observed parent instead of inventing the descendant's PID in the parent.
    text = f'''"""Temporary Cline diagnostic startup; original argv is unchanged."""
import sys as _s
import os as _o
if (_s.executable == {config["executable"]!r}
        and _s.orig_argv in {config["observed_argv"]!r}
        and _s.flags.isolated == 1 and _s.flags.no_user_site == 1):
    try:
        import hashlib as _h
        with open({config["profile_path"]!r}, "rb") as _f:
            _b = _f.read(131073)
        if len(_b) <= 131072 and _h.sha256(_b).hexdigest() == {profile_sha!r}:
            _ns = {{"__name__": {PROFILE_NAME!r}, "__file__": {config["profile_path"]!r}}}
            exec(compile(_b, {config["profile_path"]!r}, "exec"), _ns)
            _ns["activate"]({config["config_path"]!r}, {configuration_sha!r})
    except BaseException:
        pass
'''
    return text.encode("utf-8")


class Installation:
    """Own only new observer files and their exact cache; never touch the wheel."""

    def __init__(self, site: Path, output: Path, config: dict[str, Any]) -> None:
        self.site = site
        self.output = output
        self.config = dict(config)
        self.created: dict[Path, bytes] = {}
        self.cleanup_faults: list[str] = []
        self.manifest: dict[str, Any] = {}
        self.cache_before: set[Path] = set()

    def __enter__(self) -> Installation:
        owned(self.site, directory=True)
        owned(self.output, directory=True)
        if stat.S_IMODE(self.output.stat().st_mode) & 0o077:
            raise ValueError("child_observer_output_not_private")
        for name in (
            "sitecustomize.py",
            "sitecustomize.pyc",
            PROFILE_NAME + ".py",
            NESTED_NAME + ".py",
            PROCESS_NAME + ".py",
            METHOD_NAME + ".py",
            CONFIG_NAME,
        ):
            if (self.site / name).exists() or (self.site / name).is_symlink():
                raise ValueError("child_observer_preexisting_file")
        if list((self.site / "__pycache__").glob("sitecustomize.*")):
            raise ValueError("child_observer_preexisting_cache")
        self.cache_before = set((self.site / "__pycache__").glob("*"))
        config = self.config
        config.update(
            output=str(self.output),
            profile_path=str(self.site / (PROFILE_NAME + ".py")),
            config_path=str(self.site / CONFIG_NAME),
            nested_path=str(self.site / (NESTED_NAME + ".py")),
            process_path=str(self.site / (PROCESS_NAME + ".py")),
            popen_binding=process_binding(),
        )
        nested = Path(__file__).with_name("nested_run.py").read_bytes()
        config["nested_sha256"] = sha(nested)
        process = Path(__file__).with_name("process_observation.py").read_bytes()
        config["process_sha256"] = sha(process)
        data = canonical(config) + b"\n"
        if len(data) > 1_048_576:
            raise ValueError("child_observer_config_limit")
        profile = Path(__file__).with_name("profile_runtime.py").read_bytes()
        images = {
            self.site / (NESTED_NAME + ".py"): nested,
            self.site / (PROCESS_NAME + ".py"): process,
            self.site / (PROFILE_NAME + ".py"): profile,
            self.site / CONFIG_NAME: data,
            self.site / "sitecustomize.py": bootstrap(config, sha(data), sha(profile)),
        }
        if "method_source" in config:
            method = Path(__file__).with_name("method_observation.py").read_bytes()
            config.update(method_path=str(self.site / (METHOD_NAME + ".py")), method_sha256=sha(method))
            data = canonical(config) + b"\n"
            if len(data) > 1_048_576:
                raise ValueError("child_observer_config_limit")
            images[self.site / (METHOD_NAME + ".py")] = method
            images[self.site / CONFIG_NAME] = data
            images[self.site / "sitecustomize.py"] = bootstrap(config, sha(data), sha(profile))
        try:
            for path, body in images.items():
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                # Ownership starts at exclusive creation, including partial writes.
                self.created[path] = body
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(body)
                if path.read_bytes() != body:
                    raise ValueError("child_observer_write_readback")
            self.manifest = {
                "schema": "hol-guard.cline-child-installation.v1",
                "files": {path.name: {"bytes": len(body), "sha256": sha(body)} for path, body in images.items()},
                "configuration_sha256": sha(data),
                "product_distribution_modified": False,
                "diagnostic_sitecustomize_added": True,
            }
            return self
        except BaseException:
            self.close(partial=True)
            raise

    def close(self, *, partial: bool = False) -> None:
        for path, body in tuple(self.created.items())[::-1]:
            try:
                owned(path, directory=False)
                actual = path.read_bytes()
                if actual != body and not (partial and body.startswith(actual)):
                    raise ValueError("child_observer_file_changed")
                path.unlink()
                del self.created[path]
            except BaseException:
                self.cleanup_faults.append("owned_file_cleanup_failed")
        cache = self.site / "__pycache__"
        for path in cache.glob("sitecustomize.*.pyc"):
            if path in self.cache_before:
                self.cleanup_faults.append("unexpected_existing_cache")
                continue
            try:
                owned(path, directory=False)
                # Only the exact cache filename for this interpreter is owned.
                if path != Path(importlib.util.cache_from_source(str(self.site / "sitecustomize.py"))):
                    raise ValueError("child_observer_cache_identity")
                path.unlink()
            except BaseException:
                self.cleanup_faults.append("owned_cache_cleanup_failed")

    def __exit__(self, *_args: object) -> None:
        self.close()


def current_site() -> Path:
    """Admit only this private venv, before any original launcher is offered."""
    import sysconfig
    import threading

    if sys.prefix == sys.base_prefix or sys.getprofile() is not None or threading.getprofile() is not None:
        raise ValueError("child_observer_venv_or_profile_admission")
    if "sitecustomize" in sys.modules or importlib.util.find_spec("sitecustomize") is not None:
        raise ValueError("child_observer_existing_customization")
    path = Path(sysconfig.get_path("purelib"))
    if not path.is_relative_to(Path(sys.prefix)):
        raise ValueError("child_observer_site_outside_venv")
    owned(path, directory=True)
    return path
