"""Literal defaults remain source-bound while constructor I/O stays reachable."""

from pathlib import Path

import pytest

from scripts.ci import rust_io_ownership_gate as gate


def write(root, name, source):
    relative = f"src/codex_plugin_scanner/guard/{name}.py"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return relative


def records(root, monkeypatch, source):
    write(root, "leaf", source)
    path = write(root, "caller", "from .leaf import Record\ndef entry(): return Record()\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    return gate._reachable_records(root, gate._function_map(root))


def test_actual_guard_config_with_source_bound_imported_literal_defaults(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    for name in ("config", "presentation_mode", "protection_posture"):
        write(tmp_path, name, (root / f"src/codex_plugin_scanner/guard/{name}.py").read_text())
    path = write(tmp_path, "caller", "from .config import GuardConfig\ndef entry(): return GuardConfig()\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    assert any(item.qualname == "GuardConfig.<constructor>" for item in found)


@pytest.mark.parametrize(
    "declaration,default",
    [
        ("DEFAULT = 'literal'\n", "DEFAULT"),
        ("DEFAULT: str = 'literal'\nALIAS = DEFAULT\n", "ALIAS"),
        ("from .constants import VALUE as DEFAULT\n", "DEFAULT"),
        ("from .exports import ALIAS as DEFAULT\n", "DEFAULT"),
        ("from . import constants as values\n", "values.VALUE"),
        ("", "128 * 1024 * 1024"),
        ("", "frozenset()"),
        ("", "frozenset({'command', 'script'})"),
    ],
)
def test_proven_literal_default_never_hides_post_init_io(tmp_path, monkeypatch, declaration, default):
    write(tmp_path, "constants", "VALUE = 'literal'\n")
    write(tmp_path, "exports", "from .constants import VALUE as ALIAS\n")
    source = (
        "from dataclasses import dataclass\n" + declaration + "@dataclass\nclass Record:\n"
        "    value: object = " + default + "\n    def __post_init__(self): open('secret')\n"
    )
    found = records(tmp_path, monkeypatch, source)
    assert any(o.operation == "open" for item in found for o in gate._observations(item))


@pytest.mark.parametrize(
    "declaration,default",
    [
        ("DEFAULT = Descriptor()\n", "DEFAULT"),
        ("DEFAULT = 'literal'\nDEFAULT = unknown\n", "DEFAULT"),
        ("if condition:\n    DEFAULT = 'literal'\n", "DEFAULT"),
        ("from .constants import VALUE as DEFAULT\n", "DEFAULT"),
        ("DEFAULT = LATER\nLATER = 'literal'\n", "DEFAULT"),
        ("DEFAULT = OTHER\nOTHER = DEFAULT\n", "DEFAULT"),
        ("frozenset = unknown\n", "frozenset()"),
        ("", "frozenset(unknown)"),
        ("", "unknown()"),
        ("", "UnknownEnum.VALUE"),
    ],
)
def test_unproven_default_cannot_hide_descriptor_or_dynamic_authority(tmp_path, monkeypatch, declaration, default):
    write(tmp_path, "constants", "VALUE = Descriptor()\n")
    source = (
        "from dataclasses import dataclass\n"
        + declaration
        + "@dataclass\nclass Record:\n    value: object = "
        + default
        + "\n"
    )
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        records(tmp_path, monkeypatch, source)


def test_class_shadow_of_imported_literal_remains_refused(tmp_path, monkeypatch):
    source = """from dataclasses import dataclass
DEFAULT = "literal"
@dataclass
class Record:
    def DEFAULT(): return open("secret")
    value: object = DEFAULT
"""
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        records(tmp_path, monkeypatch, source)


def test_long_reexport_chain_exhausts_shared_proof_budget(tmp_path, monkeypatch):
    for index in range(140):
        write(tmp_path, f"chain{index}", f"from .chain{index + 1} import VALUE\n")
    write(tmp_path, "chain140", "VALUE = 1\n")
    source = """from dataclasses import dataclass
from .chain0 import VALUE
@dataclass
class Record:
    value: int = VALUE
"""
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        records(tmp_path, monkeypatch, source)
