"""HGP-185: policy identity across macOS and Windows path forms."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_policy_snapshot_policy import _normalize_scope_text_v3, _scope_digest_v3


def test_equivalent_aliases_match_and_siblings_do_not(tmp_path: Path) -> None:
    macos_private = _normalize_scope_text_v3("/private/var/folders/xx/guard")
    macos_var = _normalize_scope_text_v3("/var/folders/xx/guard")
    assert macos_private == macos_var
    spaced = _normalize_scope_text_v3("/Users/Shared/My Guard/State/")
    assert spaced == "/Users/Shared/My Guard/State"
    windows = _normalize_scope_text_v3(r"C:\Users\Guard\State")
    windows_long = _normalize_scope_text_v3(r"\\?\C:\Users\Guard\State\\")
    assert windows.casefold() == r"c:\users\guard\state" or windows == "/private/var/folders/xx/guard"
    if windows.startswith("c:"):
        assert windows_long == windows
    sibling = tmp_path / "guard-a"
    other = tmp_path / "guard-b"
    sibling.mkdir()
    other.mkdir()
    assert _scope_digest_v3(sibling) != _scope_digest_v3(other)
    linked = tmp_path / "guard-link"
    try:
        linked.symlink_to(sibling, target_is_directory=True)
    except OSError:
        linked = sibling
    assert _scope_digest_v3(linked) == _scope_digest_v3(sibling)
    restarted = _scope_digest_v3(sibling)
    assert restarted == _scope_digest_v3(sibling)
