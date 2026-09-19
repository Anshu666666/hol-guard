"""Verify only the two observed StoreBase lint corrections against exact prior bytes."""
from __future__ import annotations

import ast
import hashlib

RULES = {
    "src/codex_plugin_scanner/guard/store_base_keyring.py": {
        "before": "        if _base.sys.platform == \"darwin\" and not cls._macos_default_keychain_is_usable():\n",
        "after": "        if _base.sys.platform == \"darwin\" and not cls._macos_default_keychain_is_usable():  # noqa: SIM103\n"
    },
    "tests/test_guard_store_base_partition.py": {
        "before": "from codex_plugin_scanner.guard import store_base as base\nfrom codex_plugin_scanner.guard import store_base_chunks, store_base_keyring\nfrom codex_plugin_scanner.guard import store_base_secret_backends, store_base_secret_files\n",
        "after": "from codex_plugin_scanner.guard import store_base as base\nfrom codex_plugin_scanner.guard import (\n    store_base_chunks,\n    store_base_keyring,\n    store_base_secret_backends,\n    store_base_secret_files,\n)\n"
    }
}
KEYRING = "src/codex_plugin_scanner/guard/store_base_keyring.py"
TEST = "tests/test_guard_store_base_partition.py"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def grouped_test_imports(tree):
    body = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "codex_plugin_scanner.guard":
            for alias in node.names:
                body.append(ast.ImportFrom(module=node.module, names=[alias], level=node.level))
        else:
            body.append(node)
    tree.body = body
    return ast.dump(tree, include_attributes=False)


def verify_corrections(config, source, packet):
    assert set(RULES) == {KEYRING, TEST}
    assert set(packet["files"]) == set(config["partition_input_files"])
    restored = {}
    records = []
    for relative, prior in packet["files"].items():
        current = (source / relative).read_bytes()
        expected = config["partition_input_files"][relative]
        assert len(current) == expected["bytes"] and expected["mode"] == "100644", relative
        assert digest(current) == expected["sha256"] and git_blob(current) == expected["git_blob"], relative
        original = prior["content"].encode("utf-8")
        assert digest(original) == prior["sha256"] and git_blob(original) == prior["git_blob"], relative
        inverse = current
        if relative in RULES:
            rule = RULES[relative]
            after, before = rule["after"].encode("utf-8"), rule["before"].encode("utf-8")
            assert current.count(after) == 1 and original.count(before) == 1, relative
            inverse = current.replace(after, before, 1)
        assert inverse == original, relative
        old_tree = ast.parse(original.decode("utf-8"), filename=relative, type_comments=True)
        new_tree = ast.parse(current.decode("utf-8"), filename=relative, type_comments=True)
        if relative == TEST:
            assert grouped_test_imports(old_tree) == grouped_test_imports(new_tree), relative
        else:
            assert ast.dump(old_tree, include_attributes=False) == ast.dump(new_tree, include_attributes=False), relative
        assert len(current.splitlines()) <= 500, relative
        restored[relative] = inverse
        records.append({
            "path": relative, "corrected": relative in RULES,
            "prior_formatted_sha256": prior["sha256"], "current_source_sha256": digest(current),
            "inverse_reconstructed_sha256": digest(inverse), "current_source_bytes": len(current),
            "current_source_physical_lines": len(current.splitlines()),
            "whole_file_inverse_exact": True,
            "full_ast_equal_with_only_exact_test_import_grouping_normalized": True,
        })
    return restored, records
