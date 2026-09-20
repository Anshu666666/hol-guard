import ast, difflib, hashlib, json, os, pathlib, resource, subprocess, time
root = pathlib.Path("/home/user/pr2974-recovery/windows/reader-format-4d")
assert resource.getrlimit(resource.RLIMIT_AS) == (134217728, 134217728)
os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
rows = json.loads("[{\"path\":\"src/codex_plugin_scanner/guard/windows_replaceable_file.py\",\"bytes\":5222,\"sha256\":\"d2026abc09b502db0b85403906f96316a1c07908ade4ff8bf18c4843044bad29\"},{\"path\":\"src/codex_plugin_scanner/guard/private_file_io.py\",\"bytes\":5059,\"sha256\":\"222fa0aa777f7826cef9b1f683fc9a3e05dd5cb70ac5e77d9eda82e100b6fbda\"},{\"path\":\"src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py\",\"bytes\":9539,\"sha256\":\"f989759d4c231a8a4800e4505dce48e7eea4bdefab821817cd7260516da21876\"},{\"path\":\"tests/test_windows_replaceable_file.py\",\"bytes\":9171,\"sha256\":\"6f77b3ed8bc683ce52f9f950ea6266da10d1aeac6d45d4316ae20b03adcfdf04\"},{\"path\":\"tests/test_private_reader_descriptor_guards.py\",\"bytes\":4597,\"sha256\":\"182650180dd3dd4cf3450de915e52d7013e9a3894bdb2708e850634fa78a5ef7\"},{\"path\":\"ci/native_runtime/windows_replaceable_reader_child.py\",\"bytes\":6558,\"sha256\":\"d2c668f1e895e71613a4b7b5082bf27036ec5fb8e20b919a299e589b9fd8f984\"},{\"path\":\"tests/test_windows_replaceable_reader_process.py\",\"bytes\":8546,\"sha256\":\"b819964e219fe58491ca69843eac10cbc8832bb131d932d565cffdfbd687dbff\"}]")
for row in rows:
    for prefix in ("before", "after"):
        data = (root / prefix / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
environment = dict(os.environ)
environment["RAYON_NUM_THREADSS"] = "1"
environment["RAYON_NUM_THREADS"] = "1"
arguments = [str(root / "ruff"), "format", "--no-cache", "--config", str(root / "pyproject.toml")] + [str(root / "after" / row["path"]) for row in rows]
started = time.monotonic()
result = subprocess.run(arguments, capture_output=True, text=True, timeout=30, env=environment, cwd=root)
elapsed = time.monotonic() - started
(root / "formatter.stdout").write_text(result.stdout)
(root / "formatter.stderr").write_text(result.stderr)
output_rows = []
diffs = []
for row in rows:
    before = (root / "before" / row["path"]).read_bytes()
    after = (root / "after" / row["path"]).read_bytes()
    assert len(before) == row["bytes"] and hashlib.sha256(before).hexdigest() == row["sha256"]
    old_ast = ast.dump(ast.parse(before, filename=row["path"]), include_attributes=False)
    new_ast = ast.dump(ast.parse(after, filename=row["path"]), include_attributes=False)
    same = old_ast == new_ast
    output_rows.append({**row, "after_bytes": len(after), "after_sha256": hashlib.sha256(after).hexdigest(), "after_physical_lines": len(after.splitlines()), "ast_equal": same, "ast_sha256": hashlib.sha256(old_ast.encode()).hexdigest()})
    diffs.extend(difflib.unified_diff(before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True), fromfile="before/" + row["path"], tofile="after/" + row["path"]))
report = {"status": "formatting_preparation_only", "base_source": "4d10758e2cb44e5afa72a08aa631a02541dad534", "original_candidate_tree": "ad4459353855f6be90fa9cd8f0e8f3f8ff0f4dcb", "formatter_returncode": result.returncode, "formatter_stdout": result.stdout, "formatter_stderr": result.stderr, "elapsed_seconds": elapsed, "argv": arguments, "rlimit_as": list(resource.getrlimit(resource.RLIMIT_AS)), "python_ast_version": "3.13.13", "ast_comparison": "ast.dump(include_attributes=False); no source import", "all_ast_equal": all(row["ast_equal"] for row in output_rows), "all_changed_code_under_500_lines": all(row["after_physical_lines"] <= 500 for row in output_rows), "source_tests_executed": False, "native_build_executed": False, "python_3_12_validation_executed": False, "lint_executed": False, "types_executed": False, "unresolved_source_peer_blocker": "Bounded-reader CRT O_BINARY translation differs from the original os.open flags; separate reviewed repair required before candidate readiness.", "files": output_rows}
(root / "formatter.diff").write_text("".join(diffs))
(root / "format-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, sort_keys=True))
assert result.returncode == 0 and report["all_ast_equal"] and report["all_changed_code_under_500_lines"]
