import resource
resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
import base64, csv, hashlib, io, json, pathlib, subprocess, zipfile
root = pathlib.Path(__file__).parent
repo = pathlib.Path('/workspace/scratch/745337b67ff9/hol-guard')
source = 'e44008445630aad28ccc291ec234f55a14892e6d'
build = '07ae77b50b6c98e844403c2ee3f4447f7958ebe4'
tree = 'addf0c1daf8ceb6313d6805ee4d05e216d6fdac8'
def git(*args):
    return subprocess.check_output(['git', '-C', str(repo), *args], timeout=30)
for commit in (source, build):
    assert git('rev-parse', commit + '^{tree}').decode().strip() == tree
inventory = {}
for row in git('ls-tree', '-rz', source, 'src/codex_plugin_scanner').split(b'\0'):
    if not row:
        continue
    meta, path = row.split(b'\t', 1)
    if path.endswith(b'.py'):
        inventory[path.decode()[4:]] = meta.split()[2].decode()
import tomllib
config = tomllib.loads(git('show', source + ':pyproject.toml').decode())
excluded = 'src/codex_plugin_scanner/guard/native_runtime_resident.py'
assert excluded in config['tool']['hatch']['build']['exclude']
expected = {n: h for n, h in inventory.items() if n != excluded[4:]}
results = []
for wheel in sorted(root.glob('*/raw/**/*.whl')):
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and len(names) < 4096
        assert sum(i.file_size for i in z.infolist()) < 100 * 1024 * 1024
        rec = [n for n in names if n.endswith('.dist-info/RECORD')]
        assert len(rec) == 1
        rows = list(csv.reader(io.StringIO(z.read(rec[0]).decode())))
        assert len({r[0] for r in rows}) == len(rows) and {r[0] for r in rows} == set(names)
        for n, h, s in rows:
            payload = z.read(n)
            if n == rec[0]:
                assert not h and not s
            else:
                assert h == 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip('=')
                assert int(s) == len(payload)
        py = {n for n in names if n.startswith('codex_plugin_scanner/') and n.endswith('.py')}
        assert py == set(expected)
        for n in py:
            b = z.read(n)
            assert hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest() == expected[n]
        result = {'path': str(wheel.resolve()), 'bytes': wheel.stat().st_size, 'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(), 'record_entries_verified': len(rows), 'packaged_python_bytes_match_source': len(py), 'configured_legacy_exclusion': excluded}
        manifest_path = 'codex_plugin_scanner/_native/runtime-manifest.json'
        if manifest_path in names:
            m = json.loads(z.read(manifest_path))
            runtime_path = 'codex_plugin_scanner/_native/hol-guard-runtime'
            b = z.read(runtime_path)
            assert m['source_sha'] == build and m['runtime_size'] == len(b) and m['runtime_sha256'] == hashlib.sha256(b).hexdigest()
            result['runtime_manifest'] = m
            result['runtime_bytes_verified'] = True
        results.append(result)
out = {'source_sha': source, 'build_sha': build, 'same_tree': tree, 'source_python_paths': len(inventory), 'wheels': results, 'scope': 'data-only wheel RECORD, exact packaged Python Git blob and native-runtime hash verification; no installation or execution'}
(root / 'wheel-verification.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out))
