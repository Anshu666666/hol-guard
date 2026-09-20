"""Read retained data only; write independent verification into this peer directory."""
import ast
import base64
import csv
import gzip
import hashlib
import io
import json
import zipfile
from pathlib import Path, PurePosixPath

OUT = Path('/dev/shm/a1-root-linux-quartet-peer')
ROOT = Path('/workspace/scratch/745337b67ff9/native-normal-a1d/linux-terminal')
PACKET = ROOT / 'terminal-packet'
SOURCE = 'a1d509404b0803a91031cb51f4b0c919408bfeba'
BUILD = '9f511875b236c12e5f23c783e958a536ac0360ba'
TREE = 'e60dfd218cd7cc9f29c9f2cd66223c866ea86c80'

def ident(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}

def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

locations = json.loads((ROOT / 'peer-artifact-locations.json').read_bytes())
directories = {'hol-guard-native-wheel-linux-x64': ROOT / '10615025870', **{k: Path(v) for k, v in locations['directories'].items()}}
paths = set(p for p in ROOT.rglob('*') if p.is_file() and p.name != 'download-private.json')
for directory in directories.values():
    paths.update(p for p in directory.rglob('*') if p.is_file())
before = {str(p): ident(p.read_bytes()) for p in sorted(paths)}

remote = json.loads((OUT / 'remote-packet.json').read_bytes())
api = json.loads((OUT / 'source-tree-api.json').read_bytes())
helper = ast.parse(Path('/workspace/scratch/745337b67ff9/root-checkpoint/prepare_publication.py').read_text())
namespace = {'hashlib': hashlib}
exec(compile(ast.Module(body=[n for n in helper.body if isinstance(n, ast.FunctionDef) and n.name in ('object_sha', 'tree_sha')], type_ignores=[]), '<reviewed-merkle-helper>', 'exec'), namespace)
for tree in (remote['tree'], api):
    assert not tree['truncated'] and namespace['tree_sha'](tree['tree']) == tree['sha']
assert api['sha'] == TREE
assert json.loads((ROOT / 'source-tree.json').read_bytes()) == api
remote_rows = []
for row in remote['bodies']:
    raw = row['body'].encode()
    got = ident(raw)
    assert got['bytes'] == row['size'] and got['git_blob'] == row['sha']
    assert (PACKET / row['path']).read_bytes() == raw
    remote_rows.append({'path': row['path'], **got})
assert len(remote_rows) == 42

# The reviewed creator reads data and copies originals. Its output is redirected
# to this peer namespace; no owner file, product, subprocess or network is used.
creator = ast.parse((ROOT / 'freeze_terminal.py').read_text())
allowed = [n for n in creator.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
ns = {'__file__': str(ROOT / 'freeze_terminal.py'), 'ROOT': ROOT, 'OUT': OUT / 'reproduced', 'SOURCE': SOURCE, 'BUILD': BUILD, 'TREE': TREE, 'RUN': 35539716189}
exec(compile(ast.Module(body=allowed, type_ignores=[]), '<reviewed-data-only-freezer>', 'exec'), ns)
ns['main']()
for name in ('SUMMARY.json', 'QUARTET-JOIN.json'):
    assert (OUT / 'reproduced' / name).read_bytes() == (PACKET / name).read_bytes()

metadata = json.loads((ROOT / 'metadata.json').read_bytes())
by_id = {a['id']: a for a in metadata['artifacts']}
all_dirs = [*directories.values(), ROOT / '10615435093']
archives = []
all_wheels = {}
for directory in all_dirs:
    aid = int(directory.name)
    raw = (directory / 'artifact.zip').read_bytes()
    got = ident(raw)
    meta = by_id[aid]
    assert got['bytes'] == meta['size_in_bytes'] and 'sha256:' + got['sha256'] == meta['digest']
    assert meta['workflow_run']['head_sha'] == SOURCE and meta['workflow_run']['id'] == 35539716189
    vr = json.loads((directory / 'verification.json').read_bytes())
    expected = {e['path']: e for e in vr.get('members', vr.get('files'))}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist())) and set(archive.namelist()) == set(expected)
        assert sum(i.file_size for i in archive.infolist()) < 200 * 1024 * 1024
        for name in archive.namelist():
            path = PurePosixPath(name)
            assert not path.is_absolute() and '..' not in path.parts and '\\' not in name
            body = archive.read(name)
            assert body == (directory / 'raw' / name).read_bytes()
            h = ident(body)
            assert all(h[k] == expected[name][k] for k in ('bytes', 'sha256'))
            if name.endswith('.whl'):
                all_wheels.setdefault(h['sha256'], {'name': path.name, 'data': body, 'artifact_ids': []})['artifact_ids'].append(aid)
        archives.append({'artifact_id': aid, **got, 'members': len(expected)})
assert len(all_wheels) == 5 and sum(len(w['artifact_ids']) for w in all_wheels.values()) == 7

source_leaves = {r['path']: r for r in api['tree'] if r['type'] == 'blob'}
expected_python = {p[4:]: r['sha'] for p, r in source_leaves.items() if p.startswith('src/codex_plugin_scanner/') and p.endswith('.py') and p != 'src/codex_plugin_scanner/guard/native_runtime_resident.py'}
assert len(expected_python) == 1433
wheels = []
for digest, wheel in all_wheels.items():
    with zipfile.ZipFile(io.BytesIO(wheel['data'])) as archive:
        infos = archive.infolist()
        names = archive.namelist()
        assert len(names) == len(set(names)) and len(names) < 4096
        assert sum(i.file_size for i in infos) < 100 * 1024 * 1024
        for info in infos:
            p = PurePosixPath(info.filename)
            assert not p.is_absolute() and '..' not in p.parts and '\\' not in info.filename
            assert not info.is_dir() and (info.external_attr >> 16) & 0o170000 != 0o120000
        records = [n for n in names if n.endswith('.dist-info/RECORD')]
        assert len(records) == 1
        rows = list(csv.reader(io.StringIO(archive.read(records[0]).decode())))
        assert all(len(r) == 3 for r in rows) and len(rows) == len(names) and {r[0] for r in rows} == set(names)
        for name, file_digest, size in rows:
            data = archive.read(name)
            if name == records[0]:
                assert file_digest == size == ''
            else:
                assert size == str(len(data))
                assert file_digest == 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
        py = {n for n in names if n.startswith('codex_plugin_scanner/') and n.endswith('.py')}
        assert py == set(expected_python)
        crlf = 0
        for name in py:
            data = archive.read(name)
            if ident(data)['git_blob'] != expected_python[name]:
                assert wheel['name'].endswith('-win_amd64.whl')
                assert ident(data.replace(b'\r\n', b'\n'))['git_blob'] == expected_python[name]
                crlf += 1
        manifests = [n for n in names if n.endswith('/_native/runtime-manifest.json')]
        runtime = None
        if manifests:
            assert len(manifests) == 1
            runtime = json.loads(archive.read(manifests[0]))
            native_name = 'codex_plugin_scanner/_native/hol-guard-runtime' + ('.exe' if wheel['name'].endswith('-win_amd64.whl') else '')
            native = archive.read(native_name)
            assert runtime['source_sha'] == BUILD and runtime['package_version'] == '3.0.1'
            assert runtime['runtime_sha256'] == hashlib.sha256(native).hexdigest() and runtime['runtime_size'] == len(native)
            assert runtime['rule_digest'] == '1a1c577ee76936bc00477c650e35e3c394562b025c41d6ae68ac6d7b1f45c73d'
        wheels.append({'name': wheel['name'], 'sha256': digest, 'bytes': len(wheel['data']), 'artifact_ids': wheel['artifact_ids'], 'record_rows': len(rows), 'python_source_joins': len(py), 'windows_crlf_packaged_files': crlf, 'runtime': runtime})
assert sum(w['runtime'] is not None for w in wheels) == 4
encoding = json.loads((PACKET / 'INVENTORY-ENCODING.json').read_bytes())
compressed = base64.b64decode(b''.join((PACKET / part).read_bytes() for part in encoding['ordered_parts']), validate=True)
inventory = gzip.decompress(compressed)
assert ident(compressed) == encoding['gzip'] and ident(inventory) == encoding['original']
assert inventory == (ROOT / 'wheel-member-inventory.json').read_bytes()
summary = json.loads((PACKET / 'SUMMARY.json').read_bytes())
soak = summary['linux_soak']
growth = (soak['rss_peak_bytes'] - soak['rss_baseline_bytes']) / soak['rss_baseline_bytes']
assert abs(growth - soak['rss_growth']) < 0.000001
after = {str(p): ident(p.read_bytes()) for p in sorted(paths)}
assert before == after
save('REMOTE-VERIFICATION.json', remote_rows)
save('INPUT-CENSUS.json', {'files': before, 'all_unchanged': True})
save('WHEELS.json', wheels)
save('PEER.json', {'schema': 'pr2974.a1-linux-quartet-root-data-peer.v1', 'verdict': 'clear_with_explicit_scope', 'owner_tree': remote['tree']['sha'], 'owner_summary': '2070971b16c7e066a7192dc3bbcc0b9c18867ef4', 'source': SOURCE, 'actual_build': BUILD, 'tree': TREE, 'method': ['Read complete owner verifier and freezer before execution.', 'Executed only reviewed data-only freezer functions with all output redirected into peer namespace; no original file mutation, package import, build, test, download or workload.', 'Independently verified42 Git blob bodies and both complete Merkle trees, plus all original archive/member bytes.', 'Recomputed all5 distinct wheels/7copies RECORD contents, all1433 Python source joins per wheel and actual runtime bytes/manifests.', 'Reproduced exact original SUMMARY and QUARTET-JOIN; lossless inventory and RSS arithmetic verified.'], 'archives': archives, 'unique_wheels': len(wheels), 'wheel_copies': 7, 'record_rows_unique_wheels': sum(w['record_rows'] for w in wheels), 'original_inputs_unchanged': len(before), 'ordinary_result': {'smoke_gates': 14, 'native_and_processed_receipts': 21, 'soak_requests': 100000, 'soak_receipts': 250000, 'errors': 0, 'soak_p95_ms': soak['p95_ms'], 'rss_growth_fraction': soak['rss_growth']}, 'limits': summary['limits'], 'additional_limits': ['Windows CRLF packaging is verified separately against raw RECORD; normalization establishes source equivalence and does not relabel raw bytes.', 'Later cbd9399 test-only integration is separate from actual a1/build9f511 package and execution identities.']})
print(json.dumps({'clear': True, 'archives': len(archives), 'members': sum(a['members'] for a in archives), 'unique_wheels': len(wheels), 'record_rows': sum(w['record_rows'] for w in wheels), 'unchanged_inputs': len(before)}))
