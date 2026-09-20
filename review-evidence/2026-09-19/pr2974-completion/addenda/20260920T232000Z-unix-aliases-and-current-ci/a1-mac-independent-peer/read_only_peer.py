"""Pure-data peer: reads frozen inputs and prints a new independent projection."""
import base64
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import tomllib
import zipfile

resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024,) * 2)
ROOT = Path('/dev/shm/rsp078-normal-a1-mac')
PACKET = ROOT / 'mac-packet'
PEER = Path(__file__).parent
SOURCE = 'a1d509404b0803a91031cb51f4b0c919408bfeba'
BUILD = '9f511875b236c12e5f23c783e958a536ac0360ba'
TREE = 'e60dfd218cd7cc9f29c9f2cd66223c866ea86c80'
IDS = (10614825404, 10614003430)

def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}

def read_json(path):
    return json.loads(path.read_bytes())

def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT / 'source.git'), *args],
                                   timeout=30, env={**os.environ, 'GIT_NO_LAZY_FETCH': '1'})

tree = read_json(PEER / 'owner-tree.json')
assert tree['sha'] == '61a70cfb819bec8d43c98b3aaffac8f7d3b0282e' and tree['truncated'] is False
leaves = [r for r in tree['tree'] if r['type'] == 'blob']
assert len(leaves) == 41
inputs = {PACKET / r['path'] for r in leaves}
inputs.update(ROOT / name for name in ('verify_wheels.py', 'wheel-verification.json',
               'metadata-mac-terminal.json', 'jobs-mac-terminal.json', 'source-build-binding.json',
               'original-build.commit', 'build-commit-api-payload.json'))
for artifact_id in IDS:
    inputs.update(p for p in (ROOT / str(artifact_id)).rglob('*') if p.is_file())
before = {str(p): identity(p.read_bytes()) for p in sorted(inputs)}
for leaf in leaves:
    observed = before[str(PACKET / leaf['path'])]
    assert observed['bytes'] == leaf['size'] and observed['git_blob'] == leaf['sha'], leaf['path']
for row in read_json(PACKET / 'MANIFEST.json')['members']:
    assert before[str(PACKET / row['path'])] == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
for name in ('verify_wheels.py', 'wheel-verification.json', 'metadata-mac-terminal.json',
             'jobs-mac-terminal.json', 'source-build-binding.json', 'original-build.commit',
             'build-commit-api-payload.json'):
    assert (ROOT / name).read_bytes() == (PACKET / name).read_bytes()

summary = read_json(PACKET / 'SUMMARY.json')
assert summary['pr_source'] == SOURCE and summary['actual_build'] == BUILD
assert summary['same_source_tree'] == TREE and summary['artifact_ids'] == list(IDS)
for commit in (SOURCE, BUILD):
    assert git('rev-parse', commit + '^{tree}').decode().strip() == TREE
raw_commit = (ROOT / 'original-build.commit').read_bytes()
assert hashlib.sha1(b'commit ' + str(len(raw_commit)).encode() + b'\0' + raw_commit).hexdigest() == BUILD
source_py = {}
for row in git('ls-tree', '-rz', SOURCE, 'src/codex_plugin_scanner').split(b'\0'):
    if row:
        meta, path = row.split(b'\t', 1)
        if path.endswith(b'.py'):
            source_py[path.decode()[4:]] = meta.split()[2].decode()
config = tomllib.loads(git('show', SOURCE + ':pyproject.toml').decode())
exclusion = 'src/codex_plugin_scanner/guard/native_runtime_resident.py'
assert exclusion in config['tool']['hatch']['build']['exclude']
expected_py = {n: h for n, h in source_py.items() if n != exclusion[4:]}
assert len(source_py) == 1434 and len(expected_py) == 1433

compressed = base64.b64decode(b''.join((PACKET / n).read_bytes()
                                     for n in summary['member_inventory']['ordered_parts']), validate=True)
assert identity(compressed) == summary['member_inventory']['gzip']
decoded = gzip.decompress(compressed)
assert identity(decoded) == summary['member_inventory']['original']
inventory = json.loads(decoded)
assert len(inventory) == 4
by_wheel = {(r['artifact_id'], r['wheel']): r for r in inventory}
metadata = {r['id']: r for r in read_json(ROOT / 'metadata-mac-terminal.json')['artifacts']}
jobs = read_json(ROOT / 'jobs-mac-terminal.json')['jobs']
owner_wheels = read_json(ROOT / 'wheel-verification.json')
owner_by_name = {r['path']: r for r in owner_wheels['wheels']}
assert owner_wheels['source_sha'] == SOURCE and owner_wheels['build_sha'] == BUILD
assert owner_wheels['same_tree'] == TREE
cells = []
record_count = 0
archive_members = 0
for artifact_id in IDS:
    base = ROOT / str(artifact_id)
    meta = metadata[artifact_id]
    archive = (base / 'artifact.zip').read_bytes()
    archive_id = identity(archive)
    assert archive_id['bytes'] == meta['size_in_bytes']
    assert 'sha256:' + archive_id['sha256'] == meta['digest']
    assert meta['workflow_run']['id'] == 35539716189 and meta['workflow_run']['head_sha'] == SOURCE
    verified = read_json(base / 'verification.json')
    assert verified['archive_bytes'] == archive_id['bytes'] and verified['archive_sha256'] == archive_id['sha256']
    manifest_rows = {r['path']: r for r in verified['members']}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        assert len(z.namelist()) == len(set(z.namelist())) == 8
        assert set(z.namelist()) == set(manifest_rows)
        for name in z.namelist():
            payload = z.read(name)
            observed = identity(payload)
            assert payload == (base / 'raw' / name).read_bytes()
            assert observed['bytes'] == manifest_rows[name]['bytes'] and observed['sha256'] == manifest_rows[name]['sha256']
            if not name.endswith('.whl'):
                assert payload == (PACKET / str(artifact_id) / 'raw' / name).read_bytes()
            archive_members += 1
    native = None
    cell_wheels = []
    for wheel in sorted((base / 'raw').rglob('*.whl')):
        row = by_wheel[(artifact_id, wheel.name)]
        assert identity(wheel.read_bytes()) == row['identity']
        observed_owner = owner_by_name[str(wheel.resolve())]
        assert observed_owner['bytes'] == row['identity']['bytes'] and observed_owner['sha256'] == row['identity']['sha256']
        with zipfile.ZipFile(wheel) as z:
            names = z.namelist()
            assert len(names) == len(set(names)) < 4096
            assert sum(i.file_size for i in z.infolist()) < 100 * 1024 * 1024
            members = {r['path']: r for r in row['members']}
            assert len(members) == len(row['members']) and set(members) == set(names)
            records = [n for n in names if n.endswith('.dist-info/RECORD')]
            assert len(records) == 1
            records = list(csv.reader(io.StringIO(z.read(records[0]).decode())))
            assert len(records) == len({r[0] for r in records}) == len(names)
            assert {r[0] for r in records} == set(names)
            for name, digest, size in records:
                payload = z.read(name)
                observed = identity(payload)
                assert observed == {k: members[name][k] for k in ('bytes', 'sha256', 'git_blob')}
                if name.endswith('.dist-info/RECORD'):
                    assert digest == size == ''
                else:
                    assert digest == 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip('=')
                    assert int(size) == len(payload)
                if name in expected_py:
                    assert observed['git_blob'] == expected_py[name]
            py = {n for n in names if n.startswith('codex_plugin_scanner/') and n.endswith('.py')}
            assert py == set(expected_py)
            manifest = 'codex_plugin_scanner/_native/runtime-manifest.json'
            if manifest in names:
                native = json.loads(z.read(manifest))
                runtime = z.read('codex_plugin_scanner/_native/hol-guard-runtime')
                assert native['source_sha'] == BUILD and native['runtime_size'] == len(runtime)
                assert native['runtime_sha256'] == hashlib.sha256(runtime).hexdigest()
                assert observed_owner['runtime_manifest'] == native and observed_owner['runtime_bytes_verified'] is True
            assert observed_owner['record_entries_verified'] == len(records)
            assert observed_owner['packaged_python_bytes_match_source'] == len(py)
            record_count += len(records)
            cell_wheels.append({'name': wheel.name, **row['identity'], 'record_entries': len(records)})
    assert native is not None
    slo = read_json(base / 'raw/native-installed-slo.json')
    default = read_json(base / 'raw/native-default-auto.json')
    pi = read_json(base / 'raw/installed-pi-output.json')
    evidence = read_json(base / 'raw/native-artifact-evidence.json')
    stop = read_json(base / 'raw/native-stop-diagnostic.json')
    for report in (slo, pi):
        assert report['runtime']['build_sha'] == BUILD and report['runtime']['runtime_sha256'] == native['runtime_sha256']
    assert evidence['source_sha'] == BUILD and evidence['rule_digest'] == slo['runtime']['rule_digest']
    for a in evidence['artifacts']:
        wheel = next(w for w in cell_wheels if w['name'] == a['name'])
        assert wheel['bytes'] == a['size'] and wheel['sha256'] == a['sha256']
    assert slo['passed'] is True and slo['qualification_complete'] is False and slo['evidence_class'] == 'smoke'
    assert len(slo['gates']) == 14 and all(v is True for v in slo['gates'].values())
    assert default['corpus_decisions'] == default['resident_decisions'] == 21
    assert len(default['route_receipts']) == len({(r['harness'], r['event']) for r in default['route_receipts']}) == 21
    assert all(r['route'] == 'native_resident' for r in default['route_receipts'])
    assert default['receipt_metrics'] == {'accepted': 21, 'processed': 21, 'deduped': 0, 'dropped': 0, 'durable_pending': 0, 'failures': 0}
    assert default['evidence_failure_diagnostics'] == {'all_evidence': {}, 'native_receipts': {}}
    assert pi['generated_extension']['harness'] == 'omp'
    assert len(pi['generated_extension']['real_cases']) == 4 and pi['native_route_metrics'] == {'native_resident': 4}
    assert len(pi['generated_extension']['malformed_result_cases']) == 7
    for case in pi['generated_extension']['real_cases'].values():
        response = case['daemon_response']
        assert case['preserved'] is True and case['input_content_unchanged'] is True
        assert response['status'] == 200 and response['decision'] == 'allow' and response['model_output_action'] == 'allow_original'
        assert case['sha256'] == response['sha256'] == response['reviewed_output_sha256']
    assert stop['status'] == 'contained' and stop['serving_shutdown'] == 'verified'
    cells.append({'artifact_id': artifact_id, 'archive': archive_id, 'wheels': cell_wheels, 'runtime': native,
                  'slo': {k: slo[k] for k in ('concurrency', 'corpus', 'thresholds', 'installed_launcher', 'routes')},
                  'latency': {k: v for k, v in slo['latency'].items() if not k.startswith('warm_by')},
                  'default_route_count': 21, 'receipt_metrics': default['receipt_metrics'],
                  'evidence_failure_diagnostics': default['evidence_failure_diagnostics'],
                  'omp_real_cases': 4, 'omp_modeled_malformed_controls': 7, 'resident_stop': stop})
assert record_count == 5996 and archive_members == 16
assert sum(c['archive']['bytes'] for c in cells) == summary['archive_bytes_verified']
after = {str(p): identity(p.read_bytes()) for p in sorted(inputs)}
assert before == after
print(json.dumps({'result': 'clear', 'owner_packet': tree['sha'], 'source': SOURCE, 'build': BUILD, 'tree': TREE,
                  'packet_leaves': len(leaves), 'input_files_unchanged': len(before),
                  'archive_members': archive_members, 'record_entries': record_count,
                  'source_python_paths': len(source_py), 'packaged_python_paths_per_wheel': len(expected_py),
                  'cells': cells, 'source_input_identities': before}, indent=2))
