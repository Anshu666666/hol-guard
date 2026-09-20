"""Read retained source/result bytes only; never import product code or run tests."""
import ast
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path('/workspace/scratch/745337b67ff9')
HERE = Path(__file__).parent
remote = json.loads((HERE / 'remote-inputs.json').read_bytes())
extra = json.loads((HERE / 'additional-inputs.json').read_bytes())
bindings = json.loads(remote['docs']['bindings'])
integration = json.loads(Path('/dev/shm/pr2974-root-completion-2220/rsp091-integration-inputs.json').read_bytes())

def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}

def merkle(rows):
    root = {}
    for row in rows:
        at = root
        parts = row['path'].split('/')
        for part in parts[:-1]:
            at = at.setdefault(part, {})
        assert parts[-1] not in at
        at[parts[-1]] = (row['mode'], row['sha'])
    def descend(node):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                entries.append((name + '/', b'40000 ' + name.encode() + b'\0' + bytes.fromhex(descend(value))))
            else:
                mode, sha = value
                entries.append((name, mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)))
        body = b''.join(v for _, v in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    return descend(root)

current_rows = [r for r in integration['integrated_tree']['tree'] if r['type'] == 'blob']
old_rows = json.loads((ROOT / 'windows-product-run35511038686/source-tree-leaves.json').read_bytes())
assert merkle(current_rows) == '3c59e6f81f531e7b4496ae49a278c9ddf3961380'
assert merkle(old_rows) == '63272e173903e23cec374c76d78e7f115921f58c'
current = {r['path']: r for r in current_rows}
old = {r['path']: r for r in old_rows}
system = {r['path']: r for r in remote['system_tree']['selected'] + extra['extra']}
assert remote['system_tree']['sha'] == '55ae133ce01788575f227cae808513c89164d5d2'
source_root = ROOT / 'windows-admission-observer-4001185'
mapped = bindings['python_workflow_and_module_bindings'] + bindings['rust_bindings']
joined = []
source_images = {}
for row in mapped + [r for r in extra['extra'] if r['path'] not in {v['path'] for v in mapped}]:
    path = row['path']
    data = (source_root / path).read_bytes()
    image = identity(data)
    expected = row.get('git_blob', row.get('sha'))
    assert image['git_blob'] == expected
    source_images[path] = image
    joined.append({'path': path, 'retained_source': image, 'current_blob': current[path]['sha'],
                   'equal_current': expected == current[path]['sha'],
                   'historical_9b_blob': old[path]['sha'],
                   'historical_55ae_blob': system.get(path, {}).get('sha')})
assert len(joined) == 43
changed = [r for r in joined if not r['equal_current']]
assert [r['path'] for r in changed] == ['rust/crates/guard-runtime/src/resident_transport.rs']
before = extra['transport_before']
after = extra['transport_current']
addition = '\n#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]\n#[path = "resident_transport_peer_identity_tests.rs"]\nmod peer_identity_tests;\n'
assert after.replace(addition, '', 1) == before and after.count(addition) == 1
assert identity(after.encode())['git_blob'] == current[changed[0]['path']]['sha']
test_path = 'rust/crates/guard-runtime/src/resident_transport_peer_identity_tests.rs'
assert identity(extra['peer_test'].encode())['git_blob'] == current[test_path]['sha']

old_dir = ROOT / 'windows-product-run35511038686/10605251017/raw'
old_xml = (old_dir / 'controls.xml').read_bytes()
assert identity(old_xml)['git_blob'] == '626450ca87433cbcf2f882e88d1f8fa351c3cad3'
old_before = json.loads((old_dir / 'source-before.json').read_bytes())
old_after = json.loads((old_dir / 'source-after.json').read_bytes())
assert old_before['source_sha'] == old_after['source_sha'] == '9b479556a7a98f43826625ccac495875fc4f061a'
assert old_before['source_tree'] == old_after['source_tree'] == '63272e173903e23cec374c76d78e7f115921f58c'
assert old_before['platform'] == old_after['platform'] == 'Linux'
assert old_before['source_clean'] and old_after['source_clean'] and old_before['imports_from_pinned_source']
assert old_before['source_files'] == old_after['source_files']
for path in ('tests/test_guard_private_file_io.py', 'src/codex_plugin_scanner/guard/private_file_io.py'):
    row = next(r for r in old_before['source_files'] if r['path'] == path)
    assert row['checkout_sha256'] == row['git_blob_sha256'] == source_images[path]['sha256']
    assert old[path]['sha'] == current[path]['sha'] == source_images[path]['git_blob']
private_names = [
    'test_private_regular_file_read_rejects_public_file_or_parent',
    'test_private_regular_file_read_rejects_symlink',
    'test_private_regular_file_read_rejects_parent_mode_change_during_read',
]
private_cases = []
for name in private_names:
    nodes = [n for n in ET.fromstring(old_xml).iter('testcase') if n.attrib['name'] == name]
    assert len(nodes) == 1 and not list(nodes[0])
    private_cases.append(nodes[0].attrib)

system_dir = ROOT / 'root-checkpoint/combined-final-preflight'
system_xml = (system_dir / 'controls.xml').read_bytes()
assert identity(system_xml)['git_blob'] == '8602a3a7e5d8bacbaac6ca4a20e7d1ff7e511eb6'
result = json.loads((system_dir / 'RESULT.json').read_bytes())
assert result['source_tree'] == result['final_index_tree'] == '55ae133ce01788575f227cae808513c89164d5d2'
assert result['tracked_unstaged_changes'] == '' and result['case_summary'] == {'passed':108,'failed':0,'error':0,'skipped':17}
name = 'test_windows_private_descriptor_deduplicates_system_owner_ace'
nodes = [n for n in ET.fromstring(system_xml).iter('testcase') if n.attrib['name'] == name]
assert len(nodes) == 1 and not list(nodes[0])
assert nodes[0].attrib['classname'] == 'tests.test_native_policy_snapshot_v3_publisher'
assert any(r['name'] == name and r['outcome'] == 'passed' for r in result['test_cases'])
system_paths = ('tests/test_native_policy_snapshot_v3_publisher.py',
                'tests/native_policy_snapshot_windows_handles.py',
                'src/codex_plugin_scanner/guard/native_policy_snapshot_windows_support.py',
                'src/codex_plugin_scanner/guard/native_policy_snapshot_constants.py',
                'src/codex_plugin_scanner/guard/native_policy_snapshot.py')
for path in system_paths:
    assert system[path]['sha'] == current[path]['sha'] == source_images[path]['git_blob']
facade = ast.parse((source_root / system_paths[0]).read_bytes())
assignment = next(n for n in facade.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
assert isinstance(assignment.value, ast.Attribute) and assignment.value.attr == name
assert isinstance(assignment.value.value, ast.Name) and assignment.value.value.id == '_windows_handle_tests'

rust_map = json.loads(remote['docs']['rustmap'])
logs = []
for row in rust_map['retained_log_evidence']:
    data = (ROOT / row['path']).read_bytes()
    image = identity(data)
    assert image['bytes'] == row['bytes'] and image['sha256'] == row['sha256']
    lines = data.decode().splitlines()
    matched = {name: [line for line in lines if 'test ' + name + ' ... ok' in line]
               for name in row['selected_passing_nodes']}
    assert all(len(lines) == 1 for lines in matched.values())
    logs.append({'path':row['path'],'identity':image,'actual_named_passes':matched})
windows = (ROOT / rust_map['retained_log_evidence'][0]['path']).read_bytes().decode()
assert 'tests\\test_windows_config_directory_access.py ............' in windows

peer_result_path = Path('/dev/shm/pr2974-rsp091-peer-control/run35540033572/VERIFIED-RESULT.json')
peer_data = peer_result_path.read_bytes()
assert identity(peer_data)['git_blob'] == 'c701176526dfe14a68c07d8f85f21271b10e491f'
peer_result = json.loads(peer_data)
assert peer_result['run'] == 35540033572 and peer_result['overall_passed'] is True
peer_cells = []
for cell in peer_result['cells']:
    assert (cell['parent_tests_passed'], cell['owned_child_fixture_passes'], cell['driver_controls_passed']) == (4,2,11)
    assert all(c['passed'] for c in cell['cases'])
    assert cell['source_binding']['source_tree'] == '9c472594937f085864e2cb0ff60227c6a9e0f713'
    for path, text in ((changed[0]['path'], after),(test_path,extra['peer_test'])):
        actual = cell['source_binding']['members'][path]
        assert actual == {k:identity(text.encode())[k] for k in ('bytes','sha256')}
    peer_cells.append({'lane':cell['lane'],'parent_passes':4,'owned_child_passes':2,'driver_passes':11,'cases':cell['cases']})

out = {'status':'all selected source/result joins verified', 'current_source':'cbd9399e39adc4fe338bff468807656ebab3af13',
       'current_tree':integration['integrated_tree']['sha'],'current_merkle_verified':True,
       'historical_9b_merkle_verified':True,'provider_joins':joined,'only_mapped_current_change':'cfg(test) peer module declaration',
       'private_path_execution':{'xml':identity(old_xml),'source':old_before['source_sha'],'tree':old_before['source_tree'],
                                 'platform':'Linux','python':old_before['python'],'nodes':private_cases},
       'system_rule_execution':{'xml':identity(system_xml),'source_tree':result['source_tree'],'platform':result['platform'],
                                'node':nodes[0].attrib,'façade_reexport_verified':True,'source_paths_equal_current':list(system_paths)},
       'rust_selected_logs':logs, 'final_unix_execution':{'result':identity(peer_data),'cells':peer_cells},
       'scope':'Pure source/data reconciliation; no tests, product imports, compilation, workload or ref writes.'}
print(json.dumps(out,indent=2))
