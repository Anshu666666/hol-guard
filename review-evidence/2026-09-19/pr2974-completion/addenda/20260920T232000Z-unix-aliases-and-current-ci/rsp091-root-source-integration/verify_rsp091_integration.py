import ast
import base64
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path('/dev/shm/pr2974-root-completion-2220')
helper = ast.parse(Path('/workspace/scratch/745337b67ff9/root-checkpoint/prepare_publication.py').read_text())
namespace = {'hashlib': hashlib}
exec(compile(ast.Module(body=[n for n in helper.body if isinstance(n, ast.FunctionDef) and n.name in ('object_sha', 'tree_sha')], type_ignores=[]), '<reviewed-merkle-helpers>', 'exec'), namespace)
tree_sha = namespace['tree_sha']
raw_path = ROOT / 'rsp091-integration-inputs.json'
if raw_path.exists():
    input_bytes = raw_path.read_bytes()
else:
    encoding = json.loads((ROOT / 'rsp091-inputs-encoding.json').read_text())
    compressed = base64.b64decode(b''.join((ROOT / name).read_bytes() for name in encoding['ordered_parts']), validate=True)
    assert len(compressed) == encoding['gzip']['bytes']
    assert hashlib.sha256(compressed).hexdigest() == encoding['gzip']['sha256']
    input_bytes = gzip.decompress(compressed)
    assert len(input_bytes) == encoding['original']['bytes']
    assert hashlib.sha256(input_bytes).hexdigest() == encoding['original']['sha256']
inputs = json.loads(input_bytes)
trees = {}
for key in ('base_tree', 'isolated_source_tree', 'integrated_tree'):
    value = inputs[key]
    assert not value['truncated']
    assert tree_sha(value['tree']) == value['sha'], key
    trees[key] = {row['path']: row for row in value['tree'] if row['type'] != 'tree'}
before, after = trees['base_tree'], trees['integrated_tree']
assert len(before) == 4801 and len(after) == 4802
changed = {path: {'before': before.get(path), 'after': after.get(path)} for path in before.keys() | after.keys() if before.get(path, {}).get('sha') != after.get(path, {}).get('sha')}
assert set(changed) == {'rust/crates/guard-runtime/src/resident_transport.rs', 'rust/crates/guard-runtime/src/resident_transport_peer_identity_tests.rs'}
assert after['rust/crates/guard-runtime/src/resident_transport.rs']['sha'] == '0121df862f8999338ced7224bb7eba262757990c'
assert after['rust/crates/guard-runtime/src/resident_transport_peer_identity_tests.rs']['sha'] == 'ee5fa8562fb0ef97e76db7bfab16320182e6b0e6'
for row in inputs['expected']:
    assert all(after[row['path']][key] == row[key] for key in ('path', 'sha', 'type', 'mode', 'size'))
commit = inputs['integrated_commit']
assert commit['sha'] == 'cbd9399e39adc4fe338bff468807656ebab3af13'
assert commit['tree']['sha'] == inputs['integrated_tree']['sha']
assert [p['sha'] for p in commit['parents']] == [inputs['base_commit']]
assert inputs['native_terminal']['status'] == 'completed' and inputs['native_terminal']['conclusion'] == 'success'
result = {
 'schema': 'pr2974.rsp091-test-only-integration-root-verification.v1',
 'source': commit['sha'], 'tree': commit['tree']['sha'], 'sole_parent': inputs['base_commit'],
 'all_api_leaves_exact': len(after), 'independent_merkle_roots_verified': {key: inputs[key]['sha'] for key in trees},
 'delta': changed,
 'source_and_operational_peer': '7eb803dd1cfcdb9fb1bde8394b1a1a66a8e7446f',
 'original_functional_run': 35540033572,
 'original_result_tree': '34b0e1a845b9bf200fd37e0b38cacd72a58f3bfe',
 'independent_data_peer': '443e84d05afcc8c7902c9aa61c8f3ab6465c673f',
 'prior_native_run_completed_successfully': 35539716189,
 'scope': 'Exact reviewed test-only module and cfg(test) declaration. No production provider or existing test changed; all three POSIX original populations retain their actual isolated source. New normal CI must retain the integrated source identity.',
 'input_sha256': hashlib.sha256(input_bytes).hexdigest(),
 'published': False,
}
(ROOT / 'rsp091-integration-root-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
