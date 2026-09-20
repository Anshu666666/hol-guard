from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/workspace/scratch/745337b67ff9/root-checkpoint')
SOURCE = ROOT.parent / 'root-lazy-integration-a5fd'
HEAD = 'a5fdde302aba2a06265c2e6e934b6ac9b76750df'
TREE = '7a328609488ffefecd3cdd12a9c7adba6a591e97'
BASE_TREE = 'ee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9'

module = ast.parse((ROOT / 'prepare_publication.py').read_text())
definitions = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name in {'object_sha', 'tree_sha'}]
assert len(definitions) == 2
exec(compile(ast.Module(body=definitions, type_ignores=[]), 'merkle-definitions-only', 'exec'))

def git(*args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=SOURCE, text=True).strip()

assert git('rev-parse', 'HEAD') == HEAD
assert git('write-tree') == TREE
assert not git('diff', '--name-only')
staging = json.loads((ROOT / 'encrypted-lazy-source-staging.json').read_text())
base = json.loads((ROOT / 'encrypted-lazy-base-api-tree.json').read_text())
assert base['sha'] == BASE_TREE and not base['truncated']
prior = [e for e in base['tree'] if e['type'] != 'tree']
assert len(prior) == 4795 and tree_sha(prior) == BASE_TREE
prior_map = {e['path']: e for e in prior}
current = dict(prior_map)
delta = []
for item in staging['files']:
    path = item['path']
    before = prior_map.get(path)
    assert (before['sha'] if before else None) == item['before_blob'], path
    data = (SOURCE / path).read_bytes()
    assert len(data) == item['bytes']
    assert hashlib.sha256(data).hexdigest() == item['sha256']
    assert object_sha('blob', data) == item['after_blob']
    entry = {'path': path, 'mode': '100644', 'type': 'blob', 'sha': item['after_blob']}
    current[path] = {**entry, 'size': len(data)}
    delta.append(entry)
assert len(delta) == 8 and len(current) == 4800
expected = sorted(current.values(), key=lambda x: x['path'])
assert tree_sha(expected) == TREE
local = []
for row in subprocess.check_output(['git', 'ls-tree', '-rz', TREE], cwd=SOURCE).split(b'\0'):
    if not row:
        continue
    meta, path = row.decode().split('\t')
    mode, kind, sha = meta.split()
    local.append({'path': path, 'mode': mode, 'type': kind, 'sha': sha})
key = lambda e: (e['path'], e['mode'], e['type'], e['sha'])
assert sorted(map(key, local)) == sorted(map(key, expected))
changed = {e['path'] for e in expected if e['path'] not in prior_map or e['sha'] != prior_map[e['path']]['sha']}
assert changed == {e['path'] for e in delta}
record = {
    'schema': 'pr2974.encrypted-lazy-publication-preparation.v1',
    'prepared_at': datetime.now(timezone.utc).isoformat(),
    'head': HEAD, 'base_tree': BASE_TREE, 'tree': TREE,
    'changed_paths': staging['files'], 'source_leaf_count': len(expected),
    'independent_full_merkle_matches': True,
    'exact_local_index_and_base_plus_delta_match': True,
    'all_prior_leaves_except_eight_paths_preserved': True,
    'source_validation_run': 35530113949,
    'source_validation_tree': '7a33b3b5feaff3d27dae7ca70ab034ca5d5c8f63',
    'source_validation_scope': '43 Rust controls per Linux x86_64, Mac ARM and Mac Intel, all23new; unchanged exact6Rust files, locked Clippy and format passed. No installed or Windows encrypted-reference qualification.',
    'lazy_validation_scope': '393passed/3existing Windows-onlyskips in396unique final-image cases; exact2Python files; type0errors/30183warnings/1434files. Original wrapper ordering assertion failure retained separately from data-only reconciliation.',
    'authority_gate': 'Pending isolated committed-candidate validation; original local attempt failed before gate predicates because shallow history has no merge base.',
    'ready_to_update_ref': False,
}
(ROOT / 'encrypted-lazy-publication-expected.json').write_text(json.dumps(record, indent=2) + '\n')
(ROOT / 'encrypted-lazy-publication-api-input.json').write_text(json.dumps({'base_tree_sha': BASE_TREE, 'tree_elements': delta}, indent=2) + '\n')
(ROOT / 'encrypted-lazy-publication-leaves.json').write_text(json.dumps(expected, indent=2) + '\n')
print(json.dumps({'head': HEAD, 'tree': TREE, 'leaves': len(expected), 'changed_paths': len(delta), 'ready_to_update_ref': False}))
