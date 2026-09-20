"""Preserve original and corrected gate evidence; no gate is executed here."""
import base64
import fnmatch
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

OUT = Path(__file__).parent.resolve()
REPO = OUT / 'candidate'
PACKET = OUT / 'packet'
PACKET.mkdir(exist_ok=False)
source = json.loads((OUT / 'candidate.json').read_bytes())
result = json.loads((OUT / 'authority-result.json').read_bytes())


def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args])


def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}


manifest_path = 'docs/guard/contracts/hook-data-plane-ownership.v2.json'
manifest = json.loads((REPO / manifest_path).read_bytes())
base_manifest_body = git('show', source['base_ref'] + ':' + manifest_path)
(OUT / 'base-manifest.json').write_bytes(base_manifest_body)
shutil.copyfile(REPO / manifest_path, OUT / 'candidate-manifest.json')
shutil.copyfile(OUT.parent / 'root-checkpoint/run_encrypted_lazy_source_gates.py', OUT / 'original/root-runner.py')
for label, sha in [('parent', source['sole_parent']), ('base', source['base_ref']), ('candidate', source['commit'])]:
    (OUT / (label + '.commit')).write_bytes(git('cat-file', 'commit', sha))
ancestry = git('rev-list', '--ancestry-path', '--parents', source['base_ref'] + '..' + source['sole_parent']).decode()
(OUT / 'authentic-ancestry.txt').write_text(ancestry)
changed = git('diff', '--name-only', source['base_ref'] + '...HEAD').decode().splitlines()
assert changed == result['changed_files_checked'] and set(source['changed_from_parent']) <= set(changed)
coverage = []
for path in source['changed_from_parent']:
    owners = [{'id': n['id'], 'class': n['class'], 'matching_patterns': [p for p in n['paths'] if fnmatch.fnmatchcase(path, p)]}
              for n in manifest['nodes'] if any(fnmatch.fnmatchcase(path, p) for p in n['paths'])]
    coverage.append({'path': path, **identity((REPO / path).read_bytes()),
                     'changed_range_checked': True,
                     'protected_globs': [p for p in manifest['protected_change_globs'] if fnmatch.fnmatchcase(path, p)],
                     'owners': owners})
root = OUT.parent / 'root-lazy-integration-a5fd'
root_head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
root_tree = subprocess.check_output(['git', '-C', str(root), 'write-tree'], text=True).strip()
root_index = Path(subprocess.check_output(['git', '-C', str(root), 'rev-parse', '--git-path', 'index'], text=True).strip())
root_index_sha = hashlib.sha256(root_index.read_bytes()).hexdigest()
assert root_head == source['root_before']['head'] and root_tree == source['tree']
assert root_index_sha == source['root_before']['index_sha256']
analysis = {'schema': 'pr2974.encrypted-lazy-authority-gate-reconciliation.v1',
            'original_failure': {'gate_exit': 1, 'underlying_git_exit': 128,
                                 'reason': 'Shallow original checkout has no merge base for4b89...HEAD.'},
            'additional_scope_defect': 'The unchanged gate diffs committed HEAD, so repairing only ancestry would omit8 staged files under the original a5fd HEAD.',
            'correction': 'Own isolated repository fetched authentic exact parent/base ancestry; local detached commit has exact reviewed8-path tree and sole a5fd parent. No source/gate/threshold/manifest changes.',
            'local_candidate': source['commit'], 'candidate_tree': source['tree'], 'sole_parent': source['sole_parent'],
            'base_ref': source['base_ref'], 'actual_merge_base': git('merge-base', source['base_ref'], 'HEAD').decode().strip(),
            'ancestry_commits_from_base_to_parent': len(ancestry.splitlines()),
            'gate_passed': result['status'] == 'passed', 'all_changed_paths_checked': len(changed),
            'new_eight_path_coverage': coverage,
            'coverage_interpretation': 'Six Rust files are protected by rust/** and owned by native_semantics/rust_semantic through rust/crates/guard-runtime/**. Lazy daemon __init__.py and its test are included in the changed range but outside this existing authority manifest protected/owner globs. No invented mapping or new gate required.',
            'root_head_index_tree_unchanged': True, 'remote_refs_modified': False,
            'local_gate_command': json.loads((OUT / 'gate-command.json').read_bytes()),
            'limits': ['Only the originally failed authority gate was rerun.', 'The other6 original gate results remain independently retained by root.', 'No unit/native/installed workload or formatter executed.', 'This does not publish the isolated local commit or claim a500line requirement.']}
(OUT / 'ANALYSIS.json').write_text(json.dumps(analysis, indent=2, sort_keys=True) + '\n')
files = sorted(p for p in OUT.iterdir() if p.is_file() and p.suffix not in {'.jsonl'})
files += sorted(p for p in (OUT / 'original').iterdir() if p.is_file())
originals = []
for ordinal, path in enumerate(files):
    body = path.read_bytes(); row = {'path': path.relative_to(OUT).as_posix(), **identity(body)}
    if len(body) > 256 * 1024:
        compressed = gzip.compress(body, mtime=0); encoded = base64.b64encode(compressed); parts = []
        for offset in range(0, len(encoded), 64000):
            name = f'compressed/{ordinal:03d}/{offset // 64000:03d}.b64'
            target = PACKET / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded[offset:offset + 64000]); parts.append(name)
        row.update(storage='gzip-base64-parts', parts=parts, compressed_identity=identity(compressed))
    else:
        name = 'raw/' + row['path']; target = PACKET / name
        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(body)
        row.update(storage='raw', member=name)
    originals.append(row)
for path in source['changed_from_parent']:
    target = PACKET / 'candidate-source' / path; target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((REPO / path).read_bytes())
shutil.copyfile(OUT.parent / 'partition-completion-preflight-preservation/packet/verify.py', PACKET / 'verify.py')
members = [{'path': p.relative_to(PACKET).as_posix(), **identity(p.read_bytes())}
           for p in sorted(PACKET.rglob('*')) if p.is_file()]
(PACKET / 'MANIFEST.json').write_text(json.dumps({'schema': 'pr2974.authority-gate-preservation.v1',
    'originals': originals, 'members': members, 'original_count': len(originals),
    'original_bytes': sum(r['bytes'] for r in originals)}, indent=2, sort_keys=True) + '\n')
print(json.dumps({'gate': result['status'], 'checked_changed_paths': len(changed),
                  'new_paths': len(coverage), 'original_files': len(originals), 'packet_files': len(members) + 1}))
