"""Create only an isolated detached candidate; root staging/refs stay untouched."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

OUT = Path(__file__).parent.resolve()
WORKSPACE = OUT.parent
ROOT = WORKSPACE / 'root-lazy-integration-a5fd'
CANDIDATE = OUT / 'candidate'
PARENT = 'a5fdde302aba2a06265c2e6e934b6ac9b76750df'
TREE = '7a328609488ffefecd3cdd12a9c7adba6a591e97'
BASE = '4b89e0d2d496a85f04922b2e019a4aea15326bb9'


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def root_state():
    index = Path(git(ROOT, 'rev-parse', '--git-path', 'index'))
    return {'head': git(ROOT, 'rev-parse', 'HEAD'), 'index_sha256': hashlib.sha256(index.read_bytes()).hexdigest(),
            'index_tree': git(ROOT, 'write-tree'), 'status': git(ROOT, 'status', '--porcelain'),
            'refs': git(ROOT, 'show-ref')}


before = root_state()
assert before['head'] == PARENT and before['index_tree'] == TREE
assert git(CANDIDATE, 'merge-base', BASE, PARENT) == BASE
env = os.environ.copy()
env.update(GIT_AUTHOR_NAME='Codex isolated validation', GIT_AUTHOR_EMAIL='codex-validation@example.invalid',
           GIT_COMMITTER_NAME='Codex isolated validation', GIT_COMMITTER_EMAIL='codex-validation@example.invalid')
commit = subprocess.check_output(['git', '-C', str(CANDIDATE), 'commit-tree', TREE, '-p', PARENT],
                                 input='Isolated exact encrypted and lazy candidate for unchanged authority gate\n',
                                 text=True, env=env).strip()
subprocess.run(['git', '-C', str(CANDIDATE), 'checkout', '--detach', commit], check=True, capture_output=True)
assert git(CANDIDATE, 'rev-parse', 'HEAD^{tree}') == TREE
assert git(CANDIDATE, 'status', '--porcelain') == ''
assert root_state() == before
changed = git(CANDIDATE, 'diff', '--name-only', PARENT, commit).splitlines()
assert len(changed) == 8
report = {'schema': 'pr2974.authority-gate-isolated-candidate.v1', 'commit': commit, 'tree': TREE,
          'sole_parent': PARENT, 'base_ref': BASE, 'merge_base': BASE, 'changed_from_parent': changed,
          'root_before': before, 'root_after_identical': True,
          'remote_refs_changed': False, 'root_staging_modified': False,
          'source_ancestry_recovery': 'Own Git repository fetched exact authentic parent and base with depth256/blob:none; shared object store was read via alternate only.',
          'scope': 'Local detached candidate only, no branch creation or source publication.'}
(OUT / 'candidate.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({k: report[k] for k in ('commit', 'tree', 'sole_parent', 'merge_base', 'changed_from_parent', 'root_after_identical')}))
