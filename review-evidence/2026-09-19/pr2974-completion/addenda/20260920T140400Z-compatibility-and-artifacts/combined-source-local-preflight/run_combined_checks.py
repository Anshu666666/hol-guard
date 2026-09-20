from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path

REPO = Path('/workspace/scratch/745337b67ff9/combined-product-124472')
OUT = Path('/workspace/scratch/745337b67ff9/root-checkpoint/combined-preflight')
OUT.mkdir(exist_ok=True)
PYTHON = '/workspace/scratch/745337b67ff9/hol-guard/.venv/bin/python'
BIN = Path(PYTHON).parent
EXPECTED = 'a89fc1b31f245b98c044eea088b81e77be193013'

def git(*args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

assert git('write-tree') == EXPECTED
assert not git('diff', '--name-only')
paths = git('diff', '--cached', '--name-only').splitlines()
python_paths = [path for path in paths if path.endswith('.py')]
manifest = json.loads((REPO / 'scripts/ci/mcp_risk_reuse_validation.json').read_text())
tests = list(manifest['tests'])
tests += [path for path in python_paths if path.startswith('tests/')]
tests += ['tests/test_validate_release_artifacts.py', 'tests/test_guard_private_file_io.py', 'tests/test_guard_daemon_manager.py::test_daemon_token_and_state_use_atomic_replacement']
tests = list(dict.fromkeys(tests))
records = []
for name,command in [
    ('ruff', [str(BIN/'ruff'), 'check', *python_paths]),
    ('format', [str(BIN/'ruff'), 'format', '--check', *python_paths]),
    ('types-normal-src', [str(BIN/'basedpyright'), '--pythonpath', PYTHON, '--level', 'error', '--outputjson']),
    ('pytest', [PYTHON, '-m', 'pytest', '-q', '--tb=short', '--junitxml='+str(OUT/'controls.xml'), *tests]),
]:
    started = time.time()
    stdout = OUT / (name+'.stdout')
    stderr = OUT / (name+'.stderr')
    try:
        with stdout.open('wb') as out, stderr.open('wb') as err:
            result = subprocess.run(command, cwd=REPO, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=600)
        row = {'stage':name,'command':command,'returncode':result.returncode,'elapsed_seconds':time.time()-started,'timeout':False}
    except subprocess.TimeoutExpired:
        row = {'stage':name,'command':command,'returncode':None,'elapsed_seconds':time.time()-started,'timeout':True}
    for label,file in [('stdout',stdout),('stderr',stderr)]:
        data=file.read_bytes()
        row[label]={'file':file.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    records.append(row)
    (OUT/'stages.json').write_text(json.dumps(records,indent=2)+'\n')
    print(json.dumps({'stage':name,'returncode':row['returncode'],'elapsed_seconds':row['elapsed_seconds']}), flush=True)
    if row['timeout']:
        break

final = {'schema':'pr2974-combined-source-local-preflight.v1','head':git('rev-parse','HEAD'),'source_tree':EXPECTED,'final_index_tree':git('write-tree'),'tracked_unstaged_changes':git('diff','--name-only'),'platform':platform.platform(),'python':subprocess.check_output([PYTHON,'--version'],text=True).strip(),'python_realpath':os.path.realpath(PYTHON),'source_paths':paths,'test_selectors':tests,'stages':records,'scope':'Linux source correctness and ordinary source static checks; staged candidate includes known Windows raw-error parity failure, with Windows successor still being revised. This is not installed, native or performance qualification.'}
(OUT/'RESULT.json').write_text(json.dumps(final,indent=2)+'\n')
print(json.dumps({'final_index_matches':final['final_index_tree']==EXPECTED,'unstaged_clean':not final['tracked_unstaged_changes'],'stages':len(records)}),flush=True)
