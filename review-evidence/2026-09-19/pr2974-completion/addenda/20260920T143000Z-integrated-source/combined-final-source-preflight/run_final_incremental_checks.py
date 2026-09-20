from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path('/workspace/scratch/745337b67ff9')
REPO = ROOT / 'combined-product-124472'
OUT = ROOT / 'root-checkpoint/combined-final-preflight'
OUT.mkdir(exist_ok=True)
PYTHON = str(ROOT / 'hol-guard/.venv/bin/python')
BIN = Path(PYTHON).parent
EXPECTED = '55ae133ce01788575f227cae808513c89164d5d2'

def git(*args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

assert git('write-tree') == EXPECTED
assert not git('diff', '--name-only')
paths = git('diff', '--cached', '--name-only').splitlines()
python_paths = [path for path in paths if path.endswith('.py')]
tests = [
    'tests/test_native_policy_snapshot_cache_binding.py',
    'tests/test_native_policy_snapshot_inactive_namespace.py',
    'tests/test_native_policy_snapshot_resident_retry.py',
    'tests/test_native_policy_snapshot_v3_publisher.py',
    'tests/test_native_policy_snapshot_write_safety.py',
    'tests/test_windows_atomic_replace_process.py',
    'tests/test_guard_daemon_manager.py::test_daemon_token_and_state_use_atomic_replacement',
]
records = []
for name, command in [
    ('ruff', [str(BIN/'ruff'), 'check', *python_paths]),
    ('format', [str(BIN/'ruff'), 'format', '--check', *python_paths]),
    ('diff', ['git', 'diff', '--cached', '--check']),
    ('types-normal-src', [str(BIN/'basedpyright'), '--pythonpath', PYTHON, '--level', 'error', '--outputjson']),
    ('pytest', [PYTHON, '-m', 'pytest', '-q', '--tb=short', '--junitxml='+str(OUT/'controls.xml'), *tests]),
]:
    started = time.time()
    stdout, stderr = OUT/(name+'.stdout'), OUT/(name+'.stderr')
    with stdout.open('wb') as out, stderr.open('wb') as err:
        result = subprocess.run(command, cwd=REPO, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=600)
    row = {'stage':name, 'command':command, 'returncode':result.returncode, 'elapsed_seconds':time.time()-started}
    for label, file in [('stdout', stdout), ('stderr', stderr)]:
        data = file.read_bytes()
        row[label] = {'file':file.name, 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()}
    records.append(row)
    (OUT/'stages.json').write_text(json.dumps(records, indent=2)+'\n')
    print(json.dumps({'stage':name, 'returncode':result.returncode, 'elapsed_seconds':row['elapsed_seconds']}), flush=True)
cases = []
if (OUT/'controls.xml').exists():
    for case in ET.parse(OUT/'controls.xml').iter('testcase'):
        outcome = 'failed' if case.find('failure') is not None else 'error' if case.find('error') is not None else 'skipped' if case.find('skipped') is not None else 'passed'
        cases.append({'classname':case.attrib['classname'], 'name':case.attrib['name'], 'outcome':outcome})
assert len(cases) == len({(x['classname'], x['name']) for x in cases})
summary = {key:sum(x['outcome']==key for x in cases) for key in ['passed','failed','error','skipped']}
final = {'schema':'pr2974-combined-final-source-preflight.v1', 'parent':git('rev-parse','HEAD'), 'source_tree':EXPECTED, 'final_index_tree':git('write-tree'), 'tracked_unstaged_changes':git('diff','--name-only'), 'platform':platform.platform(), 'python':subprocess.check_output([PYTHON,'--version'],text=True).strip(), 'python_realpath':os.path.realpath(PYTHON), 'source_paths':paths, 'test_selectors':tests, 'test_cases':cases, 'case_summary':summary, 'stages':records, 'scope':'Final integrated source checks after Windows test/doc corrections and the inactive namespace publisher repair. Earlier 511/63 result remains specific to a89 source. This incremental result does not claim installed, native, performance or release acceptance.'}
(OUT/'RESULT.json').write_text(json.dumps(final,indent=2)+'\n')
print(json.dumps({'source_exact':final['final_index_tree']==EXPECTED, 'unstaged_clean':not final['tracked_unstaged_changes'], 'cases':summary}), flush=True)
