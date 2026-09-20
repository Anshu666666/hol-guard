from __future__ import annotations

import concurrent.futures
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path('/workspace/scratch/745337b67ff9')
SOURCE = ROOT / 'root-lazy-integration-a5fd'
OUTPUT = ROOT / 'root-checkpoint/daemon-lazy-preflight'
PYTHON = ROOT / 'hol-guard/.venv/bin/python'
EXPECTED_TREE = '50e5ce00f8207df8f4a6b36c875a0fabf05bbcae'
TESTS = [
    'tests/test_claude_daemon_hook_bridge.py',
    'tests/test_codex_daemon_hook_bridge.py',
    'tests/test_codex_daemon_hook_resume.py',
    'tests/test_guard_daemon_lazy_exports.py',
    'tests/test_guard_daemon_manager.py',
    'tests/test_guard_daemon_manager_dependencies.py',
    'tests/test_guard_daemon_server_bindings.py',
    'tests/test_guard_daemon_transport_security.py',
    'tests/test_native_codex_transport_identity.py',
    'tests/test_native_codex_live_continuation.py',
    'tests/test_native_codex_continuation_binding.py',
]
OUTPUT.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, PYTHONPATH=str(SOURCE / 'src'))
STAGING = json.loads((ROOT / 'root-checkpoint/daemon-lazy-source-staging.json').read_text())

def source_identity():
    tree = subprocess.check_output(['git', 'write-tree'], cwd=SOURCE, text=True).strip()
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=SOURCE).decode().split('\0')
    entries = []
    for relative in filter(None, tracked):
        path = SOURCE / relative
        data = path.read_bytes()
        entries.append({'path': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    for item in STAGING['files']:
        data = (SOURCE / item['path']).read_bytes()
        assert hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest() == item['after_blob']
    assert tree == EXPECTED_TREE
    return {'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip(), 'tree': tree, 'files': entries}

def run(name, arguments, timeout=600):
    started = time.time()
    result = subprocess.run(arguments, cwd=SOURCE, env=ENV, capture_output=True, timeout=timeout)
    (OUTPUT / f'{name}.stdout').write_bytes(result.stdout)
    (OUTPUT / f'{name}.stderr').write_bytes(result.stderr)
    record = {'name': name, 'argv': list(map(str, arguments)), 'cwd': str(SOURCE), 'pythonpath': ENV['PYTHONPATH'], 'exit_code': result.returncode, 'elapsed_seconds': time.time()-started}
    print(json.dumps(record), flush=True)
    return record

def cases(path):
    return [(case.attrib.get('classname'), case.attrib.get('name')) for case in ET.parse(path).iter('testcase')]

if __name__ == '__main__':
    before = source_identity()
    (OUTPUT / 'source-before.json').write_text(json.dumps(before, indent=2)+'\n')
    imports = run('source-imports', [str(PYTHON), '-c', "import json; import codex_plugin_scanner.guard.daemon.codex_native_live_decision as d; import codex_plugin_scanner.guard.native_hook_edge as n; print(json.dumps({'decision':d.__file__,'native_edge':n.__file__}))"])
    actual_imports = json.loads((OUTPUT / 'source-imports.stdout').read_text())
    assert all(Path(value).is_relative_to(SOURCE / 'src') for value in actual_imports.values())
    changed_python = [row['path'] for row in STAGING['files'] if row['path'].endswith('.py')]
    checks = [
        ('codex-regression', [str(PYTHON), '-m', 'pytest', *TESTS, '-q', f'--junitxml={OUTPUT / "codex-regression.xml"}']),
        ('ruff', [str(PYTHON), '-m', 'ruff', 'check', *changed_python]),
        ('format', [str(PYTHON), '-m', 'ruff', 'format', '--check', *changed_python]),
        ('types-full-src', [str(PYTHON), '-m', 'basedpyright', '--pythonpath', str(PYTHON), '--outputjson']),
        ('diff-check', ['git', 'diff', '--cached', '--check']),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(checks)) as pool:
        results = list(pool.map(lambda entry: run(*entry), checks))
    after = source_identity()
    (OUTPUT / 'source-after.json').write_text(json.dumps(after, indent=2)+'\n')
    assert before == after
    actual_cases = cases(OUTPUT / 'codex-regression.xml')
    owner_cases = cases(ROOT / 'qualification-recovered/daemon-lazy-regression.xml') + cases(ROOT / 'rsp136-route-evidence/codex-transport-after.xml')
    assert len(actual_cases) == len(set(actual_cases)) == 396
    assert actual_cases == owner_cases
    xml = ET.parse(OUTPUT / 'codex-regression.xml')
    assert not any(list(xml.iter(tag)) for tag in ('failure', 'error'))
    assert len(list(xml.iter('skipped'))) == 3
    types = json.loads((OUTPUT / 'types-full-src.stdout').read_text())
    summary = {'source_unchanged': before == after, 'expected_tree': EXPECTED_TREE, 'tracked_files': len(before['files']), 'imports': actual_imports, 'ordered_case_membership_matches_owner': True, 'cases': len(actual_cases), 'skipped': len(list(xml.iter('skipped'))), 'types_summary': types['summary'], 'checks': [imports, *results], 'all_checks_pass': all(item['exit_code'] == 0 for item in [imports, *results])}
    (OUTPUT / 'RESULT.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary), flush=True)
    sys.exit(0 if summary['all_checks_pass'] else 1)
