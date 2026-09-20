"""Freeze the completed source fixture result without editing its raw records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path('/workspace/scratch/745337b67ff9/rsp015-current-fixtures')
OUT = Path(__file__).parent


def identity(path: Path) -> dict[str, object]:
    body = path.read_bytes()
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}


def xml_summary(path: Path) -> dict[str, object]:
    root = ET.parse(path).getroot()
    cases = []
    for case in root.iter('testcase'):
        state = next((name for name in ('failure', 'error', 'skipped') if case.find(name) is not None), 'passed')
        record = {'classname': case.get('classname'), 'name': case.get('name'), 'state': state}
        if state != 'passed':
            record['message'] = case.find(state).get('message', '')
        cases.append(record)
    return {'identity': identity(path), 'total': len(cases),
            **{state: sum(row['state'] == state for row in cases) for state in ('passed', 'failure', 'error', 'skipped')},
            'cases': cases}


def main() -> None:
    paths = subprocess.check_output(['git', 'diff', '--cached', '--name-only'], cwd=ROOT, text=True).splitlines()
    assert len(paths) == 7 and all(p.startswith('tests/') for p in paths)
    tree = subprocess.check_output(['git', 'write-tree'], cwd=ROOT, text=True).strip()
    assert tree == '591ac8825a68decbef94c9648579d78f2c8a1cdd'
    manifest = {'schema': 'hol-guard.rsp015-final-source.v1',
                'base_commit': 'e44008445630aad28ccc291ec234f55a14892e6d',
                'base_tree': 'addf0c1daf8ceb6313d6805ee4d05e216d6fdac8',
                'prepared_tree': tree, 'source_checkout': str(ROOT),
                'files': [{'path': p, **identity(ROOT / p)} for p in paths],
                'production_changes': 0, 'source_peer_tree': 'aa8200189bc25dcccc89b00d542db17b8ce84ab3',
                'source_peer_receipt_blob': 'acd80fa4103ce49b3965fa7b8cb1100a59f019c9'}
    before = json.loads((OUT / 'corrected/before.json').read_text())
    after = json.loads((OUT / 'corrected/after.json').read_text())
    assert before['source'] == after['source_after'] and after['source_unchanged']
    assert after['stage_exit'] == after['actual_process_returncode'] == 0 and not after['timed_out']
    result = xml_summary(OUT / 'corrected/selected.xml')
    assert (result['total'], result['passed'], result['failure'], result['error'], result['skipped']) == (862, 861, 0, 0, 1)
    additions = {}
    for module, expected in [('test_cline_nonblocking_response_fixtures', 62),
                             ('test_registered_auxiliary_response_fixtures', 81),
                             ('test_hook_registration_response_roster', 9)]:
        rows = [r for r in result['cases'] if r['classname'] == 'tests.' + module]
        assert len(rows) == expected and all(r['state'] == 'passed' for r in rows)
        additions[module] = expected
    initial = xml_summary(OUT / 'selected.xml')
    assert (initial['passed'], initial['failure'], initial['skipped']) == (845, 16, 1)
    analysis = {
        'schema': 'hol-guard.rsp015-source-fixture-result.v1',
        'source': manifest,
        'original_task': {'id': 'RSP-015', 'archived_status': 'OPEN',
                          'original_object_sha256': '418aca0ea61cdbfcdb8d7a5c0d3346705ea27a1b36a3736856fc665746997969',
                          'acceptance': 'Capture harness JSON and exit behavior for current mode/posture, native misses, integrity/size failures, permission requests and lifecycle events.',
                          'dependencies': ['RSP-014']},
        'corrected_result': {k: v for k, v in result.items() if k != 'cases'},
        'new_cases_passed': additions, 'existing_cases_passed': 709,
        'existing_skip': [r for r in result['cases'] if r['state'] == 'skipped'],
        'environment': before['identity'], 'source_before_after_equal': True,
        'corrected_pytest_seconds': 451.30, 'orchestrator_seconds': after['elapsed_seconds'],
        'actual_process_returncode': 0, 'timeout': False,
        'first_attempt': {'counts': {k: initial[k] for k in ('total', 'passed', 'failure', 'error', 'skipped')},
                          'acceptance_valid': False,
                          'reason': 'The original wrapper called pytest.main at module scope and could be re-entered by multiprocessing spawn. Its 15 daemon-readiness failures and separate Kimi path-substring assertion failure remain original failures, not product acceptance evidence.',
                          'unchanged_first_daemon_reproduction': xml_summary(OUT / 'first-daemon-reproduction.xml'),
                          'kimi_scope': 'Only the incidental checkout-name substring assertion was replaced by current launcher argv, decoded configuration, exact installed events, command and timeout checks; production was unchanged.'},
        'coverage': {
            'current_mode_posture': 'Existing HookWorker/native Watch, availability and delivery fixtures; modeled native edges are identified in source.',
            'native_miss_integrity_size_permission_lifecycle': 'Original 26 cohorts retained, including real-daemon Codex paths, bounded CLI JSON/exit and registered inputs.',
            'cline_nonblocking': 'Six generated native-hook events times ten conditions; actual isolated generated-script stdout/stderr/exit capture, modeled child policy.',
            'auxiliary_events': 'Ten actual registered extra events times protected/Watch and four availability/input/output failures; full JSON/stdout/exit checked.',
            'roster': 'Closed mapping of 16 canonical harness aliases to actual current generators and fixture routes, including preflight-only, delegated and extension semantics.'},
        'static_checks': {'new_three_modules': 'Ruff and format pass; basedpyright 0 errors, 0 warnings, 0 notes.',
                          'changed_kimi_file': 'Ruff and format pass. Whole legacy file keeps the same 3 pre-existing errors; warning count changes from 15 to 22. No whole-file clean-type claim.'},
        'dependency_receipts': {'RSP014_root_acceptance_tree': 'd9dbf889d7eb33d7a738cba781580d72c85aa3f9',
                                'RSP014_root_receipt_blob': '89f0170d5705b08c5f1fe1fc7599b3e46cbabc36',
                                'inventory_tree': '56c22f3aa04d8f10d9ed1610aec172720686f9f2'},
        'recommendation': 'Original fixture-capture own scope is satisfied on this exact prepared source, conditional on integrating these seven reviewed leaves. Do not label current e440 as containing the additions. Root may derive current acceptance after integration and source readback while preserving the archived OPEN object.',
        'not_claimed': ['Installed native coverage of all harnesses or platforms', 'Windows CommandLineToArgvW execution on Linux',
                        'RSP136 approval continuation or alias qualification', 'Latency/resource acceptance',
                        'Full escaped-descendant retirement', 'Native producer execution for modeled child/edge cases',
                        'Cryptographic release or task-ledger mutation'],
    }
    (OUT / 'final-source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (OUT / 'corrected/case-membership.json').write_text(json.dumps(result, indent=2) + '\n')
    (OUT / 'ANALYSIS.json').write_text(json.dumps(analysis, indent=2) + '\n')
    print(json.dumps({'manifest': identity(OUT / 'final-source-manifest.json'),
                      'analysis': identity(OUT / 'ANALYSIS.json'),
                      'result': {k: v for k, v in result.items() if k != 'cases'}}))


if __name__ == '__main__':
    main()
