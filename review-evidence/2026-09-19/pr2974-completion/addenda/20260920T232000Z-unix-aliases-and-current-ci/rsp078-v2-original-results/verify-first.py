"""Data-only readback of the original registered Cursor/Copilot v2 result."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).parent
EXPECTED_MEMBERS = {
    'before.json', 'after.json', 'input-contract.json', 'source-controls.txt', 'source-controls.xml',
    'wheel-requirements.txt', 'install-record.json', 'install.stdout', 'install.stderr', 'provision.json',
    'run.json', 'managed-aliases-offered.json', 'managed-aliases-terminal.json', 'managed-aliases.json',
    'managed-aliases.stdout', 'managed-aliases.stderr',
}
POPULATION = {'daemon_absent': 6, 'daemon_permission_unavailable': 4, 'declared_attempts': 14,
              'native_evaluated': 4, 'validated_cases': 14}
DENIAL = {'behavior': 'deny', 'interrupt': False, 'message': 'HOL Guard could not complete the native hook decision safely.',
          'reason_code': 'native_hook_event_unavailable'}
EMPTY = hashlib.sha256(b'').hexdigest()


def image(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def sha(value):
    assert isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)


def expected_cases():
    cases = [
        ('global', 'cursor', 'beforeShellExecution', 'evaluated', 'dangerous/small', {'permission': 'deny'}, 2),
        ('global', 'cursor', 'afterShellExecution', 'evaluated', 'benign/1k', {}, 0),
        ('global', 'copilot', 'preToolUse', 'evaluated', 'dangerous/small', {'permissionDecision': 'deny'}, 0),
        ('project', 'copilot', 'postToolUse', 'evaluated', 'benign/1k', {'permissionDecision': 'allow'}, 0),
    ]
    for kind in ('permission_daemon', 'permission_no_daemon'):
        cases.extend((scope, 'copilot', event, kind, kind, DENIAL, 0)
                     for scope in ('global', 'project') for event in ('permissionRequest', 'permissionRequestV2'))
    cases.extend([
        ('global', 'cursor', 'beforeShellExecution', 'watch_no_daemon', 'watch_no_daemon', {'permission': 'allow'}, 0),
        ('global', 'cursor', 'afterShellExecution', 'watch_no_daemon', 'watch_no_daemon', {}, 0),
    ])
    return cases


def verify_cell(identifier, metadata, jobs):
    folder = ROOT / str(identifier)
    artifact = next(x for x in metadata['artifacts'] if x['id'] == identifier)
    archive = (folder / 'artifact.zip').read_bytes()
    assert len(archive) == artifact['size_in_bytes'] and 'sha256:' + image(archive)['sha256'] == artifact['digest']
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        assert len(z.namelist()) == len(EXPECTED_MEMBERS) and set(z.namelist()) == EXPECTED_MEMBERS
        bodies = {n: z.read(n) for n in z.namelist()}
    assert all(body == (folder / 'raw' / name).read_bytes() for name, body in bodies.items())
    objects = {name: json.loads(body) for name, body in bodies.items() if name.endswith('.json')}
    before, after = objects['before.json'], objects['after.json']
    assert before['passed'] is after['passed'] is True and before['binding'] == after['binding']
    binding = before['binding']
    cell = binding['cell']
    job = next(x for x in jobs if '(' + cell + ',' in x['name'])
    assert job['status'] == 'completed' and job['conclusion'] == 'success'
    assert job['head_sha'] == binding['driver_source'] == '627d48b4ce6023737a507f26a6a07ab25b159948'
    assert binding['driver_tree'] == 'e69d8d7040c91e44a90ee40e8628280dfad6ed9e'
    assert binding['candidate_source'] == '3d99b884a73568c2278e829fe53a103880fa69da'
    assert binding['candidate_tree'] == '9c00c49f09852f3444fe69ec0428e86d8488f07b'
    assert binding['product_source'] == 'a1d509404b0803a91031cb51f4b0c919408bfeba'
    assert binding['product_tree'] == binding['artifact_source']['build_tree'] == 'e60dfd218cd7cc9f29c9f2cd66223c866ea86c80'
    assert binding['artifact_source']['build_source'] == '9f511875b236c12e5f23c783e958a536ac0360ba'
    assert all(next(x for x in job['steps'] if x['number'] == number)['conclusion'] == 'success' for number in range(8, 16))
    control_rows = ET.fromstring(bodies['source-controls.xml']).findall('.//testcase')
    nodes = [(r.get('classname'), r.get('name')) for r in control_rows]
    assert len(nodes) == len(set(nodes)) == 290
    assert not any(r.find(k) is not None for r in control_rows for k in ('failure', 'error', 'skipped'))
    assert sum(c == 'tests.test_managed_aliases_installed_driver' for c, _ in nodes) == 49
    for suffix in ('accepted', 'refused'):
        assert ('tests.test_managed_aliases_installed_driver', f'test_population_owns_private_catalog_and_cleans_after_result[{suffix}]') in nodes
    install = objects['install-record.json']
    assert install['require_hashes'] is True and install['return_code'] == 0
    assert install['requirement'] == image(bodies['wheel-requirements.txt'])
    assert all(flag in install['command'] for flag in ['--no-index', '--no-deps', '--require-hashes', '--only-binary'])
    provision, run = objects['provision.json'], objects['run.json']
    assert provision['passed'] is run['passed'] is True
    assert provision['binding'] == run['binding'] == binding
    assert provision['installed_before'] == provision['installed_after'] == run['installed_before'] == run['installed_after']
    assert run['installation_unchanged'] is True
    interpreter = provision['interpreter']
    assert interpreter['passed'] is interpreter['identical_bytes'] is interpreter['original_target_preserved'] is True
    assert interpreter['production_integrity_checks_relaxed'] is interpreter['shared_interpreter_chmodded'] is interpreter['wheel_bytes_modified'] is False
    installed = run['installed_after']
    assert installed['record_entries_verified'] >= 1498 and installed['wheel_entries_verified'] >= 1498
    report = objects['managed-aliases.json']
    identity = report['identity']
    assert identity == installed['identity']
    contract = objects['input-contract.json']
    selected = contract['cells'][cell]
    assert identity['build_sha'] == binding['artifact_source']['build_source']
    assert identity['wheel_sha256'] == selected['wheel']['sha256']
    assert identity['runtime_sha256'] == binding['native_manifest']['runtime_sha256']
    assert identity['installed_package_sha256'] == report['installed_package_after_sha256']
    assert identity['package_version'] == identity['runtime_version'] == '3.0.1' and identity['mode'] == 'auto'
    assert objects['managed-aliases-offered.json'] == {'label': 'managed-aliases', 'offered': True, 'returned': False}
    terminal = objects['managed-aliases-terminal.json']
    assert run['stages'] == [terminal]
    assert terminal['population'] == POPULATION and terminal['return_code'] == 0
    assert all(terminal[k] is True for k in ['offered', 'returned', 'passed', 'reported_passed'])
    assert all(terminal[k] is False for k in ['timed_out', 'containment_failed', 'output_limit_exceeded'])
    assert terminal['report'] == image(bodies['managed-aliases.json'])
    for stream in ('stdout', 'stderr'):
        assert bodies[f'managed-aliases.{stream}'] == b'' and terminal[stream] == image(b'')
    assert report['passed'] is report['daemon_cleanup_contained'] is report['no_daemon_cleanup_contained'] is True
    assert report['declared_cases'] == len(report['rows']) == 14
    assert all(report[k] is False for k in ['native_approval_consume_qualified', 'performance_qualified', 'external_host_application_executed'])
    assert report['platform_scope'] == 'POSIX'
    output_rows = []
    for index, (expected, row) in enumerate(zip(expected_cases(), report['rows'], strict=True)):
        scope, harness, event, kind, label_tail, fields, returncode = expected
        assert [row[k] for k in ['scope', 'harness', 'event', 'kind']] == [scope, harness, event, kind]
        assert row['label'] == '/'.join((scope, harness, event, label_tail))
        assert row['status'] == 'completed' and row['stage'] == 'complete' and row['registration_unchanged'] is True
        assert all(row[k] is False for k in ['timed_out', 'containment_failed', 'output_limit_exceeded'])
        assert row['outer_containment_seconds'] == (10.0 if harness == 'cursor' else 30.0)
        assert row['returncode'] == returncode
        for name in ['registration', 'registered_argv', 'registered_executable', 'input', 'stdout', 'stderr']:
            sha(row[name + '_sha256'])
        assert row['stderr_sha256'] == EMPTY and row['registered_executable_sha256'] == interpreter['copied_sha256']
        projection = row['delivery']
        assert set(projection) == {'fields', 'nonempty_text_images', 'original_oracle_passed'}
        assert projection['fields'] == fields and projection['original_oracle_passed'] is True
        text_names = {'agent_message', 'user_message'} if index == 0 else {'permissionDecisionReason'} if index == 2 else set()
        assert set(projection['nonempty_text_images']) == text_names
        for text_image in projection['nonempty_text_images'].values():
            assert set(text_image) == {'bytes', 'sha256'} and type(text_image['bytes']) is int and text_image['bytes'] > 0
            sha(text_image['sha256'])
        assert row['native_evaluation'] is (kind == 'evaluated')
        if kind in {'evaluated', 'permission_daemon'}:
            evidence = row['evidence']
            assert evidence['native_call_count'] == evidence['native_completed_call_count'] == 1
            assert evidence['setup'] == {'effective_policy_allow': True, 'fault_scope': 'none', 'isolated_store': True, 'policy_ack_current': True, 'python_oracle_disabled': True}
            sha(evidence['validated_full_evidence_sha256'])
            route = 'native_resident' if kind == 'evaluated' else 'native_fail_safe'
            assert row['route'] == route
            keys = set(row['routes_before']) | set(row['routes_after'])
            assert {k: row['routes_after'].get(k, 0) - row['routes_before'].get(k, 0) for k in keys} == {k: int(k == route) for k in keys}
            if kind == 'permission_daemon':
                assert evidence['native_result'] is None
            elif index in (0, 2):
                assert evidence['native_result'] == {'decision': 'deny', 'minimum_action': 'block', 'policy_action': 'block', 'reason_code': 'native_destructive_command'}
            else:
                assert evidence['native_result'] == {'decision': 'allow', 'model_output_action': 'allow_original', 'policy_action': 'allow', 'reason_code': 'output_scan_allow', 'reviewed_output_sha256': '2209cc3bb03f9464144ee5e0b4e9fc5a73924be8311e637765e4fc0d32dc7aa9'}
        else:
            assert 'evidence' not in row and 'route' not in row
            assert row['daemon_endpoint_before'] == row['daemon_endpoint_after'] == {'daemon-state.json': False, 'daemon-auth-token': False}
            assert row['absence_scope'] == 'fresh_owned_home_no_daemon_started_endpoint_files_absent'
            assert row['posture'] == ('watch' if kind == 'watch_no_daemon' else 'protected')
        output_rows.append({'label': row['label'], 'kind': kind, 'returncode': returncode, 'native_evaluation': row['native_evaluation'], 'delivery_fields': fields, 'route': row.get('route')})
    return {'cell': cell, 'artifact_id': identifier, 'job_id': job['id'], 'archive': image(archive), 'members': {n: image(b) for n, b in bodies.items()},
            'controls': {'collected': 290, 'passed': 290, 'failed': 0, 'skipped': 0, 'driver_controls': 49},
            'population': POPULATION, 'rows': output_rows, 'python_version': identity['python_version'], 'wheel_sha256': identity['wheel_sha256'],
            'runtime_sha256': identity['runtime_sha256'], 'installed_record_entries': installed['record_entries_verified'],
            'installed_original_wheel_members': installed['wheel_entries_verified'], 'source_before_after_equal': True,
            'installation_unchanged': True, 'owned_interpreter_admitted': True, 'native_approval_consume_qualified': False,
            'external_host_application_executed': False, 'windows_qualified': False, 'performance_qualified': False}


def verify():
    metadata = json.loads((ROOT / 'artifacts.json').read_text())
    jobs = json.loads((ROOT / 'jobs.json').read_text())['jobs']
    cells = [verify_cell(x['id'], metadata, jobs) for x in metadata['artifacts']]
    assert {x['cell'] for x in cells} == {'linux-x64', 'mac-arm64', 'mac-x64'}
    return {'run_id': 35543060961, 'passed': True, 'product_source': 'a1d509404b0803a91031cb51f4b0c919408bfeba',
            'actual_build': '9f511875b236c12e5f23c783e958a536ac0360ba', 'driver_source': '627d48b4ce6023737a507f26a6a07ab25b159948',
            'source': '3d99b884a73568c2278e829fe53a103880fa69da', 'cells': cells,
            'original_failure_packet': '652d9e9e0477ee6bcc289de96d6b82f7536f50ea',
            'scope': 'Actual14 registered forms per POSIX cell; four evaluated native events, four unsupported permission raw-edge attempts, six explicitly no-daemon availability calls. No external IDE, approval consumption, Windows or performance qualification.'}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
