import base64
import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as ET

ROOT = pathlib.Path('/workspace/scratch/745337b67ff9')
OUT = ROOT / 'windows-startup-v3-terminal-packet'
OUT.mkdir(exist_ok=False)
members = json.loads((ROOT / 'windows-startup-v3-artifact/all-text-members.json').read_text())
verification_bytes = (ROOT / 'windows-startup-v3-artifact/verification.json').read_bytes()
verification = json.loads(verification_bytes)
metadata = json.loads((ROOT / 'windows-startup-v3-metadata-recovery.json').read_text())
expected_bytes = (ROOT / 'windows-startup-v3-local/after-driver/startup-diagnostic/expected-controls.json').read_bytes()
expected = json.loads(expected_bytes)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def put(path, data):
    dest = OUT / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data.encode() if isinstance(data, str) else data)

def js(path, value):
    put(path, json.dumps(value, indent=2, ensure_ascii=False) + '\n')

for name, content in members.items():
    row = next(r for r in verification['members'] if r['name'] == name)
    data = content.encode()
    assert len(data) == row['bytes'] and sha(data) == row['sha256']
    put('original/' + name, data)
put('archive-verification.json', verification_bytes)
put('expected-controls.json', expected_bytes)
for row in metadata['metadata']:
    put(row['path'], row['content'])
log = metadata['log']
assert len(log.encode()) == 401743 and sha(log.encode()) == '30ec996d42632c7cd8b5705521bcdc08f902fc4324c697b864845c443f78e79b'
put('job-106079140891.log', log)

def strict_pairs(pairs):
    value = {}
    for key, item in pairs:
        assert key not in value
        value[key] = item
    return value

prefix = re.compile(r'^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z HG_WINDOWS_STARTUP_FILE_V1 (.+)$')
decoded = {}
active = None
for line in log.splitlines():
    match = prefix.fullmatch(line)
    if not match:
        continue
    rec = json.loads(match[1], object_pairs_hook=strict_pairs)
    if rec['kind'] == 'begin':
        assert active is None and rec['name'] not in decoded
        assert set(rec) == {'kind', 'name', 'bytes', 'sha256', 'git_blob', 'chunks'}
        assert 0 <= rec['bytes'] <= 1024*1024 and rec['chunks'] == (rec['bytes']+3071)//3072
        active = (rec, [])
    elif rec['kind'] == 'chunk':
        assert active and set(rec) == {'kind', 'name', 'index', 'base64'}
        begin, chunks = active
        assert rec['name'] == begin['name'] and rec['index'] == len(chunks)
        data = base64.b64decode(rec['base64'], validate=True)
        assert 0 < len(data) <= 3072
        chunks.append(data)
    else:
        assert active and set(rec) == {'kind', 'name', 'sha256'} and rec['kind'] == 'end'
        begin, chunks = active
        data = b''.join(chunks)
        assert rec['name'] == begin['name'] and len(chunks) == begin['chunks']
        assert len(data) == begin['bytes'] and sha(data) == begin['sha256'] == rec['sha256'] and blob(data) == begin['git_blob']
        assert data == members[rec['name']].encode()
        decoded[rec['name']] = {'bytes':len(data), 'sha256':sha(data), 'git_blob':blob(data)}
        active = None
assert active is None and len(decoded) == 41 and sum(r['bytes'] for r in decoded.values()) <= 4*1024*1024

rust = {}
for role in ('default', 'diagnostic'):
    collected = re.findall(r'^(.+): test\r?$', members[f'rust-{role}-collection.stdout'], re.M)
    passed = re.findall(r'^test (.+) \.\.\. ok\r?$', members[f'rust-{role}-controls.stdout'], re.M)
    assert collected == passed == expected[role] and len(set(passed)) == len(passed)
    assert f'{len(passed)} passed; 0 failed; 0 ignored;' in members[f'rust-{role}-controls.stdout']
    for stage in ('collection', 'controls'):
        assert json.loads(members[f'rust-{role}-{stage}.process.json'])['returncode'] == 0
    rust[role] = {'exact_collected_and_executed_names': passed, 'passed': len(passed), 'failed':0, 'ignored':0}

collected = [x for x in members['python-collection.stdout'].splitlines() if x.startswith('ci/native_runtime/test_windows_startup_capture.py::')]
cases = list(ET.fromstring(members['python-controls.xml']).iter('testcase'))
junit = [c.attrib['classname'].replace('.', '/') + '.py::' + c.attrib['name'] for c in cases]
assert collected == junit and len(junit) == len(set(junit)) == 59
assert all(not list(c) for c in cases)
capture = json.loads(members['original-capture.json'])
assert capture['exact_calls'] == capture['target_calls'] == capture['original_stop_calls'] == 1
assert capture['phases'] == dict.fromkeys(('setup','call','teardown'), 'passed')
assert capture['returned']['returncode'] == capture['original_pytest_exit'] == 0
stdout = base64.b64decode(capture['returned']['stdout']['base64'], validate=True)
assert stdout == b'{"error":"native_request_invalid_json","retryable":false}\n'
assert sha(stdout) == capture['returned']['stdout']['sha256']
original = list(ET.fromstring(members['original-selector.xml']).iter('testcase'))
assert len(original) == 1 and not list(original[0])
assert original[0].attrib['classname'].replace('.', '/') + '.py::' + original[0].attrib['name'] == capture['selector']
before = json.loads(members['source-before.json']); after = json.loads(members['source-after.json'])
assert {k:v for k,v in before.items() if k!='phase'} == {k:v for k,v in after.items() if k!='phase'}
for label in ('python-format','python-lint','python-types','rust-format','rust-clippy-default','rust-clippy-diagnostic','diagnostic-build','original-selector'):
    assert json.loads(members[label+'.process.json'])['returncode'] == 0
assert '0 errors, 406 warnings' in members['python-types.stdout']

summary = {
 'schema':'pr2974-windows-startup-terminal.v1',
 'run_id':35511138438, 'job_id':106079140891, 'terminal_conclusion':'success',
 'source_sha':before['source_sha'], 'source_tree':before['source_tree'], 'sole_source_parent':'4afa20cf014ccba918bf2fa61552dafe66767930',
 'driver_sha':before['driver_sha'], 'driver_tree':before['driver_tree'],
 'original_selector':capture['selector'], 'original_payload_bytes':52, 'original_payload_sha256':capture['payload_sha256'],
 'original_fallback_budget_ms':750, 'original_python_timeout_seconds':3,
 'rust_controls':rust, 'python_controls':{'collected':59,'passed':59,'ordered_roster_junit_equal':True,'failed':0,'skipped':0},
 'static_gates':{'rust_format':True,'python_format':True,'python_lint':True,'python_types_errors':0,'python_types_warnings':406,'default_clippy':True,'diagnostic_clippy':True},
 'original_selector_calls':1, 'original_selector_passed':True, 'original_stdout_bytes':len(stdout), 'original_stdout_sha256':sha(stdout), 'original_response':json.loads(stdout),
 'original_stop_calls':1, 'original_stop_returncode':capture['original_stop_result']['returncode'],
 'parent_observation':capture['returned']['observation']['record'],
 'source_driver_dependencies_unchanged':True,
 'archive':{k:verification[k] for k in ('archive_id','archive_bytes','archive_sha256','runtime_bytes_verified')},
 'retention':{'archive_members_crc_and_hash_verified':55,'original_text_members_retained':54,'original_log_bytes':len(log.encode()),'original_log_sha256':sha(log.encode()),'original_log_projected_files_matched_to_archive':41,'runtime_bytes_hashed_from_archive':True,'runtime_bytes_in_git_packet':False,'archive_bytes_in_git_packet':False},
 'prior_attempts':[
  {'run_id':35507796398,'failure':'four static type errors; controls and original selector unexecuted','evidence_tree':'0d63d9ec4cf7507f9673d2b48921eb68f8905b13'},
  {'run_id':35510041482,'failure':'one projector mapping-invariance type error; controls and original selector unexecuted','evidence_tree':'004e2983e2bd9963d8bb704b90c2f17d9a84c37e'}],
 'correction_local_static_evidence_tree':'cf61388f00456a4b53f204e1b2c441e0159dcc15',
 'correction_peer_tree':'f9f48925a809d6e97552b087753fb38658419db0',
 'limits':{'historical_timeout_reproduced':False,'historical_timeout_cause_resolved':False,'serving_child_observed':False,'complete_run':False,'complete_descendant_cleanup':False,'default_artifact_timing_eligible':False,'qualification_complete':False,'offline_verification_executed_native_code':False,'archive_verifier_no_native_execution_field_scope':'Only the offline archive verification; hosted Rust controls and original selector did execute.'}
}
js('VERIFIED-RESULT.json', summary)
js('log-frame-verification.json', {'files':decoded,'strict_original_timestamp_frame_and_base64_hash_checks':True,'all_match_original_archive':True})
put('AUDIT.md', '''# Windows original-startup diagnostic v3

The single authorized diagnostic attempt completed successfully: run 35511138438, job 106079140891, ending on 20 September 2026 at 12:42:53 UTC. It ran against diagnostic source `dce62838d43a9947d2928f5caf595ab8feb40279`, a sole child of the historical failing source `4afa20cf014ccba918bf2fa61552dafe66767930`, with separate driver `8cd8bb44997ac04a1c08b60c91aebb3c0395738e`.

All 3 default Rust controls, 9 diagnostic Rust controls and 59 Python controls passed. Independent parsing joins the exact expected Rust names to collection and successful execution, and the 59 ordered Python collection names to passing JUnit cases. Rust formatting, Python format/lint/types (0 errors, 406 warnings), both Clippy modes and the diagnostic build passed. Source, driver, dependencies and interpreter records match before and after apart from the phase label.

The original duplicate-key selector executed its selected 52-byte hook-client input exactly once, retaining the original 750 ms fallback budget and 3 s subprocess timeout. The process returned code 0 and the expected 58-byte `native_request_invalid_json` response with `retryable: false`; the original test assertion and setup/call/teardown all passed. The original stop call ran once and returned 0 with empty stdout/stderr. The diagnostic returned a valid parent-only record with 292,295 us observed elapsed and 457,704 us remaining. No retry, loss or counter overflow was recorded. Repeated phase rows contain first/last timestamps across calls; their span is not an individual-call duration.

This attempt did not reproduce or establish the cause of the historical startup timeout. Serving-child phases remain unavailable; complete-run, complete-descendant-cleanup, headline-timing and qualification flags remain false. Instrumentation overhead belongs to this diagnostic. No default-artifact latency or full qualification claim follows. The runner's ordinary orphan-process cleanup is not a complete descendant certificate.

Artifact 10605067600 was downloaded and its 3,362,505 original ZIP bytes independently verified against SHA-256 `eac2a44966fe442bf4f5071602718861ff3bc4f691780215ec1698976d8fac11`. All 55 members passed CRC/size/hash reads. All 54 text members and the exact 401,743-byte original job log are retained here. All 41 framed log bodies match archive bytes. The 11,389,440-byte diagnostic runtime was read and hashed from the archive as `ba541074b9ecfd4e1a97be1d3833c960c188f1457ce3e5ca86a0836f1fb781f0`, matching the unchanged runner digest. Large ZIP/runtime bytes are excluded from this small Git packet; their identities remain explicit. Offline verification performed no native execution, separate from the hosted controls that did execute.

The first attempt's four type errors and second attempt's one projector type error remain in their original evidence trees. Both stopped before controls or the original selector. The v3 source is unchanged from v2; its only code correction is the reviewed local `dict[str, object]` annotation, with a unique branch binding. No product PR or evidence branch was changed by this diagnostic.
''')
put('verify_terminal_packet.py', pathlib.Path(__file__).read_bytes())
rows=[]
for p in sorted(OUT.rglob('*')):
    if p.is_file():
        data=p.read_bytes(); rows.append({'path':str(p.relative_to(OUT)),'bytes':len(data),'sha256':sha(data),'git_blob':blob(data)})
js('MANIFEST.json', {'schema':'pr2974-text-packet.v1','files':rows,'file_count_excluding_manifest':len(rows),'bytes_excluding_manifest':sum(r['bytes'] for r in rows),'source_of_bytes':'Original GitHub job log/API records and independently verified original archive; derived records explicitly named.','large_originals_excluded':['10605067600.zip','runtime/hol-guard-runtime.exe']})
print(json.dumps({'directory':str(OUT),'files':len(rows)+1,'bytes':sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file()),'summary_sha256':sha((OUT/'VERIFIED-RESULT.json').read_bytes())}))
