from pathlib import Path
import base64, gzip, hashlib, json, re, subprocess

ROOT = Path(__file__).resolve().parent
GIT = ['git', '--git-dir', str(ROOT.parent / 'normal400-posix/source.git')]
HEAD = '4001185e4f39cad51fd5eab314bf02b86b8a1674'
TREE = '7a328609488ffefecd3cdd12a9c7adba6a591e97'
PRIOR = 'a0c139c4e02535545c5b0e602c240a38affde5fe'
def git(*args):
    return subprocess.check_output([*GIT, *args])
def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
def identity(data):
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(), 'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}
overlay = json.loads((ROOT.parent/'root-checkpoint/a5fd-progress-docs/task-status-overlay.json').read_text())
tasks = overlay['tasks']
selected = [x for x in tasks if x['number'] in [38,39,41,43,46,47,48]]
write(ROOT/'task-clauses.json',selected)
assert git('rev-parse', HEAD+'^{tree}').decode().strip() == TREE
assert git('rev-parse', '37fd05b37685d0f4b37f836608820cf577a06602^{tree}').decode().strip() == TREE
paths = '''rust/crates/guard-runtime/src/resident_protocol.rs
rust/crates/guard-runtime/src/resident_transport.rs
rust/crates/guard-runtime/src/strict_json.rs
rust/crates/guard-runtime/src/managed_resident.rs
rust/crates/guard-runtime/src/managed_resident_client_stream.rs
rust/crates/guard-runtime/src/managed_resident_deadline_tests.rs
rust/crates/guard-runtime/src/resident_client.rs
rust/crates/guard-runtime/src/resident_client_deadline_tests.rs
rust/crates/guard-runtime/src/resident_client_connect_deadline_tests.rs
rust/crates/guard-runtime/src/edge.rs
rust/crates/guard-runtime/src/edge_tests.rs
rust/crates/guard-runtime/src/edge_identity.rs
rust/crates/guard-runtime/src/edge_identity_tests.rs
rust/crates/guard-runtime/src/edge_serialization.rs
rust/crates/guard-runtime/src/edge_serialization_tests.rs
rust/crates/guard-runtime/src/native_hook_receipt.rs
rust/crates/guard-runtime/src/policy_enforcement.rs
rust/crates/guard-runtime/src/policy_enforcement_admission.rs
rust/crates/guard-runtime/src/policy_enforcement_policy.rs
rust/crates/guard-runtime/src/policy_enforcement_tests.rs
rust/crates/guard-runtime/src/policy_store.rs
rust/crates/guard-runtime/src/policy_store_request.rs
rust/crates/guard-runtime/src/policy_store_approval.rs
rust/crates/guard-runtime/src/policy_store_tests.rs
rust/crates/guard-runtime/src/approval_v3_lifecycle_tests.rs
rust/crates/guard-runtime/src/edge_encrypted.rs
rust/crates/guard-runtime/src/edge_encrypted_file.rs
rust/crates/guard-runtime/src/edge_encrypted_tests.rs
rust/crates/guard-runtime/src/edge_encrypted_file_tests.rs
rust/crates/guard-hook-core/src/lib.rs
rust/crates/guard-hook-core/src/output.rs
rust/crates/guard-hook-core/src/output_reference_tests.rs
rust/crates/guard-scanner/src/lib.rs
rust/crates/guard-scanner/src/prefilter_bench_tests.rs
rust/crates/guard-rule-contract/src/lib.rs
rust/crates/guard-policy-snapshot/src/policy_snapshot_tests.rs
rust/crates/guard-secure-fs/src/lib.rs
ci/native_runtime/test_command_model_differential.py
ci/native_runtime/test_guard_native_runtime_differential.py
ci/native_runtime/test_guard_native_runtime_mutation_differential.py
scripts/integration/rust_pretool_adversarial.py
.github/workflows/rust-runtime.yml'''.splitlines()
source=[]
for path in paths:
    data=git('show',HEAD+':'+path)
    leaf=ROOT/'source'/path; leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(data)
    try: old=git('rev-parse',PRIOR+':'+path).decode().strip()
    except subprocess.CalledProcessError: old=None
    source.append({'path':path,**identity(data),'prior_124_blob':old,'unchanged_from_124':old==identity(data)['git_blob']})
write(ROOT/'source-manifest.json',{'head':HEAD,'tree':TREE,'test_merge':'37fd05b37685d0f4b37f836608820cf577a06602','prior_rust_tree':PRIOR,'selected_files':source,'all_rust_delta_since_124':git('diff','--name-status',PRIOR,TREE,'--','rust').decode().splitlines()})
log=(ROOT/'originals/job-106131977317.log').read_text()
rows=[]; binary=None; suites=[]
for n,line in enumerate(log.splitlines(),1):
    m=re.search(r'Running (.+)',line)
    if m: binary=m.group(1)
    m=re.search(r' test (.+) \.\.\. (ok|ignored|FAILED)(.*)$',line)
    if m: rows.append({'line':n,'binary':binary,'name':m[1],'status':m[2],'detail':m[3]})
    m=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',line)
    if m:suites.append({'line':n,'binary':binary,'status':m[1],'passed':int(m[2]),'failed':int(m[3]),'ignored':int(m[4])})
assert sum(x['passed'] for x in suites)==341 and sum(x['ignored'] for x in suites)==6
assert len([x for x in rows if x['status']=='ok'])==341 and not any(x['failed'] for x in suites)
write(ROOT/'current-workspace-rows.json',{'suites':suites,'rows':rows,'passed':341,'ignored':6,'failed':0,'method':'Read retained original log text only; no test command executed.'})
encoded=[]
for path in sorted((ROOT/'originals').glob('job-*.log')):
    data=path.read_bytes(); zipped=gzip.compress(data,mtime=0); b64=base64.b64encode(zipped).decode()
    part=ROOT/'encoded'/(path.name+'.gz.b64');part.parent.mkdir(exist_ok=True);part.write_text(b64+'\n')
    assert gzip.decompress(base64.b64decode(part.read_text()))==data
    encoded.append({'original':str(path.relative_to(ROOT)),'encoded':str(part.relative_to(ROOT)),**identity(data),'encoded_identity':identity(part.read_bytes()),'encoding':'gzip+base64','provenance':'GitHub decoded job-log text retained losslessly as UTF-8, including initial BOM; not original HTTP compressed bytes'})
write(ROOT/'log-manifest.json',encoded)
print(json.dumps({'source_files':len(source),'logs':len(encoded),'passed':341,'ignored':6,'rust_delta':len(git('diff','--name-only',PRIOR,TREE,'--','rust').decode().splitlines())}))
