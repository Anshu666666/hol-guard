import resource
resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
import collections,hashlib,json,pathlib,xml.etree.ElementTree as ET,zipfile
root=pathlib.Path('/workspace/scratch/745337b67ff9/windows-normal-ad9d')
def unique(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise ValueError('duplicate_json_key')
        out[k]=v
    return out
def parse(text):return json.loads(text,object_pairs_hook=unique)
def digest(body):return hashlib.sha256(body).hexdigest()
def props(case):
    out={}
    for p in case.findall('./properties/property'):
        k=p.attrib['name'];assert k not in out
        out[k]=p.attrib['value']
    return out
def native(case):
    module=case.attrib['classname'].rsplit('.',1)[-1]
    if module=='test_guard_daemon_manager':return case.attrib['name']=='test_daemon_token_and_state_use_atomic_replacement'
    return module in ('test_windows_replaceable_reader_process','test_windows_atomic_replace_process') or (module=='test_windows_wtext_acceptance_probe' and case.attrib['name'].startswith(('test_supported_wtext_default_preserves_original_read','test_original_audit_can_enter_wtext')))

source=parse((root/'metadata/source-commit.json').read_text())
merge=parse((root/'metadata/test-merge-commit.json').read_text())
assert source['sha']=='ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d'
assert merge['sha']=='be612a3e562a2041b3732a33c158eeae4f1dad40'
assert source['tree']['sha']==merge['tree']['sha']=='19977465d6e419f1276d75fb6bd1b3477f5c9720'
assert [x['sha']for x in merge['parents']]==['4b89e0d2d496a85f04922b2e019a4aea15326bb9',source['sha']]
leaves={x['path']:x for x in parse((root/'metadata/selected-source-leaves.json').read_text())['tree']}
archive_records=[]
for artifact in (10606624387,10606509417):
 folder=root/str(artifact);verification=parse((folder/'verification.json').read_text())
 assert digest((folder/'artifact.zip').read_bytes())==verification['archive_sha256']
 for member in verification['members']:
  body=(folder/'raw'/member['path']).read_bytes()
  assert len(body)==member['bytes'] and digest(body)==member['sha256']
 archive_records.append(verification)
raw=root/'10606624387/raw'
identity=parse((raw/'native-installed-identity.json').read_text())
default=parse((raw/'native-default-auto.json').read_text())
lock=parse((raw/'native-installed-control-lock.json').read_text())
wheel=next((raw/'native-dist').glob('*.whl'))
wheel_proofs=[]
with zipfile.ZipFile(wheel)as z:
 runtime=z.read('codex_plugin_scanner/_native/hol-guard-runtime.exe')
 manifest_body=z.read('codex_plugin_scanner/_native/runtime-manifest.json')
 manifest=parse(manifest_body.decode())
 assert len(runtime)==identity['runtime_size']==manifest['runtime_size']
 assert digest(runtime)==identity['runtime_sha256']==manifest['runtime_sha256']
 assert digest(manifest_body)==identity['manifest_sha256']
 assert identity['build_sha']==manifest['source_sha']==merge['sha']
 assert manifest['package_version']==identity['package_version']=='3.0.1'
 assert manifest['rule_digest']=='e9d2024f94d91cb5ae1a9d8e8c60a398f24bf1af7767c578e1997f33cc98a32a'
 paths=['guard/private_file_io.py','guard/adapters/codex_daemon_hook_auth.py','guard/windows_replaceable_file.py','guard/windows_atomic_replace.py','guard/daemon/manager_pending_launch.py','guard/native_runtime.py','guard/native_runtime_identity.py']
 for path in paths:
  member='codex_plugin_scanner/'+path;body=z.read(member);lf=body.replace(b'\r\n',b'\n');source_path='src/'+member
  sha=hashlib.sha1(b'blob '+str(len(lf)).encode()+b'\0'+lf).hexdigest()
  assert sha==leaves[source_path]['sha']
  wheel_proofs.append({'member':member,'bytes':len(body),'sha256':digest(body),'source_git_blob':sha,'source_normalization':'CRLF to LF'})
  if path=='guard/native_runtime.py':assert digest(body)==identity['runtime_module_sha256']
  if path=='guard/native_runtime_identity.py':assert digest(body)==identity['identity_module_sha256']
assert len(identity['cases'])==17 and all(c['result'] in ('passed','replaced')for c in identity['cases'])
assert identity['cross_release_upgrade_rollback']==identity['signing_qualification']=='not_exercised'
assert default['corpus_decisions']==default['resident_decisions']==21
assert default['resident_share']==1.0 and default['runtime_reason']=='native_ready'
assert default['default_mode']=='auto' and default['fast_path']=='enabled' and default['rollback']=='off'
assert default['receipt_metrics']=={'accepted':21,'deduped':0,'dropped':0,'durable_pending':0,'failures':0,'processed':21}
assert default['evidence_failure_diagnostics']=={'all_evidence':{'journal_checkpoint/os_permission':1},'native_receipts':{}}
assert len(default['route_receipts'])==21 and all(x['route']=='native_resident'for x in default['route_receipts'])
assert len(lock['cases'])==4 and all(x['released']for x in lock['cases'])
assert [x['child_acquired']for x in lock['cases']]==[True,False,False,False]
windows=True
data=(root/'10606509417/raw/windows-private-authority-controls.xml').read_bytes();assert len(data)<=8_000_000 and b'<!DOCTYPE' not in data and b'<!ENTITY' not in data
xml=ET.fromstring(data);suite=xml.find('testsuite');cases=xml.findall('.//testcase');assert len(cases)==152
identities=[(c.attrib['classname'],c.attrib['name']) for c in cases];assert len(set(identities))==152
module_counts=dict(collections.Counter(c.attrib['classname'].rsplit('.',1)[-1] for c in cases))
expected={'test_guard_daemon_manager':1,'test_guard_private_file_io':7,'test_private_reader_descriptor_guards':12,'test_windows_replaceable_file':37,'test_windows_replaceable_reader_process':20,'test_windows_replaceable_unicode_crt':12,'test_windows_wtext_acceptance_probe':22,'test_windows_atomic_replace':27,'test_windows_atomic_replace_process':14}
assert module_counts==expected and sum(native(c) for c in cases)==53
skipped=[c for c in cases if c.find('skipped') is not None];failed=[c for c in cases if c.find('failure') is not None];errored=[c for c in cases if c.find('error') is not None]
assert not errored
if windows:
    assert len(skipped)==3 and not any(native(c) for c in skipped)
    assert not failed
else:
    assert len(skipped)==52 and all(native(c) for c in skipped) and not failed
assert int(suite.attrib['tests'])==len(cases) and int(suite.attrib['failures'])==len(failed) and int(suite.attrib['skipped'])==len(skipped)
joins=[];pairs=[];held=[];failure_rows=[]
for case in cases:
    values=props(case);reports={}
    for label,value in values.items():
        if not label.startswith(('child_capture_','wtext_child_')):continue
        capture=parse(value);body=capture['stdout_content'].encode('utf-8')
        assert len(body)==capture['stdout_bytes'] and digest(body)==capture['stdout_sha256']
        assert capture['stderr_bytes']==0 and not capture['timed_out'] and not capture['kill_requested'] and capture['cleanup_error'] is None
        wtext=label.startswith('wtext_child_');assert capture['retired' if wtext else 'process_retired']
        report=parse(body)
        if wtext:
            assert capture['return_code']==0 and report==capture['report']
            assert report['observation_complete'] and report['operation_calls']==1 and len(report['events'])==1
            assert report['default_mode_restored'] and report['cleanup_error'] is None and report['reader_import_binding_verified'] and not report['qualification']
        else:
            assert capture['report_valid'] and capture['return_code'] in (0,1)
            suffix=label.removeprefix('child_capture_');names=[x for x in (suffix+'_report',suffix+'_writer_report') if x in values]
            assert names and all(parse(values[x])==report for x in names)
        joins.append({'case':case.attrib['name'],'label':label,'stdout_bytes':len(body),'stdout_sha256':digest(body),'return_code':capture['return_code'],'retired':True})
        reports[label]=report
    if 'wtext_child_original' in reports:
        original=reports['wtext_child_original'];candidate=reports['wtext_child_candidate']
        assert original['candidate'] is False and candidate['candidate'] is True
        assert {k:v for k,v in original.items() if k!='candidate'}=={k:v for k,v in candidate.items() if k!='candidate'}
        pairs.append({'case':case.attrib['name'],'error':original.get('error'),'parity':True})
    if windows and case.attrib['name'].startswith('test_actual_readers_allow_other_process'):
        assert case.find('failure') is None and case.find('skipped') is None
        assert values['reader_retired']==values['reader_descriptor_closed']==values['writer_is_separate_process']=='True'
        report=parse(values['writer_report']);assert report['writer_calls']==report['replace_calls']==1
        assert report['writer_locked'] and report['writer_fd_closed_before_replace'] and report['temporary_siblings_removed'] and report['original_exception_identity_preserved']
        probe=report['probe'];assert probe['volume_queries']==1 and probe['volume_query_succeeded'] and probe['volume_flags']&0x400 and probe['owned_handles_remaining']==0
        negative='separate_crt_source' in case.attrib['name']
        if negative:
            assert report['error']=={'kind':'PermissionError','errno':13,'winerror':32} and probe['rename_calls']==0 and probe['first_failed_operation']=='source_open'
        else:
            assert report['error'] is None and probe['rename_calls']==1 and probe['rename_returned']
        held.append({'case':case.attrib['name'],'error':report['error'],'probe':probe,'reader_retired':True,'reader_descriptor_closed':True,'single_writer_attempt':True})
    if case.attrib['name']=='test_actual_writer_matches_original_destination_outcomes[crt_destination]':
        assert case.find('failure') is None and case.find('skipped') is None
        original=parse(values['original_writer_report']);candidate=parse(values['candidate_writer_report'])
        assert original['reference_writer'] and original['error']=={'kind':'PermissionError','errno':13,'winerror':5}
        assert not candidate['reference_writer'] and candidate['error']=={'kind':'PermissionError','errno':13,'winerror':32}
        assert 'child_capture_original' in values and 'child_capture_candidate' in values
        for arm,report in [('original',original),('candidate',candidate)]:
            assert values[arm+'_destination_crt_reader_closed']==values[arm+'_temporary_siblings_removed']=='True'
            assert int(values[arm+'_writer_exit_code'])==1
            assert report['writer_calls']==report['replace_calls']==1 and not report['replace_returned']
            assert report['original_exception_identity_preserved'] and report['writer_fd_closed_before_replace'] and report['writer_locked']
            assert report['probe']['owned_handles_remaining']==0
        assert candidate['probe']['first_failed_operation']=='rename' and candidate['probe']['rename_calls']==1 and not candidate['probe']['rename_returned']
        assert values['original_candidate_exact_result_parity']=='False'
        assert values['original_candidate_compatibility']=='True'
        assert parse(values['native_error_codes'])=={'MoveFileExW':5,'FileRenameInfoEx':32}
        left={k:v for k,v in original.items() if k not in ('probe','reference_writer')}
        right={k:v for k,v in candidate.items() if k not in ('probe','reference_writer')}
        assert {k:v for k,v in left.items() if k!='error'}=={k:v for k,v in right.items() if k!='error'}
        assert {k:v for k,v in left['error'].items() if k!='winerror'}=={k:v for k,v in right['error'].items() if k!='winerror'}
        failure_rows.append({'case':case.attrib['name'],'original_report':original,'candidate_report':candidate,'original_exit_code':1,'candidate_exit_code':1,'candidate_arm_executed':True,'both_destination_readers_closed':True,'both_temporary_siblings_removed':True,'exact_result_parity':False,'only_observed_result_difference':'original WinError5 versus candidate WinError32','documented_native_error_difference':True,'compatibility_assertion_passed':True})
assert len(joins)==(90 if windows else 0) and len(pairs)==(18 if windows else 0)
assert len(joins)==90 and len(pairs)==18 and len(held)==4 and len(failure_rows)==1
selected=[c for c in cases if c.attrib['name']=='test_daemon_token_and_state_use_atomic_replacement']
assert len(selected)==1 and all(selected[0].find(k)is None for k in ('failure','error','skipped'))
logs={p.name:{'bytes':len(p.read_bytes()),'sha256':digest(p.read_bytes())}for p in (root/'logs').iterdir()}
report={'schema':'pr2974.ad9d-normal-windows.v1','source_sha':source['sha'],'source_tree':source['tree']['sha'],'test_merge_build_sha':merge['sha'],'same_source_tree':True,'archive_records':archive_records,'wheel_identity':{'runtime_sha256':digest(runtime),'runtime_bytes':len(runtime),'manifest_sha256':digest(manifest_body),'manifest':manifest,'verified_source_modules':wheel_proofs},'installed_identity':identity,'installed_default_auto':default,'installed_control_lock':lock,'private_authority_controls':{'suite':suite.attrib,'counts':{'total':152,'passed':149,'skipped':3,'failed':0,'errors':0,'mandatory_windows':53,'child_frames':90,'wtext_pairs':18},'module_counts':module_counts,'case_identities':[{'module':a,'name':b}for a,b in identities],'child_joins':joins,'WTEXT_pairs':pairs,'actual_held_reader_controls':held,'documented_native_error_contract':failure_rows,'existing_manager_selector_passed':True},'normal_resident_log_scope':{'job_id':106093201942,'source_fixture_tests':5,'passed':5,'binary_hash_retained':False,'artifact_list_empty':True},'logs':logs,'limits':['The ordinary private-reader controls are source tests; installed validation is the separate retained identity/control-lock/default-auto scope.','journal_checkpoint/os_permission:1 remains unresolved; this is not all-evidence zero-error.','Resident source fixture used a separate release build without retained executable bytes/hash.','No speedup, expanded corpus, cross-release rollback or signing qualification follows.','Native errors preserve original WinError5/candidate WinError32; no full raw-code parity claim.']}
(root/'verified-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'source_sha':source['sha'],'build_sha':merge['sha'],'wheel_verified_modules':len(wheel_proofs),'private_controls':report['private_authority_controls']['counts'],'native_receipts':default['receipt_metrics'],'all_evidence':default['evidence_failure_diagnostics']['all_evidence'],'xml_sha256':digest(data)}))
