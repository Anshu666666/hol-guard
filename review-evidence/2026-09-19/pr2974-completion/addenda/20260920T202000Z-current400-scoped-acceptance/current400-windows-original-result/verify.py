import resource
resource.setrlimit(resource.RLIMIT_AS,(192*1024*1024,192*1024*1024))
import collections,hashlib,json,pathlib,re,xml.etree.ElementTree as ET,zipfile
root=pathlib.Path('/workspace/scratch/745337b67ff9/windows-normal-4001185')
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

source=parse((root/'metadata/source-commit.json').read_text());merge=parse((root/'metadata/test-merge-commit.json').read_text())
assert source['sha']=='4001185e4f39cad51fd5eab314bf02b86b8a1674'
assert merge['sha']=='37fd05b37685d0f4b37f836608820cf577a06602'
assert source['tree']['sha']==merge['tree']['sha']=='7a328609488ffefecd3cdd12a9c7adba6a591e97'
assert [x['sha']for x in source['parents']]==['a5fdde302aba2a06265c2e6e934b6ac9b76750df']
assert [x['sha']for x in merge['parents']]==['4b89e0d2d496a85f04922b2e019a4aea15326bb9',source['sha']]
archives=[]
metadata=parse((root/'metadata/native-artifacts.json').read_text())['artifacts']
for artifact in (10611104153,10611094102):
 proof=parse((root/f'{artifact}.manifest.json').read_text());body=(root/f'{artifact}.zip').read_bytes();meta=next(x for x in metadata if x['id']==artifact)
 assert len(body)==proof['archive_bytes']==meta['size_in_bytes'] and digest(body)==proof['archive_sha256']==meta['digest'].split(':')[1]
 with zipfile.ZipFile(root/f'{artifact}.zip') as z:
  assert set(z.namelist())=={x['path']for x in proof['members']}
  for row in proof['members']:
   original=z.read(row['path']);retained=(root/str(artifact)/'raw'/row['path']).read_bytes();assert original==retained and len(original)==row['bytes'] and digest(original)==row['sha256']
 archives.append(proof)
failure=parse((root/'10611104153/raw/native-default-auto-failure.json').read_text())
assert failure['schema']=='hol-guard.native-default-auto-failure.v1' and failure['passed'] is False and failure['qualification'] is False
assert failure['required_native_decisions']==21 and len(failure['deliveries'])==21
assert [r['index']for r in failure['deliveries']]==list(range(21))
assert failure['corpus']['routes']=={'native_resident':20}
assert failure['corpus']['receipt_counts']=={'receipt_accepted':20,'receipt_deduped':0,'receipt_dropped':0,'receipt_durable_pending':0,'receipt_failures':0,'receipt_processed':20}
assert failure['corpus']['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
assert failure['expected_build_sha']==failure['installed_identity']['build_sha']==merge['sha']
assert failure['original_failure_category']=='RuntimeError' and failure['primary_failure_before_cleanup'] is None and failure['detail_incomplete'] is False
native_log=(root/'logs/job-106131976672.log').read_text();resident_log=(root/'logs/job-106131977141.log').read_text()
assert 'routes'+"': {'native_resident': 20}" in native_log
assert '5 passed in 4.90s' in resident_log and '201 passed; 0 failed; 2 ignored' in resident_log
assert merge['sha'] in native_log and merge['sha'] in resident_log
clean='\n'.join(re.sub(r'^\d{4}-\d\d-\d\dT\S+ ', '',x) for x in native_log.splitlines());decoder=json.JSONDecoder(object_pairs_hook=unique);logged={}
for match in re.finditer(r'(?m)^\{',clean):
 try:value,_=decoder.raw_decode(clean[match.start():])
 except ValueError:continue
 if isinstance(value,dict) and 'schema' in value:
  assert value['schema'] not in logged;logged[value['schema']]=value
identity=logged['hol-guard.installed-runtime-identity.v1'];lock=logged['hol-guard.installed-command-control-lock.v1']
assert identity['build_sha']==merge['sha'] and identity['runtime_sha256']==failure['installed_identity']['runtime_sha256'] and identity['runtime_size']==failure['installed_identity']['runtime_size']
assert len(identity['cases'])==17 and all(row['result'] in ('passed','replaced')for row in identity['cases'])
assert len(lock['cases'])==4 and [row['child_acquired']for row in lock['cases']]==[True,False,False,False] and all(row['released']for row in lock['cases'])
for kind,job,conclusion in [('native',106131976672,'failure'),('resident',106131977141,'success')]:
 row=next(x for x in parse((root/f'metadata/{kind}-jobs.json').read_text())['jobs'] if x['id']==job);assert row['status']=='completed' and row['conclusion']==conclusion
windows=True
data=(root/'10611094102/raw/windows-private-authority-controls.xml').read_bytes();assert len(data)<=8_000_000 and b'<!DOCTYPE' not in data and b'<!ENTITY' not in data
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

report={'schema':'pr2974.4001185-normal-windows.v1','source_sha':source['sha'],'source_tree':source['tree']['sha'],'test_merge_build_sha':merge['sha'],'same_source_tree':True,'archives':archives,'installed_default_auto_failure':failure,'logged_installed_identity':identity,'logged_installed_control_lock':lock,'private_authority_controls':{'suite':suite.attrib,'counts':{'total':152,'passed':149,'skipped':3,'failed':0,'errors':0,'mandatory_windows':53,'child_frames':90,'wtext_pairs':18},'module_counts':module_counts,'case_identities':[{'module':a,'name':b}for a,b in identities],'child_joins':joins,'WTEXT_pairs':pairs,'actual_held_reader_controls':held,'documented_native_error_contract':failure_rows,'existing_manager_selector_passed':True},'normal_resident_log_scope':{'job_id':106131977141,'status':'success','tests_passed':5,'duration_seconds':4.90,'runtime_rust_tests_passed':201,'runtime_rust_tests_ignored':2,'artifacts_retained':0,'binary_hash_retained':False},'logs':{p.name:{'bytes':len(p.read_bytes()),'sha256':digest(p.read_bytes())}for p in (root/'logs').iterdir()},'limits':['The installed default-auto gate failed:21 delivery records but only20 native routes/accepted/processed receipts. No rerun or requirement change.','This archive has no wheel or runtime executable. Runtime identity agrees across the original log and failure report but cannot be independently rehashed.','Private-authority152/149/3 and resident5pass are separate source-test successes; neither overrides the installed default-auto failure.','Failure capture contains no before/after route counter per delivery, raw response reason, native operation leaf or durable database. OMPPost allow/other is only a source lead; no missing route or cause is assigned.','Current empty persistence error maps do not explain any historical journal/receipt/command failure.','Resident fixture used a separate release build whose executable bytes/hash were not retained.','No performance, full installed qualification, cross-release rollback or signing claim follows.']}
(root/'verified-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'source':source['sha'],'native_gate':'failed20of21','private_controls':report['private_authority_controls']['counts'],'resident':report['normal_resident_log_scope']}))
