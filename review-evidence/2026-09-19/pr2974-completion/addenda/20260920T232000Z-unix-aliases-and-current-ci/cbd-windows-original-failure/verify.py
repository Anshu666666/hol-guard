import resource
resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
import collections,hashlib,json,pathlib,xml.etree.ElementTree as ET,zipfile
root=pathlib.Path(__file__).resolve().parent
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


def verify():
    source=parse((root/'metadata/source-commit.json').read_text())
    merge=parse((root/'metadata/build-commit.json').read_text())
    assert source['sha']=='cbd9399e39adc4fe338bff468807656ebab3af13'
    assert merge['sha']=='ef40a5833b75109593755ca3a4e74f9b2a193caa'
    assert source['tree']['sha']==merge['tree']['sha']=='3c59e6f81f531e7b4496ae49a278c9ddf3961380'
    assert [x['sha'] for x in source['parents']]==['a1d509404b0803a91031cb51f4b0c919408bfeba']
    assert [x['sha'] for x in merge['parents']]==['4b89e0d2d496a85f04922b2e019a4aea15326bb9',source['sha']]
    metadata=parse((root/'metadata/artifacts.json').read_text())['artifacts']
    archive_records=[]
    for artifact in (10614672882,10614652993):
     folder=root/str(artifact);record=parse((folder/'verification.json').read_text());body=(folder/'artifact.zip').read_bytes();remote=next(x for x in metadata if x['id']==artifact)
     assert len(body)==record['archive_bytes']==remote['size_in_bytes']
     assert digest(body)==record['archive_sha256']==remote['digest'].split(':')[1]
     with zipfile.ZipFile(folder/'artifact.zip') as z:
      assert z.namelist()==[x['path'] for x in record['members']]
      for member in record['members']:
       body=(folder/'raw'/member['path']).read_bytes();assert body==z.read(member['path'])
       assert len(body)==member['bytes'] and digest(body)==member['sha256']
     archive_records.append(record)
    source_manifest=parse((root/'source-manifest.json').read_text());leaves={x['path']:x for x in parse((root/'metadata/selected-source-tree.json').read_text())['tree']}
    for row in source_manifest['files']:
     body=(root/'source'/row['path']).read_bytes();assert len(body)==row['bytes'] and digest(body)==row['sha256']
     assert hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==row['git_blob']==leaves[row['path']]['sha']
    failure=parse((root/'10614672882/raw/native-default-auto-failure.json').read_bytes())
    assert failure['passed'] is False and failure['qualification'] is False and failure['detail_incomplete'] is False
    assert failure['required_native_decisions']==21 and failure['allowed_fail_safe_decisions']==0
    assert failure['expected_build_sha']==failure['installed_identity']['build_sha']==merge['sha']
    assert failure['corpus']['routes']=={'native_resident':20,'native_fail_safe':1}
    assert failure['corpus']['receipt_counts']=={'receipt_accepted':20,'receipt_deduped':0,'receipt_dropped':0,'receipt_durable_pending':0,'receipt_failures':0,'receipt_processed':20}
    assert failure['corpus']['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
    assert failure['corpus']['client_context']=={'code':None,'daemon_worker_attribution':False,'scope':'probe_context_only'}
    assert failure['corpus']['capture_boundary']=='before_mode_changes_and_daemon_cleanup'
    assert len(failure['deliveries'])==21 and [r['index'] for r in failure['deliveries']]==list(range(21))
    assert all(r['response_present'] and r['publisher_attribution']=='state_observed_after_delivery_not_request_cause' for r in failure['deliveries'])
    unavailable=[r for r in failure['deliveries'] if r['reason_code']=='native_post_tool_unavailable']
    assert len(unavailable)==1 and unavailable[0]['index']==1 and unavailable[0]['harness']=='claude-code' and unavailable[0]['event']=='PostToolUse'
    assert failure['original_failure_category']=='RuntimeError' and failure['primary_failure_before_cleanup'] is None
    assert not any(x['name']=='hol-guard-native-wheel-windows-x64' for x in metadata)
    compare=parse((root/'metadata/a1-cbd-compare.json').read_text());assert compare['ahead_by']==1
    assert [(x['filename'],x['status']) for x in compare['files']]==[('rust/crates/guard-runtime/src/resident_transport.rs','modified'),('rust/crates/guard-runtime/src/resident_transport_peer_identity_tests.rs','added')]
    assert '#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]' in compare['files'][0]['patch']
    windows=True
    data=(root/'10614652993/raw/windows-private-authority-controls.xml').read_bytes();assert len(data)<=8_000_000 and b'<!DOCTYPE' not in data and b'<!ENTITY' not in data
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
    native_log=(root/'logs/native.log').read_text()
    resident_log=(root/'logs/resident.log').read_text()
    assert '149 passed, 3 skipped' in native_log and '40 passed in 6.38s' in native_log
    assert '5 passed in 5.10s' in resident_log and '201 passed; 0 failed; 2 ignored' in resident_log
    assert 'observed_routes.get("native_resident") == expected' in native_log
    assert "'routes': {'native_resident': 20, 'native_fail_safe': 1}" in native_log
    identity=failure['installed_identity'];assert identity['runtime_sha256']=='f561fbf102bf6177dbd8032535a710991c47694988e68ee1923fbffe36ef948a' and identity['runtime_size']==11347968
    assert identity['runtime_sha256'] in native_log
    for log in (native_log,resident_log):
     caps=[parse(line[line.index('{'):])['capabilities'] for line in log.splitlines() if '{"capabilities":{' in line and '"ok":true}' in line]
     assert len(caps)==1 and caps[0]['build_sha']==merge['sha'] and caps[0]['rule_digest']==identity['rule_digest']
    logs={p.name:{'bytes':len(p.read_bytes()),'sha256':digest(p.read_bytes())}for p in (root/'logs').iterdir()}
    report={'schema':'pr2974.cbd-normal-windows-failure.v1','source_sha':source['sha'],'source_tree':source['tree']['sha'],'test_merge_build_sha':merge['sha'],'same_source_tree':True,'archive_records':archive_records,'original_failure':failure,'private_authority_controls':{'suite':suite.attrib,'counts':{'total':152,'passed':149,'skipped':3,'failed':0,'errors':0,'mandatory_windows':53,'child_frames':90,'wtext_pairs':18},'module_counts':module_counts,'case_identities':[{'module':a,'name':b}for a,b in identities],'child_joins':joins,'WTEXT_pairs':pairs,'actual_held_reader_controls':held,'documented_native_error_contract':failure_rows,'existing_manager_selector_passed':True},'normal_resident_log_scope':{'job_id':106160019954,'status':'success','tests_passed':5,'duration_seconds':5.10,'runtime_rust_tests_passed':201,'runtime_rust_tests_ignored':2,'artifacts_retained':0,'binary_hash_retained':False},'source_bindings':source_manifest,'logs':logs,'failed_predicate':'observed_routes.get(native_resident) == expected21 at probe line291','offered_scope':{'corpus_deliveries_retained':21,'unique_unavailable_response':{'index':1,'harness':'claude-code','event':'PostToolUse','reason_code':'native_post_tool_unavailable'},'native_resident':20,'native_fail_safe':1,'native_receipts_accepted_processed':20,'receipt_final_assertion_reached':False,'final_disabled_mode_assertion_reached':False,'successful_receipt_or_native_wheel_uploaded':False},'limits':['The unique unavailable response identifies the visible affected delivery. No per-delivery native request/error/route counter join or lower operation cause is captured.','Publisher ACK/availability are after-delivery observations. Null client context explicitly has no daemon-worker attribution; empty persistence counters do not prove a transport/policy/deadline cause or absence.','All21 delivery records and aggregate route/receipt observations remain failed qualification; none are reclassified by source149/3 or separate resident5 passes.','The installed runtime hash/size/build are retained in original failure/log only; wheel and executable bytes were not uploaded. Separate resident release executable has no retained hash either.','cbd differs from prior a1 only by cfg(test,Linux/macOS) Rust controls; no Windows production change is demonstrated. Different actual build/runtime identity is retained honestly.','Current normal a1 success and prior40020/21 failure remain separate observations; no blind rerun, deadline/policy change or cause-specific repair occurred.']}
    return report

if __name__=='__main__':
 result=verify()
 (root/'verified-result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'source':result['source_sha'],'build':result['test_merge_build_sha'],'controls':result['private_authority_controls']['counts'],'failure':result['offered_scope']}))
