import resource
resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
import collections,hashlib,json,pathlib,xml.etree.ElementTree as ET
root=pathlib.Path('/workspace/scratch/745337b67ff9/windows-product-run35511038686')
source=pathlib.Path('/workspace/scratch/745337b67ff9/windows-product-candidate-124472')
tree={x['path']:x['sha'] for x in json.loads((root/'source-tree-leaves.json').read_text())}
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
    return module in ('test_windows_replaceable_reader_process','test_windows_atomic_replace_process') or (module=='test_windows_wtext_acceptance_probe' and case.attrib['name'].startswith(('test_supported_wtext_default_preserves_original_read','test_original_audit_can_enter_wtext')))
rows=[]
for artifact in (10605980519,10605107148,10605251017):
    folder=root/str(artifact);raw=folder/'raw';verification=parse((folder/'verification.json').read_text())
    assert digest((folder/'artifact.zip').read_bytes())==verification['archive_sha256']
    for m in verification['members']:
        data=(raw/m['path']).read_bytes();assert len(data)==m['bytes'] and digest(data)==m['sha256']
    before=parse((raw/'source-before.json').read_text());after=parse((raw/'source-after.json').read_text())
    assert before['phase']=='before' and after['phase']=='after'
    compared={k:before[k]==after[k] for k in before if k!='phase'};assert all(compared.values())
    assert before['source_sha']=='9b479556a7a98f43826625ccac495875fc4f061a'
    assert before['source_tree']=='63272e173903e23cec374c76d78e7f115921f58c'
    assert before['driver_sha']=='e116a3d1dbe04a73e917fbb3de1f1b700c86ee19'
    assert before['driver_tree']=='bc12e60e6e01c0c8eccfdd725b245775a48b4593'
    assert before['source_clean'] and before['driver_clean'] and before['imports_from_pinned_source']
    checked=[];windows=before['platform']=='Windows'
    for f in before['source_files']:
        body=(source/f['path']).read_bytes()
        assert hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==tree[f['path']]
        assert len(body)==f['git_blob_bytes'] and digest(body)==f['git_blob_sha256']
        checkout=body.replace(b'\n',b'\r\n') if windows else body
        assert len(checkout)==f['checkout_bytes'] and digest(checkout)==f['checkout_sha256']
        checked.append({'path':f['path'],'git_blob':tree[f['path']],'lf_sha256':digest(body),'checkout_sha256':digest(checkout),'line_endings':'CRLF' if windows else 'LF'})
    assert len(checked)==20
    static=parse((raw/'static-result.json').read_text());assert len(static)==3 and all(x['return_code']==0 and not x['timed_out'] for x in static)
    data=(raw/'controls.xml').read_bytes();assert len(data)<=8_000_000 and b'<!DOCTYPE' not in data and b'<!ENTITY' not in data
    xml=ET.fromstring(data);suite=xml.find('testsuite');cases=xml.findall('.//testcase');assert len(cases)==151
    identities=[(c.attrib['classname'],c.attrib['name']) for c in cases];assert len(set(identities))==151
    module_counts=dict(collections.Counter(c.attrib['classname'].rsplit('.',1)[-1] for c in cases))
    expected={'test_guard_private_file_io':7,'test_private_reader_descriptor_guards':12,'test_windows_replaceable_file':37,'test_windows_replaceable_reader_process':20,'test_windows_replaceable_unicode_crt':12,'test_windows_wtext_acceptance_probe':22,'test_windows_atomic_replace':27,'test_windows_atomic_replace_process':14}
    assert module_counts==expected and sum(native(c) for c in cases)==52
    skipped=[c for c in cases if c.find('skipped') is not None];failed=[c for c in cases if c.find('failure') is not None];errored=[c for c in cases if c.find('error') is not None]
    assert not errored
    if windows:
        assert len(skipped)==3 and not any(native(c) for c in skipped)
        assert len(failed)==1 and failed[0].attrib['name']=='test_actual_writer_matches_original_destination_outcomes[crt_destination]'
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
        if case.find('failure') is not None:
            report=parse(values['original_writer_report']);assert report['reference_writer'] and report['error']=={'kind':'PermissionError','errno':13,'winerror':5}
            assert 'child_capture_candidate' not in values
            assert values['original_destination_crt_reader_closed']==values['original_temporary_siblings_removed']=='True'
            failure_rows.append({'case':case.attrib['name'],'original_report':report,'original_exit_code':int(values['original_writer_exit_code']),'candidate_arm_executed':False,'original_destination_reader_closed':True,'temporary_siblings_removed':True,'expected_error':{'kind':'PermissionError','errno':13,'winerror':32},'raw_failure_text':case.find('failure').text})
    assert len(joins)==(89 if windows else 0) and len(pairs)==(18 if windows else 0)
    gate=parse((raw/'control-gate.json').read_text());assert gate['child_frame_joins']==joins
    assert gate['checks_passed'] is (not windows)
    record={'artifact_id':artifact,'artifact':verification,'source_binding':{'fields_equal':compared,'checked_source_files':checked,'python':before['python'],'platform':before['platform'],'python_executable_sha256_runner_recorded_only':before['python_executable_sha256'],'dependencies_equal':before['dependencies']==after['dependencies'],'source_sha':before['source_sha'],'source_tree':before['source_tree'],'driver_sha':before['driver_sha'],'driver_tree':before['driver_tree']},'static':static,'static_type_target':parse((raw/'static-type-target.json').read_text()),'suite':suite.attrib,'module_counts':module_counts,'counts':{'total':151,'passed':151-len(skipped)-len(failed),'failed':len(failed),'errors':0,'skipped':len(skipped),'mandatory_Windows_cases':52,'child_frames_present':len(joins),'child_frames_expected':90 if windows else 0,'WTEXT_pairs':len(pairs)},'case_identities':[{'module':a,'name':b} for a,b in identities],'child_joins':joins,'WTEXT_pairs':pairs,'actual_held_reader_controls':held,'failures':failure_rows,'original_gate':{'checks_passed':gate['checks_passed'],'verification_stage':gate['verification_stage'],'verification_error_type':gate.get('verification_error_type')},'scope':'source controls on exact isolated product proposal; no installed/performance qualification, no historical-holder attribution; candidate CRT-destination comparison arm remains unexecuted on Windows','binary_limit':'Python executable digest is runner-recorded only; executable bytes were not uploaded.'}
    (folder/'verified-result.json').write_text(json.dumps(record,indent=2)+'\n');rows.append(record)
    print(json.dumps({'artifact':artifact,'counts':record['counts'],'source_files_verified':len(checked),'held_reader_controls_verified':len(held),'original_gate':record['original_gate']}))
(root/'verified-results-index.json').write_text(json.dumps([{'artifact':r['artifact_id'],'result_sha256':digest((root/str(r['artifact_id'])/'verified-result.json').read_bytes()),'counts':r['counts']} for r in rows],indent=2)+'\n')

