"""Data-only joins of one original Windows admission diagnostic artifact."""
from __future__ import annotations
import hashlib
import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

HERE = Path(__file__).resolve().parent
SOURCE = 'cae549421ecaea55715adcad32afd7d9043a172c'
SOURCE_TREE = '48e237aa34fb80b27f3b11ab609c8705cc96c3e1'
DRIVER = 'c90833fc1d3551e39d61f86e315d0f0aee3ae885'
DRIVER_TREE = '9c7257f3aa6dc9e1011b106ebd32381c7f3c44cf'
PRODUCT = '4001185e4f39cad51fd5eab314bf02b86b8a1674'
PRODUCT_TREE = '7a328609488ffefecd3cdd12a9c7adba6a591e97'
ROUTES = {'native_resident','native_oneshot','native_fail_safe','native_degraded','python_semantic'}


def digest(body):
    return hashlib.sha256(body).hexdigest()


def read(path):
    return json.loads(path.read_bytes().decode('utf-8-sig'))


def counters(value):
    assert type(value) is dict
    assert all(type(k) is str and type(v) is int and 0 <= v < 2**63 for k,v in value.items())
    return value


def delta(before, after):
    before,after=counters(before),counters(after)
    return {k:after.get(k,0)-before.get(k,0) for k in sorted(set(before)|set(after)) if before.get(k,0)!=after.get(k,0)}


def verify():
    run=read(HERE/'run.json'); jobs=read(HERE/'jobs.json')
    assert run['id']==35533705972 and run['head_sha']==DRIVER and run['conclusion']=='success'
    assert len(jobs['jobs'])==1 and jobs['jobs'][0]['id']==106138831185 and jobs['jobs'][0]['conclusion']=='success'
    assert all(step['conclusion']=='success' for step in jobs['jobs'][0]['steps'])
    meta=read(HERE/'artifact-metadata.json')
    archive=HERE/'artifact.zip'
    raw=archive.read_bytes()
    assert len(raw)==meta['size_in_bytes'] and 'sha256:'+digest(raw)==meta['digest']
    directory=HERE/'raw'
    members=[]
    with zipfile.ZipFile(archive) as z:
        assert len(z.namelist())==len(set(z.namelist()))
        for info in z.infolist():
            assert not info.is_dir() and not Path(info.filename).is_absolute() and '..' not in Path(info.filename).parts
            data=z.read(info)
            target=directory/info.filename
            assert target.read_bytes()==data
            members.append({'path':info.filename,'bytes':len(data),'sha256':digest(data)})
    def find(name):
        matches=list(directory.rglob(name))
        assert len(matches)==1,(name,len(matches))
        return matches[0]
    before,after=read(find('binding-before.json')),read(find('binding-after.json'))
    assert before==after and read(find('binding-comparison.json'))=={'equal':True}
    assert before['diagnostic_source']==SOURCE and before['diagnostic_tree']==SOURCE_TREE
    assert before['driver']==DRIVER and before['product_source']==PRODUCT and before['product_tree']==PRODUCT_TREE
    checkout_before=read(find('checkouts-before.json'))
    checkout_after=read(find('checkouts-after.json'))
    for c in (checkout_before,checkout_after):
        assert c['driver']==DRIVER and c['driver_tree']==DRIVER_TREE
        assert c['source']==SOURCE and c['source_tree']==SOURCE_TREE
        assert c['product']==PRODUCT and c['product_tree']==PRODUCT_TREE
    assert checkout_after['tracked_changes']==[]
    assert checkout_before['historical_failed_executable'] is False and checkout_before['new_isolated_build'] is True
    wheels=list(directory.rglob('*.whl')); assert len(wheels)==1
    wheel=wheels[0]; wm=before['artifact']
    assert wm['wheel_name']==wheel.name and wm['wheel_bytes']==wheel.stat().st_size and wm['wheel_sha256']==digest(wheel.read_bytes())
    assert wm['build_source']==PRODUCT and wm['new_isolated_build'] is True and wm['historical_failed_executable'] is False
    with zipfile.ZipFile(wheel) as z:
        assert len(z.namelist())==len(set(z.namelist()))
        for row in wm['native_members']:
            data=z.read(row['member']); assert len(data)==row['bytes'] and digest(data)==row['sha256']
        manifest=json.loads(z.read('codex_plugin_scanner/_native/runtime-manifest.json'))
        assert manifest['source_sha']==PRODUCT and manifest['target']=='x86_64-pc-windows-msvc'
        for row in before['sources']:
            if row['source'].startswith('src/'):
                data=z.read(row['source'].removeprefix('src/'))
                assert digest(data.replace(b'\r\n',b'\n'))==row['lf_sha256']
    source_manifest=read(HERE/'inputs/SOURCE-MANIFEST.json')
    assert source_manifest['source_tree']==SOURCE_TREE
    for name in ('admission_observation_binding.py','admission_observation_capture.py'):
        row=next(x for x in source_manifest['files'] if x['path']=='ci/native_runtime/'+name)
        body=(HERE/'inputs'/name).read_bytes()
        assert len(body)==row['bytes'] and digest(body)==row['sha256']
    # Expected original source hashes are parsed as data, never imported.
    import ast
    parsed=ast.parse((HERE/'inputs/admission_observation_binding.py').read_text())
    guards=next(ast.literal_eval(node.value) for node in parsed.body if isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name) and node.target.id=='GUARDS')
    assert {row['source']:row['lf_sha256'] for row in before['sources']}==guards and len(guards)==22
    controls=ET.parse(find('controls.xml')); cases=controls.findall('.//testcase')
    identities=[(case.attrib['classname'],case.attrib['name']) for case in cases]
    expected=ET.parse(HERE/'inputs/expected-controls.xml').findall('.//testcase')
    assert identities==[(c.attrib['classname'],c.attrib['name']) for c in expected]
    assert len(cases)==len(set(identities))==34 and all(not list(c) for c in cases)
    types=read(find('types.json')); assert types['summary']['errorCount']==0
    observed=read(find('admission-observation.json'))
    assert observed['schema']=='hol-guard.default-auto-admission-observation.v1'
    assert observed['original_probe_invocations']==1
    assert observed['counter_scope']=='sequential_nonatomic_observed_boundaries_not_automatic_request_cause'
    assert observed['extra_product_requests']==0 and observed['retries_added'] is False and observed['deadlines_changed'] is False and observed['qualification'] is False
    assert observed['receipt_snapshot_scope']=='original_end_corpus_argument_sampled_before_callback'
    assert observed['end_boundary_scope']=='callback_exit_observed_not_shutdown_success'
    parsed=ast.parse((HERE/'inputs/admission_observation_capture.py').read_text())
    roster=next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ROSTER' for t in n.targets))
    rows=[]
    for index,row in enumerate(observed['deliveries']):
        assert row['index']==index and (row['harness'],row['event'])==roster[index]
        item={'index':index,'harness':row['harness'],'event':row['event'],'returned':row['returned'],'response':row.get('response')}
        if 'after' in row:
            for name in ('metrics','scheduler','admission'):
                available=all(row[b][name]['available'] is True for b in ('before','after'))
                item[name+'_available']=available
                if not available: continue
                b,a=row['before'][name]['values'],row['after'][name]['values']
                if name=='metrics':
                    assert set(b['routes'])<=ROUTES and set(a['routes'])<=ROUTES
                    item['routes_delta']=delta(b['routes'],a['routes'])
                    item['failure_stages_delta']=delta(b['failure_stages'],a['failure_stages'])
                elif name=='scheduler':
                    item['scheduler_delta']=delta({k:v for k,v in b.items() if type(v) is int},{k:v for k,v in a.items() if type(v) is int})
                    item['scheduler_rejected_delta']=delta(b['rejected'],a['rejected'])
                    item['scheduler_active_by_harness_delta']=delta(b['per_harness_active'],a['per_harness_active'])
                    item['scheduler_queued_by_harness_delta']=delta(b['per_harness_queued'],a['per_harness_queued'])
                else:
                    item['admission_delta']=delta({k:b[k] for k in ('active','rejected')},{k:a[k] for k in ('active','rejected')})
                    item['harness_rejected_delta']=delta(b['per_harness_rejected'],a['per_harness_rejected'])
        rows.append(item)
    original_exit=read(find('original-probe-exit.json'))
    assert original_exit['driver_invocations']==1 and original_exit['timing_qualification'] is False and original_exit['historical_failed_executable'] is False
    original = read(find('native-default-auto.json'))
    assert original['schema']=='hol-guard.native-default-installed-receipt.v1'
    assert original['corpus_decisions']==original['resident_decisions']==21
    assert original['oneshot_decisions']==original['python_semantic_decisions']==original['fail_safe_decisions']==0
    assert [(r['harness'],r['event']) for r in original['route_receipts']]==list(roster)
    assert {k.removeprefix('receipt_'):v for k,v in observed['original_receipt_snapshot'].items()}==original['receipt_metrics']
    assert observed['original_worker_snapshot']['routes']=={'native_resident':original['resident_decisions']}
    assert original['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
    assert observed['observation_complete'] is True and observed['callbacks_restored'] is True and observed['faults']==[]
    assert len(rows)==21 and all(row['returned'] is True and row['routes_delta']=={'native_resident':1} for row in rows)
    assert all(row['scheduler_delta'].get('admitted')==1 and not row['scheduler_rejected_delta'] and not row['harness_rejected_delta'] and not row['failure_stages_delta'] for row in rows)
    assert sum(row['scheduler_delta'].get('completed',0) for row in rows)==21
    assert rows[18]['scheduler_delta'].get('completed',0)==0 and rows[19]['scheduler_delta']['completed']==2
    caps=read(find('build-capabilities.json')); self_test=read(find('build-self-test.json'))
    assert caps['build_sha']==PRODUCT and self_test=={'capabilities':caps,'ok':True}
    assert manifest['rule_digest']==caps['rule_digest']
    result={'schema':'hol-guard.windows-admission-result.v1','run':35533705972,'job':106138831185,'source':SOURCE,'driver':DRIVER,'product_source':PRODUCT,'artifact':{'id':meta['id'],'bytes':len(raw),'sha256':digest(raw),'members':members},'controls':{'passed':len(cases),'failed':0,'skipped':0,'ordered_identity_join':True},'types':types['summary'],'source_binding':before,'new_wheel':wm,'original_exit':original_exit,'original_outcome':observed['original_outcome'],'observation_complete':observed['observation_complete'],'callbacks_restored':observed['callbacks_restored'],'faults':observed['faults'],'original_probe_receipt':original,'build_capabilities':caps,'completion_boundary_limit':'Pi pre completed delta0 and following Pi post delta2: row snapshots do not independently assign completion to a request','original_worker_snapshot':observed['original_worker_snapshot'],'original_receipt_snapshot':observed['original_receipt_snapshot'],'deliveries':rows,'historical_failure_cause_established':False,'automatic_per_request_cause_assignment':False,'timing_qualification':False,'historical_binary_equivalence':False}
    return result


if __name__=='__main__':
    result=verify()
    (HERE/'VERIFIED-RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'controls':result['controls'],'original_exit':result['original_exit'],'complete':result['observation_complete'],'deliveries':len(result['deliveries'])}))
