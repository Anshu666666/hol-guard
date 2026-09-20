import ast
import copy
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

H=Path('/dev/shm/cline-root-v6-operational')
W=Path('/dev/shm/cline-intel-method-v6')
OLD=Path('/workspace/scratch/745337b67ff9/cline-intel-process-v5')
i=json.loads((H/'inputs.json').read_text())
n={'hashlib':hashlib}
helpers=ast.parse(Path('/workspace/scratch/745337b67ff9/root-checkpoint/prepare_publication.py').read_text())
exec(compile(ast.Module(body=[x for x in helpers.body if isinstance(x,ast.FunctionDef) and x.name in {'object_sha','tree_sha'}],type_ignores=[]),'git_hashes','exec'),n)
git,merkle=n['object_sha'],n['tree_sha']

def leaves(t):
    assert not t['truncated'] and merkle(t['tree'])==t['sha']
    return {x['path']:{k:x[k] for k in ['path','mode','type','sha','size']} for x in t['tree'] if x['type']!='tree'}

base,source=leaves(i['base']),leaves(i['source'])
assert len(base)==4801 and len(source)==4815
assert i['base']['sha']=='e60dfd218cd7cc9f29c9f2cd66223c866ea86c80'
assert i['source']['sha']=='73adb587cdfd7387a04c5fd05e3795688128375d'
assert all(source[p]==v for p,v in base.items())
new={x['path']:x for x in i['prep']['source_files']}
assert set(source)-set(base)==set(new)
commit=i['commit']
assert commit['sha']=='b7f7ac898d1e6bf752315450de675e896b9b8442'
assert commit['tree']['sha']==i['source']['sha']
assert [x['sha'] for x in commit['parents']]==['a1d509404b0803a91031cb51f4b0c919408bfeba']
records={x['path']:x for x in [*i['prep']['source_files'],*i['prep']['records']]}
before={}
for path,row in i['bodies'].items():
    local=W/(path.removeprefix('driver/') if path.startswith('driver/') else path)
    body=local.read_bytes();before[str(local)]=hashlib.sha256(body).hexdigest()
    declared=records[path]
    assert body.decode()==row['body']
    assert len(body)==declared['bytes'] and git('blob',body)==declared['git_blob']==row['sha']
    assert hashlib.sha256(body).hexdigest()==declared['sha256']
    if not path.startswith('driver/'):
        assert source[path]['sha']==row['sha'] and source[path]['size']==len(body)

def functions(path):
    return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(path.read_text()).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

unchanged={}
for name in ['scripts/ci/cline_witness/nested_run.py','scripts/ci/cline_witness/process_observation.py','scripts/ci/cline_witness/validation.py']:
    assert (OLD/name).read_bytes()==(W/name).read_bytes(),name
    unchanged[name]=hashlib.sha256((W/name).read_bytes()).hexdigest()
oldf,newf=functions(OLD/'scripts/ci/cline_installed_driver/driver.py'),functions(W/'scripts/ci/cline_installed_driver/driver.py')
assert oldf.keys()==newf.keys()
assert {name for name in newf if newf[name]!=oldf[name]}=={'population'}

contract_path=W/'scripts/ci/cline_installed_driver/input-contract.json'
original=contract_path.read_bytes();contract=json.loads(original)
assert contract['ready'] is False and contract['candidate_source']=='CANDIDATE_SOURCE_SHA'
assert contract['candidate_tree']==i['source']['sha']
assert contract['artifact_base_source']==contract['product_source']=='a1d509404b0803a91031cb51f4b0c919408bfeba'
assert contract['artifact_base_tree']==contract['product_tree']==i['base']['sha']
assert contract['candidate_files']==i['prep']['source_files']
assert len(contract['cells'])==1
cell=contract['cells']['mac-x64']
assert cell['artifact_id']==10614003430 and cell['artifact_run']==35539716189
assert cell['build_source']=='9f511875b236c12e5f23c783e958a536ac0360ba' and cell['build_tree']==i['base']['sha']
assert cell['archive']['bytes']==13433129 and cell['archive']['sha256']=='46db53e8fffc7305eee29e1869ac7f2828254f295617356698ab8d09420efeaa'
assert len(cell['artifact_members'])==8
assert cell['wheel']['sha256']=='7096ab45878081e32a170ead2a13fee7f4d736816ecc0389d1236fb545bfe4e9'
assert contract['declared_population']=={'cline-witness':4}
assert contract['observer_scope']['original_nested_timeout_seconds']==9 and contract['observer_scope']['original_outer_delivery_timeout_seconds']==10
assert contract['observer_scope']['selected_control_count']==270
assert contract['observer_scope']['global_profile_installed'] is False
bound=copy.deepcopy(contract);bound['candidate_source']=commit['sha'];bound['ready']=True
raw=(json.dumps(bound,indent=2,sort_keys=True)+'\n').encode()
inverse=copy.deepcopy(bound);inverse['candidate_source']='CANDIDATE_SOURCE_SHA';inverse['ready']=False
assert (json.dumps(inverse,indent=2,sort_keys=True)+'\n').encode()==original
(H/'bound-input-contract.json').write_bytes(raw)
elements=[];combined=list(source.values())
for path,row in i['bodies'].items():
    if not path.startswith('driver/'):continue
    actual=path.removeprefix('driver/')
    assert actual not in source
    body=raw if actual.endswith('input-contract.json') else row['body'].encode()
    sha=git('blob',body)
    elements.append({'path':actual,'mode':'100644','type':'blob','content':body.decode()})
    combined.append({'path':actual,'mode':'100644','type':'blob','sha':sha,'size':len(body)})
assert len(elements)==4 and len(combined)==4819
assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in before.items())
receipt={
 'schema':'pr2974.cline-v6-root-operational-peer.v1',
 'created_at':datetime.now(timezone.utc).isoformat(),
 'verdict':'clear for the exact four-path bound driver after its complete tree/parent/ref guard; one original Intel cohort only',
 'base_source':contract['product_source'],'base_tree':i['base']['sha'],'source_commit':commit['sha'],'source_tree':i['source']['sha'],
 'expected_driver_tree':merkle(combined),'driver_leaf_count':len(combined),'sole_driver_parent':commit['sha'],
 'all_4801_original_leaves_unchanged':True,'source_additions':14,'remote_full_bodies_compared':18,'owner_inputs_unchanged':18,
 'source_peer':'064468ce3a3491042978197088cd26bae756aa6f','preparation_tree':'d3e826a644ed318bfefc067a61817d3a4b692b05',
 'read_scope':['Complete selected-method implementation and its controls; complete installation/profile/run integration, workflow, input contract and driver; CI substantive source peer and V6 plan.','Complete V5-to-V6 workflow/driver/control diff. The driver changes only its population consumer; original nested-run, Popen operation observer and complete native validator bodies are independently byte-equal.','Two actual template changes only: candidate_source bound to the verified sole-a1 source commit, ready false to true; inverse serialization exactly reproduces original template.','The exact current a1 Intel archive/wheel/member metadata joins the already independently verified a1 artifact packet and root quartet review; this operational peer does not redownload or execute the package.'],
 'unchanged_original_bodies':unchanged,
 'controls':{'owner_passed':270,'owner_failed':0,'owner_skipped':0,'source_peer_checked_both_XMLs':True,'root_rerun':False},
 'execution':{'platform':'macos-15-intel','cohorts':1,'original_case_count':4,'first_failure_stops':True,'nested_seconds':9,'outer_delivery_seconds':10,'cohort_seconds':180,'job_minutes':50,'extra_product_requests':0,'extra_popen_actions':0,'normal_nested_zero_and_pid_join_required':True,'full_native_oracle_required':True,'instrumented_functional_only':True},
 'limitations':['No historical timeout cause established. No normal Cline return or performance credit before original run.','Additional import/source-compilation/snapshot/oracle/export cost remains inside unchanged original deadlines.','Observation lifetime ends when owned wrappers restore at diagnostic atexit callback; later atexit calls are not covered.','Absent sidecars or unproved original containment refuse completion; cleanup may remain deferred and is not hidden by a new wait or kill.','This is a source/operational review, not GitHub approval or full PR qualification.'],
 'binding':{'template_blob':git('blob',original),'bound_blob':git('blob',raw),'bound_bytes':len(raw),'bound_sha256':hashlib.sha256(raw).hexdigest()},
 'no_product_import_control_or_workload_executed':True,'branch_or_workflow_created_by_this_verifier':False}
(H/'PEER.json').write_text(json.dumps(receipt,indent=2)+'\n')
(H/'driver-elements.json').write_text(json.dumps({'base_tree_sha':i['source']['sha'],'tree_elements':elements})+'\n')
(H/'expected-driver-leaves.json').write_text(json.dumps(combined)+'\n')
print(json.dumps({k:receipt[k] for k in ['verdict','expected_driver_tree','driver_leaf_count','binding']},indent=2))
