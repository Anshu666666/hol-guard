"""Read retained bytes only; never invoke a workload or native runtime."""
from pathlib import Path
import base64,hashlib,json,sys,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parent; RAW=ROOT/'raw'; SOURCE=ROOT.parent/'native-workspace100-f8-prep'
sys.path[:0]=[str(SOURCE/'workspace100-validation'),str(SOURCE),str(SOURCE/'src')]
from admission import decode,reconstruct,admit

def identity(raw): return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def read(name):return decode((RAW/name).read_bytes())
def verify():
 manifest=decode((SOURCE/'workspace100-validation/MANIFEST.json').read_bytes()); archive=decode((ROOT/'archive-verification.json').read_bytes()); assert identity((ROOT/'artifact.zip').read_bytes())['sha256']==archive['sha256']
 for row in archive['members']:
  actual=identity((RAW/row['path']).read_bytes());assert all(actual[k]==row[k] for k in ['bytes','sha256'])
 groups={}; frames=0
 for line in (ROOT/'job.log').read_text().splitlines():
  marker='HG_WORKSPACE100_FILE_V1 '; where=line.find(marker)
  if where<0:continue
  frame=json.loads(line[where+len(marker):]);assert frame['kind']=='part'; groups.setdefault(frame['path'],[]).append(frame); frames+=1
 projection=[]
 for name,rows in groups.items():
  rows.sort(key=lambda x:x['part']);first=rows[0];assert [x['part'] for x in rows]==list(range(first['parts']))
  assert all(all(x[k]==first[k] for k in ['parts','path','bytes','sha256','git_blob']) for x in rows)
  body=b''.join(base64.b64decode(x['base64'],validate=True) for x in rows); observed=identity(body); assert all(observed[k]==first[k] for k in observed)
  if name=='projection-index.json': index=json.loads(body)
  else: assert body==(RAW/name).read_bytes()
  projection.append({'path':name,**observed})
 assert {row['path'] for row in projection if row['path']!='projection-index.json'}=={row['path'] for row in index['admitted']}
 before,after=read('binding-before.json'),read('binding-after.json'); assert before==after
 assert before['source']['head']==manifest['source_sha'] and before['source']['tree']==manifest['source_tree']
 assert before['driver']['head']=='2877b4118f9ed2c122f31e8ff78c322f2833f725' and before['driver']['tree']=='abaff21a7186a17b15dbdb09d9efec641f7887d6'
 assert before['files']==manifest['driver_files'] and before['source_files']==manifest['source_files']
 assert read('installed-before.json')==read('installed-after.json')
 expected=read('expected-installed.json');assert expected['runtime_manifest']==manifest['retained_wheel']['runtime_manifest']
 for key in ['bytes','sha256']:assert identity((RAW/manifest['retained_wheel']['wheel_name']).read_bytes())[key]==manifest['retained_wheel']['wheel_identity'][key]
 controls=read('reader-controls-result.json'); nodes=manifest['expected_reader_nodes']; assert controls['collected']==nodes==controls['executed'] and controls['passed']==30 and controls['skipped']==0
 cases=list(ET.parse(RAW/'reader-controls.xml').getroot().iter('testcase')); actual=[c.attrib['classname'].replace('.','/')+'.py::'+c.attrib['name'] for c in cases]; assert actual==nodes and not any(list(c.iter(kind)) for c in cases for kind in ['failure','error','skipped'])
 report=read('workspace-lifecycle.json');cells=reconstruct(report,(RAW/'workspace-lifecycle.jsonl').read_bytes());assert cells==read('reconstructed-cells.json')
 result=read('validation-result.json');assert result['original_command_attempts']==1 and result['original_exit']==1 and result['source_driver_installed_preserved'] is True and result['passed'] is False
 expected_codes={'sync':0,'uninstall':0,'install':0,'ruff':0,'format':0,'types':0,'reader-collect':0,'reader-controls':0,'installed-before':0,'original-five-cells':1,'admit-original':1,'installed-after':0}; commands=read('commands.json');assert {row['name']:row['returncode'] for row in commands}==expected_codes
 for row in commands:
  assert row['timed_out'] is False and row['direct_child_exited'] is True
  for label in ['stdout','stderr']:assert all(identity((RAW/'commands'/f"{row['name']}.{label}").read_bytes())[k]==row[label][k] for k in ['bytes','sha256'])
 runtime={**report['runtime']}
 try:admit(report,cells,returncode=1,runtime=runtime)
 except ValueError as e:assert str(e)=='original_cell_failure:lost_metadata_hint'
 else:raise AssertionError('original_failure_lost')
 summaries=[]
 for cell in cells:
  accepted=cell.get('accepted_ms');observations=[]
  for row in cell.get('publication_rows',[]):
   r={k:row[k] for k in ['kind','phase','publication','started_ms','finished_ms','ready','validated','config_loads'] if k in row}
   if accepted is not None:r['finished_relative_to_publication_acceptance_ms']=row['finished_ms']-accepted
   observations.append(r)
  requests=cell.get('requests',{});witness=requests.get('receipt_witness',cell.get('receipt_witness',{}))
  summaries.append({'scenario':cell['scenario'],'passed':cell['passed'],'failure':cell.get('failure'),'acceptance_boundary':cell.get('acceptance_boundary'),'publication_accepted_ms':accepted,'accept_to_ack_ms':cell.get('accept_to_ack_ms'),'lifecycle_clocks':cell.get('lifecycle_clocks'),'publication_observer':cell.get('publication_observer'),'publication_observations':observations,'receipt_counts':{k:witness.get(k) for k in ['native_receipts','committed','missing','binding_mismatches']},'request_checks':cell.get('request_checks'),'publisher_contained':cell.get('publisher_contained'),'writer_drained':cell.get('writer_drained')})
 return {'schema':'pr2974.workspace100.original-five-cell-result.v1','run_id':35518521594,'job_id':106098451260,'conclusion':'failure','driver_sha':result['driver_sha'],'source_sha':manifest['source_sha'],'source_tree':manifest['source_tree'],'wheel':manifest['retained_wheel'],'archive':{'artifact_id':archive['artifact_id'],'bytes':archive['bytes'],'sha256':archive['sha256'],'members':len(archive['members'])},'job_log':identity((ROOT/'job.log').read_bytes()),'projection_frames':frames,'projection_files':len(projection),'projection_missing':index['unavailable'],'controls_passed':30,'controls_skipped':0,'original_invocations_observed':1,'original_exit':1,'all_source_driver_installed_bindings_preserved':True,'declared_cells_visited':report['declared_cells_visited'],'cell_passes':sum(c['passed'] for c in cells),'cell_failures':sum(not c['passed'] for c in cells),'cells':summaries,'original_full_matrix_visited':report['complete_lifecycle_matrix_visited'],'original_implemented_checks_passed':report['implemented_checks_passed'],'strict_five_cell_admission':False,'no_workload_replay':True,'headline_or_full_qualification_claimed':False,'limits':['Publication rows timestamp observed return/state, not exact internal commit instants.','Lifecycle caller clocks and publication clocks have distinct origins; no direct cross-origin subtraction was used.','Earlier validated ACK and ready observations do not establish later authenticated/current admission. The failing predicate within await_ack is not retained.','False installed_runtime_matches on a failed cell is its default uncompleted-check value, not proof of a binary mismatch; complete before/after installed identity did match.','First-admission-fault failed initial setup before entering its injected-fault stage.','The original cancelled normal job has no completed soak receipt. Its admitted wheel identity remains usable for this separate finite diagnostic.']}
if __name__=='__main__':
 result=verify();(ROOT/'VERIFIED-RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({k:v for k,v in result.items() if k in ['cell_passes','cell_failures','controls_passed','projection_frames','projection_files','strict_five_cell_admission']}))
