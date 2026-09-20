"""Independent data-only checks; no application imports or mutation of originals."""
import base64,hashlib,json,resource,runpy,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(192*1024*1024,192*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU,(30,30))
sys.dont_write_bytecode=True
root=Path('/dev/shm/rsp078-run35543060961');out=Path(__file__).parent
remote=json.loads((out/'remote.json').read_text())
def h(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def census():return {str(p.relative_to(root)):h(p.read_bytes()) for p in root.rglob('*') if p.is_file()}
before=census();joins=[]
for row in remote['tree']:
 p=root/row['path']
 if row['path']=='MANIFEST.json':body=remote['manifest'].encode()
 elif row['path'].endswith('artifact.zip.base64'):body=base64.b64encode(p.with_suffix('').read_bytes())+b'\n'
 else:body=p.read_bytes()
 assert len(body)==row['size'] and git(body)==row['sha'],row['path']
 joins.append({'path':row['path'],'bytes':len(body),'git_blob':row['sha'],'sha256':h(body)})
reader=root/'verify.py';assert git(reader.read_bytes())=='c97e54bd1929cc87956f1f89058021217cda83e6'
module=runpy.run_path(str(reader),run_name='rsp078_data_peer')
actual=module['verify']();expected=json.loads((root/'VERIFIED-RESULT.json').read_text());assert actual==expected
contract=json.loads((root/'10615213488/raw/input-contract.json').read_text())
sources=[]
for i,body in enumerate(remote['sources']):
 data=body.encode();row=contract['candidate_files'][i if i<2 else 2]
 assert len(data)==row['bytes'] and h(data)==row['sha256'] and git(data)==row['git_blob']
 sources.append(row)
# Independently join raw case lists rather than rely only on owner's projection.
raw_cells=[]
for identifier in [10615213488,10614899426,10614519887]:
 p=root/str(identifier)/'raw';raw=json.loads((p/'managed-aliases.json').read_text());binding=json.loads((p/'before.json').read_text())['binding'];rows=raw['rows']
 assert len(rows)==14 and len({r['label'] for r in rows})==14
 counts={kind:sum(r['kind']==kind for r in rows) for kind in ['evaluated','permission_daemon','permission_no_daemon','watch_no_daemon']};assert counts=={'evaluated':4,'permission_daemon':4,'permission_no_daemon':4,'watch_no_daemon':2}
 assert all(r['stage']=='complete' and r['status']=='completed' for r in rows)
 assert all(r['delivery']['original_oracle_passed'] is True and r['registration_unchanged'] is True for r in rows)
 assert all(r['timed_out'] is False and r['containment_failed'] is False and r['output_limit_exceeded'] is False for r in rows)
 assert sum(r['native_evaluation'] is True for r in rows)==4
 assert [r.get('route') for r in rows]==['native_resident']*4+['native_fail_safe']*4+[None]*6
 assert all(r['evidence']['native_result'] is None for r in rows[4:8])
 assert all('evidence' not in r and r['daemon_endpoint_before']==r['daemon_endpoint_after']=={'daemon-state.json':False,'daemon-auth-token':False} for r in rows[8:])
 assert raw['daemon_cleanup_contained'] is raw['no_daemon_cleanup_contained'] is True
 raw_cells.append({'cell':binding['cell'],'counts':counts,'labels':[r['label'] for r in rows],'exact_case_outputs_and_native_oracle':True,'registration_stable':True,'original_containment_limits':[r['outer_containment_seconds'] for r in rows]})
after=census();assert before==after
result={'remote_tree':'4eeeab7570f20dc55aced570881baf30597f46ad','all_62_remote_blob_images_exact':len(joins)==62,'joined_files':joins,'source_bodies':sources,'original_files_unchanged':len(before),'owner_read_only_verifier_exact_result':True,'independent_raw_cells':raw_cells,'archive_count':3,'original_member_count':48,'controls_per_cell':290,'scope':'Data-only source/result peer. No downloads, source imports, tests, installed requests or workload.'}
(out/'CHECKS.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'clear':True,'originals_unchanged':len(before),'remote_leaves':len(joins),'cells':[x['cell'] for x in raw_cells],'controls_each':290,'cases_each':14}))
