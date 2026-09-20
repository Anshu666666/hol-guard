from pathlib import Path
import base64,gzip,hashlib,json,shutil,subprocess,xml.etree.ElementTree as ET
ROOT=Path('/workspace/scratch/745337b67ff9'); EVID=ROOT/'qualification-launcher-consumer-validation'; PACKET=EVID/'campaign-packet-v1'; WORK=ROOT/'qualification-launcher-campaign-400'
def desc(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def dump(p,d):p.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
m=json.loads((PACKET/'SOURCE-MANIFEST.json').read_text())
for row in m['source_paths']:
 assert desc((WORK/row['path']).read_bytes())=={k:row[k] for k in ('bytes','sha256','git_blob')}
 assert (WORK/row['path']).read_bytes()==(PACKET/'source'/row['path']).read_bytes()
xml=ET.parse(EVID/'campaign-controls-v2.xml');nodes=[n for n in xml.iter('testcase')]
assert len(nodes)==84 and len({(n.attrib['classname'],n.attrib['name']) for n in nodes})==84
assert not any(list(n) for n in nodes)
types=json.loads((EVID/'campaign-types-v7.json').read_text());assert types['summary']['errorCount']==0
validation={'pytest_exit':0,'tests':84,'passed':84,'skipped':0,'xml':desc((EVID/'campaign-controls-v2.xml').read_bytes()),'ordered_nodes':[n.attrib['classname']+'::'+n.attrib['name'] for n in nodes],'type_summary':types['summary'],'types':desc((EVID/'campaign-types-v7.json').read_bytes()),'ruff_format_exit':0,'ruff_lint_exit':0,'original_workload_executed':False,'prior_source_types':'Earlier type failures are preserved as original historical files; final84 includes14 installed-identity and5 controller-flow additions over earlier65. Real finite pipe/child controls are test-owned and unrelated to installed launcher population.','scope':'Nine new source/test paths. Prior17 reviewed bytes are unchanged and their original255/1 result is not rerun or relabeled.'}
dump(PACKET/'VALIDATION.json',validation)
validation_files=[]
for p in sorted(EVID.glob('campaign-*')):
 if not p.is_file():continue
 target=PACKET/'validation'/p.name;target.parent.mkdir(exist_ok=True);shutil.copyfile(p,target)
 validation_files.append({'path':target.relative_to(PACKET).as_posix(),**desc(target.read_bytes())})
for name in ['prepare_campaign_packet.py','finalize_campaign_packet.py']:
 shutil.copyfile(EVID/name,PACKET/name)
m['validation_pending_final_freeze']=False;m['validation']=validation;m['validation_files']=validation_files
m['plans']=[{'path':'PLAN-v4.json',**desc((PACKET/'PLAN-v4.json').read_bytes())}]
dump(PACKET/'SOURCE-MANIFEST.json',m)
# Retain full large original documents exactly via bounded reversible gzip parts.
originals=[]
for p in sorted(PACKET.rglob('*')):
 if not p.is_file() or p.stat().st_size<=100000:continue
 b=p.read_bytes();compressed=gzip.compress(b,mtime=0);encoded=base64.b64encode(compressed).decode();relative=p.relative_to(PACKET).as_posix();token=hashlib.sha256(relative.encode()).hexdigest()[:16];parts=[]
 for i in range(0,len(encoded),40000):
  name=f'encoded/{token}-{i//40000:03d}.gzip.base64';target=PACKET/name;target.parent.mkdir(exist_ok=True);target.write_text(encoded[i:i+40000]+'\n');parts.append({'path':name,**desc(target.read_bytes())})
 assert gzip.decompress(base64.b64decode(''.join((PACKET/x['path']).read_text().strip() for x in parts)))==b
 originals.append({'path':relative,**desc(b),'encoding':'gzip_base64_ordered_parts','compressed':desc(compressed),'parts':parts})
 # Leave local full original in a separate sibling; packet paths remain honest.
 retained=EVID/'campaign-full-originals'/relative;retained.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,retained);p.unlink()
dump(PACKET/'ORIGINALS.json',{'schema':'pr2974.campaign-preparation-large-originals.v1','originals':originals,'all_round_trips_verified':True})
(PACKET/'INDEX.md').write_text('''# Priority-launcher campaign preparation\n\nThis packet freezes nine new orchestration, installed-identity, controller and reader/control paths over seventeen byte-identical previously reviewed diagnostic paths. It contains no original benchmark execution. The final new cohort is 84 passed, no skips; nine-file types report zero errors and 457 warnings. Earlier source-control and type results remain historical originals.\n\nPLAN-v4 selects authentic a5fd/d7f30 baseline and a1d/9f511 candidate Linux artifacts. A read-only exhaustive comparison covers every source leaf and wheel member: eleven source differences and five wheel differences; all98 original measurement/setup provider bodies are identical. The product change is combined, so no pure lazy-import causal claim is made.\n\nSOURCE-COMPARISON.json, WHEEL-COMPARISON.json and large original type outputs are losslessly encoded as bounded ordered gzip/base64 parts named by ORIGINALS.json; every original length/SHA/Git-blob identity and every part is retained. Smaller originals are ordinary files. No artifact has been reinstalled, rebuilt or remeasured by this preservation step.\n\nThe original minimum is30 steady-state resource samples, separate from at least5 independent paired timing runs; this proposal selects six alternating pairs. Protected kernel CPU and sampled live-member USS/RSS are independent prerequisites. Missing metrics, incomplete rows, failed original contracts or missing cleanup block admission. Sampled peak is not instantaneous peak, and producer-interval CPU excludes later cleanup and privileged-controller work.\n\nThe actual CPU5 and private3 mechanism results have separate immutable records and independent peers. This source packet still requires substantive source review plus a concrete outer-driver/workflow/hardware/artifact peer before any161,568-call maximum campaign. Stopped E/F, historical probes and failed predecessors are never replayed or pooled here.\n''')
files=[{'path':p.relative_to(PACKET).as_posix(),**desc(p.read_bytes())} for p in sorted(PACKET.rglob('*')) if p.is_file()]
dump(PACKET/'PACKET-MANIFEST.json',{'schema':'pr2974.campaign-preparation-packet.v1','files':files,'count':len(files),'total_bytes':sum(x['bytes'] for x in files),'execution':False})
# Local Git tree is an independent expected Merkle identity, no commit/ref.
tree_rows=[]
for p in sorted(PACKET.rglob('*')):
 if not p.is_file():continue
 blob=subprocess.check_output(['git','hash-object','-w','--stdin'],input=p.read_bytes(),cwd=ROOT/'hol-guard').decode().strip();assert blob==desc(p.read_bytes())['git_blob'];tree_rows.append({'path':p.relative_to(PACKET).as_posix(),'mode':'100644','type':'blob','sha':blob})
index=EVID/'campaign-packet-v1.index'
env=__import__('os').environ|{'GIT_INDEX_FILE':str(index)}
subprocess.run(['git','read-tree','--empty'],cwd=ROOT/'hol-guard',env=env,check=True)
subprocess.run(['git','update-index','--index-info'],input=''.join('100644 '+r['sha']+'\t'+r['path']+'\n' for r in tree_rows).encode(),cwd=ROOT/'hol-guard',env=env,check=True)
tree=subprocess.check_output(['git','write-tree'],cwd=ROOT/'hol-guard',env=env).decode().strip()
dump(EVID/'CAMPAIGN-PACKET-LOCAL.json',{'tree':tree,'entries':tree_rows,'files':len(tree_rows),'source_manifest':desc((PACKET/'SOURCE-MANIFEST.json').read_bytes()),'plan':desc((PACKET/'PLAN-v4.json').read_bytes())})
print(json.dumps({'tree':tree,'files':len(tree_rows),'packet_bytes':sum(p.stat().st_size for p in PACKET.rglob('*') if p.is_file()),'source_manifest':desc((PACKET/'SOURCE-MANIFEST.json').read_bytes()),'plan':desc((PACKET/'PLAN-v4.json').read_bytes())},indent=2))
