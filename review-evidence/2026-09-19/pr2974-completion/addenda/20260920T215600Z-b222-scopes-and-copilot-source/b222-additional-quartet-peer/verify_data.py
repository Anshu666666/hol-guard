"""Read-only joins of previously retained original artifacts; no extraction/import/workload."""
import base64,gzip,hashlib,json
from pathlib import Path
P=Path('/workspace/scratch/745337b67ff9')
D=P/'normalb222-posix/linux-terminal/terminal-packet'
def hash_file(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def read(path):return json.loads(path.read_bytes())
def verify():
 manifest=read(D/'MANIFEST.json')['files']
 before={r['path']:hash_file(D/r['path']) for r in manifest}
 for row in manifest:
  path=D/row['path'];assert path.stat().st_size==row['bytes'] and before[row['path']]==row['sha256']
 summary=read(D/'SUMMARY.json');join=read(D/'QUARTET-JOIN.json')
 assert summary['source']==join['source']=='b222318cca2811ac7ae90c7364e2ec6d0a10651f'
 assert summary['actual_build']==join['actual_build']=='6aa63accf753de56aef380bdf59710a031973bfa'
 assert summary['same_tree']==join['tree']=='ef0c0b8abb8144ed010b4c23c05a2dc70f20c354'
 slo=read(D/'10613212321/raw/native-installed-slo.json');soak=read(D/'10613212321/raw/native-soak.json');default=read(D/'10613212321/raw/native-default-auto.json')
 assert summary['linux_soak']==soak and summary['linux_concurrency']==slo['concurrency']
 assert summary['linux_warm_all_harnesses']==slo['latency']['warm_all_harnesses']
 assert len(slo['gates'])==14 and all(v is True for v in slo['gates'].values())
 assert slo['qualification_complete'] is summary['slo_qualification_complete'] is False
 assert soak['requests']==soak['responses']==100000 and soak['receipts']==250000 and soak['errors']==soak['health_failures']==0
 assert round(soak['rss_peak_bytes']/soak['rss_baseline_bytes']-1,6)==soak['rss_growth']
 assert default['resident_decisions']==default['corpus_decisions']==21
 assert default['receipt_metrics']['accepted']==default['receipt_metrics']['processed']==21
 assert default['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
 matrix=read(D/'10612847968/raw/native-matrix-evidence.json')
 assert matrix['passed'] is True and matrix['validation']['windows_waiver'] is None
 assert [{k:v for k,v in r.items() if k!='artifact_id'} for r in join['all_seven_collected_rows']]==matrix['collected']
 dirs={10613212321:P/'normalb222-posix/linux-terminal/10613212321',10612531698:P/'normalb222-posix/10612531698',10612109684:P/'normalb222-posix/10612109684',10612488444:P/'windows-normal-b222318/10612488444'}
 for r in join['all_original_archives_rehashed']:
  path=dirs[r['artifact_id']]/'artifact.zip';assert path.stat().st_size==r['bytes'] and hash_file(path)==r['sha256']
 seen={};pure=[]
 for row in join['all_seven_collected_rows']:
  path=dirs[row['artifact_id']]/'raw'/row['member'];assert path.stat().st_size==row['bytes'] and hash_file(path)==row['sha256']
  name=path.name;assert row['identical_duplicate'] is (name in seen)
  if name in seen:assert seen[name]==(row['bytes'],row['sha256'])
  seen[name]=(row['bytes'],row['sha256'])
  if name.endswith('-any.whl'):pure.append(seen[name])
 assert len(seen)==5 and len(pure)==3 and len(set(pure))==1
 assert len(matrix['validation']['artifacts'])==5
 for row in matrix['validation']['artifacts']:assert seen[row['name']]==(row['size'],row['sha256'])
 runtime=summary['original_linux_runtime'];assert slo['runtime']['runtime_sha256']==runtime['runtime_sha256']
 assert slo['runtime']['rule_digest']==runtime['rule_digest']==matrix['validation']['rule_digest']
 assert slo['runtime']['build_sha']==runtime['source_sha']==summary['actual_build']
 inventory=summary['member_inventory'];compressed=base64.b64decode(b''.join((D/n).read_bytes() for n in inventory['ordered_parts']),validate=True)
 assert len(compressed)==inventory['gzip']['bytes'] and hashlib.sha256(compressed).hexdigest()==inventory['gzip']['sha256']
 raw=gzip.decompress(compressed);assert len(raw)==inventory['original']['bytes'] and hashlib.sha256(raw).hexdigest()==inventory['original']['sha256']
 wheels=json.loads(raw);assert len(wheels)==2 and sum(len(w['members']) for w in wheels)==2998
 assert {r['wheel'] for r in wheels}=={r['name'] for r in matrix['validation']['artifacts'] if r['name'].endswith(('-any.whl','-manylinux_2_17_x86_64.whl'))}
 for wheel in wheels:
  assert seen[wheel['wheel']]==(wheel['bytes'],wheel['sha256'])
  assert len({m['path'] for m in wheel['members']})==len(wheel['members'])
 after={r['path']:hash_file(D/r['path']) for r in manifest};assert before==after
 return {'result':'clear within ordinary smoke and authentic retained artifact admission scope','packet':'a05e99ef76209af04df87b94cae97b9406c3254c','packet_payloads_verified':len(manifest),'original_archives_rehashed':4,'collected_wheels_rehashed':7,'distinct_admitted_wheels':5,'member_digest_roster_rows':2998,'member_content_reinflated':False,'source':summary['source'],'actual_build':summary['actual_build'],'same_tree':summary['same_tree'],'summary_sha256':before['SUMMARY.json'],'manifest_sha256':hash_file(D/'MANIFEST.json'),'quartet_sha256':before['QUARTET-JOIN.json'],'linux_soak':soak,'linux_smoke_c16':slo['concurrency']['sixteen'],'full_qualification':False,'files_unchanged':True,'limits':summary['limits'],'method':['Read complete freeze_terminal.py and verify_wheels.py before pure data checks; neither script executed.','Rehashed retained ZIP files and extracted wheel files, joined all seven collected rows to five admitted identities; no download, extraction or release validator rerun.','Decoded only retained small gzip/base64 member-digest inventory; prior original full RECORD/content validation remains owner evidence, not repeated here.','Recomputed original summary/raw SLO/soak/default-native counter joins and RSS growth; no tests, native execution, imports from product, or performance workload.']}
if __name__=='__main__':print(json.dumps(verify(),indent=2,sort_keys=True))
