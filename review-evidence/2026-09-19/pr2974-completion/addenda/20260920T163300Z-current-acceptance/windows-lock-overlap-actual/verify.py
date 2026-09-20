"""Read/hash/parse retained data only; never import or execute product controls."""
import resource
resource.setrlimit(resource.RLIMIT_AS, (128*1024*1024,128*1024*1024))
import hashlib,json,pathlib,subprocess,xml.etree.ElementTree as ET
root=pathlib.Path('/workspace/scratch/745337b67ff9/windows-journal-lock-run35521747666')
raw=root/'10608331487/raw'
def pairs(rows):
 out={}
 for k,v in rows:
  assert k not in out,'duplicate_key';out[k]=v
 return out
def parse(body):return json.loads(body,object_pairs_hook=pairs)
def read(path):return parse(path.read_text(encoding='utf-8-sig'))
def digest(b):return hashlib.sha256(b).hexdigest()
verification=read(root/'10608331487/verification.json')
assert verification['archive_bytes']==12180
assert digest((root/'10608331487/artifact.zip').read_bytes())==verification['archive_sha256']=='63b8df6cb61a7d0dfa4113a5a2204d337419e58de3a0f75c03d39b0b7b585470'
for member in verification['members']:
 body=(raw/member['path']).read_bytes();assert len(body)==member['bytes'] and digest(body)==member['sha256']
before,after=read(raw/'binding-before.json'),read(raw/'binding-after.json');assert before==after
assert read(raw/'binding-comparison.json')=={'equal':True}
assert before['source']=='68db7b905ccabbb504360c366264a503e95440de' and before['tree']=='c932d1a536954b9e1571f905d385c0b450376417' and before['parent']=='ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d'
assert before['python']=='3.12.10'
source_records=[]
for member in before['members']:
 b=subprocess.run(['git','-C','/workspace/scratch/745337b67ff9/windows-journal-lock-control-ad9d','show',before['tree']+':'+member['path']],check=True,capture_output=True,timeout=10).stdout
 assert digest(b)==member['lf_sha256']
 actual=b.replace(b'\n',b'\r\n');assert len(actual)==member['bytes'] and digest(actual)==member['actual_sha256']
 source_records.append({**member,'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'exact_LF_to_CRLF_checkout_verified':True})
assert len(source_records)==7
checkout_before,checkout_after=read(raw/'checkouts-before.json'),read(raw/'checkouts-after.json')
assert checkout_after['tracked_changes']==[]
assert {k:v for k,v in checkout_after.items()if k!='tracked_changes'}==checkout_before
assert checkout_before['driver']=='87fb3a692dd907d3a296f64dce57a62449bdd2b3' and checkout_before['driver_tree']=='d55b5b4a82a2dcccfa4910ab77027e6e96512533'
assert checkout_before['source']==before['source'] and checkout_before['source_tree']==before['tree']
xml_body=(raw/'controls.xml').read_bytes();assert b'<!DOCTYPE'not in xml_body and b'<!ENTITY'not in xml_body
xml=ET.fromstring(xml_body);cases=xml.findall('.//testcase');ids=[(c.attrib['classname'],c.attrib['name'])for c in cases]
assert len(cases)==len(set(ids))==26
assert not any(c.find(k)is not None for c in cases for k in ('failure','error','skipped'))
local=ET.parse('/workspace/scratch/745337b67ff9/windows-journal-lock-control-validation/controls-final26.xml').getroot().findall('.//testcase')
assert ids==[(c.attrib['classname'],c.attrib['name'])for c in local]
result=read(raw/'result.json');assert result['total']==26 and result['failures_or_errors']==result['skipped']==0
assert result['historical_journal_cause_established']==result['timing_qualification']==result['installed_artifact_qualification']==False
actual={}
for case in cases:
 props={}
 for item in case.findall('./properties/property'):
  name=item.attrib['name'];assert name not in props;props[name]=item.attrib['value']
 if not case.attrib['name'].startswith('test_actual_windows_journal_overlap['):continue
 cell=case.attrib['name'].split('[',1)[1][:-1];value=parse(props['journal_lock_report']);assert value==result['windows_cells'][cell];actual[cell]=value
assert set(actual)=={'uncontended','held','released','nonblocking','blocking'}
children=0
for cell,row in actual.items():
 assert row['controller_error']is None and 'holder_cleanup_error'not in row
 assert len(row['cleanup'])==(1 if cell=='uncontended'else 2)
 for cleanup in row['cleanup']:
  assert cleanup['returncode']==0 and not cleanup['killed'] and cleanup['reader_joined'] and cleanup['reader_error']is None
  assert 1<=cleanup['frames']<=16;children+=1
 for report in (row['holder'],row['contender']):
  if report is None:continue
  assert report['callbacks_restored'] and report['recording_failures']==0
  assert report['opened_descriptors']==1 and report['original_descriptors_closed']==[True] and report['emergency_close_results']==[]
  assert report['source_sha256']=='ae6482f105278138f419ae2b33771cc3a91a8bcd8b3552a0bc082b5e9e424988'
  assert report['calls']['open']==report['calls']['close']==report['calls']['acquire']==1
  if report['role']=='nonblocking':
   assert not report['entered'] and report['error']=={'kind':'permission','errno':13,'winerror':None}
   assert report['calls']['unlock']==report['calls']['ftruncate']==0
   assert report['failures']==[{'operation':'acquire',**report['error']}]
  else:
   assert report['entered'] and report['error']is None and report['failures']==[]
   assert report['calls']['unlock']==1 and report['calls']['ftruncate']==(0 if report['role']=='blocking'else 1)
 if cell in ('held','blocking'):assert row['completed_before_release']is False
 if cell=='nonblocking':assert row['completed_before_release']is True
assert children==9
assert read(raw/'original-control-exit.json')=={'invocations':1,'returncode':0}
types=read(raw/'types.json')['summary'];assert types['errorCount']==0
log=(raw/'controls.log').read_text();assert '26 passed, 5 warnings in 5.53s'in log
report={'schema':'pr2974.journal-lock-overlap-result.v1','run':35521747666,'job':106106908254,'source':before['source'],'source_tree':before['tree'],'source_parent':before['parent'],'driver':checkout_before['driver'],'driver_tree':checkout_before['driver_tree'],'archive':verification,'source_bindings':source_records,'before_after_source_environment_equal':True,'checkouts_clean':True,'control_counts':{'total':26,'passed':26,'skipped':0,'failures':0,'windows_cells':5,'portable_controls':21,'warnings':5,'seconds':5.53,'case_identities_match_original_local_collection':True,'retired_direct_children_in_windows_cells':9},'types':types,'windows_cells':actual,'findings':['The unchanged original journal lock succeeds uncontended, under the declared held-byte0 overlap, and after release. Its original held ftruncate succeeded; no pre-lock truncate failure was observed.','The separate same-open/guard nonblocking CRT control denies acquisition with PermissionError/errno13/winerror null while the original holder owns the lock. The blocking primitive succeeds after the declared release ordering.','All nine holder/contender records report original descriptor closure, callback restoration, no emergency cleanup, no recording loss, zero child return, joined reader and no forced kill.'],'limits':['This source-only Windows2025/Python3.12.10 control is not installed artifact, timing, whole-filesystem or universal platform qualification.','The250ms noncompletion interval is observed event ordering, not proof of exact OS blocking duration or scheduler progress.','This controlled case does not reproduce the proposed pre-lock truncate defect and supplies no basis for a product change at that seam.','Historical journal_checkpoint/os_permission remains unattributed. The separate command_activity/sqlite_busy and current native receipt_persistence/sqlite_busy events remain distinct and unexplained.','No corpus replay, timeout/retry increase, error masking, expected-value relaxation or product fix occurred.']}
(root/'verified-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'counts':report['control_counts'],'types':types,'source_bindings':len(source_records),'hypothesis_reproduced':False}))
