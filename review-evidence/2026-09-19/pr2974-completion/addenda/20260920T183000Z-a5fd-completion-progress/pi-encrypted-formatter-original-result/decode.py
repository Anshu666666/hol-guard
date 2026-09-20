import base64, hashlib, json, re, difflib
from pathlib import Path
root=Path(__file__).parent
log=(root/'original-job.log').read_bytes()
def describe(body):
 return {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()}
def unique(pairs):
 result={}
 for k,v in pairs:
  if k in result: raise ValueError('duplicate key')
  result[k]=v
 return result
frames={}; current=None; chunks=[]; summary=None
for line in log.decode().splitlines():
 m=re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z HOL_GUARD_FORMAT_PROJECTION_(BEGIN|CHUNK|END|SUMMARY) (.*)',line)
 if not m: continue
 kind,raw=m.groups(); value=json.loads(raw,object_pairs_hook=unique)
 if kind=='BEGIN':
  assert current is None and value['path'] not in frames
  assert value['bytes']<=1048576 and value['chunks']==(value['bytes']+4095)//4096
  p=Path(value['path']); assert not p.is_absolute() and '..' not in p.parts
  current=value; chunks=[]
 elif kind=='CHUNK':
  assert current and value['path']==current['path'] and value['index']==len(chunks)
  b=base64.b64decode(value['base64'],validate=True); assert len(b)<=4096
  chunks.append(b)
 elif kind=='END':
  assert current==value and len(chunks)==value['chunks']
  b=b''.join(chunks); assert describe(b)=={k:value[k] for k in describe(b)}
  frames[value['path']]=b; current=None
 else:
  assert summary is None; summary=value
assert current is None and summary['projection_complete'] and summary['formatter_preparation_passed']
index=json.loads(frames['log-projection-index.json']); result=json.loads(frames['formatting-result.json'])
assert index['projection_complete'] and result['formatting_preparation_passed']
assert result['source_before']==result['source_after'] and result['driver_before']==result['driver_after']
assert result['source_before']['head']=='098bcdce84ff39afc52b3dbe5ee3ddb451a323f9'
assert result['driver_before']['head']=='353dbf3fffd6691b0df0542d1ed65f7dbd8298cc'
assert len(index['files'])+1==len(frames)==34
for row in index['files']:
 assert describe(frames[row['path']])=={k:row[k] for k in describe(b'')}
assert len(result['formatted_files'])==6
for row in result['formatted_files']:
 assert row['idempotent'] and describe(frames[row['output_path']])==row['output']
 old=(root.parent/'pi-encrypted-format-prep'/row['input_path']).read_bytes()
 assert describe(old)==row['input']
 diff=''.join(difflib.unified_diff(old.decode().splitlines(True),frames[row['output_path']].decode().splitlines(True),fromfile='before',tofile='after'))
 (root/(Path(row['output_path']).name+'.diff')).write_text(diff)
for path,body in frames.items():
 p=root/'returned'/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(body)
receipt={'run':35528060952,'job':106123602636,'original_log':describe(log),'frames_verified':len(frames),'source':result['source_before'],'driver':result['driver_before'],'formatted_files':result['formatted_files'],'native_compilation_executed':False,'native_controls_executed':False,'archive_scope':'Metadata only; log projection is a selected original artifact subset.'}
(root/'verification.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'frames':len(frames),'source_images':[(Path(x['output_path']).name,x['output']['git_blob'],x['changed']) for x in result['formatted_files']]}))
