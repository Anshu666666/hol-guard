from pathlib import Path
import base64,gzip,hashlib,json
P=Path(__file__).resolve().parent;OUT=P/'packet';OUT.mkdir(exist_ok=False)
def desc(path,body):return {'path':path,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()}
def write(path,body):
 q=OUT/path;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(body)
originals=['PUBLICATION.json','artifact-metadata.json','jobs.json','run-discovery.json','run-terminal.json','original-job.log','contract.json','driver-nodes.json','VERIFICATION.json','VERIFIED-RESULT.json','download.py','verify.py','artifact.zip']
originals += [str(p.relative_to(P)) for p in sorted((P/'raw').rglob('*')) if p.is_file()]
rows=[]
for name in originals:
 body=(P/name).read_bytes();stored=name;encoding='identity'
 if name=='artifact.zip':stored+=' .b64';stored=stored.replace(' ','');encoding='base64';encoded=base64.b64encode(body)+b'\n'
 elif len(body)>100000:stored+='.gz.b64';encoding='gzip-base64';encoded=base64.b64encode(gzip.compress(body,mtime=0))+b'\n'
 else:encoded=body
 write(stored,encoded);rows.append({**desc(name,body),'stored_path':stored,'encoding':encoding})
write('ORIGINALS.json',(json.dumps(rows,indent=2,sort_keys=True)+'\n').encode())
restore='''"""Materialize only exact bounded original evidence into a fresh directory."""
from pathlib import Path
import base64,gzip,hashlib,io,json,sys
root=Path(__file__).resolve().parent
out=Path(sys.argv[1]);out.mkdir(exist_ok=False)
rows=json.loads((root/'ORIGINALS.json').read_bytes())
assert len(rows)<100 and sum(r['bytes'] for r in rows)<4*1024*1024
for row in rows:
 name=Path(row['path']);assert not name.is_absolute() and '..' not in name.parts
 body=(root/row['stored_path']).read_bytes()
 if row['encoding'] in {'base64','gzip-base64'}:body=base64.b64decode(body.strip(),validate=True)
 if row['encoding']=='gzip-base64':
  with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:body=stream.read(row['bytes']+1)
 assert len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256']
 p=out/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(body)
print(json.dumps({'originals':len(rows),'bytes':sum(r['bytes'] for r in rows),'exact':True}))
'''
write('restore_originals.py',restore.encode())
write('INDEX.md',b'''# Finite protected live-member private-memory prerequisite\n\nOriginal run 35540050314, job 106155953451, exact source 331fcfe5 and driver 42e917f9 completed successfully. This packet retains the authentic 32,927-byte original artifact losslessly, all 27 original members, decoded job log, endpoint metadata, strict data reader and its derived result. No private download URL is included.\n\n255 source controls and 19 driver controls passed. The three actual finite cases each have 33 retained samples: live child/grandchild, a protected member outside ancestry, and explicit denied USS. The denied value is null and its minimum false. Stable finite live sampling is not an instantaneous memory-peak proof or a benchmark result. All actual singleton membership witnesses and the root cleanup result are separately retained; no orphan waitpid claim.\n\n`ORIGINALS.json` gives original and stored encoding identities. `restore_originals.py NEW_DIRECTORY` reconstructs exact original evidence without executing a product; run the restored `verify.py` only for data reconciliation. The original worker stdout was not separately exported by the bound controller; its safe parsed object is in original controller stdout and source serialization exactly joins its length and hash.\n\nOriginal CPU5 execution is not repeated. No installed launcher, native workload, performance campaign, or program qualification is claimed. Prior transport403/error1010 is retained in VERIFICATION; the approved temporary artifact URI with ordinary Mozilla User-Agent then supplied authenticated original bytes.\n''')
write('freeze_result.py',Path(__file__).read_bytes())
files=[desc(str(p.relative_to(OUT)),p.read_bytes()) for p in sorted(OUT.rglob('*')) if p.is_file()]
write('MANIFEST.json',(json.dumps({'files':files,'original_count':len(rows),'original_bytes':sum(r['bytes'] for r in rows),'original_workload':False},indent=2,sort_keys=True)+'\n').encode())
print(json.dumps({'leaves':len(files)+1,'originals':len(rows),'bytes':sum(r['bytes'] for r in files),'original_bytes':sum(r['bytes'] for r in rows)}))
