"""Bounded authorized artifact read; never a workload."""
import hashlib,json,pathlib,resource,urllib.request,zipfile
resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
p=pathlib.Path(__file__).resolve().parent
m=json.loads((p/'artifact-metadata.json').read_text())['artifacts'][0]
url=json.loads((p/'download-private.json').read_text())['url']
request=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
with urllib.request.urlopen(request,timeout=30) as stream:
 body=stream.read(m['size_in_bytes']+1)
assert len(body)==m['size_in_bytes']==32927
sha=hashlib.sha256(body).hexdigest();assert 'sha256:'+sha==m['digest']
with (p/'artifact.zip').open('xb') as stream:stream.write(body)
rows=[]
with zipfile.ZipFile(p/'artifact.zip') as z:
 names=z.namelist();assert len(names)==len(set(names)) and len(names)<100
 assert sum(i.file_size for i in z.infolist())<4*1024*1024
 for name in names:
  path=pathlib.PurePosixPath(name);assert not path.is_absolute() and '..' not in path.parts
  raw=z.read(name);out=p/'raw'/name;out.parent.mkdir(parents=True,exist_ok=True)
  with out.open('xb') as stream:stream.write(raw)
  rows.append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
proof={'archive_bytes':len(body),'archive_sha256':sha,'members':rows,'prior_transport_failure':{'default_user_agent':{'status':403,'body':'error code: 1010\n\n','artifact_bytes_received':0,'error_body_bytes':17},'successful_accessor':'original GitHub artifact-download temporary file URI with ordinary Mozilla/5.0 User-Agent; no special credentials'}}
(p/'VERIFICATION.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
print(json.dumps({'archive_bytes':len(body),'archive_sha256':sha,'members':len(rows),'hosted_result':json.loads((p/'raw/kernel-private-evidence/RESULT.json').read_text()),'controller':json.loads((p/'raw/kernel-private-evidence/finite-controller.stdout').read_text())},indent=2))
