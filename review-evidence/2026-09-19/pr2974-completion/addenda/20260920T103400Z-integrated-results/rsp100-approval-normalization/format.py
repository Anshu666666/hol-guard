from pathlib import Path
import ast,base64,difflib,hashlib,json,os,resource,shutil,subprocess
root=Path('/home/user/pr2974-recovery/requirements/approval-v1-driver-format')
resource.setrlimit(resource.RLIMIT_AS,(134217728,134217728))
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
os.environ['RAYON_NUM_THREADS']='1'
ruff=Path('/home/user/pr2974-recovery/windows/reader-format-4d/ruff')
cfg=Path('/home/user/pr2974-recovery/windows/reader-linux-final-format/after/reader-source/pyproject.toml')
assert hashlib.sha256(ruff.read_bytes()).hexdigest()=='ae9e6252f6021b1303a08a29ffe4e6c627352b57e03137008b1efc4dca803d23'
assert hashlib.sha256(cfg.read_bytes()).hexdigest()=='f6538a00756a7604c72127732774267f8549cace4b6b29468a4e6d18fc6511cb'
files=json.loads(base64.b64decode((root/'payload.b64').read_bytes()))['files']
for f in files:
 data=f['content'].encode();assert hashlib.sha256(data).hexdigest()==f['sha256']
 for scope in ('before','after'):
  p=root/scope/f['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
for scope in ('before','after'):
 shutil.copyfile(cfg,root/scope/'pyproject.toml')
report={'scope':'Ruff/AST/read-only lint only; no product imports/tests/builds','rlimit_as':134217728,'cpu_affinity':list(os.sched_getaffinity(0)),'ruff_sha256':hashlib.sha256(ruff.read_bytes()).hexdigest(),'config_sha256':hashlib.sha256(cfg.read_bytes()).hexdigest(),'commands':[],'files':[]}
paths=[f['path'] for f in files]
for args in (['format',*paths],['check',*paths],['format','--check',*paths]):
 r=subprocess.run([str(ruff),*args],cwd=root/'after',capture_output=True,text=True,timeout=60)
 report['commands'].append({'argv':[str(ruff),*args],'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
records=[]
for f in files:
 before=f['content'];after=(root/'after'/f['path']).read_text()
 item={'path':f['path'],'ast_equal':ast.dump(ast.parse(before),include_attributes=False)==ast.dump(ast.parse(after),include_attributes=False),'identities':{}}
 for scope,text in [('before',before),('after',after)]:
  data=text.encode();item['identities'][scope]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'git_blob_sha':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'physical_lines':len(text.splitlines())}
 report['files'].append(item)
 records.extend([{'path':'before/'+f['path'],'content':before},{'path':'after/'+f['path'],'content':after},{'path':'diff/'+f['path']+'.diff','content':''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='before/'+f['path'],tofile='after/'+f['path']))}])
records.append({'path':'report.json','content':json.dumps(report,indent=2)+'\n'})
out=json.dumps({'records':records},ensure_ascii=False).encode();(root/'result.json').write_bytes(out)
print(json.dumps({'bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),'report':report}))
