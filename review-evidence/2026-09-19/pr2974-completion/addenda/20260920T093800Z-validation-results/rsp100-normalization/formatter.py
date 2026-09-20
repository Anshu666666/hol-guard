from pathlib import Path
import ast,base64,collections,copy,difflib,hashlib,json,os,resource,shutil,subprocess
root=Path('/home/user/pr2974-recovery/requirements/risk-v8-final-format')
old=Path('/home/user/pr2974-recovery/requirements/approval-v5-format')
resource.setrlimit(resource.RLIMIT_AS,(134217728,134217728))
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
os.environ['RAYON_NUM_THREADS']='1'
ruff=Path('/home/user/pr2974-recovery/windows/reader-format-4d/ruff')
cfg=Path('/home/user/pr2974-recovery/windows/reader-linux-final-format/after/reader-source/pyproject.toml')
assert hashlib.sha256(ruff.read_bytes()).hexdigest()=='ae9e6252f6021b1303a08a29ffe4e6c627352b57e03137008b1efc4dca803d23'
assert hashlib.sha256(cfg.read_bytes()).hexdigest()=='f6538a00756a7604c72127732774267f8549cace4b6b29468a4e6d18fc6511cb'
payload=json.loads(base64.b64decode((root/'payload.b64').read_bytes()))
for e in payload['entries']:
 data=e['content'].encode();assert hashlib.sha256(data).hexdigest()==e['sha256']
 p=root/'input'/e['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
approval_paths=[x['path'] for x in json.loads((old/'report.json').read_text())['files']]
pair_paths=[e['path'][5:] for e in payload['entries'] if e['path'].startswith('pair/')]
all_paths=approval_paths+pair_paths
for scope in ('before','after'):
 for path in approval_paths:
  p=root/scope/path;p.parent.mkdir(parents=True,exist_ok=True)
  src=root/'input'/'approval'/path
  shutil.copyfile(src if src.exists() else old/'after'/path,p)
 for path in pair_paths:
  p=root/scope/path;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/'input'/'pair'/path,p)
 for ctx in (old/'context',root/'input'/'context'):
  for p in ctx.rglob('*'):
   if p.is_file():
    q=root/scope/p.relative_to(ctx);q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
 shutil.copyfile(cfg,root/scope/'pyproject.toml')
report={'scope':'format/AST/read-only lint only; no product imports/tests/builds','resource_limit_bytes':134217728,'affinity':list(os.sched_getaffinity(0)),'ruff_sha256':hashlib.sha256(ruff.read_bytes()).hexdigest(),'config_sha256':hashlib.sha256(cfg.read_bytes()).hexdigest(),'commands':[],'files':[],'approval_prior_tree':'72a1760625b95cf8a993bf5b71da3d71afab99b2','pair_prior_tree':'fe65b8da4bd85b17f5673997b37ba0e280cbc1ae','lint_context':[e['path'][8:] for e in payload['entries'] if e['path'].startswith('context/')]}
for args in (['format',*all_paths],['check',*all_paths],['format','--check',*all_paths]):
 r=subprocess.run([str(ruff),*args],cwd=root/'after',capture_output=True,text=True,timeout=60)
 report['commands'].append({'argv':[str(ruff),*args],'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
class ImportNormalizer(ast.NodeTransformer):
 def visit_Import(self,node):
  node.names.sort(key=lambda x:(x.name,x.asname or ''))
  return node
 def visit_ImportFrom(self,node):
  node.names.sort(key=lambda x:(x.name,x.asname or ''))
  return node
 def generic_visit(self,node):
  node=super().generic_visit(node)
  for field,value in ast.iter_fields(node):
   if isinstance(value,list):
    start=0
    while start<len(value):
     if not isinstance(value[start],(ast.Import,ast.ImportFrom)):
      start+=1;continue
     end=start+1
     while end<len(value) and isinstance(value[end],(ast.Import,ast.ImportFrom)):end+=1
     value[start:end]=sorted(value[start:end],key=lambda n:ast.dump(n,include_attributes=False))
     start=end
  return node
def norm(text):
 return ast.dump(ImportNormalizer().visit(ast.parse(text)),include_attributes=False)
records=[]
for path in all_paths:
 before=(root/'before'/path).read_text();after=(root/'after'/path).read_text()
 entry={'path':path,'kind':'approval' if path in approval_paths else 'pair','format_ast_equal':ast.dump(ast.parse(before),include_attributes=False)==ast.dump(ast.parse(after),include_attributes=False),'identities':{}}
 if path in approval_paths:
  prior=(old/'after'/path).read_text()
  entry['prior_exact_ast_equal']=ast.dump(ast.parse(prior),include_attributes=False)==ast.dump(ast.parse(before),include_attributes=False)
  entry['prior_import_normalized_ast_equal']=norm(prior)==norm(before)
  delta=''.join(difflib.unified_diff(prior.splitlines(True),after.splitlines(True),fromfile='prior/'+path,tofile='after/'+path))
 else:
  delta=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='before/'+path,tofile='after/'+path))
 for scope,text in [('before',before),('after',after)]:
  data=text.encode()
  entry['identities'][scope]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'git_blob_sha':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'physical_lines':len(text.splitlines())}
 report['files'].append(entry)
 records.extend([{'path':'after/'+path,'content':after},{'path':'diff/'+path+'.diff','content':delta}])
records.append({'path':'report.json','content':json.dumps(report,indent=2)+'\n'})
out=json.dumps({'records':records},ensure_ascii=False).encode()
(root/'results.json').write_bytes(out)
print(json.dumps({'result_bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),'report':report}))
