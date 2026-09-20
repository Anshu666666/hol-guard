import ast,base64,hashlib,json,zipfile
from email.parser import BytesParser
from pathlib import Path
P=Path('/dev/shm/public-updater-release-inputs')
current=json.loads(Path('/dev/shm/public-updater-rollback-plan/source-bindings.json').read_text())
rows=[]
for tag,key in [('v3.0.193','193'),('v3.0.192','192'),('v3.0.0','300')]:
 p=P/tag;z=zipfile.ZipFile(next(p.glob('*.whl')));names=z.namelist()
 tree=json.loads((P/f'release{key}-tree.json').read_text());commit=json.loads((P/f'release{key}-commit.json').read_text());refs=json.loads((P/f'release{key}-tag.json').read_text());assert not tree['truncated'] and refs['object']['sha']==commit['sha']
 blobs={r['path']:r['sha'] for r in tree['tree'] if r['type']=='blob'}
 d={'tag':tag,'tag_commit':commit['sha'],'tree':commit['tree']['sha'],'all_packaged_python':[],'current_plan_provider_comparison':[]}
 metadata=[n for n in names if n.endswith('.dist-info/METADATA')];assert len(metadata)==1
 msg=BytesParser().parsebytes(z.read(metadata[0]));version=msg['Version'];d.update(version=version,requires_python=msg['Requires-Python'],requires_dist=msg.get_all('Requires-Dist'))
 for n in names:
  if n.startswith('codex_plugin_scanner/') and n.endswith('.py'):
   body=z.read(n);blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest();expected=blobs.get('src/'+n)
   d['all_packaged_python'].append({'path':n,'wheel_git_blob':blob,'source_git_blob':expected,'equal':blob==expected})
 for n in ('codex_plugin_scanner/version.py','codex_plugin_scanner/_native/runtime-manifest.json'):
  if n not in names:continue
  b=z.read(n);dest=p/'members'/n;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
  if n.endswith('version.py'):
   code=ast.parse(b);declared=[ast.literal_eval(v.value) for v in code.body if isinstance(v,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='__version__' for t in v.targets)]
   assert declared==[version];d['code_version']=declared[0]
  else:
   m=json.loads(b);runtime=z.read('codex_plugin_scanner/_native/hol-guard-runtime');assert hashlib.sha256(runtime).hexdigest()==m['runtime_sha256'] and len(runtime)==m['runtime_size'] and m['package_version']==version and m['source_sha']==commit['sha'];d['native_manifest']=m
 for provider in current['providers']:
  n=provider['path'].removeprefix('src/')
  if not provider['path'].startswith('src/'):continue
  if n in names:
   b=z.read(n);bh=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
   d['current_plan_provider_comparison'].append({'path':provider['path'],'current':provider['git_blob'],'release':bh,'equal':bh==provider['git_blob']})
  else:d['current_plan_provider_comparison'].append({'path':provider['path'],'current':provider['git_blob'],'release':None,'equal':False})
 att=next(p.glob('*.intoto.jsonl'));v=json.loads(att.read_text());d['attestation_container_keys']=list(v)
 # Record subjects if a DSSE envelope is present. This is parsing, not signature verification.
 envelope=v.get('dsseEnvelope',v.get('bundle',{}).get('dsseEnvelope'))
 if envelope:
  payload=json.loads(base64.b64decode(envelope['payload']));d['attestation_subjects']=payload.get('subject');d['attestation_predicate_type']=payload.get('predicateType');(p/'attestation-statement.json').write_text(json.dumps(payload,indent=2)+'\n')
 d['cryptographic_attestation_verification']=False
 rows.append(d)
 print(json.dumps({'tag':tag,'version':version,'python_members':len(d['all_packaged_python']),'source_mismatches':[x['path'] for x in d['all_packaged_python'] if not x['equal']],'native':bool(d.get('native_manifest')),'current_providers_equal':sum(x['equal'] for x in d['current_plan_provider_comparison']),'current_providers':len(d['current_plan_provider_comparison']),'attestation_keys':d['attestation_container_keys']}))
(P/'source-comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
