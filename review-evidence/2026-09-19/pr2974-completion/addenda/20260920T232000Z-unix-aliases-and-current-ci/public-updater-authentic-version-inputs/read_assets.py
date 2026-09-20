import base64,csv,hashlib,io,json,zipfile
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path('/dev/shm/public-updater-release-inputs')
selected=json.loads((ROOT/'selection.json').read_text())
result=[]
for release in selected:
 row={k:release[k] for k in ('release_id','tag','target_commitish','published_at')};row['assets']=[]
 dest=ROOT/release['tag'];dest.mkdir(exist_ok=True)
 for a in release['assets']:
  path=dest/a['name'];h=hashlib.sha256();total=0
  if path.exists(): raise RuntimeError('original output already exists')
  with urlopen(Request(a['browser_download_url']),timeout=30) as stream,path.open('xb') as out:
   status=stream.status
   while chunk:=stream.read(1024*1024):
    total+=len(chunk)
    if total>a['size']: raise RuntimeError('oversize response')
    out.write(chunk);h.update(chunk)
  assert status==200 and total==a['size'] and 'sha256:'+h.hexdigest()==a['digest']
  ar={'asset_id':a['id'],'name':a['name'],'size':total,'sha256':h.hexdigest(),'status':status,'source_url':a['browser_download_url']}
  if a['name'].endswith('.whl'):
   with zipfile.ZipFile(path) as z:
    names=z.namelist();assert len(names)==len(set(names))
    recs=[n for n in names if n.endswith('.dist-info/RECORD')];assert len(recs)==1
    records=list(csv.reader(io.StringIO(z.read(recs[0]).decode())))
    seen=[]
    for n,digest,size in records:
     assert n in names and n not in seen;seen.append(n)
     body=z.read(n)
     if n==recs[0]:assert not digest and not size;continue
     assert digest.startswith('sha256=') and int(size)==len(body)
     expected=base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip('=')
     assert expected==digest.split('=',1)[1]
    assert set(seen)==set(names)
    ar['members']=len(names);ar['verified_record_rows']=len(records)
    ar['retained_text_members']=[]
    for n in names:
     if n.endswith(('.dist-info/METADATA','.dist-info/WHEEL','.dist-info/entry_points.txt')) or n.endswith('/_version.py') or 'native-runtime.json' in n or 'native_runtime_manifest' in n or n.endswith('/__about__.py'):
      b=z.read(n);target=dest/'members'/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b)
      ar['retained_text_members'].append({'path':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    ar['native_candidates']=[n for n in names if 'native' in n and not n.endswith(('.py','.json'))]
    ar['updater_providers']=[]
    for n in names:
     if n.startswith('codex_plugin_scanner/guard/cli/update_') and n.endswith('.py'):
      b=z.read(n);target=dest/'members'/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b)
      ar['updater_providers'].append({'path':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
  else:
   ar['cryptographic_verification_performed']=False
  row['assets'].append(ar)
  print(json.dumps({'tag':release['tag'],'name':ar['name'],'bytes':total,'verified':True}),flush=True)
 result.append(row)
(ROOT/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
