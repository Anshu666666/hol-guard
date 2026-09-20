"""Independent stdlib data-only source/roster/census joins; no product imports."""
import base64,gzip,hashlib,json,zipfile,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path('/workspace/scratch/745337b67ff9')
P=ROOT/'qualification-launcher-consumer-validation/campaign-packet-v1'
def ident(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def match(b,r):assert all(ident(b)[k]==r[k] for k in ('bytes','sha256','git_blob'))
def merkle(rows):
 def digest(prefix):
  entries=[];dirs=set()
  for name,r in rows.items():
   if not name.startswith(prefix):continue
   suffix=name[len(prefix):]
   if '/' in suffix:dirs.add(suffix.split('/')[0])
   else:entries.append((suffix,False,r['mode'],r['git_blob']))
  for d in dirs:entries.append((d,True,'40000',digest(prefix+d+'/')))
  entries.sort(key=lambda r:(r[0]+('/' if r[1] else '')).encode())
  b=b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha) for name,_,mode,sha in entries)
  return hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).hexdigest()
 return digest('')
def verify():
 packet=json.loads((P/'PACKET-MANIFEST.json').read_bytes())
 rows=packet['files']; originals=json.loads((P/'ORIGINALS.json').read_bytes())['originals']; decoded={}
 for r in rows:match((P/r['path']).read_bytes(),r)
 for r in originals:
  chunks=[]
  for part in r['parts']:
   b=(P/part['path']).read_bytes();match(b,part);chunks.append(b.strip())
  packed=base64.b64decode(b''.join(chunks),validate=True);match(packed,r['compressed'])
  b=gzip.decompress(packed);match(b,r);decoded[r['path']]=b
  if (P/r['path']).exists():assert (P/r['path']).read_bytes()==b
 manifest=json.loads((P/'SOURCE-MANIFEST.json').read_bytes())
 for row in manifest['source_paths']:
  raw=(P/'source'/row['path']).read_bytes();match(raw,row)
  if row['scope']=='unchanged_reviewed_predecessor':assert raw==(ROOT/'qualification-launcher-consumer-validation/packet-v3/source'/row['path']).read_bytes()
 xml=(P/'validation/campaign-controls-v2.xml').read_bytes();match(xml,manifest['validation']['xml'])
 cases=list(ET.fromstring(xml).iter('testcase'));nodes=[c.attrib['classname']+'::'+c.attrib['name'] for c in cases]
 assert nodes==manifest['validation']['ordered_nodes'] and len(nodes)==len(set(nodes))==84
 assert not any(list(c.iter(k)) for c in cases for k in ('skipped','failure','error'))
 types=decoded['validation/campaign-types-v7.json'];match(types,manifest['validation']['types'])
 assert json.loads(types)['summary']==manifest['validation']['type_summary']
 comparison=json.loads(decoded['SOURCE-COMPARISON.json']); old=comparison['full_baseline'];new=comparison['full_candidate']
 assert merkle(old)==comparison['baseline_tree'] and merkle(new)==comparison['candidate_tree']
 assert len(old)==4795 and len(new)==4801
 changes=[{'path':n,'baseline':old.get(n),'candidate':new.get(n)} for n in sorted(old.keys()|new.keys()) if old.get(n)!=new.get(n)]
 assert changes==comparison['changes'] and len(changes)==11
 providers=json.loads((P/'ORIGINAL-PROVIDERS.json').read_bytes())['providers']
 for r in providers:
  raw=(ROOT/'qualification-launcher-campaign-400'/r['path']).read_bytes();match(raw,r['baseline']);match(raw,r['candidate'])
  assert r['byte_equal'] is True and old[r['path']]['git_blob']==new[r['path']]['git_blob']==ident(raw)['git_blob']
 assert len(providers)==98
 wheels=json.loads(decoded['WHEEL-COMPARISON.json'])
 locations=[ROOT/'normal-a5fd-posix/10609894892/raw/native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl',ROOT/'native-normal-a1d/linux-terminal/10615025870/raw/native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl']
 for side,path in zip(('baseline','candidate'),locations,strict=True):
  match(path.read_bytes(),wheels[side+'_wheel'])
  with zipfile.ZipFile(path) as z:
   assert len(z.namelist())==len(set(z.namelist()))==1500
   actual={n:{k:v for k,v in ident(z.read(n)).items() if k!='git_blob'} for n in z.namelist()}
  assert actual==wheels['full_'+side]
 wc=[{'path':n,'baseline':wheels['full_baseline'].get(n),'candidate':wheels['full_candidate'].get(n)} for n in sorted(wheels['full_baseline'].keys()|wheels['full_candidate'].keys()) if wheels['full_baseline'].get(n)!=wheels['full_candidate'].get(n)]
 assert wc==wheels['changes'] and len(wc)==5
 return {'source_packet':'0b126e77bdf7c7392c789ffd6fd4d89cbafef593','packet_leaves_checked':len(rows),'reversible_originals':len(originals),'source_paths':26,'new_paths':9,'unchanged_predecessor_paths':17,'ordered_controls_passed':len(nodes),'type_summary':json.loads(types)['summary'],'source_census':{'baseline':4795,'candidate':4801,'exact_changes':11,'both_full_tree_merkles_match':True},'original_providers_rehashed':98,'wheel_census':{'baseline':1500,'candidate':1500,'exact_changes':5,'both_actual_wheel_bytes_and_all_members_equal':True},'scope':'Pure stdlib data joins of frozen source/original reports; no tests/product imports/benchmark/native/privileged controller executed.'}
if __name__=='__main__':print(json.dumps(verify(),indent=2,sort_keys=True))
