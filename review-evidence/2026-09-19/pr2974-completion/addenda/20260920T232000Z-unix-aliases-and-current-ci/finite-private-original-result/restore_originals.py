"""Materialize only exact bounded original evidence into a fresh directory."""
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
