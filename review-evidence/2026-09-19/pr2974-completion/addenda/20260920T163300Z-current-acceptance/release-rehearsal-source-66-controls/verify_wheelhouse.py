import email.parser, hashlib, json, platform, sys, urllib.request, zipfile
from pathlib import Path
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
root=Path(sys.argv[1]); dest=Path(sys.argv[2]); dest.mkdir(exist_ok=True)
records=[]
for wheel in sorted(root.glob('*.whl')):
    with zipfile.ZipFile(wheel) as z:
        names=[n for n in z.namelist() if n.endswith('.dist-info/METADATA')]
        assert len(names)==1
        md=email.parser.BytesParser().parsebytes(z.read(names[0]))
    name=canonicalize_name(md['Name']); version=md['Version']
    request=urllib.request.Request(f'https://pypi.org/pypi/{name}/{version}/json',headers={'User-Agent':'HOL-Guard-artifact-rehearsal/1'})
    with urllib.request.urlopen(request,timeout=30) as response:
        raw=response.read(4*1024*1024+1)
    assert len(raw)<=4*1024*1024
    (dest/f'{name}-{version}.pypi.json').write_bytes(raw)
    meta=json.loads(raw); matches=[f for f in meta['urls'] if f['filename']==wheel.name]; assert len(matches)==1
    expected=matches[0]; sha=hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert expected['digests']['sha256']==sha and expected['size']==wheel.stat().st_size and not expected['yanked']
    records.append({'name':name,'version':version,'filename':wheel.name,'bytes':wheel.stat().st_size,'sha256':sha,'url':expected['url'],'requires_dist':md.get_all('Requires-Dist',[]),'metadata_sha256':hashlib.sha256(raw).hexdigest()})
versions={r['name']:Version(r['version']) for r in records}
for record in records:
    for text in record['requires_dist']:
        requirement=Requirement(text)
        if requirement.marker and not requirement.marker.evaluate({'extra':''}): continue
        assert canonicalize_name(requirement.name) in versions, text
        assert versions[canonicalize_name(requirement.name)] in requirement.specifier, text
lock=''.join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n" for r in records)
(dest/'requirements.txt').write_text(lock)
report={'schema':'hol-guard-rehearsal-build-lock.v1','python':platform.python_version(),'platform':platform.platform(),'resolver':'pip 26.2.1 download --only-binary=:all:','historical_backend_identity_only':'Hatchling 1.30.1; newly resolved dependency bytes, not a claim of original isolated backend closure','requirements_sha256':hashlib.sha256(lock.encode()).hexdigest(),'wheels':records}
(dest/'wheelhouse-lock.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'wheel_count':len(records),'total_bytes':sum(r['bytes'] for r in records),'versions':{r['name']:r['version'] for r in records},'lock_sha256':report['requirements_sha256']}))
