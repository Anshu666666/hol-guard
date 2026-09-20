"""Freeze already verified original text; never execute product code."""
import base64
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'packet'

def ident(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def put(name, raw):
    p=OUT/name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(raw)

def dump(name, obj):
    put(name,(json.dumps(obj,indent=2,sort_keys=True)+'\n').encode())

def main():
    OUT.mkdir(exist_ok=False)
    paths = ['FAILURE-PATH.json','LAUNCH.json','VERIFIED-RESULT.json','artifacts.json','jobs.json','run.json','job.log','verify.py','verify.stderr','download.py','download.log','download.stderr','10614508539/verification.json','projected/projection-index.json']
    paths += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT/'source').rglob('*')) if p.is_file()]
    rawpaths = [p for p in sorted((ROOT/'10614508539/raw').rglob('*')) if p.is_file()]
    omitted = []
    for p in rawpaths:
        if p.suffix == '.whl':
            omitted.append({'path':p.relative_to(ROOT).as_posix(),**ident(p.read_bytes())})
        else:
            paths.append(p.relative_to(ROOT).as_posix())
    assert len(rawpaths)==38 and len(omitted)==1
    encoded=[]
    for name in paths:
        raw=(ROOT/name).read_bytes()
        raw.decode('utf-8')
        if len(raw)>64000:
            packed=gzip.compress(raw,mtime=0)
            b64=base64.b64encode(packed)
            parts=[]
            for offset in range(0,len(b64),64000):
                part=f'encodings/{name.replace("/","__")}.part-{offset//64000:03d}.b64'
                put(part,b64[offset:offset+64000]);parts.append(part)
            assert gzip.decompress(base64.b64decode(b''.join((OUT/p).read_bytes() for p in parts)))==raw
            encoded.append({'path':name,'original':ident(raw),'gzip':ident(packed),'parts':parts})
        else: put(name,raw)
    dump('ENCODINGS.json',{'schema':'pr2974.lossless-original-text.v1','entries':encoded})
    dump('ORIGINALS.json',{'preserved_original_texts':[{'path':n,**ident((ROOT/n).read_bytes())} for n in paths], 'omitted_local_binary':omitted,'archive':ident((ROOT/'10614508539/artifact.zip').read_bytes()),'archive_artifact_id':10614508539,'scope':'All 37 original text artifact members are retained exactly, plus exact full original tool log and metadata. Binary ZIP and wheel remain retained locally and cryptographically bound; their bytes are not duplicated into this Git packet. Projected originals can be re-derived from the exact retained log and join the original member bytes. No signed download URL is included.'})
    put('README.md',b'''# Actual current-artifact first-admission result\n\nRun 35541994314 failed before the first-reply fault was offered. It used the authentic a1d5094 source / 9f511875 installed wheel, with all source, driver and installed identities preserved. Forty-one reader controls passed; the original CLI ran once and returned 1.\n\nThe initial await_ack raised its original line 73 authenticated acknowledgement deadline error. That initial 400 ms deadline begins after the strict overlay write and request_publish return. Replacement, fault activation, cold-registration acceptance and the recovered request were not reached. No original clock samples or failed-predicate state survive. PublicationObserver is installed only in the later replacement callback, so publication_events=0 is not proof that no background publication happened.\n\nThe original publisher cleanup reports contained=true. This does not establish earlier readiness or a full descendant cleanup census. The original cell has no successful binding; its derived installed_runtime_matches=false is not a runtime mismatch, because independent before/after package and runtime bindings pass. No source correction, historical cause or full15/performance qualification is established.\n\nVERIFIED-RESULT.json is produced by the retained pure-data verify.py against the original local ZIP, wheel, log and reports. FAILURE-PATH.json binds the exact original two source bodies and separates the initial and recovered deadlines. ENCODINGS.json reversibly preserves large original text bodies as gzip/base64 chunks. ORIGINALS.json inventories every retained original and explicitly identifies binary ZIP/wheel bytes retained locally rather than in this Git tree. Signed download URLs are excluded. No workload or native test was repeated during this data admission.\n''')
    put('freeze_packet.py',Path(__file__).read_bytes())
    files=[{'path':p.relative_to(OUT).as_posix(),**ident(p.read_bytes())} for p in sorted(OUT.rglob('*')) if p.is_file()]
    dump('MANIFEST.json',{'schema':'pr2974.current-first-admission-result-packet.v1','files':files})
    print(json.dumps({'files':len(files)+1,'bytes':sum(r['bytes'] for r in files),'encoded_files':len(encoded),'original_text_artifact_members':37}))

if __name__=='__main__': main()
