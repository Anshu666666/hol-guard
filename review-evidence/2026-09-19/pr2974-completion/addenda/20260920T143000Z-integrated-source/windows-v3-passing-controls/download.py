import resource
resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
import hashlib,json,pathlib,sys,time,urllib.request,zipfile
root=pathlib.Path('/workspace/scratch/745337b67ff9/windows-product-run35515370428')
spec=json.loads((root/'download-spec.json').read_text())
for row in spec:
    folder=root/str(row['id']);folder.mkdir(exist_ok=False)
    archive=folder/'artifact.zip'
    started=time.monotonic()
    request=urllib.request.Request(row['url'],headers={'User-Agent':'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(request,timeout=20) as response:
            data=response.read(2*1024*1024)
        assert len(data)==row['size'],'archive_size_mismatch'
        assert hashlib.sha256(data).hexdigest()==row['digest'],'archive_digest_mismatch'
        archive.write_bytes(data)
        members=[]
        with zipfile.ZipFile(archive) as z:
            assert len(z.infolist())<=40,'member_bound'
            assert sum(x.file_size for x in z.infolist())<=12*1024*1024,'expanded_size_bound'
            for member in z.infolist():
                p=pathlib.PurePosixPath(member.filename)
                assert not p.is_absolute() and '..' not in p.parts,'member_path_invalid'
                assert not member.is_dir(),'unexpected_directory_member'
                body=z.read(member);content=body.decode('utf-8')
                target=folder/'raw'/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
                members.append({'path':member.filename,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
        record={'artifact_id':row['id'],'artifact_name':row['name'],'archive_bytes':len(data),'archive_sha256':hashlib.sha256(data).hexdigest(),'matches_GitHub_metadata':True,'members':members,'duration_seconds':time.monotonic()-started,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'python':sys.version,'executable':sys.executable,'address_space_limit_bytes':128*1024*1024,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'scope':'data-only download/hash/extraction; no source imports, controls, or workload'}
    except BaseException as error:
        record={'artifact_id':row['id'],'failure_type':type(error).__name__,'duration_seconds':time.monotonic()-started,'scope':'data-only retrieval failed; no workload retry'}
        (folder/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
        raise
    (folder/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k!='members'}))

