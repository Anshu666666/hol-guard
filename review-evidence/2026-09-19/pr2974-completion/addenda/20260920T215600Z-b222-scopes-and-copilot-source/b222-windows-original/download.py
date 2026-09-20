import resource
resource.setrlimit(resource.RLIMIT_AS, (128*1024*1024,128*1024*1024))
import hashlib,json,pathlib,sys,time,urllib.request,zipfile
root=pathlib.Path("/workspace/scratch/745337b67ff9/windows-normal-b222318")
for row in json.loads((root/'download-private.json').read_text()):
    folder=root/str(row['id']); folder.mkdir(exist_ok=False)
    archive=folder/'artifact.zip'; started=time.monotonic()
    digest=hashlib.sha256(); size=0
    try:
        request=urllib.request.Request(row['url'],headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(request,timeout=20) as response, archive.open('wb') as output:
            while chunk:=response.read(65536):
                size+=len(chunk); assert size<=row['size'],'archive_size_overflow'
                digest.update(chunk); output.write(chunk)
        assert size==row['size'],'archive_size_mismatch'
        assert digest.hexdigest()==row['digest'],'archive_digest_mismatch'
        members=[]
        with zipfile.ZipFile(archive) as z:
            assert len(z.infolist())<=100,'member_bound'
            assert sum(x.file_size for x in z.infolist())<=64*1024*1024,'expanded_size_bound'
            for member in z.infolist():
                p=pathlib.PurePosixPath(member.filename)
                assert not p.is_absolute() and '..' not in p.parts,'member_path_invalid'
                assert not member.is_dir(),'unexpected_directory'
                target=folder/'raw'/p; target.parent.mkdir(parents=True,exist_ok=True)
                digest_member=hashlib.sha256(); member_size=0
                with z.open(member) as inp, target.open('wb') as out:
                    while chunk:=inp.read(65536):
                        digest_member.update(chunk);member_size+=len(chunk);out.write(chunk)
                assert member_size==member.file_size
                members.append({'path':member.filename,'bytes':member_size,'sha256':digest_member.hexdigest()})
        record={'artifact_id':row['id'],'artifact_name':row['name'],'archive_bytes':size,'archive_sha256':digest.hexdigest(),'matches_GitHub_metadata':True,'members':members,'duration_seconds':time.monotonic()-started,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'python':sys.version,'executable':sys.executable,'address_space_limit_bytes':128*1024*1024,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'scope':'data-only download/hash/extraction; no application imports, controls, or workloads'}
    except BaseException as error:
        record={'artifact_id':row['id'],'failure_type':type(error).__name__,'duration_seconds':time.monotonic()-started,'scope':'data-only retrieval failure'}
        (folder/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
        raise
    (folder/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ('artifact_id','archive_bytes','archive_sha256','matches_GitHub_metadata','duration_seconds','peak_rss_kib')}))

