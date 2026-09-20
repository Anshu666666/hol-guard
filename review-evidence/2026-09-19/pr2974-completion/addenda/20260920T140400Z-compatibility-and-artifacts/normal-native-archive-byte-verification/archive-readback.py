import hashlib,json,pathlib,resource,sys,urllib.request,zipfile
resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,256*1024*1024))
rows=json.loads(pathlib.Path(sys.argv[1]).read_text())
root=pathlib.Path('/workspace/scratch/745337b67ff9/normal124-artifact-readback')
root.mkdir(exist_ok=True)
records=[]
for row in rows:
    target=root/(str(row['id'])+'.zip')
    h=hashlib.sha256(); size=0
    with urllib.request.urlopen(urllib.request.Request(row['url'],headers={'User-Agent':'Mozilla/5.0'}),timeout=30) as response,target.open('xb') as out:
        while chunk:=response.read(1048576):
            size+=len(chunk)
            if size>row['size']:raise ValueError('archive bound exceeded')
            h.update(chunk);out.write(chunk)
    if size!=row['size'] or h.hexdigest()!=row['sha256']:raise ValueError('archive identity mismatch')
    with zipfile.ZipFile(target) as archive:
        info=archive.infolist()
        if len(info)>500 or len({m.filename for m in info})!=len(info):raise ValueError('member cardinality')
        if sum(m.file_size for m in info)>512*1024*1024:raise ValueError('total expanded bound')
        members=[]
        for member in info:
            path=pathlib.PurePosixPath(member.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in member.filename or member.flag_bits&1 or member.file_size>96*1024*1024:raise ValueError('member admission')
            if member.is_dir():continue
            digest=hashlib.sha256(); observed=0
            with archive.open(member) as body:
                while chunk:=body.read(1048576):
                    observed+=len(chunk)
                    if observed>member.file_size:raise ValueError('member overflow')
                    digest.update(chunk)
            if observed!=member.file_size:raise ValueError('member length')
            members.append({'name':member.filename,'bytes':observed,'sha256':digest.hexdigest()})
    records.append({'artifact_id':row['id'],'artifact_name':row['name'],'archive_bytes':size,'archive_sha256':h.hexdigest(),'all_members_crc_and_sha256_verified':True,'members':members})
report={'schema':'pr2974.normal124-binary-archive-readback.v1','source':'124472b8949805e0dd36052df6894b335d8b519d','normal_build_commit':'50b39d7e7a4722c2773d94da0ea4c2482f055ef5','source_tree':'a0c139c4e02535545c5b0e602c240a38affde5fe','run':35505324310,'no_imports_or_workload':True,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'archives':records,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
(root/'archive-readback.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
