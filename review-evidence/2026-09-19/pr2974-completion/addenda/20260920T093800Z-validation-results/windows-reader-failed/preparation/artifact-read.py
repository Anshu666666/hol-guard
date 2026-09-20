import datetime,hashlib,json,os,pathlib,platform,resource,sys,urllib.request,zipfile
assert resource.getrlimit(resource.RLIMIT_AS)==(134217728,134217728)
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()=="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
root=pathlib.Path("/home/user/pr2974-recovery/windows/reader-60619956")
assert root.is_dir() and not list(root.iterdir())
artifact_url="SIGNED_DOWNLOAD_URL_NOT_RETAINED"
try:
    with urllib.request.urlopen(artifact_url,timeout=30) as response:
        archive=response.read(33071)
except Exception as error:
    print(json.dumps({"stage":"artifact_download","failed":True,"error_kind":type(error).__name__,"http_status":getattr(error,"code",None)}))
    raise SystemExit(1)
assert len(archive)==33070
assert hashlib.sha256(archive).hexdigest()=="b5fd787a912bc4e0ea90f72a82e21b0312c21cceca63da8daf5266f73c9f7a58"
(root/"artifact.zip").write_bytes(archive)
members=[]
with zipfile.ZipFile(root/"artifact.zip") as bundle:
    infos=bundle.infolist()
    assert len({info.filename for info in infos})==len(infos)
    assert sum(info.file_size for info in infos)<=4000000
    for info in infos:
        name=pathlib.PurePosixPath(info.filename)
        assert not name.is_absolute() and ".." not in name.parts
        if info.is_dir(): continue
        assert info.file_size<=2000000
        data=bundle.read(info)
        assert len(data)==info.file_size
        data.decode("utf-8")
        target=root/"raw"/pathlib.Path(*name.parts)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
        members.append({"name":info.filename,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
record={"schema":"windows-reader-60619956-artifact-extraction.v1","run_id":35501374231,"job_id":106053608942,"attempt":1,
"artifact_id":10602586264,"artifact_bytes":len(archive),"artifact_sha256":hashlib.sha256(archive).hexdigest(),
"source_sha":"60619956b77c7770c0e53c474f948be095340ffb","driver_sha":"634267a7bbe843efbd6c4c9556b79a64543a27e9",
"members":members,"environment":{"session":"wife","suffix":"asnf","boot_id":"c6aba711-75f6-4cbb-90b1-d991ba91b54e",
"python":sys.version,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"as_limit":list(resource.getrlimit(resource.RLIMIT_AS)),
"peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},"data_only":True,"source_imports_tests_builds":False}
(root/"extraction.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
print(json.dumps(record,sort_keys=True))
