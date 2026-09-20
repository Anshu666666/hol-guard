import hashlib, io, json, os, pathlib, platform, resource, sys, urllib.request, urllib.error, zipfile
resource.setrlimit(resource.RLIMIT_AS, (134217728, 134217728))
base=pathlib.Path("/home/user/pr2974-recovery/windows/wtext-typed-17f902-result")
base.mkdir(parents=True,exist_ok=False)
boot=pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
if boot!="c6aba711-75f6-4cbb-90b1-d991ba91b54e": raise RuntimeError("unexpected_environment_boot")
request=urllib.request.Request("SIGNED_DOWNLOAD_URL_OMITTED",headers={"User-Agent":"Mozilla/5.0"})
try:
    with urllib.request.urlopen(request,timeout=20) as response:
        archive=response.read(31442)
except urllib.error.HTTPError as error:
    print(json.dumps({"success":False,"error":"HTTPError","status":error.code}))
    raise SystemExit(1)
except Exception as error:
    print(json.dumps({"success":False,"error":type(error).__name__}))
    raise SystemExit(1)
expected="eef9059e06dc303ffed0314cdac7185489c493a0c912e31d987f2ca043d422dd"
if len(archive)!=31441 or hashlib.sha256(archive).hexdigest()!=expected: raise RuntimeError("archive_binding_failed")
(base/"artifact.zip").write_bytes(archive)
files=[]; total=0; names=set()
with zipfile.ZipFile(io.BytesIO(archive)) as z:
    if len(z.infolist())>64: raise RuntimeError("member_count_bound")
    for entry in z.infolist():
        if entry.is_dir(): continue
        name=entry.filename
        p=pathlib.PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts or "\\" in name or name in names: raise RuntimeError("member_name_invalid")
        names.add(name)
        if entry.file_size>2097152: raise RuntimeError("member_size_bound")
        total+=entry.file_size
        if total>8388608: raise RuntimeError("expanded_size_bound")
        data=z.read(entry); content=data.decode("utf-8")
        if content.encode("utf-8")!=data: raise RuntimeError("text_roundtrip_failed")
        out=base/"members"/p;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
        files.append({"path":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"content":content})
receipt={"schema":"pr2974-ex-probe-archive-verification-v1","source_sha":"17f902933bd80eee30f99bd0dd28c950068c8612","driver_sha":"226cb3ae1602007eac704398c7046cd3a207722e","run_id":35507531640,"job_id":106069763851,"artifact_id":10604806432,"archive_bytes":len(archive),"archive_sha256":expected,"member_count":len(files),"member_bytes":total,"environment":{"session":"wife","suffix":"asnf","boot_id":boot,"python":sys.version,"executable":sys.executable,"hostname":platform.node(),"path":str(base),"address_space_limit":134217728,"peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},"limits":{"data_only":True,"source_imports":False,"source_tests":False,"workload_replay":False,"binary_uploaded":False}}
bundle={"verification":receipt,"files":files}
data=json.dumps(bundle,ensure_ascii=False,sort_keys=True).encode("utf-8")
(base/"retained-bundle.json").write_bytes(data)
(base/"verification.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"success":True,"bundle_bytes":len(data),"bundle_sha256":hashlib.sha256(data).hexdigest(),"verification":receipt,"members":[{k:v for k,v in f.items() if k!="content"} for f in files]}))
