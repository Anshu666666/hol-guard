import hashlib, json, os, pathlib, resource, signal, zipfile
resource.setrlimit(resource.RLIMIT_AS, (128*1024*1024, 128*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU, (15,15))
signal.alarm(30)
expected_boot="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()==expected_boot
archive_path=pathlib.Path("/home/user/pr2974-native-observer-gap-8f-original-v1/artifact.zip")
root=pathlib.Path("/home/user/pr2974-native-workspace-8f-original-v1")
root.mkdir(mode=0o700,exist_ok=False)
expected_archive_sha="693aab90fd15e90619994c54a50675b7c8ac2d5501b44d97f29bfadb92d4ce57"
selected={
"hol-guard/hol-guard/candidate-src/phase-evidence/workspace-lifecycle.json":(25061,"209be9c3d774b1279151180fc510ee14bed3405cfbf459e469d0db5f38ca6fa6"),
"hol-guard/hol-guard/candidate-src/phase-evidence/workspace-lifecycle.jsonl":(255626,"18e9cb4a408e233f1ddeb5d7710823550341984113d813bd644166b8bf77c1bb"),
}
report={"schema":"pr2974.workspace8f-original-member-recovery.v1","artifact_id":10599581007,"passed":False,"native_or_test_execution":False,"new_network_download":False,"selected_member_count":2}
stage="archive_hash"
try:
    before=archive_path.stat()
    assert archive_path.resolve(strict=True)==archive_path and archive_path.is_file()
    assert before.st_size==22575317
    h=hashlib.sha256();size=0
    with archive_path.open("rb") as source:
        while chunk:=source.read(65536):
            size+=len(chunk);assert size<=22575317;h.update(chunk)
    assert size==22575317 and h.hexdigest()==expected_archive_sha
    stage="zip_member_admission"
    members={};descriptions=[]
    with zipfile.ZipFile(archive_path) as archive:
        entries=archive.infolist()
        assert len(entries)==54 and len({x.filename for x in entries})==54
        for entry in entries:
            p=pathlib.PurePosixPath(entry.filename)
            assert not p.is_absolute() and ".." not in p.parts and "\\" not in entry.filename
        for name,(expected_size,expected_sha) in selected.items():
            item=archive.getinfo(name)
            assert item.file_size==expected_size and 0<item.compress_size<=22575317
            with archive.open(item) as stream:
                body=stream.read(expected_size+1)
            assert len(body)==expected_size and hashlib.sha256(body).hexdigest()==expected_sha
            text=body.decode("utf-8")
            (root/pathlib.PurePosixPath(name).name).write_bytes(body)
            members[name]=text
            descriptions.append({"path":name,"bytes":len(body),"sha256":expected_sha,
                "git_blob":hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()})
    after=archive_path.stat()
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
    report.update({"passed":True,"zip_hash_verified":True,"archive_bytes":size,"archive_sha256":h.hexdigest(),
       "archive_member_count":54,"selected_members":descriptions,"unselected_member_bodies_read":False,
       "source_archive_unchanged":True,"boot":expected_boot})
    bundle=(json.dumps({"verification":report,"members":members},ensure_ascii=True,sort_keys=True,indent=2)+"\n").encode("ascii")
    assert len(bundle)<=512*1024
    (root/"member-transfer.json").write_bytes(bundle)
    report["transfer"]={"bytes":len(bundle),"sha256":hashlib.sha256(bundle).hexdigest(),"chunk_bytes":16384,"chunks":(len(bundle)+16383)//16384}
except BaseException as error:
    report.update({"failed_stage":stage,"failure_type":type(error).__name__})
report["maximum_rss_bytes"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
(root/"recovery-verification.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
print(json.dumps(report,sort_keys=True))
