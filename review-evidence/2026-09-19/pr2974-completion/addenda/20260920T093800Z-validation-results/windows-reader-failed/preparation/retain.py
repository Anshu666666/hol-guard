import hashlib,json,pathlib,resource
assert resource.getrlimit(resource.RLIMIT_AS)==(134217728,134217728)
root=pathlib.Path("/home/user/pr2974-recovery/windows/reader-60619956")
receipt=json.loads((root/"extraction.json").read_bytes())
files=[]
for row in receipt["members"]:
    path=root/"raw"/row["name"]
    data=path.read_bytes()
    assert len(data)==row["bytes"] and hashlib.sha256(data).hexdigest()==row["sha256"]
    files.append({"path":"raw/"+row["name"],"content":data.decode("utf-8")})
for name in ("extraction.json","windows-cases.json"):
    files.append({"path":name,"content":(root/name).read_bytes().decode("utf-8")})
body=json.dumps({"files":files},ensure_ascii=True,separators=(",",":")).encode("ascii")
target=root/"retained-bundle.json"
assert not target.exists()
target.write_bytes(body)
print(json.dumps({"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest(),"files":len(files),"all_original_member_bytes_verified":True}))
