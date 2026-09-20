import base64, hashlib, json, os, pathlib, resource, signal, sys, time
LIMIT=95*1024*1024
resource.setrlimit(resource.RLIMIT_AS,(LIMIT,LIMIT))
resource.setrlimit(resource.RLIMIT_CPU,(45,45))
signal.alarm(90)
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()=="c6aba711-75f6-4cbb-90b1-d991ba91b54e", "sandbox boot changed"
ROOT=pathlib.Path("/home/user/pr2974-worker-retirement-decode-asnf")
SRC=ROOT/"framed-reports.json"
assert SRC.stat().st_size==57292752
CAP=8*1024*1024
OUT=ROOT/"members-v1"
OUT.mkdir(exist_ok=False)

def strict_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result
def reject_constant(value):
    raise ValueError("nonfinite_json")
def strict_loads(raw):
    return json.loads(raw, object_pairs_hook=strict_pairs, parse_constant=reject_constant)

class Reader:
 def __init__(self,f):
  self.f=f; self.buf=b""; self.i=0; self.pos=0; self.h=hashlib.sha256()
 def peek(self):
  if self.i==len(self.buf):
   self.buf=self.f.read(65536); self.i=0; self.h.update(self.buf)
  return self.buf[self.i] if self.i<len(self.buf) else None
 def take(self):
  b=self.peek()
  if b is None: raise ValueError("unexpected eof")
  self.i+=1; self.pos+=1; return b
 def space(self):
  while self.peek() in (9,10,13,32): self.take()
 def expect(self,v):
  self.space(); assert self.take()==v, ("delimiter",self.pos,v)
 def value(self,cap):
  self.space(); start=self.pos; first=self.peek()
  assert first is not None
  out=bytearray(); digest=hashlib.sha256(); block=bytearray()
  stack=[]; quoted=False; escaped=False; primitive=first not in (34,91,123)
  while True:
   b=self.peek()
   if primitive and (b is None or b in (9,10,13,32,44,93,125)): break
   b=self.take(); block.append(b)
   if len(out)<cap: out.append(b)
   if len(block)==65536: digest.update(block); block.clear()
   if quoted:
    if escaped: escaped=False
    elif b==92: escaped=True
    elif b==34:
     quoted=False
     if not stack and not primitive: break
   else:
    if b==34: quoted=True
    elif b==123: stack.append(125)
    elif b==91: stack.append(93)
    elif b in (93,125):
     assert stack and stack.pop()==b, ("bad nesting",self.pos)
     if not stack: break
  digest.update(block); n=self.pos-start
  assert n>0 and not quoted and not stack, ("incomplete value",start)
  return {"start":start,"bytes":n,"sha256":digest.hexdigest(),"raw":bytes(out) if n<=cap else None}
 def small(self,cap=4096):
  row=self.value(cap); assert row["raw"] is not None
  return strict_loads(row["raw"])
started=time.monotonic(); metadata={}; members=[]; seen=set(); top_seen=set(); total=0
with SRC.open("rb") as f:
 r=Reader(f); r.expect(123)
 while True:
  r.space()
  if r.peek()==125: r.take(); break
  key=r.small(); assert type(key) is str and key not in top_seen
  top_seen.add(key)
  r.expect(58)
  if key!="files":
   metadata[key]=r.small()
  else:
   assert not members
   r.expect(123)
   while True:
    r.space()
    if r.peek()==125: r.take(); break
    name=r.small(); assert type(name) is str and name not in seen
    seen.add(name); p=pathlib.PurePosixPath(name)
    assert name == p.as_posix() and not p.is_absolute() and p.parts and all(x not in ("","..",".") for x in p.parts) and "\\" not in name
    r.expect(58); item=r.value(CAP)
    info={"path":name,"packet_value_bytes":item["bytes"],"packet_value_sha256":item["sha256"],"packet_offset":item["start"]}
    if item["raw"] is None:
     info.update(verified=False,reason="encoded_member_exceeds_8MiB_selection_limit")
    else:
     obj=strict_loads(item["raw"]); del item["raw"]
     assert type(obj) is dict and set(obj)=={"bytes","content","encoding","sha256"}, name
     assert type(obj["bytes"]) is int and 0<=obj["bytes"]<=32*1024*1024
     assert type(obj["content"]) is str and type(obj["sha256"]) is str
     assert obj["encoding"] in ("utf-8","base64")
     raw=obj["content"].encode("utf-8") if obj["encoding"]=="utf-8" else base64.b64decode(obj["content"],validate=True)
     assert len(raw)==obj["bytes"] and hashlib.sha256(raw).hexdigest()==obj["sha256"], name
     dest=OUT.joinpath(*p.parts); dest.parent.mkdir(parents=True,exist_ok=True)
     with dest.open("xb") as w: w.write(raw)
     info.update(verified=True,bytes=len(raw),sha256=obj["sha256"],encoding=obj["encoding"])
     total+=len(raw); del raw,obj
    members.append(info); assert len(members)<=256
    r.space(); b=r.take()
    if b==125: break
    assert b==44, ("member delimiter",r.pos)
  r.space(); b=r.take()
  if b==125: break
  assert b==44, ("top delimiter",r.pos)
 r.space(); assert r.peek() is None and r.pos==57292752
 assert r.h.hexdigest()=="fddb9ac6055a15229d7f425f5a924a83d12492b55747ba158d033049123764cb"
assert metadata["schema"]=="pr2974-current-integration-validation-complete-reports.v1"
assert metadata["source_sha"]=="2ac6b1bd84516c75fc169c7d1c849f9aad7b89bd"
assert metadata["source_tree"]=="89c4343c8a528e2abdc0b755b3242f9ae52e6323"
assert metadata["harness_sha"]=="869856a68204fe4662fbbc87414f492d8306ef7b"
assert str(metadata["run_id"])=="35496733388" and str(metadata["run_attempt"])=="1"
assert metadata["file_count"]==len(members)==114
unsupported=[x for x in members if not x["verified"]]
if not unsupported: assert metadata["original_bytes"]==total
result={"schema":"hol-guard.pr2974.native-framed-members.v1","passed":True,"metadata":metadata,"members":members,"verified_count":len(members)-len(unsupported),"unsupported_count":len(unsupported),"verified_original_bytes":total,"all_members_verified":not unsupported,"semantic_acceptance_checked":False,"native_or_workload_executed":False,"qualification_complete":False,"packet_bytes":r.pos,"packet_sha256":r.h.hexdigest(),"encoded_member_selection_limit_bytes":CAP,"memory_limit_bytes":LIMIT,"maximum_rss_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,"elapsed_seconds":time.monotonic()-started}
receipt=json.dumps(result,sort_keys=True,indent=2)+"\n"
with (ROOT/"member-extraction-v1.json").open("x") as target: target.write(receipt)
print(json.dumps({**{k:v for k,v in result.items() if k!="members"},"receipt_sha256":hashlib.sha256(receipt.encode()).hexdigest(),"members":[{k:v for k,v in x.items() if k in ("path","bytes","verified","reason")} for x in members]},sort_keys=True))
