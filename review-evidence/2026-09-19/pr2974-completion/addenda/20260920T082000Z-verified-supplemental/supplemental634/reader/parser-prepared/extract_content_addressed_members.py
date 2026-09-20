import resource
LIMIT=95*1024*1024
resource.setrlimit(resource.RLIMIT_AS,(LIMIT,LIMIT))
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
import base64,hashlib,json,os,pathlib,re,signal,time
def timed_out(signum,frame):
 raise TimeoutError("bounded_content_decode_deadline")
signal.signal(signal.SIGALRM,timed_out)
signal.alarm(120)
BOOT="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()==BOOT
ROOT=pathlib.Path("/home/user/pr2974-corrective634-decode-asnf")
PACKET=ROOT/"framed-reports.json"
RAW_BYTES=80685332
RAW_SHA="1efcb42481c407a7048963e368f5a5e7e3e851c9d84669d45412c0928bca83e3"
CAP=8*1024*1024
MEMBER_LIMIT=32*1024*1024
CHUNK=65536
CONTENTS=ROOT/"contents-v1"
MEMBERS=ROOT/"members-v1"
CONTENTS.mkdir(exist_ok=False)
MEMBERS.mkdir(exist_ok=False)
def unique_pairs(pairs):
 value={}
 for k,v in pairs:
  assert k not in value, "duplicate JSON key"
  value[k]=v
 return value
def invalid_constant(value): raise ValueError("non-finite JSON")
def decode(raw):
 return json.loads(raw,object_pairs_hook=unique_pairs,parse_constant=invalid_constant)
class Reader:
 def __init__(self,f):
  self.f=f; self.buf=b""; self.i=0; self.pos=0; self.h=hashlib.sha256()
 def peek(self):
  if self.i==len(self.buf):
   self.buf=self.f.read(CHUNK); self.i=0; self.h.update(self.buf)
  return self.buf[self.i] if self.i<len(self.buf) else None
 def take(self):
  v=self.peek()
  assert v is not None, "unexpected EOF"
  self.i+=1; self.pos+=1
  return v
 def space(self):
  while self.peek() in (9,10,13,32): self.take()
 def expect(self,c):
  self.space(); assert self.take()==c, ("delimiter",self.pos,c)
 def value(self,cap=CAP):
  self.space(); start=self.pos; first=self.peek()
  assert first is not None
  raw=bytearray(); stack=[]; quoted=False; escaped=False
  primitive=first not in (34,91,123)
  while True:
   b=self.peek()
   if primitive and (b is None or b in (9,10,13,32,44,93,125)): break
   b=self.take()
   assert len(raw)<cap, ("semantic_value_limit",start)
   raw.append(b)
   if quoted:
    if escaped: escaped=False
    elif b==92: escaped=True
    elif b==34:
     quoted=False
     if not stack and not primitive: break
   elif b==34: quoted=True
   elif b==123: stack.append(125)
   elif b==91: stack.append(93)
   elif b in (93,125):
    assert stack and stack.pop()==b
    if not stack: break
  assert raw and not quoted and not stack
  return decode(raw)
 def string_to(self,sink):
  self.expect(34)
  escapes={34:b'"',92:b'\\',47:b'/',98:b'\b',102:b'\f',110:b'\n',114:b'\r',116:b'\t'}
  while True:
   self.peek()
   assert self.i<len(self.buf), "unterminated JSON string"
   slash=self.buf.find(b"\\",self.i); quote=self.buf.find(b'"',self.i)
   stop=min((x for x in (slash,quote) if x>=0),default=len(self.buf))
   if stop>self.i:
    part=self.buf[self.i:stop]
    assert all(32<=x<128 for x in part), "raw non-ASCII/control JSON string"
    self.pos+=len(part); self.i=stop; sink(part)
   if self.i==len(self.buf): continue
   marker=self.take()
   if marker==34: return
   assert marker==92
   kind=self.take()
   if kind in escapes: sink(escapes[kind]); continue
   assert kind==117, "unknown JSON escape"
   digits=bytes(self.take() for _ in range(4))
   assert re.fullmatch(rb"[0-9a-fA-F]{4}",digits)
   point=int(digits,16)
   if 0xD800<=point<=0xDBFF:
    assert self.take()==92 and self.take()==117
    low_raw=bytes(self.take() for _ in range(4))
    assert re.fullmatch(rb"[0-9a-fA-F]{4}",low_raw)
    low=int(low_raw,16); assert 0xDC00<=low<=0xDFFF
    point=0x10000+((point-0xD800)<<10)+(low-0xDC00)
   else: assert not 0xDC00<=point<=0xDFFF
   sink(chr(point).encode("utf-8"))
def copy_base64(source,target):
 count=0; digest=hashlib.sha256(); finished=False
 while encoded:=source.read(CHUNK):
  assert not finished and len(encoded)%4==0
  finished=b"=" in encoded
  raw=base64.b64decode(encoded,validate=True)
  count+=len(raw); assert count<=MEMBER_LIMIT
  digest.update(raw); target.write(raw)
 return count,digest.hexdigest()
def entries(reader):
 reader.expect(123)
 seen=set()
 if reader.peek()==125: reader.take(); return
 while True:
  key=reader.value(4096)
  assert type(key) is str and key not in seen
  seen.add(key); reader.expect(58)
  yield key
  reader.space(); c=reader.take()
  if c==125: return
  assert c==44
def safe_name(name):
 p=pathlib.PurePosixPath(name)
 assert not p.is_absolute() and p.parts and str(p)==name and "\\" not in name
 assert all(x not in ("",".","..") for x in p.parts)
 return p
state={"schema":"hol-guard.pr2974.corrective634-content-extraction.v1","passed":False,"new_test_or_workload_executed":False,"qualification_complete":False}
started=time.monotonic(); contents={}; files={}; metadata={}
try:
 assert PACKET.stat().st_size==RAW_BYTES
 with PACKET.open("rb") as source:
  r=Reader(source)
  for key in entries(r):
   if key=="contents":
    for digest in entries(r):
     assert re.fullmatch(r"[0-9a-f]{64}",digest) and len(contents)<256
     fields={}; count=[0]; h=hashlib.sha256(); temporary=CONTENTS/(digest+".decoded-json-string")
     with temporary.open("xb") as target:
      def sink(part):
       count[0]+=len(part)
       assert count[0]<=4*((MEMBER_LIMIT+2)//3), "streamed string limit"
       target.write(part); h.update(part)
      for field in entries(r):
       assert field in ("bytes","content","encoding","sha256")
       if field=="content":
        assert list(fields)==["bytes"] and 0<=fields["bytes"]<=MEMBER_LIMIT
        r.string_to(sink); fields[field]=None
       else: fields[field]=r.value(4096)
     assert list(fields)==["bytes","content","encoding","sha256"]
     assert type(fields["bytes"]) is int and fields["sha256"]==digest
     final=CONTENTS/digest
     if fields["encoding"]=="utf-8":
      assert count[0]==fields["bytes"] and h.hexdigest()==digest
      temporary.rename(final)
     else:
      assert fields["encoding"]=="base64"
      with temporary.open("rb") as inp, final.open("xb") as target:
       out_count,out_digest=copy_base64(inp,target)
      assert out_count==fields["bytes"] and out_digest==digest
      temporary.unlink()
     contents[digest]={"sha256":digest,"bytes":fields["bytes"],"encoding":fields["encoding"],"verified":True}
   elif key=="files":
    for name in entries(r):
     safe_name(name); item=r.value(4096)
     assert type(item) is dict and set(item)=={"bytes","encoding","sha256","content_sha256"}
     assert item["sha256"]==item["content_sha256"]
     assert len(files)<256
     files[name]=item
   else: metadata[key]=r.value(4096)
  r.space(); assert r.peek() is None and r.pos==RAW_BYTES and r.h.hexdigest()==RAW_SHA
 assert metadata["schema"]=="pr2974-current-integration-validation-content-addressed-reports.v1"
 assert metadata["source_sha"]=="4d10758e2cb44e5afa72a08aa631a02541dad534"
 assert metadata["source_tree"]=="fbc00caa3788eb422158a2263a578e83ac626183"
 assert metadata["harness_sha"]=="b05127dd2cec4f02eb97d715138179c741e52ec0"
 assert str(metadata["run_id"])=="35494533524" and str(metadata["run_attempt"])=="1"
 assert all(type(metadata[k]) is int for k in ("file_count","unique_content_count","unique_original_bytes","original_bytes","original_limit_bytes"))
 assert len(files)==metadata["file_count"]==216
 assert len(contents)==metadata["unique_content_count"]
 assert sum(x["bytes"] for x in contents.values())==metadata["unique_original_bytes"]
 assert sum(x["bytes"] for x in files.values())==metadata["original_bytes"]
 assert metadata["original_limit_bytes"]==128*1024*1024 and metadata["original_bytes"]<=metadata["original_limit_bytes"]
 assert metadata["all_original_report_bytes_included"] is True and metadata["qualification_complete"] is False
 assert set(contents)=={x["content_sha256"] for x in files.values()}
 for name,item in files.items():
  content=contents[item["content_sha256"]]
  assert all(item[k]==content[k] for k in ("bytes","sha256","encoding"))
  target=MEMBERS.joinpath(*safe_name(name).parts)
  target.parent.mkdir(parents=True,exist_ok=True)
  os.link(CONTENTS/item["content_sha256"],target)
 state.update(passed=True,metadata=metadata,contents=contents,files=files,all_named_member_hashes_and_content_references_verified=True,semantic_control_rows_recounted=False)
except BaseException as error:
 state["failure"]={"type":type(error).__name__,"reason":str(error)[:200],"packet_position":r.pos if "r" in globals() else None}
finally:
 signal.alarm(0)
 state.update(memory_limit_bytes=LIMIT,maximum_materialized_json_value_bytes=CAP,streamed_member_limit_bytes=MEMBER_LIMIT,maximum_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,elapsed_seconds=time.monotonic()-started)
 encoded=json.dumps(state,sort_keys=True,indent=2)+"\n"
 with (ROOT/"content-extraction-v1.json").open("x") as receipt:
  receipt.write(encoded)
 print(json.dumps({k:v for k,v in state.items() if k not in ("files","contents")}|{"receipt_bytes":len(encoded.encode()),"receipt_sha256":hashlib.sha256(encoded.encode()).hexdigest(),"named_files":len(files),"unique_contents":len(contents)},sort_keys=True))
raise SystemExit(0 if state["passed"] else 1)
