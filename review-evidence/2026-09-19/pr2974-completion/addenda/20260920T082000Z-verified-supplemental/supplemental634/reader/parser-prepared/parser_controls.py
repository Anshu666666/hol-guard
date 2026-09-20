import resource
LIMIT=95*1024*1024
resource.setrlimit(resource.RLIMIT_AS,(LIMIT,LIMIT))
resource.setrlimit(resource.RLIMIT_CPU,(20,20))
import ast,base64,contextlib,hashlib,io,json,pathlib,re,signal,time
signal.alarm(30)
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()=="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
HERE=pathlib.Path("/home/user/pr2974-corrective634-parser-prep")
codes={n:(HERE/n).read_text() for n in ("decode_log_stream.py","extract_content_addressed_members.py","decode_log_stream-pre-preservation-fix.py")}
trees={n:ast.parse(s,filename=n) for n,s in codes.items()}
scope={"base64":base64,"hashlib":hashlib,"json":json,"pathlib":pathlib,"re":re,"CAP":8*1024*1024,"MEMBER_LIMIT":32*1024*1024,"CHUNK":65536}
definitions=[n for n in trees["extract_content_addressed_members.py"].body if isinstance(n,(ast.FunctionDef,ast.ClassDef))]
exec(compile(ast.Module(body=definitions,type_ignores=[]),"selected-reader-definitions","exec"),scope)
checks=[]
def passed(name): checks.append({"name":name,"passed":True})
def rejects(name,operation):
 try: operation()
 except (AssertionError,ValueError,TypeError,FileExistsError): passed(name); return
 raise AssertionError("accepted invalid control: "+name)
def quoted(raw,chunk):
 scope["CHUNK"]=chunk
 reader=scope["Reader"](io.BytesIO(raw)); out=io.BytesIO()
 reader.string_to(out.write)
 assert reader.peek() is None
 return out.getvalue()
for chunk in (1,2,3,65536):
 value='a"\\\n\r\té😀z'
 assert quoted(json.dumps(value).encode(),chunk)==value.encode()
 passed("quote_escape_surrogate_chunk_"+str(chunk))
assert quoted(b'""',1)==b""
passed("empty_string")
for label,raw in (("unknown_escape",br'"\q"'),("unfinished_escape",b'"\\'),("unpaired_high",br'"\ud800"'),("unpaired_low",br'"\udc00"'),("bad_surrogate_pair",br'"\ud800\u0041"'),("literal_control",b'"\n"'),("literal_nonascii",b'"\xff"')):
 rejects(label,lambda raw=raw:quoted(raw,1))
rejects("duplicate_json_value_key",lambda:scope["decode"](b'{"x":1,"x":2}'))
rejects("nonfinite_json",lambda:scope["decode"](b'{"x":NaN}'))
def members(raw):
 reader=scope["Reader"](io.BytesIO(raw))
 return [(key,reader.value()) for key in scope["entries"](reader)]
rejects("duplicate_structural_names",lambda:members(b'{"same":1,"same":2}'))
assert members(b'{"a":1,"b":2}')==[("a",1),("b",2)]
passed("ordered_distinct_names")
for name in ("/absolute","../escape","a/../escape","a//b",".","a\\b"):
 rejects("unsafe_name_"+repr(name),lambda name=name:scope["safe_name"](name))
assert str(scope["safe_name"]("controls/one/run.json"))=="controls/one/run.json"
passed("safe_relative_name")
scope["CHUNK"]=65536
raw=bytes(i%251 for i in range(50000)); output=io.BytesIO()
count,digest=scope["copy_base64"](io.BytesIO(base64.b64encode(raw)),output)
assert count==len(raw) and output.getvalue()==raw and digest==hashlib.sha256(raw).hexdigest()
passed("binary_base64_across_64KiB")
rejects("invalid_base64_alphabet",lambda:scope["copy_base64"](io.BytesIO(b"!!!!"),io.BytesIO()))
rejects("invalid_base64_padding",lambda:scope["copy_base64"](io.BytesIO(b"YQ=A"),io.BytesIO()))
scope["CHUNK"]=4
rejects("base64_data_after_padding",lambda:scope["copy_base64"](io.BytesIO(b"YQ==Yg=="),io.BytesIO()))
scope["MEMBER_LIMIT"]=1
rejects("streamed_original_member_limit",lambda:scope["copy_base64"](io.BytesIO(b"YWI="),io.BytesIO()))
scope["MEMBER_LIMIT"]=32*1024*1024
rejects("semantic_value_limit",lambda:scope["Reader"](io.BytesIO(b'"abcd"')).value(4))
stream_scope={"hashlib":hashlib,"json":json,"CHUNK":65536}
stream_definitions=[n for n in trees["decode_log_stream.py"].body if isinstance(n,ast.FunctionDef)]
exec(compile(ast.Module(body=stream_definitions,type_ignores=[]),"stream-definitions","exec"),stream_scope)
class MemoryFile(io.BytesIO):
 def close(self): pass
class MemoryTarget:
 def __init__(self): self.file=MemoryFile(); self.opened=False
 def open(self,mode):
  assert mode=="xb"
  if self.opened: raise FileExistsError("already present")
  self.opened=True; return self.file
correct=hashlib.sha256(b"abc").hexdigest()
assert stream_scope["stream_copy"](io.BytesIO(b"abc"),MemoryTarget(),3,correct)=={"bytes":3,"sha256":correct}
passed("exact_stream_identity")
rejects("stream_size_exceeded",lambda:stream_scope["stream_copy"](io.BytesIO(b"abcd"),MemoryTarget(),3,correct))
rejects("stream_size_short",lambda:stream_scope["stream_copy"](io.BytesIO(b"ab"),MemoryTarget(),3,correct))
rejects("stream_hash_mismatch",lambda:stream_scope["stream_copy"](io.BytesIO(b"abc"),MemoryTarget(),3,"0"*64))
class ExistingRoot:
 def __init__(self): self.writes=0; self.sentinel="prior receipt"
 def mkdir(self,**kw): raise FileExistsError("existing root")
 def is_dir(self): return True
 def __truediv__(self,child): return self
 def write_text(self,value): self.writes+=1; self.sentinel=value
 def open(self,mode): self.writes+=1; raise AssertionError("existing root receipt opened")
class Boot:
 def read_text(self): return "c6aba711-75f6-4cbb-90b1-d991ba91b54e"
def admission_attempt(name):
 root=ExistingRoot()
 env=dict(stream_scope,ROOT=root,Path=lambda path:Boot(),EXPECTED_BOOT=hashlib.sha256(Boot().read_text().encode()).hexdigest(),MEMORY_LIMIT=LIMIT,resource=resource,signal=signal,time=time,started=time.monotonic(),state={"passed":False},stage="environment_admission",created_root=False)
 node=next(n for n in trees[name].body if isinstance(n,ast.Try))
 with contextlib.redirect_stdout(io.StringIO()):
  exec(compile(ast.Module(body=[node],type_ignores=[]),"existing-root-admission","exec"),env)
 return root,env["state"]
old,_=admission_attempt("decode_log_stream-pre-preservation-fix.py")
assert old.writes==1 and old.sentinel!="prior receipt"
passed("old_existing_root_control_reproduces_overwrite")
new,state=admission_attempt("decode_log_stream.py")
assert new.writes==0 and new.sentinel=="prior receipt" and state["failure"]=={"stage":"environment_admission","exception_type":"FileExistsError"}
passed("new_existing_root_preserves_receipt")
pattern=next(n.value for n in ast.walk(trees["decode_log_stream.py"]) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="framed_line" for t in n.targets))
compiled=eval(compile(ast.Expression(pattern),"frame-pattern","eval"),{"re":re})
for prefix in (b"",b"\xef\xbb\xbf"):
 assert compiled.fullmatch(prefix+b"2026-09-20T06:45:00.123Z PR2974_CURRENT_INTEGRATION_PART 0001/1797 YQ==\n")
assert not compiled.fullmatch(b"unbound PR2974_CURRENT_INTEGRATION_PART 0001/1797 YQ==\n")
passed("frame_timestamp_optional_bom_only")
signal.alarm(0)
result={"schema":"hol-guard.pr2974.corrective634-parser-controls.v1","checks":checks,"passed":True,"count":len(checks),"original634_tests_executed":False,"native_or_workload_executed":False,"filesystem_scope":"read prepared parser source only; synthetic readers use in-memory streams and fake existing-root objects","memory_limit_bytes":LIMIT,"maximum_rss_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,"source_hashes":{k:hashlib.sha256(v.encode()).hexdigest() for k,v in codes.items()}}
print(json.dumps(result,sort_keys=True))
