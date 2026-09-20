from pathlib import Path
import json,hashlib
p=Path('native-workspace-constructor-tail-run35536922548/job.log');raw=p.read_bytes();s=raw.decode();assert len(s)==890420 and s.endswith('\n\n');p.write_bytes(raw[:-1]);p.with_name('log-transfer-correction.json').write_text(json.dumps({'scope':'local apply_patch transfer only','extra_trailing_LF_removed':1,'initial_byte_length_guard_refused':True,'reason':'UTF8 multibyte content makes character count differ from byte length','before_bytes':len(raw),'after_bytes':len(raw)-1,'after_sha256':hashlib.sha256(raw[:-1]).hexdigest(),'original_log_changed':False},sort_keys=True,indent=2)+'\n')
frames=[]
for line in s[:-1].splitlines():
 prefix='HG_WORKSPACE_PREDICATE_FILE_V1 '
 if prefix in line: frames.append(json.loads(line.split(prefix,1)[1]))
p.with_name('frames.json').write_text(json.dumps(frames,sort_keys=True,indent=2)+'\n');print(len(frames))
