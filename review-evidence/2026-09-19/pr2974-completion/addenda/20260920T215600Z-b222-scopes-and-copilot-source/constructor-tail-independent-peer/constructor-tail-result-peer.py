"""Independent read-only adaptation plus original source/clock checks."""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path('/workspace/scratch/745337b67ff9')
ROOT = BASE / 'native-workspace-constructor-tail-run35536922548'
SOURCE = BASE / 'cline-intel-process-v5'

def identity(b):
    return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}

def files():
    return {str(p.relative_to(ROOT)):identity(p.read_bytes()) for p in ROOT.rglob('*') if p.is_file()}

before=files()
verifier=ROOT/'verify_and_freeze.py'
tree=ast.parse(verifier.read_bytes(),str(verifier))
class ReadOnly(ast.NodeTransformer):
    changed=[]
    def visit_FunctionDef(self,node):
        if node.name=='dump':
            self.changed.append('dump_compares_existing_json')
            node.body=ast.parse('assert json.loads((ROOT / name).read_bytes()) == value').body
        return self.generic_visit(node)
    def visit_Expr(self,node):
        if isinstance(node.value,ast.Call):
            value=node.value
            if ast.unparse(value.func)=='target.parent.mkdir':
                self.changed.append('projection_parent_exists')
                return ast.copy_location(ast.parse('assert target.parent.is_dir()').body[0],node)
            if ast.unparse(value.func)=='target.write_bytes':
                self.changed.append('projection_compares_existing_bytes')
                return ast.copy_location(ast.parse('assert target.read_bytes() == raw').body[0],node)
        return self.generic_visit(node)
edit=ReadOnly(); read_only=edit.visit(tree)
assert edit.changed==['dump_compares_existing_json','projection_parent_exists','projection_compares_existing_bytes']
namespace={'__file__':str(verifier),'__name__':'peer_read_only'}
exec(compile(ast.fix_missing_locations(read_only),str(verifier),'exec'),namespace)
assert files()==before
summary=json.loads((ROOT/'VERIFIED-RESULT.json').read_bytes())
manifest=json.loads((BASE/'native-workspace-constructor-tail-e440-prep/workspace-constructor-validation/MANIFEST.json').read_bytes())
assert len(manifest['source_files'])==25
for d in manifest['source_files']:
    assert identity((SOURCE/d['path']).read_bytes())=={k:d[k] for k in ('bytes','sha256','git_blob')}
record=json.loads((ROOT/'archive/constructors/00.json').read_bytes())
o=record['observation']; rows=o['rows']; tail=o['tail_rows']
accepted=o['accepted_monotonic']; origin=o['origin_monotonic']
return_times={r['stage']:(origin+r['exit_seconds']-accepted)*1000 for r in rows}
for stage,value in return_times.items():
    assert abs(value-summary['constructor_phases']['acceptance_to_successful_returns_ms'][stage])<1e-8
assert return_times['publisher_wait']<return_times['hook_worker_constructor']<400<return_times['request_services']<return_times['service_constructor']
spans={r['stage']:(r['exit_seconds']-r['entry_seconds'])*1000 for r in tail}
assert spans==summary['constructor_phases']['tail_inclusive_spans_ms']
assert all(r['parent']==2 for r in tail)
assert rows[3]['exit_seconds']<=tail[0]['entry_seconds']<=tail[0]['exit_seconds']<=tail[1]['entry_seconds']<=tail[1]['exit_seconds']<=tail[2]['entry_seconds']<=tail[2]['exit_seconds']<=rows[2]['exit_seconds']
paths=['scripts/native_slo_workspace_lifecycle.py','src/codex_plugin_scanner/guard/daemon/server_http.py']
source_text={p:(SOURCE/p).read_text() for p in paths}
assert 'accepted = time.monotonic()' in source_text[paths[0]]
assert 'if time.monotonic() >= deadline:' in source_text[paths[0]]
assert 'raise RuntimeError("workspace lifecycle authenticated acknowledgment deadline")' in source_text[paths[0]]
assert source_text[paths[0]].splitlines()[72].strip().startswith('raise RuntimeError(')
assert 'self.store.read_extension_control_authority_for_registry(' in source_text[paths[1]].splitlines()[204]
assert 'self.general_request_executor =' in source_text[paths[1]].splitlines()[218]
assert 'self.control_request_executor =' in source_text[paths[1]].splitlines()[225]
result={
 'schema':'pr2974.constructor-tail-independent-result-peer.v1',
 'verdict':'clear for the declared instrumented result and its explicit limitations',
 'packet_tree':'d6e080f22ceb8d068ab879231be2052c8a6b1aa4',
 'result_blob':'68f8c7c194e49c87eafde3131a7439c0716944fb',
 'run_id':35536922548,'driver':'858fb5c6b7daa35c1bab38674e6987a446417962',
 'local_files_before_after_unchanged':len(before),'read_only_adaptation':edit.changed,
 'owner_verifier':identity(verifier.read_bytes()),
 'independent_source_provider_bytes':25,'original_zip_members_verified':41,
 'original_zip':identity((ROOT/'artifact.zip').read_bytes()),
 'ordered_controls':109,'original_cell_passed':False,'diagnostic_complete':True,
 'acceptance_to_returns_ms':return_times,'tail_inclusive_spans_ms':spans,
 'independent_findings':[
  'One original first_admission100 invocation, strict400ms; full15 remains false; original return1 and failed await_ack73 retained independently of diagnostic success.',
  'The original accepted monotonic value and constructor-relative offsets reproduce each return time; publication rows retain a distinct origin and are not cross-subtracted.',
  'HookWorker returns within400ms and request services returns afterward; selected authority41.408030ms and real32/8executor spans are ordered, nested in request services and inclusive of observer/scheduling overhead.',
  'Source lines205/219/226 bind actual authority and executor calls. Authority payload remains opaque; no internal database/filesystem/Rust/CPU leaf or historical cause is established.',
  'Exact25E440 provider images,109ordered controls, original archive41members, retained wheel/package/runtime, framed output and before/after identities are joined by read-only data verification.',
  'Original two real transport attempts and withheld first ACK remain distinct; no recovered hook request/receipt was offered, and zero receipt counts do not indicate persistence loss.',
  'No product import, native execution, download, rerun or extra probe performed by this peer.'
 ],
 'limits':['No default or uninstrumented timing claim','No broader qualification or full matrix claim','No historical failure cause or proposed product fix','Original cancelled historical normal soak remains incomplete']
}
assert files()==before
print(json.dumps(result,indent=2))
Path('/dev/shm/constructor-tail-result-peer.json').write_text(json.dumps(result,indent=2)+'\n')
