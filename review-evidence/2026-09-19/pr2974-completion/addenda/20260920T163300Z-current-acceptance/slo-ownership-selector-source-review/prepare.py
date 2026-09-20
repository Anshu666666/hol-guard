from pathlib import Path
import ast
import difflib
import hashlib
import json

ROOT = Path('/workspace/scratch/745337b67ff9')
OUT = ROOT / 'release-set-rehearsal/rsp006-022-review'
SOURCE = ROOT / 'release-set-rehearsal/source'
def identity(data):
    return {'bytes':len(data),'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'sha256':hashlib.sha256(data).hexdigest()}
tree = json.loads((ROOT/'release-set-rehearsal/rsp001-census/candidate-tree.json').read_text())
entries = {x['path']:x for x in tree['tree'] if x['type']=='blob'}
paths = '''scripts/bench_guard_native_release_gate.py
scripts/native_benchmark_oracle.py
scripts/native_release_reporting.py
scripts/native_slo_contract.py
scripts/native_slo_reporting.py
scripts/native_slo_launcher.py
src/codex_plugin_scanner/guard/runtime/hook_review_engine.py
src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py
src/codex_plugin_scanner/guard/daemon/hook_worker.py
src/codex_plugin_scanner/guard/daemon/hook_worker_native.py
src/codex_plugin_scanner/guard/daemon/server_http.py
src/codex_plugin_scanner/guard/daemon/config_read_scope.py
scripts/ci/rust_io_ownership_gate.py
scripts/ci/rust_io_ownership_contract.py
scripts/ci/rust_io_ownership_scopes.py
scripts/ci/rust_io_ownership_resolver.py
tests/test_rust_io_ownership_gate.py
tests/test_guard_native_release_gate_benchmark.py
tests/test_native_runtime_delivery_contract.py
tests/test_hook_availability_policy.py
tests/test_hook_worker_native_post_tool_watch.py
tests/test_release_32_workflow_gates.py
docs/guard/native-hook-data-plane-ownership.md
docs/guard/native-runtime-technical-contract-review.md
.github/workflows/decision-critical-io.yml
.github/workflows/rust-authority-ownership.yml
.github/workflows/native-wheel-ci.yml
.github/workflows/rust-runtime-performance.yml
.github/workflows/rust-runtime-recovery.yml
.github/workflows/mcp-risk-reuse.yml'''.splitlines()
manifest=[]
for path in paths:
    data=(SOURCE/path).read_bytes()
    record={'path':path,**identity(data),'source_commit':'e44008445630aad28ccc291ec234f55a14892e6d'}
    assert record['git_blob']==entries[path]['sha'],path
    target=OUT/'source'/path
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(data)
    manifest.append(record)

relative='scripts/native_slo_contract.py'
before=(SOURCE/relative).read_text()
old='''        # These samples cross the installed adapter boundary.  The direct
        # native 20/50/120/350 ms ceilings belong to the release gate that
        # calls Rust directly and must not be applied to this path.
'''
new='''        # These samples measure normalized DAEMON_INGRESS, including Python
        # transport. The release benchmark measures NATIVE_CLIENT through its
        # Python adapter; it does not measure the declared native size ceilings.
        # Keep those separate targets out of these adapter smoke predicates.
'''
assert before.count(old)==1
after=before.replace(old,new)
assert ast.dump(ast.parse(before),include_attributes=False)==ast.dump(ast.parse(after),include_attributes=False)
dest=OUT/'proposed'/relative; dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(after)
(OUT/'comment-only.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+relative,tofile='b/'+relative)))
fix={'path':relative,'before':identity(before.encode()),'after':identity(after.encode()),'ast_equal':True,'runtime_change':False,'published_to_product':False}

bench=ast.parse((SOURCE/'scripts/bench_guard_native_release_gate.py').read_text())
main=next(n for n in bench.body if isinstance(n,ast.FunctionDef) and n.name=='main')
tests=[ast.unparse(n.test) for n in ast.walk(main) if isinstance(n,ast.If)]
required=['warm_speedup < _MIN_WARM_P95_SPEEDUP and native_warm_summary[\'p95_ms\'] > _MAX_WARM_P95_MS','cold_speedup < _MIN_COLD_P95_SPEEDUP',"native_oneshot_summary['p95_ms'] > _MAX_COLD_P95_MS"]
assert all(x in tests for x in required)
constants={n.targets[0].id:ast.literal_eval(n.value) for n in bench.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in {'_MIN_WARM_P95_SPEEDUP','_MAX_WARM_P95_MS','_MIN_COLD_P95_SPEEDUP','_MAX_COLD_P95_MS','_MAX_NATIVE_READINESS_MS'}}
assert constants=={'_MIN_WARM_P95_SPEEDUP':1.15,'_MAX_WARM_P95_MS':20.0,'_MIN_COLD_P95_SPEEDUP':5.0,'_MAX_COLD_P95_MS':150.0,'_MAX_NATIVE_READINESS_MS':400.0}
imports=[]
for path in (SOURCE/'src').rglob('*.py'):
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node,ast.ImportFrom) and 'native_benchmark_oracle' in (node.module or ''):
            imports.append(str(path.relative_to(SOURCE)))
        if isinstance(node,ast.Import) and any('native_benchmark_oracle' in a.name for a in node.names):
            imports.append(str(path.relative_to(SOURCE)))
assert not imports
checks={'kind':'source-only AST/byte checks; no imported product, test or benchmark execution','threshold_constants':constants,'exact_main_failure_predicates':required,'production_static_oracle_imports':imports,'comment_ast_equal':True,'all_selected_bytes_match_current_commit':True}
tasks=json.loads((ROOT/'root-checkpoint/integrated-docs/task-status-overlay.json').read_text())['tasks']
selected=[x for x in tasks if x['id'] in {'RSP-003','RSP-004','RSP-005','RSP-006','RSP-013','RSP-014','RSP-015','RSP-022','RSP-133'}]
receipt={'schema':'pr2974-rsp006-rsp022-documentary-source-review.v1','source_commit':'e44008445630aad28ccc291ec234f55a14892e6d','source_tree':'addf0c1daf8ceb6313d6805ee4d05e216d6fdac8','archival_PRD_blob':'39d27bfa693117f8df3816d44b106921ca8efc94','task_records_from_prior_overlay':selected,'source_manifest':manifest,'source_checks':checks,'proposed_comment_correction':fix,'findings':{'RSP-006':'Exact current thresholds and boundaries reconciled in README; one stale inline description has a comment-only proposed fix. RSP003/004/005 current timing and isolated semantic-reference implementation mapped, no new execution credited.','RSP-022':'Own source requirement supported: actual synchronous compatibility posture caller, explicit injected-reader roots, promotion from asynchronous_policy to synchronous_posture_config, closed operations and mutation controls. RSP013 current graph mapped.','RSP-133':'Own workflow-selection requirement supported by unfiltered ownership/native jobs, expanded wrappers/publisher/evidence/benchmark helper paths, permanent risk matrix and retained source/terminal peers.','dependency_limit':'RSP022 explicitly depends on RSP015. The 118/46 renderer packet is not a complete size/lifecycle/exit fixture inventory; full RSP015/014 acceptance is not established here. Do not claim dependency-complete RSP022/RSP133 from this receipt alone. No global RSP137 dependency is introduced.'},'retained_evidence':{'workflow_audit_tree':'b5ea2fc7e610d1f994a4785086fa3770f53f8a62','composition_peer_tree':'11b7f7ff76b903dd3320631d25dc7eaa66611770','normal_f8_terminal_tree':'e946e2e03449eda571c4bf941a1e3e2588fac2ef','current_risk_eight_cell_tree':'5b6878c4ecce75c57a1c4f03da1fa124fe44d6c2','renderer_118_46_tree':'8144231fa55d7791981fd75310bfd1c589763265'},'execution_scope':{'source_text_ast_checks_only':True,'tests_run':0,'product_imports':0,'benchmarks_run':0,'workflows_dispatched':0,'product_ref_mutations':0,'archived_status_changes':0,'performance_qualification':False}}
(OUT/'source-review.json').write_text(json.dumps(receipt,indent=2)+'\n')
packet=[]
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path.name not in {'packet.json'}:
        packet.append({'path':str(path.relative_to(OUT)),'mode':'100644','type':'blob','content':path.read_text()})
(OUT/'packet.json').write_text(json.dumps(packet))
print(json.dumps({'source_paths':len(paths),'packet_leaves':len(packet),'checks':checks,'proposed_fix':fix}))
