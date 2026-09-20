"""Summarize retained same-child intervals only; no workload or clean-cost estimate."""
import collections
import hashlib
import json
from pathlib import Path
import statistics

ROOT=Path(__file__).resolve().parent

def analyze():
 report=json.loads((ROOT/'raw/observation.json').read_bytes())
 verified=json.loads((ROOT/'result.json').read_bytes())
 groups=collections.defaultdict(list)
 for row in verified['child_statistics']:
  c=row['coordinate'];group='claude_c16' if c['sample']>=1000000 else c['harness']+'_serial'
  groups[group].append(row)
 def summary(values):return {'n':len(values),'minimum':min(values),'median':statistics.median(values),'maximum':max(values)}
 output={}
 selected=('import:codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge','import:codex_plugin_scanner.guard.daemon','import:codex_plugin_scanner.guard.daemon.manager','import:codex_plugin_scanner.guard.mdm','import:codex_plugin_scanner.guard.config','import:codex_plugin_scanner.guard.adapters.codex_daemon_hook_bridge_flow','codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge:main','codex_plugin_scanner.guard.adapters.codex_daemon_hook_bridge:main','codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport:authenticated_claude_hook_response','codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth:_authenticated_state','codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport:_daemon_response_once','stdlib_http:HTTPConnection.getresponse')
 for name,rows in groups.items():
  output[name]={'children':len(rows),'observer':{key:summary([r[key] for r in rows]) for key in ('observer_setup_ms','callback_body_ms','finish_through_report_export_ms','callback_count','record_count')},'inclusive_stages':{stage:summary([r['stage_inclusive_ms'][stage]['sum'] for r in rows if stage in r['stage_inclusive_ms']]) for stage in selected if any(stage in r['stage_inclusive_ms'] for r in rows)}}
 return {'schema':'pr2974.child-same-clock-analysis.v1','run_id':35526804206,'original_observation_sha256':hashlib.sha256((ROOT/'raw/observation.json').read_bytes()).hexdigest(),'actual_artifact_source':'753850955c33eb15f992d1fe7ca375dd26c3a070','equal_tree_product':'f8f190a286159b46bf14a624a62ba52b5d2371a3','groups':output,'interpretation':['Selected import/frame spans establish where instrumented elapsed time occurred in these exact child processes. They do not estimate clean cost or expected optimization savings.','Claude discovery import enters daemon package initializer, which eagerly imports manager, whose mdm.file_lock import initializes the MDM package. The observed manager/MDM spans are nested within bridge import.','Codex bridge directly imports config solely for MAX_APPROVAL_WAIT_TIMEOUT_SECONDS; config eagerly imports MDM and settings modules. Other bridge-flow imports independently load availability/runtime dependencies.','Codex bridge module top-level includes its __main__ call under runpy; only its explicit import and function spans are labeled accordingly. Dynamic-string frames have unresolved origin.'],'measurement_limits':['Per-child perf_counter_ns intervals and same-thread parent containment are verified. No parent/daemon/child clock subtraction.','Nested imports and function intervals overlap; aggregate stage sums must not be added across stages. HTTP getresponse is nested within authenticated transport and bridge main.','Callback body counter starts after initial bookkeeping/first-lock admission and omits callback dispatch plus some lock overhead. Setup and export are separately measured, but all these and unmeasured observer work remain within parent wall time; no subtraction is performed.','Preactivation interpreter/sitecustomize work remains blind. Setup imports, module roster capture, provider validation, and profiler callbacks perturb startup/caches/scheduling.','Eight serial examples and one sixteen-call Claude Post block are explanatory, not original88 minimums or clean50/100/200 qualification. No product regression inferred across other recorded populations.']}
if __name__=='__main__':print(json.dumps(analyze(),indent=2))
