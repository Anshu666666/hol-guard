from __future__ import annotations
import hashlib, importlib, json, os, pathlib, platform, subprocess, sys, time
import pytest
def main():
    root=pathlib.Path('/workspace/scratch/745337b67ff9/rsp015-current-fixtures')
    out=pathlib.Path('/workspace/scratch/745337b67ff9/rsp015-validation')
    plan=json.loads(pathlib.Path('/workspace/scratch/745337b67ff9/release-set-rehearsal/rsp014-015-review/validation-plan.json').read_text())
    paths=plan['existing_cohorts']+['tests/test_cline_nonblocking_response_fixtures.py','tests/test_registered_auxiliary_response_fixtures.py','tests/test_hook_registration_response_roster.py']
    os.chdir(root)
    sys.path[:0]=[str(root/'src'),str(root)]
    def binding():
     return {'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip(),'tracked_diff':subprocess.check_output(['git','diff','HEAD','--'],text=True),'paths':{p:{'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest(),'bytes':(root/p).stat().st_size} for p in paths},'fixture_paths':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root/'tests/fixtures/guard-hook-responses').glob('*.json'))}}
    def origins():
     names=['codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge','codex_plugin_scanner.guard.adapters.cline_hooks','codex_plugin_scanner.guard.daemon.hook_worker','codex_plugin_scanner.guard.native_resident_client']
     rows={}
     for n in names:
      m=importlib.import_module(n);p=pathlib.Path(m.__file__).resolve();assert p.is_relative_to(root/'src'),str(p);rows[n]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
     return rows
    before=binding();assert before['head']=='e44008445630aad28ccc291ec234f55a14892e6d';assert before['tracked_diff']==''
    env={'python':sys.version,'executable':sys.executable,'prefix':sys.prefix,'platform':platform.platform(),'origins':origins(),'source':before,'cohorts':paths,'argv':['-q',*paths,'--junitxml='+str(out/'selected.xml')]}
    (out/'selected-before.json').write_text(json.dumps(env,indent=2)+'\n')
    start=time.monotonic()
    code=pytest.main(env['argv'])
    after=binding()
    module_paths={name:str(pathlib.Path(m.__file__).resolve()) for name,m in sys.modules.copy().items() if name.startswith('tests.') and getattr(m,'__file__',None)}
    for name,p in module_paths.items(): assert pathlib.Path(p).is_relative_to(root), (name,p)
    result={'returncode':int(code),'elapsed_seconds':time.monotonic()-start,'source_after':after,'source_unchanged':before==after,'test_module_origins':module_paths}
    (out/'selected-after.json').write_text(json.dumps(result,indent=2)+'\n')
    assert before==after
    raise SystemExit(code)

if __name__ == "__main__":
    main()
