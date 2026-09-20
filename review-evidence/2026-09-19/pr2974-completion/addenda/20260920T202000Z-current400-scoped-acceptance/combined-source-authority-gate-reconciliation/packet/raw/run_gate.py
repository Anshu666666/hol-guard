"""Run only the previously failed unchanged authority gate on the exact candidate."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

OUT = Path(__file__).parent.resolve()
ROOT = OUT / 'candidate'
source = json.loads((OUT / 'candidate.json').read_bytes())
argv = [str(OUT.parent / 'hol-guard/.venv/bin/python'), 'scripts/ci/rust_authority_ownership_gate.py',
        '--root', '.', '--base-ref', source['base_ref'], '--json', str(OUT / 'authority-result.json')]


def snapshot():
    rows = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in rows if name}


before = snapshot()
start = time.monotonic()
result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=120)
(OUT / 'authority.stdout').write_bytes(result.stdout)
(OUT / 'authority.stderr').write_bytes(result.stderr)
after = snapshot()
report = {'argv': argv, 'cwd': str(ROOT), 'return_code': result.returncode,
          'elapsed_seconds': time.monotonic() - start, 'source_commit': source['commit'],
          'source_tree': source['tree'], 'tracked_files': len(before), 'source_before_after_equal': before == after,
          'scope': 'Only original failed authority gate rerun after Git ancestry and detached candidate correction.'}
(OUT / 'gate-command.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
(OUT / 'candidate-source-hashes.json').write_text(json.dumps(before, sort_keys=True) + '\n')
assert before == after
print(json.dumps(report))
raise SystemExit(result.returncode)
