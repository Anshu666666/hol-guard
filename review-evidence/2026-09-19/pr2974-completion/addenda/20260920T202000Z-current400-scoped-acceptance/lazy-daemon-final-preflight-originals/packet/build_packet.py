"""Preserve the frozen original lazy-daemon preflight and publication records."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import stat

ROOT = Path('/workspace/scratch/745337b67ff9')
OUT = Path(__file__).parent / 'packet'
OUT.mkdir(parents=True, exist_ok=False)
files = sorted(p for p in (ROOT / 'root-checkpoint/daemon-lazy-preflight').rglob('*') if p.is_file())
files += [ROOT / p for p in (
    'root-checkpoint/run_daemon_lazy_preflight.py',
    'root-checkpoint/finalize_daemon_lazy_result.py',
    'root-checkpoint/daemon-lazy-source-staging.json',
    'qualification-recovered/daemon-lazy-regression.xml',
    'rsp136-route-evidence/codex-transport-after.xml',
    'root-checkpoint/a5fd-publication-receipt.json',
    'root-checkpoint/pr-a5fd-terminal-body.md',
    'root-checkpoint/pr-a5fd-terminal-body-receipt.json',
)]


def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}


rows = []
for ordinal, path in enumerate(files):
    assert stat.S_ISREG(path.lstat().st_mode)
    body = path.read_bytes()
    row = {'path': path.relative_to(ROOT).as_posix(), **identity(body)}
    if len(body) > 256 * 1024:
        compressed = gzip.compress(body, compresslevel=9, mtime=0)
        encoded = base64.b64encode(compressed)
        parts = []
        for offset in range(0, len(encoded), 64000):
            name = f'compressed/{ordinal:03d}/part-{offset // 64000:03d}.txt'
            target = OUT / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded[offset:offset + 64000])
            parts.append(name)
        row.update(storage='gzip-base64-parts', parts=parts, compressed_identity=identity(compressed))
    else:
        name = 'raw/' + row['path']
        target = OUT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        row.update(storage='raw', member=name)
    assert path.read_bytes() == body
    rows.append(row)
shutil.copyfile(ROOT / 'partition-completion-preflight-preservation/packet/verify.py', OUT / 'verify.py')
shutil.copyfile(__file__, OUT / 'build_packet.py')
(OUT / 'README.md').write_text('''# Exact lazy-daemon preflight preservation

This packet preserves all 17 finalized files under root-checkpoint/daemon-lazy-preflight, the original preflight wrapper, the pure data reconciliation reader, staging record, two predecessor XML inputs, and three postcheckpoint publication records. Every original byte count, SHA-256 and Git blob identity is recorded. Three large originals use deterministic gzip plus ordered base64 chunks.

The original pytest process passed 393 cases with three existing Windows-only skips. The original outer wrapper exited 1 because it compared raw predecessor XML order with a different declared argv order. The unchanged original wrapper and failure description are retained. MATCHED-RESULT and FINAL-NODES are derived data-only reconciliation, not a rerun: all 396 ordered identities and outcomes match the actual declared pytest argv. Qualification independently reviewed that result.

The full type output retains zero errors and 30,183 warnings. Source before/after maps retain all 4,796 unchanged tracked files. No warning-clean, installed, latency benefit or whole resource qualification is inferred.

Run `python verify.py` for pure data verification or `python verify.py --reconstruct <new-directory>` for exact reconstruction. That copied verifier imports only the standard library and does not run any retained script or product code. Its legacy verification schema name remains unchanged because the reconstruction mechanics are identical. The original reconciliation reader is retained as data and was not executed for this preservation.

The three publication records describe the already completed a5fd evidence/PR-body checkpoint. They do not publish the lazy source candidate or the separately proposed encrypted Rust correction. No Git ref is changed by this packet.
''')
members = [{'path': p.relative_to(OUT).as_posix(), **identity(p.read_bytes())}
           for p in sorted(OUT.rglob('*')) if p.is_file()]
manifest = {'schema': 'hol-guard.lazy-daemon-preflight-preservation.v1',
            'source_parent': 'a5fdde302aba2a06265c2e6e934b6ac9b76750df',
            'candidate_tree': '50e5ce00f8207df8f4a6b36c875a0fabf05bbcae',
            'originals': rows, 'original_count': len(rows),
            'original_bytes': sum(r['bytes'] for r in rows), 'members': members,
            'preservation_only': True, 'new_tests_or_workload': False}
(OUT / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
print(json.dumps({'original_files': len(rows), 'original_bytes': manifest['original_bytes'],
                  'packet_files': len(members) + 1,
                  'compressed_files': [{'path': r['path'], 'bytes': r['bytes'], 'parts': len(r['parts'])}
                                       for r in rows if r['storage'] != 'raw']}, sort_keys=True))
