"""Preserve exact combined encrypted/lazy gate and publication originals."""
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
files = sorted(p for p in (ROOT / 'root-checkpoint/encrypted-lazy-source-gates').rglob('*') if p.is_file())
files += sorted(p for p in (ROOT / 'root-checkpoint').glob('*encrypted*') if p.is_file())
files += sorted(p for p in (ROOT / 'root-checkpoint').glob('pr-4001185*') if p.is_file())
assert len(files) == len(set(files)) == 45



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
(OUT / 'README.md').write_text("""# Exact encrypted/lazy source-gate and publication preservation

This packet retains all 29 finalized raw source-gate records, the source-gate runner, preparation runner, composition/staging/source API input and full tree/body readbacks, main refresh and exact publication guards, final publication receipt, and initial PR body plus receipt. Every original byte size, SHA-256 and Git blob identity is recorded; large files use deterministic gzip and ordered base64 chunks. No retained script or product is executed by preservation.

The original seven-gate result is unchanged: six gates passed; the authority gate exited 1 because its Git diff exited 128 with no merge base in the shallow checkout. The independent correction is preserved in standalone tree 5c59fec2834be6ff98ff6b0a582d6ef384e1184d: authentic ancestry plus an isolated committed copy of the exact eight-file candidate let the unchanged gate inspect the intended HEAD. That justified single gate passed. Neither this packet nor that repair reruns the other six gates or changes the gate.

Root subsequently published source 4001185e4f39cad51fd5eab314bf02b86b8a1674, tree 7a328609488ffefecd3cdd12a9c7adba6a591e97, sole parent a5fdde302aba2a06265c2e6e934b6ac9b76750df at 2026-09-20T19:06:09Z. The publication records retain all 4,800 tree leaves and eight source afterimages; no signature, fresh normal-CI, installed encrypted route, or overall qualification claim is added here. Main fba6f742 review has no overlap with the eight paths and did not change the PR base.

Prior full lazy preflight originals remain separately durable in tree 79c11338d8e2f685852d7f571ab3800558dd0291 and are not duplicated here. The encrypted three-platform Rust results remain separately durable in tree 86a98c31a0f21dc1f7011c4b96fde002aa63c8e1. This packet preserves publication evidence and initial failures without promoting those source controls to installed outcomes.

Run `python verify.py` for pure-data verification or `python verify.py --reconstruct <new-directory>` for exact reconstruction. The copied standard-library verifier executes none of the retained programs. Its legacy schema name remains because the reconstruction mechanics are unchanged. No commit or Git ref is created or updated by this preservation.
""")

members = [{'path': p.relative_to(OUT).as_posix(), **identity(p.read_bytes())}
           for p in sorted(OUT.rglob('*')) if p.is_file()]
manifest = {'schema': 'hol-guard.encrypted-lazy-publication-preservation.v1',
            'source_parent': 'a5fdde302aba2a06265c2e6e934b6ac9b76750df',
            'candidate_tree': '7a328609488ffefecd3cdd12a9c7adba6a591e97',
            'published_commit': '4001185e4f39cad51fd5eab314bf02b86b8a1674',
            'authority_correction_tree': '5c59fec2834be6ff98ff6b0a582d6ef384e1184d',
            'prior_lazy_originals_tree': '79c11338d8e2f685852d7f571ab3800558dd0291',
            'originals': rows, 'original_count': len(rows),
            'original_bytes': sum(r['bytes'] for r in rows), 'members': members,
            'preservation_only': True, 'new_tests_or_workload': False}
(OUT / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
print(json.dumps({'original_files': len(rows), 'original_bytes': manifest['original_bytes'],
                  'packet_files': len(members) + 1,
                  'compressed_files': [{'path': r['path'], 'bytes': r['bytes'], 'parts': len(r['parts'])}
                                       for r in rows if r['storage'] != 'raw']}, sort_keys=True))
