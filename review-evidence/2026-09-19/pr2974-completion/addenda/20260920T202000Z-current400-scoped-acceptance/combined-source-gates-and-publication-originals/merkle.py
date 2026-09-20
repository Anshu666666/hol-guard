"""Compute Git object framing and compare every reconstruction to its source."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
WORKSPACE = ROOT.parent


def digest(kind, body):
    return hashlib.sha1(kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body).hexdigest()


def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'git_blob': digest('blob', body)}


def tree_id(directory):
    records = []
    for path in directory.iterdir():
        if path.is_dir():
            records.append((path.name + '/', b'40000', path.name, tree_id(path)))
        else:
            records.append((path.name, b'100644', path.name, digest('blob', path.read_bytes())))
    body = b''.join(mode + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
                    for _, mode, name, sha in sorted(records))
    return digest('tree', body)


manifest = json.loads((ROOT / 'packet/MANIFEST.json').read_bytes())
for row in manifest['originals']:
    before = (WORKSPACE / row['path']).read_bytes()
    restored = (ROOT / 'reconstructed' / row['path']).read_bytes()
    assert before == restored and identity(before) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
files = [{'path': p.relative_to(ROOT / 'packet').as_posix(), **identity(p.read_bytes())}
         for p in sorted((ROOT / 'packet').rglob('*')) if p.is_file()]
value = {'schema': 'hol-guard.lossless-packet-merkle.v1', 'packet_tree': tree_id(ROOT / 'packet'),
         'algorithm': 'Git SHA-1 object framing; regular100644 and tree40000 modes; directory slash sort.',
         'files': files, 'original_count': len(manifest['originals']),
         'original_bytes': manifest['original_bytes'], 'all_reconstructed_equal_current_originals': True,
         'product_code_tests_workload_executed': False}
(ROOT / 'MERKLE.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
elements = [{'path': 'packet/' + r['path'], 'mode': '100644', 'type': 'blob',
             'content': (ROOT / 'packet' / r['path']).read_text()} for r in files]
for name in ('VERIFICATION.json', 'MERKLE.json', 'merkle.py'):
    elements.append({'path': name, 'mode': '100644', 'type': 'blob', 'content': (ROOT / name).read_text()})
(ROOT / 'tree-elements.json').write_text(json.dumps(elements))
print(json.dumps({'packet_tree': value['packet_tree'], 'original_count': value['original_count'],
                  'original_bytes': value['original_bytes'], 'leaf_count': len(elements),
                  'serialized_tree_elements_bytes': (ROOT / 'tree-elements.json').stat().st_size}))
