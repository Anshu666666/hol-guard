"""Read-only reconciliation of retained first-admission evidence."""
import base64
import gzip
import hashlib
import json
import resource
import runpy
from pathlib import Path

resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
ROOT = Path('/workspace/scratch/745337b67ff9/native-current-first-admission-run35541994314')


def identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def inventory():
    return {str(p.relative_to(ROOT)): identity(p.read_bytes()) for p in sorted(ROOT.rglob('*')) if p.is_file()}


def tree_digest(rows):
    root = {}
    for path, blob in rows.items():
        parts = path.split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = blob
    def digest(node):
        entries = []
        for name, value in node.items():
            directory = isinstance(value, dict)
            sha = digest(value) if directory else value
            entries.append((name + ('/' if directory else ''),
                            (b'40000' if directory else b'100644') + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)))
        data = b''.join(body for _, body in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    return digest(root)


before = inventory()
packet = ROOT / 'packet'
manifest = json.loads((packet / 'MANIFEST.json').read_bytes())
assert len({r['path'] for r in manifest['files']}) == len(manifest['files'])
for row in manifest['files']:
    assert identity((packet / row['path']).read_bytes()) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
entries = {str(p.relative_to(packet)): identity(p.read_bytes())['git_blob'] for p in packet.rglob('*') if p.is_file()}
assert set(entries) == {r['path'] for r in manifest['files']} | {'MANIFEST.json'}
packet_tree = tree_digest(entries)
assert packet_tree == 'a42b5763f5e1ef9a6177dcbe50b685c8427ef19e'
encodings = json.loads((packet / 'ENCODINGS.json').read_bytes())['entries']
for row in encodings:
    compressed = base64.b64decode(b''.join((packet / part).read_bytes() for part in row['parts']), validate=True)
    assert identity(compressed) == row['gzip']
    original = gzip.decompress(compressed)
    assert identity(original) == row['original']
    assert original == (ROOT / row['path']).read_bytes()
reader = ROOT / 'verify.py'
assert identity(reader.read_bytes())['git_blob'] == 'cc19e6ff0ad01279f028ed30e9015725928745ef'
module = runpy.run_path(str(reader), run_name='data_peer_not_main')
actual = module['verify']()
assert actual == json.loads((ROOT / 'VERIFIED-RESULT.json').read_bytes())
raw = ROOT / '10614508539/raw'
ledger = [json.loads(line) for line in (raw / 'workspace-lifecycle.jsonl').read_bytes().splitlines()]
assert len(ledger) == 2 and ledger[0]['kind'] == 'lifecycle_cell_offer'
cell = json.loads(ledger[1]['content'])
assert cell['summary']['passed'] is False
assert cell['proof']['failure']['line'] == 73
assert cell['proof']['lifecycle_clocks']['boundaries_ms'] == {}
assert not {'fault', 'requests', 'service_replacement', 'binding', 'accepted_ms'} & cell['proof'].keys()
source = (ROOT / 'source/scripts/native_slo_workspace_lifecycle.py').read_text()
assert source.index('before = await_ack(') < source.index('result["service_replacement"] = replace_service')
assert source.index('observer = lifetime.enter_context(PublicationObserver(current, workspaces))') < source.index('fault = lifetime.enter_context(FirstAdmissionReplyFault(current))')
assert inventory() == before
print(json.dumps({'packet_tree': packet_tree, 'packet_leaves': len(entries),
                  'manifest_payloads': len(manifest['files']), 'lossless_reconstructions': len(encodings),
                  'all_input_files_unchanged': len(before), 'verifier_result_equal': True,
                  'archive_members': actual['original_members'], 'projection_frames': actual['projection_frames'],
                  'projection_files': actual['projection_files'], 'reader_controls': actual['reader_controls'],
                  'original_invocations': actual['original_cli_invocations'], 'original_exit': actual['original_exit'],
                  'fault_offered': actual['first_admission_fault_offered'], 'source': actual['source'],
                  'artifact_build': actual['artifact_build'], 'archive': actual['archive']}, indent=2, sort_keys=True))
