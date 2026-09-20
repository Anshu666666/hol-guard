import resource
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
resource.setrlimit(resource.RLIMIT_FSIZE, (40 * 1024 * 1024, 40 * 1024 * 1024))
import hashlib
import json
import pathlib
import sys
import urllib.request
import zipfile

BOOT = 'd8473220-c565-48d8-846e-d827a04a33a0'
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT
platform = sys.argv[1]
expected = {'arm': (10606424536, 13268363, '3277fb66b43ce4f43212ae771a60ba29f7dc6ab25e2e9d477d4760241f135d0c'), 'intel': (10606991867, 8412204, '48c3dddbf80749f61e5d44d22161caad2c619cc61d45601156d596e55b6aa3bb')}[platform]
root = pathlib.Path('/workspace/scratch/745337b67ff9/qualification-recovered/normal-ad9-mac') / platform
root.mkdir(parents=True, exist_ok=False)
request = urllib.request.Request(sys.stdin.readline().strip(), headers={'User-Agent': 'Mozilla/5.0'})
digest = hashlib.sha256()
size = 0
with urllib.request.urlopen(request, timeout=30) as response, (root/'original.zip').open('xb') as output:
    while data := response.read(65536):
        size += len(data)
        assert size <= expected[1]
        digest.update(data)
        output.write(data)
assert size == expected[1] and digest.hexdigest() == expected[2]
records = []
with zipfile.ZipFile(root/'original.zip') as archive:
    entries = archive.infolist()
    assert 1 <= len(entries) <= 16 and sum(x.file_size for x in entries) <= 40*1024*1024
    names = set()
    for row in entries:
        name = pathlib.PurePosixPath(row.filename)
        assert row.filename not in names and not name.is_absolute() and all(x not in ('', '.', '..') for x in name.parts)
        assert not row.is_dir() and not row.flag_bits & 1 and row.file_size <= 20*1024*1024
        names.add(row.filename)
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256(); count=0
        with archive.open(row) as source, target.open('xb') as output:
            while data := source.read(65536):
                count += len(data); assert count <= row.file_size
                sha.update(data); output.write(data)
        assert count == row.file_size
        records.append({'name':row.filename, 'bytes':count, 'sha256':sha.hexdigest()})
result = {'schema':'normal-native-mac-archive-read.v1','run':35516487925,'platform':platform,'artifact':expected[0],'archive_bytes':size,'archive_sha256':digest.hexdigest(),'members':records,'boot':BOOT,'address_space_bytes':128*1024*1024,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'product_import_or_execution':False,'complete':True}
with (root/'READBACK.json').open('x') as output: json.dump(result,output,indent=2); output.write('\n')
print(json.dumps(result))
