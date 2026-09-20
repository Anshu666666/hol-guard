import resource
resource.setrlimit(resource.RLIMIT_AS, (96 * 1024 * 1024, 96 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
import hashlib
import io
import json
import pathlib
import sys
import urllib.request
import zipfile
BOOT = "d8473220-c565-48d8-846e-d827a04a33a0"
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == BOOT
ROOT = pathlib.Path("/workspace/scratch/745337b67ff9/qualification-recovered/phase-untimed-35511122796")
ROOT.mkdir(parents=True, exist_ok=False)
owned = True
try:
    request = urllib.request.Request(sys.stdin.read().strip(), headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(41804)
    assert len(raw) == 41803
    assert hashlib.sha256(raw).hexdigest() == "b82ec5f4bb570e9a68b51971a3e6afd51789194c68d6a11734fa75cf0582e1fc"
    with (ROOT / "original.zip").open("xb") as stream:
        stream.write(raw)
    archive = zipfile.ZipFile(io.BytesIO(raw))
    entries = archive.infolist()
    assert len(entries) == 23 and sum(row.file_size for row in entries) <= 4 * 1024 * 1024
    names = set()
    records = []
    for row in entries:
        name = row.filename
        assert name not in names and pathlib.PurePosixPath(name).name == name and name not in ("", ".", "..")
        assert not row.is_dir() and not (row.flag_bits & 1) and row.file_size <= 2 * 1024 * 1024
        names.add(name)
        with archive.open(row) as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        assert len(data) == row.file_size and len(data) <= 2 * 1024 * 1024
        data.decode("utf-8")
        with (ROOT / name).open("xb") as stream:
            stream.write(data)
        records.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    result = {"schema": "priority-phase-artifact-data-read.v1", "run": 35511122796, "artifact": 10605491806,
              "archive_bytes": len(raw), "archive_sha256": hashlib.sha256(raw).hexdigest(), "members": records,
              "boot": BOOT, "address_space_bytes": 96 * 1024 * 1024,
              "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
              "imports_of_product_or_tests_or_workload": False, "complete": True}
except BaseException as error:
    result = {"schema": "priority-phase-artifact-data-read.v1", "complete": False, "error_kind": type(error).__name__}
with (ROOT / "READBACK.json").open("x") as stream:
    json.dump(result, stream, indent=2)
    stream.write("\n")
print(json.dumps(result))
