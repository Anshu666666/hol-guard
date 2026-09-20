import hashlib, json, os, pathlib, platform, resource, stat, subprocess, sys, urllib.request, zipfile
root = pathlib.Path("/home/user/pr2974-recovery/windows/reader-format-4d")
assert root.is_dir()
assert resource.getrlimit(resource.RLIMIT_AS) == (134217728, 134217728)
allowed = sorted(os.sched_getaffinity(0))
os.sched_setaffinity(0, {allowed[0]})
url = "https://files.pythonhosted.org/packages/11/93/f10377bb04109ca0e8cbc483ff1982c54b6d418210041776f93e8cdc7fa9/ruff-0.15.17-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
expected = "ecfc3c7878fff94633ab0348524e093f9ce3243080416dd7d14f8ba400174719"
wheel = root / "ruff-0.15.17.whl"
assert not wheel.exists()
digest = hashlib.sha256()
count = 0
with urllib.request.urlopen(url, timeout=15) as response, wheel.open("xb") as output:
    while block := response.read(65536):
        output.write(block)
        digest.update(block)
        count += len(block)
assert count == 11557614 and digest.hexdigest() == expected
with zipfile.ZipFile(wheel) as archive:
    scripts = [entry for entry in archive.infolist() if entry.filename.endswith(".data/scripts/ruff")]
    assert len(scripts) == 1
    entry = scripts[0]
    metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    assert len(metadata_names) == 1
    metadata = archive.read(metadata_names[0]).decode("utf-8")
    assert "\nName: ruff\n" in "\n" + metadata and "\nVersion: 0.15.17\n" in "\n" + metadata
    executable = root / "ruff"
    digest = hashlib.sha256()
    size = 0
    with archive.open(entry) as source, executable.open("xb") as output:
        while block := source.read(65536):
            output.write(block)
            digest.update(block)
            size += len(block)
executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
environment = dict(os.environ)
environment["RAYON_NUM_THREADS"] = "1"
version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, timeout=10, env=environment)
identity = {"wheel_url": url, "wheel_bytes": count, "wheel_sha256": expected, "version_returncode": version.returncode, "version_stdout": version.stdout, "version_stderr": version.stderr, "executable_zip_member": entry.filename, "executable_bytes": size, "executable_sha256": digest.hexdigest(), "metadata_sha256": hashlib.sha256(metadata.encode()).hexdigest(), "python_version": platform.python_version(), "machine": platform.machine(), "rlimit_as": list(resource.getrlimit(resource.RLIMIT_AS)), "affinity": sorted(os.sched_getaffinity(0)), "rayon_num_threads": "1", "scope": "isolated formatter only; no global installation, source imports, source tests, or native builds"}
(root / "formatter-identity.json").write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")
print(json.dumps(identity, sort_keys=True))
assert version.returncode == 0 and version.stdout.strip() == "ruff 0.15.17"
