import resource
MEMORY_LIMIT = 95 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
from pathlib import Path
import base64, gzip, hashlib, json, re, signal, sys, urllib.request, time
EXPECTED_BOOT = "9426be4816cf3a00cb9b929a3d1ae121eac2369c7275dadeedc94caa521ee2e5"
ROOT = Path("/home/user/pr2974-native-decode-asnf")
LOG_BYTES = 13281325
LOG_SHA = "933b9dcaec995c208acf9c8a6b5704cac7e7fbca5d5648b34f248923d6815fd0"
GZIP_BYTES = 9497492
GZIP_SHA = "8e883c4bb40e11f70222c985d6d24bc28571976a982ff2e61170a1cdc8e7ea84"
RAW_BYTES = 55913684
RAW_SHA = "32f15e3d0473e8e3fcd3d305832e56c30c55a94cd442eafbecd47230b051641f"
URL = "https://raw.githubusercontent.com/hashgraph-online/hol-guard/aba7420f54eaa658d0422f09b08767a030317de8/review-evidence/2026-09-19/pr2974-completion/addenda/20260920T065000Z-surviving-records/evidence/qualification/native-corrective-4d/original-job-106032601355.log"
CHUNK = 65536
def timeout(signum, frame):
    raise TimeoutError("bounded_data_read_deadline")
signal.signal(signal.SIGALRM, timeout)
signal.alarm(90)
def require(condition, label):
    if not condition:
        raise ValueError(label)
def stream_copy(source, target, expected_bytes, expected_sha):
    count = 0
    digest = hashlib.sha256()
    with target.open("xb") as dest:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            count += len(chunk)
            require(count <= expected_bytes, "bounded_length_exceeded")
            digest.update(chunk)
            dest.write(chunk)
    require(count == expected_bytes, "bounded_length_mismatch")
    require(digest.hexdigest() == expected_sha, "sha256_mismatch")
    return {"bytes": count, "sha256": digest.hexdigest()}
started = time.monotonic()
state = {"schema": "hol-guard.pr2974.native-framed-stream-admission.v1",
         "run_id": 35493601886, "job_id": 106032601355,
         "source_sha": "4d10758e2cb44e5afa72a08aa631a02541dad534",
         "driver_sha": "0bfdfe115e7ad1b2bf4b3e890f1033c63522720b",
         "published_log_commit": "aba7420f54eaa658d0422f09b08767a030317de8",
         "memory_limit_bytes": MEMORY_LIMIT, "chunk_bytes": CHUNK,
         "native_or_workload_executed": False, "qualification_complete": False,
         "raw_member_semantics_parsed": False, "passed": False}
stage = "environment_admission"
try:
    actual_boot = hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_text().strip().encode()).hexdigest()
    require(actual_boot == EXPECTED_BOOT, "sandbox_boot_changed")
    require(resource.getrlimit(resource.RLIMIT_AS) == (MEMORY_LIMIT, MEMORY_LIMIT), "memory_limit_unavailable")
    ROOT.mkdir(mode=0o700, exist_ok=False)
    stage = "published_log_read"
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        state["log"] = stream_copy(response, ROOT/"original-job.log", LOG_BYTES, LOG_SHA)
    stage = "compressed_frame_read"
    prefix = b"PR2974_CURRENT_INTEGRATION_"
    begin = None
    end = None
    count = 0
    b64_chars = 0
    compressed_bytes = 0
    compressed_digest = hashlib.sha256()
    with (ROOT/"original-job.log").open("rb") as src, (ROOT/"framed-reports.json.gz").open("xb") as dest:
        while True:
            line = src.readline(8193)
            if not line:
                break
            require(len(line) <= 8192, "log_line_bound_exceeded")
            if prefix not in line:
                continue
            body = line.split(prefix, 1)[1].strip()
            if body.startswith(b"BEGIN "):
                require(begin is None and count == 0, "duplicate_begin")
                begin = json.loads(body[6:])
            elif body.startswith(b"PART "):
                require(begin is not None and end is None, "part_outside_frame")
                ordinal, encoded = body[5:].split(b" ", 1)
                count += 1
                require(count <= 2111, "part_count_exceeded")
                require(ordinal == (str(count).zfill(4)+"/2111").encode(), "part_ordinal_mismatch")
                require(len(encoded) <= 6000, "part_length_exceeded")
                b64_chars += len(encoded)
                decoded = base64.b64decode(encoded, validate=True)
                compressed_bytes += len(decoded)
                require(compressed_bytes <= GZIP_BYTES, "compressed_length_exceeded")
                compressed_digest.update(decoded)
                dest.write(decoded)
            elif body.startswith(b"END "):
                require(end is None, "duplicate_end")
                end = json.loads(body[4:])
            else:
                raise ValueError("unknown_frame_marker")
    require(begin == end and isinstance(begin, dict), "frame_metadata_mismatch")
    require(count == 2111 and b64_chars == 12663324, "frame_population_mismatch")
    require(compressed_bytes == GZIP_BYTES and compressed_digest.hexdigest() == GZIP_SHA, "compressed_identity_mismatch")
    expected = {"parts": 2111, "files": 114, "base64_chars": 12663324,
                "gzip_bytes": GZIP_BYTES, "gzip_sha256": GZIP_SHA,
                "raw_bytes": RAW_BYTES, "raw_sha256": RAW_SHA,
                "run_id": "35493601886", "run_attempt": "1",
                "source_sha": state["source_sha"], "source_tree": "fbc00caa3788eb422158a2263a578e83ac626183",
                "harness_sha": state["driver_sha"], "qualification_complete": False}
    require(all(begin.get(k) == v for k, v in expected.items()), "source_bound_frame_metadata")
    state["gzip"] = {"bytes": compressed_bytes, "sha256": compressed_digest.hexdigest(),
                     "parts": count, "begin_end_equal": True}
    stage = "bounded_raw_inflate"
    with gzip.open(ROOT/"framed-reports.json.gz", "rb") as source:
        state["raw"] = stream_copy(source, ROOT/"framed-reports.json", RAW_BYTES, RAW_SHA)
    stage = "bounded_schema_prefix"
    with (ROOT/"framed-reports.json").open("rb") as source:
        head = source.read(4096).decode("utf-8")
    keys = re.findall(r'"([A-Za-z_][A-Za-z0-9_-]{0,70})"\s*:', head)
    start = re.search(r'"files"\s*:\s*([\[{])', head)
    state["schema_prefix"] = {"first_character": head.lstrip()[:1],
                              "field_names": list(dict.fromkeys(keys))[:24],
                              "files_value_kind": start.group(1) if start else None,
                              "prefix_bytes_read": min(4096, RAW_BYTES)}
    state["passed"] = True
except BaseException as exc:
    state["failure"] = {"stage": stage, "exception_type": type(exc).__name__}
finally:
    signal.alarm(0)
    state["finished_stage"] = stage
    state["elapsed_data_processing_seconds"] = time.monotonic() - started
    state["maximum_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    state["memory_limit_verified_below_96MiB"] = resource.getrlimit(resource.RLIMIT_AS)[0] < 96*1024*1024
    if ROOT.is_dir():
        result = json.dumps(state, indent=2, sort_keys=True)+"\n"
        (ROOT/"stream-admission.json").write_text(result)
        state["receipt_sha256"] = hashlib.sha256(result.encode()).hexdigest()
    output = json.dumps(state, sort_keys=True)
    require(len(output.encode()) <= 8192, "stdout_bound_exceeded")
    print(output)
sys.exit(0 if state["passed"] else 1)
