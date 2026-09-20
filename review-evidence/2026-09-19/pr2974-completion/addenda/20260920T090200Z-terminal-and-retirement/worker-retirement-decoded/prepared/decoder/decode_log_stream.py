import resource
MEMORY_LIMIT = 95 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
from pathlib import Path
import base64, gzip, hashlib, json, re, signal, sys, urllib.request, time
EXPECTED_BOOT = "9426be4816cf3a00cb9b929a3d1ae121eac2369c7275dadeedc94caa521ee2e5"
ROOT = Path("/home/user/pr2974-worker-retirement-decode-asnf")
LOG_BYTES = 13397608
LOG_SHA = "a6a7da3ab90f3f689bdb0c4d6173c79f4f68b7ae4bf1d3dfa80f6e67954e9ad7"
GZIP_BYTES = 9583213
GZIP_SHA = "edbf83343a0a47eca316e5d4d0f53e2097d6b2a10eb301c24a3a287365ad6dbb"
RAW_BYTES = 57292752
RAW_SHA = "fddb9ac6055a15229d7f425f5a924a83d12492b55747ba158d033049123764cb"
URL = "https://raw.githubusercontent.com/hashgraph-online/hol-guard/e5dd87805911e0f95d25f1474398d62235eee2fb/review-evidence/2026-09-19/pr2974-completion/addenda/20260920T075800Z-worker-terminal/worker-terminal/original-terminal.log"
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

def strict_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result
def reject_constant(value):
    raise ValueError("nonfinite_json")
def strict_loads(raw):
    return json.loads(raw, object_pairs_hook=strict_pairs, parse_constant=reject_constant)

started = time.monotonic()
state = {"schema": "hol-guard.pr2974.native-framed-stream-admission.v1",
         "run_id": 35496733388, "job_id": 106040961917,
         "source_sha": "2ac6b1bd84516c75fc169c7d1c849f9aad7b89bd",
         "driver_sha": "869856a68204fe4662fbbc87414f492d8306ef7b",
         "published_log_commit": "e5dd87805911e0f95d25f1474398d62235eee2fb",
         "memory_limit_bytes": MEMORY_LIMIT, "chunk_bytes": CHUNK,
         "native_or_workload_executed": False, "qualification_complete": False,
         "raw_member_semantics_parsed": False, "passed": False}
stage = "environment_admission"
created_root = False
try:
    actual_boot = hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_text().strip().encode()).hexdigest()
    require(actual_boot == EXPECTED_BOOT, "sandbox_boot_changed")
    require(resource.getrlimit(resource.RLIMIT_AS) == (MEMORY_LIMIT, MEMORY_LIMIT), "memory_limit_unavailable")
    ROOT.mkdir(mode=0o700, exist_ok=False)
    created_root = True
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
                begin = strict_loads(body[6:])
            elif body.startswith(b"PART "):
                require(begin is not None and end is None, "part_outside_frame")
                ordinal, encoded = body[5:].split(b" ", 1)
                count += 1
                require(count <= 2130, "part_count_exceeded")
                require(ordinal == (str(count).zfill(4)+"/2130").encode(), "part_ordinal_mismatch")
                require(len(encoded) <= 6000, "part_length_exceeded")
                b64_chars += len(encoded)
                decoded = base64.b64decode(encoded, validate=True)
                compressed_bytes += len(decoded)
                require(compressed_bytes <= GZIP_BYTES, "compressed_length_exceeded")
                compressed_digest.update(decoded)
                dest.write(decoded)
            elif body.startswith(b"END "):
                require(end is None, "duplicate_end")
                end = strict_loads(body[4:])
            else:
                raise ValueError("unknown_frame_marker")
    require(begin == end and isinstance(begin, dict), "frame_metadata_mismatch")
    require(count == 2130 and b64_chars == 12777620, "frame_population_mismatch")
    require(compressed_bytes == GZIP_BYTES and compressed_digest.hexdigest() == GZIP_SHA, "compressed_identity_mismatch")
    expected = {"parts": 2130, "files": 114, "base64_chars": 12777620,
                "gzip_bytes": GZIP_BYTES, "gzip_sha256": GZIP_SHA,
                "raw_bytes": RAW_BYTES, "raw_sha256": RAW_SHA,
                "run_id": "35496733388", "run_attempt": "1",
                "source_sha": state["source_sha"], "source_tree": "89c4343c8a528e2abdc0b755b3242f9ae52e6323",
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
    if created_root:
        result = json.dumps(state, indent=2, sort_keys=True)+"\n"
        with (ROOT/"stream-admission.json").open("x") as receipt:
            receipt.write(result)
        state["receipt_sha256"] = hashlib.sha256(result.encode()).hexdigest()
    output = json.dumps(state, sort_keys=True)
    require(len(output.encode()) <= 8192, "stdout_bound_exceeded")
    print(output)
sys.exit(0 if state["passed"] else 1)
