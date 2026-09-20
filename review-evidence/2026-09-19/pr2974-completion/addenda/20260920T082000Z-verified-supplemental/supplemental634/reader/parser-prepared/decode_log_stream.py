import resource
MEMORY_LIMIT = 95 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
from pathlib import Path
import base64, gzip, hashlib, json, re, signal, sys, urllib.request, time
EXPECTED_BOOT = "9426be4816cf3a00cb9b929a3d1ae121eac2369c7275dadeedc94caa521ee2e5"
ROOT = Path("/home/user/pr2974-corrective634-decode-asnf")
LOG_BYTES = 11373473
LOG_SHA = "498649c47878f3a4b76d69363264f92ed88f2ec181daf0bffad62c931fc7b822"
GZIP_BYTES = 8084748
GZIP_SHA = "2f62975dd776557915baf3cf3180f484f20d0f8685c6898fe67f79dc200ffa43"
RAW_BYTES = 80685332
RAW_SHA = "1efcb42481c407a7048963e368f5a5e7e3e851c9d84669d45412c0928bca83e3"
URL = "https://raw.githubusercontent.com/hashgraph-online/hol-guard/f1b033246d3d5fe623573e5bb3bafe588260fafd/review-evidence/2026-09-19/pr2974-completion/addenda/20260920T072135Z-terminal-supplemental/supplemental/original-terminal.log"
CHUNK = 65536
def timeout(signum, frame):
    raise TimeoutError("bounded_data_read_deadline")
signal.signal(signal.SIGALRM, timeout)
signal.alarm(120)
def require(condition, label):
    if not condition:
        raise ValueError(label)
def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate_json_key")
        value[key] = item
    return value
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
state = {"schema": "hol-guard.pr2974.corrective634-framed-stream-admission.v1",
         "run_id": 35494533524, "job_id": 106035074778,
         "source_sha": "4d10758e2cb44e5afa72a08aa631a02541dad534",
         "driver_sha": "b05127dd2cec4f02eb97d715138179c741e52ec0",
         "published_log_commit": "f1b033246d3d5fe623573e5bb3bafe588260fafd",
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
    framed_line = re.compile(rb"^(?:\xef\xbb\xbf)?[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z PR2974_CURRENT_INTEGRATION_(.*)\r?\n?$")
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
            match = framed_line.fullmatch(line)
            if match is None:
                continue
            body = match.group(1).strip()
            if body.startswith(b"BEGIN "):
                require(begin is None and count == 0, "duplicate_begin")
                begin = json.loads(body[6:], object_pairs_hook=unique_pairs)
            elif body.startswith(b"PART "):
                require(begin is not None and end is None, "part_outside_frame")
                ordinal, encoded = body[5:].split(b" ", 1)
                count += 1
                require(count <= 1797, "part_count_exceeded")
                require(ordinal == (str(count).zfill(4)+"/1797").encode(), "part_ordinal_mismatch")
                require(len(encoded) <= 6000, "part_length_exceeded")
                b64_chars += len(encoded)
                decoded = base64.b64decode(encoded, validate=True)
                compressed_bytes += len(decoded)
                require(compressed_bytes <= GZIP_BYTES, "compressed_length_exceeded")
                compressed_digest.update(decoded)
                dest.write(decoded)
            elif body.startswith(b"END "):
                require(end is None, "duplicate_end")
                end = json.loads(body[4:], object_pairs_hook=unique_pairs)
            else:
                raise ValueError("unknown_frame_marker")
    require(begin == end and isinstance(begin, dict), "frame_metadata_mismatch")
    require(count == 1797 and b64_chars == 10779664, "frame_population_mismatch")
    require(compressed_bytes == GZIP_BYTES and compressed_digest.hexdigest() == GZIP_SHA, "compressed_identity_mismatch")
    expected = {"parts": 1797, "files": 216, "base64_chars": 10779664,
                "gzip_bytes": GZIP_BYTES, "gzip_sha256": GZIP_SHA,
                "raw_bytes": RAW_BYTES, "raw_sha256": RAW_SHA,
                "run_id": "35494533524", "run_attempt": "1",
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
    if created_root:
        result = json.dumps(state, indent=2, sort_keys=True)+"\n"
        with (ROOT/"stream-admission.json").open("x") as receipt:
            receipt.write(result)
        state["receipt_sha256"] = hashlib.sha256(result.encode()).hexdigest()
    output = json.dumps(state, sort_keys=True)
    require(len(output.encode()) <= 8192, "stdout_bound_exceeded")
    print(output)
sys.exit(0 if state["passed"] else 1)
