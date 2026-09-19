"""Fetch original job-log bytes without forwarding API credentials through redirects."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from common import REPORT, digest, write_json
from download import API_ROOT, NoRedirect, TOKEN

TOTAL_BYTES = 0


def job_log(job_id: int, limit: int, aggregate_limit: int) -> str:
    global TOTAL_BYTES
    assert TOKEN, "Missing Actions token"
    request = urllib.request.Request(API_ROOT + "/actions/jobs/" + str(job_id) + "/logs", headers={
        "Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "hol-guard-original-runtime-call-observer"})
    try:
        urllib.request.build_opener(NoRedirect).open(request, timeout=60)
    except urllib.error.HTTPError as response:
        assert response.code == 302, "Job log API HTTP " + str(response.code)
        location = response.headers.get("Location")
        response.close()
    except urllib.error.URLError:
        raise AssertionError("Job log API transport failure: " + str(job_id)) from None
    else:
        raise AssertionError("Job log API did not return the documented redirect")
    assert location
    parsed = urllib.parse.urlsplit(location)
    assert parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
    assert not parsed.fragment
    request = urllib.request.Request(location, headers={"User-Agent": "hol-guard-original-runtime-call-observer"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=90) as response:
            assert response.status == 200
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        raise AssertionError("Signed job log transfer HTTP " + str(error.code) + ": " + str(job_id)) from None
    except urllib.error.URLError:
        raise AssertionError("Signed job log transport failure: " + str(job_id)) from None
    destination = REPORT / ("original-job-" + str(job_id) + ".log")
    destination.write_bytes(data)
    TOTAL_BYTES += len(data)
    receipt = {"job_id": job_id, **digest(data), "per_log_limit": limit,
               "aggregate_bytes": TOTAL_BYTES, "aggregate_limit": aggregate_limit,
               "token_sent_only_to_api_github_com": True}
    write_json(REPORT / ("original-job-" + str(job_id) + "-receipt.json"), receipt)
    assert len(data) <= limit and TOTAL_BYTES <= aggregate_limit, "Original job log bound exceeded"
    return data.decode("utf-8")
