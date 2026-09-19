"""Compile the actual observer around a deterministic SDK fixture; no native DNS claim."""

from __future__ import annotations

import errno
import json
import shutil
import subprocess
from pathlib import Path

import pytest

HEADER = r"""
#pragma once
#include <stdint.h>
typedef void *DNSServiceRef;
typedef int32_t DNSServiceErrorType;
DNSServiceErrorType DNSServiceProcessResult(DNSServiceRef reference);
"""
QUERY = r"""
#include <assert.h>
#include <errno.h>
extern unsigned cycles;
extern int scenario;
extern char reference_token;
int hol_guard_original_resolver_main(int argc, char **argv) {
    assert(argc == 2 && (!strcmp(argv[1], "dns_simple") || !strcmp(argv[1], "dns_shared")));
    for (unsigned index = 0; index < cycles; index++) {
        struct pollfd event = {.fd = 42, .events = POLLIN, .revents = 0};
        errno = EDOM;
        assert(poll(&event, 1, -1) == (scenario == 1 ? -1 : 1));
        assert(errno == EOVERFLOW);
        errno = ERANGE;
        assert(DNSServiceProcessResult(&reference_token) == (scenario == 2 ? -65537 : 0));
        assert(errno == ENOTSUP);
    }
    return 0;
}
"""
SHIM = r"""
/* Do not attach the host header's write-only poll attribute to this reading fixture. */
#define poll host_poll_declaration
#include <poll.h>
#undef poll
#include "dns_sd.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
unsigned cycles, poll_calls, process_calls;
int scenario;
char reference_token;
int hol_guard_dnssd_python_call(unsigned operation);
int poll(struct pollfd *fds, nfds_t count, int timeout) {
    assert(errno == EDOM && count == 1 && timeout == -1);
    assert(fds[0].fd == 42 && fds[0].events == POLLIN && fds[0].revents == 0);
    poll_calls++;
    fds[0].revents = POLLIN;
    errno = EOVERFLOW;
    return scenario == 1 ? -1 : 1;
}
DNSServiceErrorType DNSServiceProcessResult(DNSServiceRef reference) {
    assert(errno == ERANGE && reference == &reference_token);
    process_calls++;
    errno = ENOTSUP;
    return scenario == 2 ? -65537 : 0;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    cycles = (unsigned)strtoul(argv[1], NULL, 10);
    scenario = atoi(argv[2]);
    assert(hol_guard_dnssd_python_call(0) == 0);
    assert(poll_calls == cycles && process_calls == cycles);
    return 0;
}
"""


@pytest.fixture(scope="module")
def program(tmp_path_factory):
    directory = tmp_path_factory.mktemp("phase-forwarding")
    root = Path(__file__).resolve().parents[1] / "scripts/ci"
    for name in ("native_macos_dnssd_phase_probe.c", "native_macos_dnssd_python_bridge.c"):
        shutil.copyfile(root / name, directory / name)
    (directory / "dns_sd.h").write_text(HEADER)
    (directory / "native_macos_python_resolver_bridge.c").write_text(QUERY)
    (directory / "shim.c").write_text(SHIM)
    executable = directory / "probe"
    compiler = shutil.which("cc")
    assert compiler is not None, "A C compiler is required for the forwarding controls"
    subprocess.run(
        [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-DHOL_GUARD_PHASE_LIBRARY",
         "-I", str(directory), str(directory / "native_macos_dnssd_phase_probe.c"),
         str(directory / "shim.c"), "-o", str(executable)],
        check=True, capture_output=True, timeout=15,
    )
    return executable


@pytest.mark.parametrize("cycles", (1, 8, 17))
@pytest.mark.parametrize("scenario", (0, 1, 2))
def test_arguments_returns_errno_and_underlying_calls_survive_trace_limit(program, cycles, scenario):
    result = subprocess.run([str(program), str(cycles), str(scenario)], capture_output=True, timeout=5, check=True)
    assert not result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    count = min(4 * cycles, 32)
    assert [row["sequence"] for row in rows] == list(range(1, min(4 * cycles, 33) + 1))
    assert all(row["kind"] == "call_trace" for row in rows[:count])
    assert len(rows) == count + (cycles > 8)
    for offset in range(0, count, 4):
        enter_poll, return_poll, enter_process, return_process = rows[offset : offset + 4]
        assert enter_poll["call"] == return_poll["call"] == "poll"
        assert enter_poll["phase"] == enter_process["phase"] == "enter"
        assert return_poll["phase"] == return_process["phase"] == "return"
        assert {key: enter_poll[key] for key in ("fd", "events", "nfds", "timeout")} == {
            "fd": 42, "events": 1, "nfds": 1, "timeout": -1,
        }
        assert return_poll["result"] == (-1 if scenario == 1 else 1) and return_poll["revents"] == 1
        assert enter_process["call"] == return_process["call"] == "DNSServiceProcessResult"
        assert return_process["result"] == (-65537 if scenario == 2 else 0)
        assert return_poll["errno"] == errno.EOVERFLOW and return_process["errno"] == errno.ENOTSUP
    if cycles > 8:
        assert rows[-1] == {"kind": "call_trace_overflow", "sequence": 33}
