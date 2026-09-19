"""Actual C forwarding with owned socket fixtures; no resolver or macOS qualification."""

from __future__ import annotations

import errno
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "scripts/ci"
DNS_HEADER = r"""
#pragma once
#include <stdint.h>
typedef void *DNSServiceRef;
typedef int32_t DNSServiceErrorType;
int DNSServiceRefSockFD(DNSServiceRef);
void DNSServiceQueryRecord(void);
DNSServiceErrorType DNSServiceProcessResult(DNSServiceRef);
"""
PHASE_FIXTURE = r"""
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
struct mach_header { int dummy; };
static const struct mach_header * _dyld_get_image_header(unsigned index) {
    static struct mach_header image;
    assert(index == 0);
    return &image;
}
static bool image_uuid(const void *symbol, char output[33]) {
    assert(symbol);
    memset(output, 'a', 32);
    output[32] = 0;
    return true;
}
#if defined(__APPLE__)
int fixture_thread_id(pthread_t thread, uint64_t *value) { (void)thread; *value = 7; return 0; }
#else
int fixture_thread_id(void *thread, uint64_t *value) { (void)thread; *value = 7; return 0; }
#endif
int fixture_main_thread(void) { return 1; }
int fixture_call(DNSServiceRef reference) {
    int result = DNSServiceRefSockFD(reference);
    assert(errno == E2BIG);
    return result;
}
"""
SOCKET_FIXTURE = r"""
#include "dns_sd.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static int descriptor, getter_calls;
int hol_guard_endpoint_configure(unsigned, int);
int fixture_call(DNSServiceRef);
void DNSServiceQueryRecord(void) {}
DNSServiceErrorType DNSServiceProcessResult(DNSServiceRef reference) { (void)reference; return 0; }
int DNSServiceRefSockFD(DNSServiceRef reference) {
    assert(reference == &descriptor);
    getter_calls++;
    errno = E2BIG;
    return descriptor;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    int scenario = atoi(argv[1]), repeats = atoi(argv[2]), pair[2] = {-1, -1};
    if (scenario == 0) { assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0); descriptor = pair[0]; }
    else if (scenario == 1) descriptor = -1;
    else { descriptor = open("/dev/null", O_RDONLY); assert(descriptor >= 0); }
    assert(hol_guard_endpoint_configure(1, RTLD_NOW | RTLD_LOCAL) == 0);
    assert(hol_guard_endpoint_configure(1, RTLD_NOW | RTLD_LOCAL) == 64);
    for (int index = 0; index < repeats; index++) assert(fixture_call(&descriptor) == descriptor);
    assert(getter_calls == repeats);
    if (descriptor >= 0) close(descriptor);
    if (pair[1] >= 0) close(pair[1]);
    return 0;
}
"""
HOST_LIBRARY = r"""
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned configured, calls;
int hol_guard_endpoint_configure(unsigned context, int flags) {
    assert(!configured && context == 1 && flags == (RTLD_NOW | RTLD_LOCAL));
    configured = 1;
    return 0;
}
int hol_guard_resolver_bridge_identity(char *bridge, char *libinfo, char *dnssd, unsigned capacity) {
    assert(configured && capacity == 33);
    memset(bridge, 'a', 32); bridge[32] = 0;
    memset(libinfo, 'b', 32); libinfo[32] = 0;
    memset(dnssd, 'c', 32); dnssd[32] = 0;
    return 0;
}
int hol_guard_dnssd_python_call(unsigned operation) {
    assert(configured && !calls++ && operation <= 1);
    assert(setvbuf(stdout, NULL, _IONBF, 0) == 0);
    printf("{\"kind\":\"fixture_call\",\"operation\":%u}\n", operation);
    return operation ? 2 : 0;
}
"""


def compile_c(directory: Path, arguments: list[str]) -> None:
    compiler = shutil.which("cc")
    assert compiler is not None, "The owned finite C controls require a compiler"
    result = subprocess.run(
        [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *arguments],
        cwd=directory, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


@pytest.fixture(scope="module")
def programs(tmp_path_factory):
    directory = tmp_path_factory.mktemp("endpoint-forwarding")
    for name in ("native_macos_dnssd_endpoint_probe.c", "native_macos_dnssd_dlopen_host.c"):
        shutil.copyfile(ROOT / name, directory / name)
    (directory / "dns_sd.h").write_text(DNS_HEADER)
    (directory / "native_macos_dnssd_phase_probe.c").write_text(PHASE_FIXTURE)
    (directory / "socket_fixture.c").write_text("#include <dlfcn.h>\n" + SOCKET_FIXTURE)
    (directory / "host_library.c").write_text(HOST_LIBRARY)
    compile_c(directory, [
        "-D_POSIX_C_SOURCE=200809L", "-D_DEFAULT_SOURCE", "-DHOL_GUARD_PHASE_LIBRARY",
        "-Dpthread_threadid_np=fixture_thread_id", "-Dpthread_main_np=fixture_main_thread",
        "-I", str(directory), "native_macos_dnssd_endpoint_probe.c", "socket_fixture.c", "-o", "socket_fixture",
    ])
    import sys
    shared = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
    compile_c(directory, [*shared, "host_library.c", "-o", "host_library.dylib"])
    extra = [] if sys.platform == "darwin" else ["-ldl"]
    compile_c(directory, ["native_macos_dnssd_dlopen_host.c", "-o", "native_host", *extra])
    return directory


@pytest.mark.parametrize("scenario", (0, 1, 2))
@pytest.mark.parametrize("repeats", (1, 3))
def test_actual_getter_arguments_errno_and_calls_survive_snapshot_failures(programs, scenario, repeats):
    result = subprocess.run(
        [str(programs / "socket_fixture"), str(scenario), str(repeats)], capture_output=True, timeout=5, check=True,
    )
    assert result.stderr == b""
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == (1 if repeats == 1 else 2)
    snapshot = rows[0]
    assert snapshot["kind"] == "endpoint_context" and snapshot["sequence"] == 1 and snapshot["context"] == 1
    if scenario == 0:
        assert snapshot["stat_before"] == snapshot["stat_after"]
        assert snapshot["stat_before"]["rc"] == snapshot["socket_type"]["rc"] == 0
        assert snapshot["socket_type"]["value"] == 1
    else:
        assert snapshot["socket_type"]["rc"] == -1
        assert snapshot["socket_type"]["errno"] == (errno.EBADF if scenario == 1 else errno.ENOTSOCK)
    if repeats > 1:
        assert rows[1] == {"kind": "endpoint_overflow"}


@pytest.mark.parametrize("mode,operation,code", (("dns_simple", 0, 0), ("dns_shared", 1, 2)))
def test_actual_native_host_loader_abi_single_call_and_return(programs, mode, operation, code):
    result = subprocess.run(
        [str(programs / "native_host"), str(programs / "host_library.dylib"), mode],
        capture_output=True, timeout=5,
    )
    assert result.returncode == code and result.stderr == b""
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row.get("phase", row["kind"]) for row in rows] == ["load_enter", "call_enter", "fixture_call", "complete"]
    assert rows[2] == {"kind": "fixture_call", "operation": operation}
    assert rows[3]["return_code"] == code
    for key in ("bridge_uuid", "libinfo_uuid", "dnssd_uuid"):
        assert rows[1][key] == rows[3][key]


def test_actual_native_host_refuses_missing_image_before_query(programs):
    result = subprocess.run(
        [str(programs / "native_host"), str(programs / "absent.dylib"), "dns_simple"],
        capture_output=True, timeout=5,
    )
    assert result.returncode == 3 and result.stderr == b""
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows[-1] == {"kind": "native_host_failure", "stage": "load"}
    assert len(rows) == 2
