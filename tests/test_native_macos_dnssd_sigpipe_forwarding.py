"""Compile the exact new signal helper and native host with owned finite controls."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "scripts/ci"

CONTROL = r'''
#define _DARWIN_C_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static int endpoint_configured = 1, endpoint_context = 1;
static int main_thread = 1, scenario, set_calls, socket_calls;
static unsigned requested;
static struct sigaction original_action, fixture_action;
static int raw_action(int sig, const struct sigaction *set, struct sigaction *old) {
    return sigaction(sig, set, old);
}
static int fixture_action_call(int sig, const struct sigaction *set, struct sigaction *old) {
    assert(sig == SIGPIPE);
    if (set) {
        set_calls++;
        assert(set->sa_flags == fixture_action.sa_flags);
        for (int number = 1; number < NSIG; number++)
            assert(sigismember(&set->sa_mask, number) == sigismember(&fixture_action.sa_mask, number));
        if ((scenario == 1 && set_calls == 1) || (scenario == 2 && set_calls == 2)) {
            errno = EACCES;
            return -1;
        }
    }
    return raw_action(sig, set, old);
}
static int fixture_option(int fd, int level, int name, void *value, socklen_t *length) {
    assert(fd == 37 && level == SOL_SOCKET && name == SO_NOSIGPIPE);
    assert(*length == sizeof(int) && !socket_calls++);
    if (scenario == 3) { errno = EBADF; return -1; }
    *(int *)value = 4096;
    *length = sizeof(int);
    errno = ERANGE;
    return 0;
}
static int fixture_main(void) { return main_thread; }
#define sigaction(...) fixture_action_call(__VA_ARGS__)
#define getsockopt(...) fixture_option(__VA_ARGS__)
#define pthread_main_np() fixture_main()
#include "native_macos_dnssd_sigpipe_control.h"
int main(int argc, char **argv) {
    assert(argc == 3);
    requested = (unsigned)atoi(argv[1]);
    scenario = atoi(argv[2]);
    assert(requested <= 1 && scenario >= 0 && scenario <= 3);
    assert(raw_action(SIGPIPE, NULL, &original_action) == 0);
    fixture_action = original_action;
    fixture_action.sa_handler = SIG_DFL;
    fixture_action.sa_flags = SA_RESTART;
    assert(sigemptyset(&fixture_action.sa_mask) == 0);
    assert(sigaddset(&fixture_action.sa_mask, SIGUSR1) == 0);
    assert(raw_action(SIGPIPE, &fixture_action, NULL) == 0);
    errno = E2BIG;
    main_thread = 0;
    assert(hol_guard_sigpipe_enter(requested) == 64 && errno == E2BIG);
    main_thread = 1;
    assert(hol_guard_sigpipe_enter(2) == 64 && errno == E2BIG && set_calls == 0);
    int code = hol_guard_sigpipe_enter(requested);
    assert(errno == E2BIG && code == (scenario == 1 ? 3 : 0));
    assert(hol_guard_sigpipe_enter(requested) == 64 && set_calls == 1);
    if (scenario != 1) {
        signal_query_record(37);
        assert(errno == E2BIG && socket_calls == 1);
        assert(hol_guard_sigpipe_leave() == (scenario == 2 ? 3 : 0));
        assert(errno == E2BIG && set_calls == 2);
        assert(hol_guard_sigpipe_leave() == (scenario == 2 ? 64 : 0));
        assert(set_calls == 2);
    } else {
        assert(hol_guard_sigpipe_leave() == 0 && set_calls == 1 && socket_calls == 0);
    }
    struct sigaction after;
    assert(raw_action(SIGPIPE, NULL, &after) == 0);
    if (scenario != 2) {
        assert(after.sa_handler == fixture_action.sa_handler && after.sa_flags == fixture_action.sa_flags);
        for (int number = 1; number < NSIG; number++)
            assert(sigismember(&after.sa_mask, number) == sigismember(&fixture_action.sa_mask, number));
    }
    /* Finite-fixture cleanup is separate from the production helper's single attempt. */
    assert(raw_action(SIGPIPE, &original_action, NULL) == 0);
    return 0;
}
'''

HOST_LIBRARY = r'''
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static unsigned configured, calls, active, condition, restored;
int hol_guard_endpoint_configure(unsigned context, int flags) {
    assert(!configured && context == 1 && flags == (RTLD_NOW | RTLD_LOCAL));
    configured = 1; return 0;
}
int hol_guard_sigpipe_enter(unsigned requested) {
    assert(configured && !active && !restored && requested <= 1);
    condition = requested; active = 1;
    char data[100];
    int length = snprintf(data, sizeof(data), "{\"kind\":\"fixture_enter\",\"condition\":%u}\n", condition);
    assert(length > 0 && (unsigned)length < sizeof(data) && write(1, data, (size_t)length) == length);
    return 0;
}
int hol_guard_sigpipe_leave(void) {
    assert(active && calls == 1 && !restored);
    active = 0; restored = 1;
    const char data[] = "{\"kind\":\"fixture_leave\"}\n";
    assert(write(1, data, sizeof(data)-1) == (ssize_t)(sizeof(data)-1));
    return 0;
}
int hol_guard_resolver_bridge_identity(char *bridge, char *libinfo, char *dnssd, unsigned capacity) {
    assert(configured && capacity == 33);
    assert((calls == 0 && active) || (calls == 1 && restored && !active));
    memset(bridge, 'a', 32); bridge[32] = 0;
    memset(libinfo, 'b', 32); libinfo[32] = 0;
    memset(dnssd, 'c', 32); dnssd[32] = 0;
    return 0;
}
int hol_guard_dnssd_python_call(unsigned operation) {
    assert(configured && active && !calls++ && operation <= 1);
    assert(setvbuf(stdout, NULL, _IONBF, 0) == 0);
    printf("{\"kind\":\"fixture_call\",\"operation\":%u,\"condition\":%u}\n", operation, condition);
    return operation ? 2 : 0;
}
__attribute__((destructor)) static void unloaded(void) {
    assert(restored && !active && calls == 1);
    const char data[] = "{\"kind\":\"fixture_unload\"}\n";
    assert(write(1, data, sizeof(data)-1) == (ssize_t)(sizeof(data)-1));
}
'''


def compile_c(directory, arguments):
    assert sys.platform == "darwin", "These new compiled controls require the admitted macOS SDK"
    result = subprocess.run(
        ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", *arguments],
        cwd=directory, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


@pytest.fixture(scope="module")
def programs(tmp_path_factory):
    directory = tmp_path_factory.mktemp("sigpipe-forwarding")
    for name in ("native_macos_dnssd_sigpipe_control.h", "native_macos_dnssd_sigpipe_host.c"):
        shutil.copyfile(ROOT / name, directory / name)
    (directory / "control.c").write_text(CONTROL)
    (directory / "host_library.c").write_text(HOST_LIBRARY)
    compile_c(directory, ["control.c", "-o", "control"])
    compile_c(directory, ["-dynamiclib", "host_library.c", "-o", "library.dylib"])
    compile_c(directory, ["native_macos_dnssd_sigpipe_host.c", "-o", "host"])
    return directory


@pytest.mark.parametrize("requested", (0, 1))
@pytest.mark.parametrize("scenario", (0, 1, 2, 3))
def test_compiled_control_preserves_masks_errno_and_single_attempt_failures(programs, requested, scenario):
    result = subprocess.run(
        [str(programs / "control"), str(requested), str(scenario)], capture_output=True, timeout=5, check=True,
    )
    assert result.stderr == b""
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    states = [row for row in rows if row["kind"] == "sigpipe_condition"]
    assert [row["stage"] for row in states] == (
        ["before", "installed"] if scenario == 1 else ["before", "installed", "query", "after", "restored"]
    )
    assert all(row["requested"] == requested for row in states)
    assert states[0]["action_mask"] != "0"
    if scenario == 1:
        assert states[1]["set_rc"] == -1 and states[1]["active"] is False
    else:
        assert all(row["handler_kind"] == requested for row in states[1:4])
        socket = next(row for row in rows if row["kind"] == "sigpipe_socket")
        assert socket["fd"] == 37 and socket["integer_bytes"] == 4
        assert socket["rc"] == (-1 if scenario == 3 else 0)
        assert states[-1]["set_rc"] == (-1 if scenario == 2 else 0)
        assert states[-1]["active"] is (scenario == 2)


@pytest.mark.parametrize("condition,requested", (("default", 0), ("ignore", 1)))
@pytest.mark.parametrize("mode,operation,code", (("dns_simple", 0, 0), ("dns_shared", 1, 2)))
def test_compiled_native_host_holds_the_image_across_condition_query_and_restore(
    programs, condition, requested, mode, operation, code,
):
    result = subprocess.run(
        [str(programs / "host"), str(programs / "library.dylib"), mode, condition], capture_output=True, timeout=5,
    )
    assert result.returncode == code and result.stderr == b""
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row.get("phase", row["kind"]) for row in rows] == [
        "load_enter", "fixture_enter", "call_enter", "fixture_call", "fixture_leave", "complete", "fixture_unload"
    ]
    assert rows[1]["condition"] == requested and rows[3]["operation"] == operation
    assert rows[3]["condition"] == requested and rows[5]["return_code"] == code


def test_compiled_native_host_missing_image_never_installs_a_condition(programs):
    result = subprocess.run(
        [str(programs / "host"), str(programs / "absent"), "dns_simple", "default"],
        capture_output=True, timeout=5,
    )
    assert result.returncode == 3 and result.stderr == b""
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == 2 and rows[-1] == {"kind": "native_host_failure", "stage": "load"}
