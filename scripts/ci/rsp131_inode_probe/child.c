/* The fixed child performs no allocation, exec, clone or external lookup. */
#define _GNU_SOURCE
#include "probe.h"

#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

static void require_result(long actual, long expected) {
    if (actual != expected) syscall(SYS_exit_group, 70);
}

_Noreturn void child_control(int fd_a, int fd_b, int directory) {
    const char first[] = "owned-a-1";
    const char second[] = "owned-b-two";
    const char third[] = "again";
    pid_t parent = getppid();
    pid_t self = getpid();

    /* This descriptor is preparation, outside the admitted syscall interval. */
    require_result(close(directory), 0);
    if (getppid() != parent) _exit(78);
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
        int error = errno;
        _exit(error > 0 && error <= 155 ? 100 + error : 99);
    }
    /* The observer records any trailing bootstrap exit separately. */
    require_result(syscall(SYS_kill, self, SIGSTOP), 0);

    require_result(syscall(SYS_write, fd_a, first, sizeof(first) - 1), 9);
    long alias = syscall(SYS_dup, fd_a);
    if (alias < 3 || alias == fd_a || alias == fd_b) syscall(SYS_exit_group, 70);
    require_result(syscall(SYS_fsync, alias), 0);
    require_result(syscall(SYS_close, fd_a), 0);
    require_result(syscall(SYS_dup2, fd_b, fd_a), fd_a);
    require_result(syscall(SYS_pwrite64, fd_a, second, sizeof(second) - 1, 7), 11);
    require_result(syscall(SYS_fdatasync, fd_a), 0);
    require_result(syscall(SYS_close, fd_a), 0);
    errno = 0;
    long invalid_sync = syscall(SYS_fsync, fd_a);
    if (invalid_sync != -1 || errno != EBADF) syscall(SYS_exit_group, 70);
    require_result(syscall(SYS_write, alias, third, sizeof(third) - 1), 5);
    require_result(syscall(SYS_close, alias), 0);
    require_result(syscall(SYS_close, fd_b), 0);
    syscall(SYS_exit_group, 0);
    _exit(71);
}
