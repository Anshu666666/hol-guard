/* Strict single-thread event grammar; no reconstruction from completion order. */
#define _GNU_SOURCE
#include "probe.h"

#include <errno.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <stddef.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK \
    | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT \
    | PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL)

struct operation {
    const char *name;
    long number;
    int fd;
    int target;
    int role;
    unsigned requested;
    unsigned offset;
};

/* Return 0 only for actual EBADF; all permission/capture errors refuse. */
static int bound_identity(struct probe *probe, int fd, int role) {
    errno = 0;
    int copy = (int)syscall(SYS_pidfd_getfd, probe->pidfd, fd, 0);
    if (copy < 0) {
        int error = errno;
        if (error == EBADF && role == 0) return 0;
        refuse(probe, "pidfd_getfd", error);
        return -1;
    }
    struct stat value;
    bool inspected = fstat(copy, &value) == 0;
    int error = inspected ? 0 : errno;
    /* No reads, offset changes, flag changes, syncs or retained open reference. */
    bool closed = close(copy) == 0;
    if (!closed && error == 0) error = errno;
    if (!inspected || !closed) {
        refuse(probe, "duplicate_identity_or_close", error);
        return -1;
    }
    const struct stat *expected = role == 1 ? &probe->identity_a : &probe->identity_b;
    if (role == 0 || !S_ISREG(value.st_mode) || value.st_uid != getuid()
        || value.st_dev != expected->st_dev || value.st_ino != expected->st_ino) {
        refuse(probe, "descriptor_identity_mismatch", 0);
        return -1;
    }
    return role;
}

static struct operation expected_operation(struct probe *probe, int alias) {
    const int a = probe->fd_a, b = probe->fd_b;
    const struct operation operations[] = {
        {"write", SYS_write, a, -1, 1, 9, 0},
        {"dup", SYS_dup, a, -1, 1, 0, 0},
        {"fsync", SYS_fsync, alias, -1, 1, 0, 0},
        {"close", SYS_close, a, -1, 1, 0, 0},
        {"dup2", SYS_dup2, b, a, 2, 0, 0},
        {"pwrite64", SYS_pwrite64, a, -1, 2, 11, 7},
        {"fdatasync", SYS_fdatasync, a, -1, 2, 0, 0},
        {"close", SYS_close, a, -1, 2, 0, 0},
        {"fsync", SYS_fsync, a, -1, 0, 0, 0},
        {"write", SYS_write, alias, -1, 1, 5, 0},
        {"close", SYS_close, alias, -1, 1, 0, 0},
        {"close", SYS_close, b, -1, 2, 0, 0},
    };
    return operations[probe->calls];
}

static bool entry_record(struct probe *probe, const struct operation *op) {
    const struct stat *identity = op->role == 1 ? &probe->identity_a : &probe->identity_b;
    return emit_record(probe,
        "\"kind\":\"entry\",\"call_id\":%u,\"pid\":%d,\"call\":\"%s\",\"number\":%ld,"
        "\"fd\":%d,\"target_fd\":%d,\"role\":%d,\"dev\":%" PRIuMAX ",\"ino\":%" PRIuMAX ","
        "\"requested\":%u,\"offset\":%u,\"duplicate_closed_before_resume\":true",
        probe->calls + 1, probe->child, op->name, op->number, op->fd, op->target, op->role,
        op->role ? (uintmax_t)identity->st_dev : 0,
        op->role ? (uintmax_t)identity->st_ino : 0, op->requested, op->offset);
}

static bool check_entry(
    struct probe *probe, const struct ptrace_syscall_info *info, const struct operation *op
) {
    if (info->entry.nr != (uint64_t)op->number || info->entry.args[0] != (uint64_t)op->fd)
        return refuse(probe, "unexpected_syscall_or_descriptor", 0);
    if ((op->number == SYS_dup2 && info->entry.args[1] != (uint64_t)op->target)
        || (op->requested && info->entry.args[2] != op->requested)
        || (op->number == SYS_pwrite64 && info->entry.args[3] != op->offset))
        return refuse(probe, "unexpected_control_arguments", 0);
    if (bound_identity(probe, op->fd, op->role) != op->role) return false;
    if (op->number == SYS_dup2 && bound_identity(probe, op->target, 0) != 0) return false;
    return entry_record(probe, op);
}

static bool check_exit(
    struct probe *probe, const struct ptrace_syscall_info *info,
    const struct operation *op, int *alias
) {
    int64_t result = info->exit.rval;
    int error = info->exit.is_error ? (int)-result : 0;
    if (info->exit.is_error > 1 || (info->exit.is_error && (result >= 0 || result < -4095))
        || (!info->exit.is_error && result < 0))
        return refuse(probe, "syscall_error_encoding", 0);
    bool valid = false;
    if (op->number == SYS_dup) {
        valid = !error && result >= 3 && result <= 1024
            && result != probe->fd_a && result != probe->fd_b
            && bound_identity(probe, (int)result, 1) == 1;
        if (valid) *alias = (int)result;
    } else if (op->number == SYS_dup2) {
        valid = !error && result == op->target && bound_identity(probe, op->target, 2) == 2;
    } else if (op->role == 0) {
        valid = error == EBADF && result == -EBADF;
    } else {
        valid = !error && result == op->requested;
    }
    if (!valid) return refuse(probe, "unexpected_control_result", error);
    if (!emit_record(probe,
        "\"kind\":\"exit\",\"call_id\":%u,\"pid\":%d,\"call\":\"%s\","
        "\"result\":%" PRId64 ",\"error\":%d,\"result_descriptor_bound\":%s",
        probe->calls + 1, probe->child, op->name, result, error,
        op->number == SYS_dup || op->number == SYS_dup2 ? "true" : "false")) return false;
    probe->calls++;
    return true;
}

bool observe_control(struct probe *probe) {
    int status = 0;
    if (!wait_owned(probe, &status)) return false;
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP || (unsigned)status >> 16) {
        int error = WIFEXITED(status) && WEXITSTATUS(status) > 100 ? WEXITSTATUS(status) - 100 : 0;
        return refuse(probe, error ? "traceme_denied" : "initial_child_stop", error);
    }
    if (ptrace(PTRACE_SETOPTIONS, probe->child, 0, (void *)(uintptr_t)OPTIONS) != 0)
        return refuse(probe, "ptrace_options", errno);
    probe->pidfd = (int)syscall(SYS_pidfd_open, probe->child, 0);
    if (probe->pidfd < 0) return refuse(probe, "pidfd_open", errno);
    if (bound_identity(probe, probe->fd_a, 1) != 1 || bound_identity(probe, probe->fd_b, 2) != 2)
        return false;
    if (!emit_record(probe, "\"kind\":\"admitted\",\"options\":%lu,\"arch\":%u,"
        "\"both_initial_descriptors_bound\":true,\"duplicate_closed_before_resume\":true",
        (unsigned long)OPTIONS, AUDIT_ARCH_X86_64)) return false;

    bool pending = false, exit_entered = false, bootstrap_exit = false;
    int alias = -1;
    struct operation operation = {0};
    while (true) {
        if (ptrace(PTRACE_SYSCALL, probe->child, 0, 0) != 0)
            return refuse(probe, "ptrace_resume", errno);
        if (!wait_owned(probe, &status)) return false;
        if (!WIFSTOPPED(status)) return refuse(probe, "premature_child_retirement", 0);
        unsigned event = (unsigned)status >> 16;
        if (event == PTRACE_EVENT_EXIT) {
            unsigned long value = 0;
            if (!exit_entered || pending || probe->calls != 12
                || ptrace(PTRACE_GETEVENTMSG, probe->child, 0, &value) != 0 || value != 0)
                return refuse(probe, "exit_event_binding", errno);
            probe->exit_event = true;
            if (!emit_record(probe, "\"kind\":\"exit_event\",\"pid\":%d,\"status\":0", probe->child))
                return false;
            if (ptrace(PTRACE_CONT, probe->child, 0, 0) != 0 || !wait_owned(probe, &status))
                return refuse(probe, "final_child_wait", errno);
            return probe->child_reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (event || WSTOPSIG(status) != (SIGTRAP | 0x80))
            return refuse(probe, "unexpected_event_or_signal", 0);
        struct ptrace_syscall_info info;
        memset(&info, 0, sizeof(info));
        long size = ptrace(PTRACE_GET_SYSCALL_INFO, probe->child, sizeof(info), &info);
        if (size < 0) return refuse(probe, "syscall_info", errno);
        if (info.arch != AUDIT_ARCH_X86_64 || size > (long)sizeof(info))
            return refuse(probe, "syscall_info_arch_or_size", 0);
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            size_t required = offsetof(struct ptrace_syscall_info, entry.args) + sizeof(info.entry.args);
            if ((size_t)size < required || pending || exit_entered)
                return refuse(probe, "entry_pairing_or_size", 0);
            if (probe->calls == 12) {
                if (info.entry.nr != SYS_exit_group || info.entry.args[0] != 0)
                    return refuse(probe, "final_syscall", 0);
                exit_entered = true;
                if (!emit_record(probe, "\"kind\":\"exit_group_entry\",\"pid\":%d,\"code\":0", probe->child))
                    return false;
            } else {
                operation = expected_operation(probe, alias);
                if (!check_entry(probe, &info, &operation)) return false;
                pending = true;
            }
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
            size_t required = offsetof(struct ptrace_syscall_info, exit.is_error) + sizeof(info.exit.is_error);
            if ((size_t)size < required) return refuse(probe, "exit_info_size", 0);
            if (!pending) {
                /* Only the known SIGSTOP bootstrap can precede the first entry. */
                if (probe->calls || bootstrap_exit || exit_entered || info.exit.is_error || info.exit.rval)
                    return refuse(probe, "unpaired_exit", 0);
                bootstrap_exit = true;
                if (!emit_record(probe, "\"kind\":\"bootstrap_exit\",\"result\":0,\"error\":0"))
                    return false;
            } else {
                if (!check_exit(probe, &info, &operation, &alias)) return false;
                pending = false;
            }
        } else {
            return refuse(probe, "unknown_syscall_stop", 0);
        }
    }
}
