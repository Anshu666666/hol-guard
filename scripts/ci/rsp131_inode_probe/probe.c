/* Bounded owned-child ptrace/pidfd_getfd feasibility, never qualification. */
#define _GNU_SOURCE
#include "probe.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "This first feasibility control admits Linux x86_64 only."
#endif

int64_t clock_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

bool refuse(struct probe *probe, const char *reason, int error) {
    if (probe->failure == NULL) {
        probe->failure = reason;
        probe->failure_errno = error;
    }
    return false;
}

bool emit_record(struct probe *probe, const char *format, ...) {
    char body[1536], line[1664];
    if (probe->output_lost || probe->sequence >= RSP131_MAX_RECORDS) {
        probe->output_lost = true;
        return refuse(probe, "record_limit", 0);
    }
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(body, sizeof(body), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(body)) {
        probe->output_lost = true;
        return refuse(probe, "record_size", 0);
    }
    unsigned sequence = ++probe->sequence;
    int size = snprintf(line, sizeof(line), "{\"sequence\":%u,%s}\n", sequence, body);
    if (size <= 0 || (size_t)size >= sizeof(line)) {
        probe->output_lost = true;
        return refuse(probe, "record_size", 0);
    }
    /* Nonblocking atomic pipe write: an incomplete record invalidates capture. */
    ssize_t written = write(STDOUT_FILENO, line, (size_t)size);
    if (written != size) {
        probe->output_lost = true;
        return refuse(probe, "output_write", written < 0 ? errno : 0);
    }
    return true;
}

bool wait_owned(struct probe *probe, int *status) {
    while (true) {
        pid_t result = waitpid(probe->child, status, WNOHANG | __WALL);
        if (result == probe->child) {
            if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
                probe->child_reaped = true;
                probe->child_status = *status;
            }
            return true;
        }
        if (result < 0 && errno != EINTR) return refuse(probe, "waitpid", errno);
        int64_t now = clock_ns();
        if (now < 0 || now >= probe->deadline_ns) return refuse(probe, "deadline", 0);
        const struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
}

bool retire_owned(struct probe *probe) {
    if (probe->child <= 0 || probe->child_reaped) return true;
    /* The fork child PID remains reserved because it has not been reaped. */
    if (kill(probe->child, SIGKILL) != 0 && errno != ESRCH)
        return refuse(probe, "child_kill", errno);
    int64_t now = clock_ns();
    if (now < 0) return refuse(probe, "cleanup_clock", errno);
    probe->deadline_ns = now + INT64_C(500000000);
    while (!probe->child_reaped) {
        int status = 0;
        if (!wait_owned(probe, &status)) return false;
        if (WIFSTOPPED(status)) {
            /* SIGKILL is already pending; no register or syscall mutation. */
            if (ptrace(PTRACE_CONT, probe->child, 0, 0) != 0 && errno != ESRCH)
                return refuse(probe, "cleanup_continue", errno);
        }
    }
    return true;
}

static bool regular_identity(int descriptor, struct stat *value) {
    return fstat(descriptor, value) == 0 && S_ISREG(value->st_mode)
        && value->st_uid == getuid() && (value->st_mode & 0777) == 0600
        && value->st_size == 0;
}

static bool readback_one(
    int directory, const char *name, const struct stat *expected,
    const unsigned char *payload, size_t length
) {
    int descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0) return false;
    struct stat actual;
    unsigned char data[32];
    bool bound = fstat(descriptor, &actual) == 0 && S_ISREG(actual.st_mode)
        && actual.st_dev == expected->st_dev && actual.st_ino == expected->st_ino;
    ssize_t count = bound ? read(descriptor, data, sizeof(data)) : -1;
    bool closed = close(descriptor) == 0;
    return bound && closed && count == (ssize_t)length && memcmp(data, payload, length) == 0;
}

static bool fixed_readback(int directory, struct probe *probe) {
    const unsigned char expected_a[] = "owned-a-1again";
    const unsigned char expected_b[] = "\0\0\0\0\0\0\0owned-b-two";
    return readback_one(directory, "owned-a", &probe->identity_a, expected_a, sizeof(expected_a) - 1)
        && readback_one(directory, "owned-b", &probe->identity_b, expected_b, sizeof(expected_b) - 1);
}

int main(int argc, char **argv) {
    struct probe probe = {.pidfd = -1, .fd_a = -1, .fd_b = -1};
    int directory = -1;
    bool created_a = false, created_b = false;
    bool cleaned = false, observed = false, readback = false;
    struct stat root;
    int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) != 0) return 2;
    if (argc != 2 || getuid() == 0 || geteuid() != getuid()) {
        refuse(&probe, "unprivileged_arguments", 0);
        goto finish;
    }
    directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || fstat(directory, &root) != 0 || root.st_uid != getuid()
        || (root.st_mode & 0777) != 0700) {
        refuse(&probe, "private_directory", errno);
        goto finish;
    }
    probe.fd_a = openat(directory, "owned-a", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (probe.fd_a < 0) {
        refuse(&probe, "create_a", errno);
        goto finish;
    }
    created_a = true;
    probe.fd_b = openat(directory, "owned-b", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (probe.fd_b < 0) {
        refuse(&probe, "create_b", errno);
        goto finish;
    }
    created_b = true;
    if (!regular_identity(probe.fd_a, &probe.identity_a)
        || !regular_identity(probe.fd_b, &probe.identity_b)
        || (probe.identity_a.st_dev == probe.identity_b.st_dev
            && probe.identity_a.st_ino == probe.identity_b.st_ino)) {
        refuse(&probe, "fixture_identity", errno);
        goto finish;
    }
    int64_t started = clock_ns();
    if (started < 0) {
        refuse(&probe, "clock", errno);
        goto finish;
    }
    probe.deadline_ns = started + (int64_t)RSP131_SECONDS * INT64_C(1000000000);
    probe.child = fork();
    if (probe.child == 0) child_control(probe.fd_a, probe.fd_b, directory);
    if (probe.child < 0) {
        refuse(&probe, "fork", errno);
        goto finish;
    }
    /* The parent retains inode metadata, not either file description. */
    int close_a = close(probe.fd_a);
    int close_b = close(probe.fd_b);
    if (close_a != 0 || close_b != 0) {
        refuse(&probe, "parent_fixture_close", errno);
        goto finish;
    }
    if (!emit_record(&probe,
        "\"kind\":\"begin\",\"schema\":%d,\"pid\":%d,\"parent_pid\":%d,"
        "\"fd_a\":%d,\"fd_b\":%d,\"a_dev\":%" PRIuMAX ",\"a_ino\":%" PRIuMAX ","
        "\"b_dev\":%" PRIuMAX ",\"b_ino\":%" PRIuMAX ",\"single_thread_control\":true",
        RSP131_SCHEMA, probe.child, getpid(), probe.fd_a, probe.fd_b,
        (uintmax_t)probe.identity_a.st_dev, (uintmax_t)probe.identity_a.st_ino,
        (uintmax_t)probe.identity_b.st_dev, (uintmax_t)probe.identity_b.st_ino)) goto finish;
    observed = observe_control(&probe);
finish:
    if (probe.child > 0) {
        if (!retire_owned(&probe)) observed = false;
    } else {
        if (probe.fd_a >= 0) close(probe.fd_a);
        if (probe.fd_b >= 0) close(probe.fd_b);
    }
    if (observed && probe.child_reaped && directory >= 0) {
        /* Corroboration only; counters never come from a retrospective stat. */
        readback = fixed_readback(directory, &probe);
        if (!readback) refuse(&probe, "fixed_control_readback", 0);
    }
    if (probe.pidfd >= 0 && close(probe.pidfd) != 0)
        refuse(&probe, "pidfd_close", errno);
    if (directory >= 0 && (probe.child <= 0 || probe.child_reaped)) {
        bool a = !created_a || unlinkat(directory, "owned-a", 0) == 0;
        bool b = !created_b || unlinkat(directory, "owned-b", 0) == 0;
        cleaned = a && b;
        if (!cleaned) refuse(&probe, "owned_file_cleanup", errno);
    }
    if (directory >= 0 && close(directory) != 0)
        refuse(&probe, "directory_close", errno);
    bool feasible = observed && probe.failure == NULL && probe.child_reaped
        && WIFEXITED(probe.child_status) && WEXITSTATUS(probe.child_status) == 0
        && !probe.output_lost && cleaned && readback;
    const char *failure = probe.failure == NULL ? "none" : probe.failure;
    emit_record(&probe,
        "\"kind\":\"terminal\",\"feasible\":%s,\"failure\":\"%s\",\"failure_errno\":%d,"
        "\"child_reaped\":%s,\"child_exit_code\":%d,\"child_signal\":%d,\"calls\":%u,"
        "\"exit_event\":%s,\"output_lost\":%s,\"owned_files_removed\":%s,"
        "\"fixed_control_readback_matches\":%s,"
        "\"installed_workload\":false,\"rsp131_qualified\":false,"
        "\"sqlite_ingestion_observed\":false,\"physical_device_bytes_measured\":false",
        feasible ? "true" : "false", failure, probe.failure_errno,
        probe.child_reaped ? "true" : "false",
        probe.child_reaped && WIFEXITED(probe.child_status) ? WEXITSTATUS(probe.child_status) : -1,
        probe.child_reaped && WIFSIGNALED(probe.child_status) ? WTERMSIG(probe.child_status) : 0,
        probe.calls, probe.exit_event ? "true" : "false",
        probe.output_lost ? "true" : "false", cleaned ? "true" : "false", readback ? "true" : "false");
    return feasible && !probe.output_lost ? 0 : 1;
}
