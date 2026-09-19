/* Private single-thread feasibility controls; no installed SQLite workload. */
#ifndef HOL_GUARD_RSP131_INODE_PROBE_H
#define HOL_GUARD_RSP131_INODE_PROBE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#define RSP131_MAX_RECORDS 64
#define RSP131_SECONDS 6
#define RSP131_SCHEMA 1

struct probe {
    pid_t child;
    int pidfd;
    int fd_a;
    int fd_b;
    struct stat identity_a;
    struct stat identity_b;
    unsigned sequence;
    unsigned calls;
    bool output_lost;
    bool child_reaped;
    bool exit_event;
    int child_status;
    const char *failure;
    int failure_errno;
    int64_t deadline_ns;
};

int64_t clock_ns(void);
bool emit_record(struct probe *probe, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
bool refuse(struct probe *probe, const char *reason, int error);
bool wait_owned(struct probe *probe, int *status);
bool retire_owned(struct probe *probe);
_Noreturn void child_control(int fd_a, int fd_b, int directory);
bool observe_control(struct probe *probe);

#endif
