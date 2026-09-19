/* Query-time SIGPIPE control shared by the two owned main-thread hosts. */
#ifndef HOL_GUARD_SIGPIPE_CONTROL_H
#define HOL_GUARD_SIGPIPE_CONTROL_H
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

_Static_assert(NSIG > 1 && NSIG <= 65, "The complete signal mask must fit the bounded record");

struct signal_snapshot {
    struct sigaction action;
    uint64_t action_mask, blocked_mask;
    int action_rc, action_errno, action_bits_rc, blocked_bits_rc, mask_rc, main_thread;
};
static struct signal_snapshot signal_before;
static unsigned signal_requested, signal_sequence, signal_query_seen;
static int signal_active, signal_used, signal_leave_used;

static int signal_emit(const char *format, ...) {
    char data[1024];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(data, sizeof(data), format, arguments);
    va_end(arguments);
    if (length <= 0 || (unsigned)length >= sizeof(data)) return 3;
    return write(STDOUT_FILENO, data, (size_t)length) == length ? 0 : 3;
}

static int signal_bits(const sigset_t *set, uint64_t *bits) {
    *bits = 0;
    for (int number = 1; number < NSIG; number++) {
        int member = sigismember(set, number);
        if (member < 0) return -1;
        if (member) *bits |= UINT64_C(1) << (number - 1);
    }
    return 0;
}

static struct signal_snapshot signal_observe(void) {
    struct signal_snapshot value = {0};
    sigset_t blocked;
    sigemptyset(&blocked);
    value.main_thread = pthread_main_np();
    value.action_rc = sigaction(SIGPIPE, NULL, &value.action);
    value.action_errno = value.action_rc ? errno : 0;
    value.action_bits_rc = value.action_rc ? -1 : signal_bits(&value.action.sa_mask, &value.action_mask);
    value.mask_rc = pthread_sigmask(SIG_SETMASK, NULL, &blocked);
    value.blocked_bits_rc = value.mask_rc ? -1 : signal_bits(&blocked, &value.blocked_mask);
    return value;
}

static int signal_kind(const struct signal_snapshot *value) {
    return value->action_rc ? -1 : value->action.sa_handler == SIG_DFL ? 0 :
           value->action.sa_handler == SIG_IGN ? 1 : 2;
}

static int signal_valid(const struct signal_snapshot *value) {
    return value->main_thread == 1 && value->action_rc == 0 && value->action_errno == 0 &&
           value->action_bits_rc == 0 && value->mask_rc == 0 && value->blocked_bits_rc == 0;
}

static int signal_matches(const struct signal_snapshot *value, int kind) {
    return signal_valid(value) && signal_kind(value) == kind &&
           value->action.sa_flags == signal_before.action.sa_flags &&
           value->action_mask == signal_before.action_mask &&
           value->blocked_mask == signal_before.blocked_mask;
}

static int signal_record(const char *stage, const struct signal_snapshot *value,
                         int set_called, int set_rc, int set_errno) {
    return signal_emit(
        "{\"kind\":\"sigpipe_condition\",\"sequence\":%u,\"stage\":\"%s\","
        "\"requested\":%u,\"pid\":%ld,\"main_thread\":%d,\"active\":%s,"
        "\"action_rc\":%d,\"action_errno\":%d,\"handler_kind\":%d,\"flags\":%d,"
        "\"action_mask\":\"%" PRIu64 "\",\"action_mask_rc\":%d,"
        "\"blocked_mask\":\"%" PRIu64 "\",\"blocked_mask_rc\":%d,\"mask_rc\":%d,"
        "\"set_called\":%s,\"set_rc\":%d,\"set_errno\":%d}\n",
        ++signal_sequence, stage, signal_requested, (long)getpid(), value->main_thread,
        signal_active ? "true" : "false", value->action_rc, value->action_errno,
        signal_kind(value), value->action_rc ? 0 : value->action.sa_flags,
        value->action_mask, value->action_bits_rc, value->blocked_mask,
        value->blocked_bits_rc, value->mask_rc, set_called ? "true" : "false", set_rc, set_errno
    );
}

int hol_guard_sigpipe_enter(unsigned requested) {
    int saved_errno = errno;
    if (requested > 1 || signal_used || !endpoint_configured ||
        (endpoint_context != 1 && endpoint_context != 2) || pthread_main_np() != 1) {
        errno = saved_errno;
        return 64;
    }
    signal_used = 1;
    signal_requested = requested;
    signal_before = signal_observe();
    if (signal_record("before", &signal_before, 0, 0, 0) ||
        !signal_valid(&signal_before) || signal_kind(&signal_before) > 1) {
        errno = saved_errno;
        return 3;
    }
    struct sigaction desired = signal_before.action;
    desired.sa_handler = requested ? SIG_IGN : SIG_DFL;
    int set_rc = sigaction(SIGPIPE, &desired, NULL), set_errno = set_rc ? errno : 0;
    signal_active = set_rc == 0;
    struct signal_snapshot installed = signal_observe();
    int output_rc = signal_record("installed", &installed, 1, set_rc, set_errno);
    int result = set_rc || output_rc || !signal_matches(&installed, (int)requested) ? 3 : 0;
    errno = saved_errno;
    return result;
}

static void signal_query_record(int descriptor) {
    int saved_errno = errno;
    if (signal_query_seen++) {
        if (signal_query_seen == 2) (void)signal_emit("{\"kind\":\"sigpipe_overflow\"}\n");
        errno = saved_errno;
        return;
    }
    struct signal_snapshot current = signal_observe();
    (void)signal_record("query", &current, 0, 0, 0);
    int value = 0;
    socklen_t length = sizeof(value);
    int rc = getsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &value, &length);
    int error = rc ? errno : 0;
    (void)signal_emit(
        "{\"kind\":\"sigpipe_socket\",\"sequence\":1,\"pid\":%ld,\"fd\":%d,"
        "\"rc\":%d,\"errno\":%d,\"length\":%u,\"integer_bytes\":%u,\"value\":%d}\n",
        (long)getpid(), descriptor, rc, error, (unsigned)length, (unsigned)sizeof(value), value
    );
    errno = saved_errno;
}

int hol_guard_sigpipe_leave(void) {
    int saved_errno = errno;
    if (!signal_active) {
        errno = saved_errno;
        return 0;
    }
    if (pthread_main_np() != 1 || signal_leave_used) {
        errno = saved_errno;
        return 64;
    }
    signal_leave_used = 1;
    struct signal_snapshot after = signal_observe();
    int output_after = signal_record("after", &after, 0, 0, 0);
    int set_rc = sigaction(SIGPIPE, &signal_before.action, NULL), set_errno = set_rc ? errno : 0;
    signal_active = set_rc != 0;
    struct signal_snapshot restored = signal_observe();
    int output_restored = signal_record("restored", &restored, 1, set_rc, set_errno);
    int result = set_rc || output_after || output_restored ||
                 !signal_matches(&after, (int)signal_requested) ||
                 !signal_matches(&restored, signal_kind(&signal_before)) ? 3 : 0;
    errno = saved_errno;
    return result;
}
#endif
