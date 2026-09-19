/* New observation only. All included resolver/callback/poll code stays verbatim. */
#define _DARWIN_C_SOURCE 1
#include <dns_sd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>

static int endpoint_sockfd(DNSServiceRef reference);
static unsigned endpoint_context, endpoint_count;
static int endpoint_loader_flags;
#ifdef HOL_GUARD_PHASE_LIBRARY
static int endpoint_configured;
#else
static int endpoint_configured = 1;
#endif

int hol_guard_endpoint_configure(unsigned context, int flags) {
#ifdef HOL_GUARD_PHASE_LIBRARY
    if (endpoint_configured || (context != 1 && context != 2) || flags != (RTLD_NOW | RTLD_LOCAL)) return 64;
    endpoint_context = context;
    endpoint_loader_flags = flags;
    endpoint_configured = 1;
    return 0;
#else
    (void)context;
    (void)flags;
    return 64;
#endif
}

#define DNSServiceRefSockFD endpoint_sockfd
#include "native_macos_dnssd_phase_probe.c"
#undef DNSServiceRefSockFD
#include "native_macos_dnssd_sigpipe_control.h"

static void address_record(int descriptor, int peer) {
    struct sockaddr_storage address = {0};
    socklen_t length = sizeof(address);
    int rc = peer ? getpeername(descriptor, (struct sockaddr *)&address, &length)
                  : getsockname(descriptor, (struct sockaddr *)&address, &length);
    int error = rc ? errno : 0;
    unsigned captured = rc ? 0U : (length < sizeof(address) ? length : (unsigned)sizeof(address));
    printf("{\"rc\":%d,\"errno\":%d,\"length\":%u,\"captured\":%u,\"hex\":\"",
           rc, error, (unsigned)length, captured);
    const unsigned char *bytes = (const unsigned char *)&address;
    for (unsigned index = 0; index < captured; index++) printf("%02x", bytes[index]);
    printf("\"}");
}

static void stat_record(const struct stat *value, int rc, int error) {
    printf("{\"rc\":%d,\"errno\":%d,\"dev\":\"%" PRIu64 "\",\"ino\":\"%" PRIu64
           "\",\"mode\":%" PRIu32 "}",
           rc, error, rc ? UINT64_C(0) : (uint64_t)value->st_dev,
           rc ? UINT64_C(0) : (uint64_t)value->st_ino, rc ? 0U : (uint32_t)value->st_mode);
}

static int endpoint_sockfd(DNSServiceRef reference) {
    int descriptor = DNSServiceRefSockFD(reference);
    int result_errno = errno;
    if (endpoint_count++) {
        if (endpoint_count == 2) {
            printf("{\"kind\":\"endpoint_overflow\"}\n");
            fflush(stdout);
        }
        errno = result_errno;
        return descriptor;
    }
    struct stat before = {0}, after = {0};
    int before_rc = fstat(descriptor, &before), before_errno = before_rc ? errno : 0;
    int fd_flags = fcntl(descriptor, F_GETFD), fd_errno = fd_flags < 0 ? errno : 0;
    int status_flags = fcntl(descriptor, F_GETFL), status_errno = status_flags < 0 ? errno : 0;
    int socket_type = 0;
    socklen_t type_length = sizeof(socket_type);
    int type_rc = getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socket_type, &type_length);
    int type_errno = type_rc ? errno : 0;
    uint64_t thread_id = 0;
    int thread_rc = pthread_threadid_np(NULL, &thread_id);
    sigset_t signals;
    sigemptyset(&signals);
    int mask_rc = pthread_sigmask(SIG_SETMASK, NULL, &signals);
    uint64_t blocked = 0;
    if (!mask_rc) {
        for (int number = 1; number < NSIG && number <= 64; number++) {
            if (sigismember(&signals, number) == 1) blocked |= UINT64_C(1) << (number - 1);
        }
    }
    struct sigaction pipe_action = {0};
    int pipe_rc = sigaction(SIGPIPE, NULL, &pipe_action), pipe_errno = pipe_rc ? errno : 0;
    int pipe_kind = pipe_rc ? -1 : pipe_action.sa_handler == SIG_DFL ? 0 : pipe_action.sa_handler == SIG_IGN ? 1 : 2;
    char main_uuid[33] = {0}, observer_uuid[33] = {0}, query_uuid[33] = {0};
    char descriptor_uuid[33] = {0}, process_uuid[33] = {0}, poll_uuid[33] = {0};
    const struct mach_header *main_image = _dyld_get_image_header(0);
    bool images_ok = main_image && image_uuid(main_image, main_uuid);
    images_ok = image_uuid((const void *)(uintptr_t)&hol_guard_endpoint_configure, observer_uuid) && images_ok;
    images_ok = image_uuid((const void *)(uintptr_t)&DNSServiceQueryRecord, query_uuid) && images_ok;
    images_ok = image_uuid((const void *)(uintptr_t)&DNSServiceRefSockFD, descriptor_uuid) && images_ok;
    images_ok = image_uuid((const void *)(uintptr_t)&DNSServiceProcessResult, process_uuid) && images_ok;
    images_ok = image_uuid((const void *)(uintptr_t)&poll, poll_uuid) && images_ok;
    printf("{\"kind\":\"endpoint_context\",\"sequence\":1,\"context\":%u,\"configured\":%s,"
           "\"loader_flags\":%d,\"fd\":%d,\"pid\":%ld,\"ppid\":%ld,"
           "\"uid\":%lu,\"euid\":%lu,\"gid\":%lu,\"egid\":%lu,\"main_thread\":%d,"
           "\"thread_rc\":%d,\"thread_id\":\"%" PRIu64 "\",\"mask_rc\":%d,"
           "\"blocked_signals\":\"%" PRIu64 "\",\"pipe_rc\":%d,\"pipe_errno\":%d,\"pipe_kind\":%d,"
           "\"images_ok\":%s,\"images\":{\"main\":\"%s\",\"observer\":\"%s\",\"query\":\"%s\","
           "\"descriptor\":\"%s\",\"process\":\"%s\",\"poll\":\"%s\"},",
           endpoint_context, endpoint_configured ? "true" : "false", endpoint_loader_flags, descriptor,
           (long)getpid(), (long)getppid(), (unsigned long)getuid(), (unsigned long)geteuid(),
           (unsigned long)getgid(), (unsigned long)getegid(), pthread_main_np(), thread_rc, thread_id,
           mask_rc, blocked, pipe_rc, pipe_errno, pipe_kind, images_ok ? "true" : "false",
           main_uuid, observer_uuid, query_uuid, descriptor_uuid, process_uuid, poll_uuid);
    printf("\"stat_before\":");
    stat_record(&before, before_rc, before_errno);
    printf(",\"fd_flags\":{\"rc\":%d,\"errno\":%d},\"status_flags\":{\"rc\":%d,\"errno\":%d},"
           "\"socket_type\":{\"rc\":%d,\"errno\":%d,\"length\":%u,\"value\":%d},\"local\":",
           fd_flags, fd_errno, status_flags, status_errno, type_rc, type_errno, (unsigned)type_length, socket_type);
    address_record(descriptor, 0);
    printf(",\"peer\":");
    address_record(descriptor, 1);
    int after_rc = fstat(descriptor, &after), after_errno = after_rc ? errno : 0;
    printf(",\"stat_after\":");
    stat_record(&after, after_rc, after_errno);
    printf("}\n");
    fflush(stdout);
    signal_query_record(descriptor);
    /* Neither observations nor output may change the original getter's errno/result. */
    errno = result_errno;
    return descriptor;
}
