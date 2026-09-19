/* Observe only the existing query's call boundaries; preserve its implementation. */
#define _DARWIN_C_SOURCE 1
#include <dns_sd.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

#define TRACE_LIMIT 32
static unsigned trace_sequence;

static int trace_next(void) {
    if (trace_sequence > TRACE_LIMIT) return 0;
    trace_sequence++;
    if (trace_sequence > TRACE_LIMIT) {
        printf("{\"kind\":\"call_trace_overflow\",\"sequence\":%u}\n", trace_sequence);
        fflush(stdout);
        return 0;
    }
    return 1;
}

static int observe_poll(struct pollfd *fds, nfds_t count, int timeout) {
    int entry_errno = errno;
    if (trace_next()) {
        printf("{\"kind\":\"call_trace\",\"sequence\":%u,\"call\":\"poll\",\"phase\":\"enter\","
               "\"fd\":%d,\"events\":%d,\"nfds\":%lu,\"timeout\":%d}\n",
               trace_sequence, fds[0].fd, (int)fds[0].events, (unsigned long)count, timeout);
        fflush(stdout);
    }
    errno = entry_errno;
    int result = poll(fds, count, timeout);
    int result_errno = errno;
    if (trace_next()) {
        printf("{\"kind\":\"call_trace\",\"sequence\":%u,\"call\":\"poll\",\"phase\":\"return\","
               "\"result\":%d,\"errno\":%d,\"revents\":%d}\n",
               trace_sequence, result, result_errno, (int)fds[0].revents);
        fflush(stdout);
    }
    errno = result_errno;
    return result;
}

static DNSServiceErrorType observe_process(DNSServiceRef reference) {
    int entry_errno = errno;
    if (trace_next()) {
        printf("{\"kind\":\"call_trace\",\"sequence\":%u,"
               "\"call\":\"DNSServiceProcessResult\",\"phase\":\"enter\"}\n", trace_sequence);
        fflush(stdout);
    }
    errno = entry_errno;
    DNSServiceErrorType result = DNSServiceProcessResult(reference);
    int result_errno = errno;
    if (trace_next()) {
        printf("{\"kind\":\"call_trace\",\"sequence\":%u,\"call\":\"DNSServiceProcessResult\","
               "\"phase\":\"return\",\"result\":%d,\"errno\":%d}\n",
               trace_sequence, (int)result, result_errno);
        fflush(stdout);
    }
    errno = result_errno;
    return result;
}

#define poll observe_poll
#define DNSServiceProcessResult observe_process
#include "native_macos_dnssd_python_bridge.c"
#undef DNSServiceProcessResult
#undef poll

#ifndef HOL_GUARD_PHASE_LIBRARY
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "dns_simple") && strcmp(argv[1], "dns_shared"))) return 64;
    return hol_guard_original_resolver_main(argc, argv);
}
#endif
