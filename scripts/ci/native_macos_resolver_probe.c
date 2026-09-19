/* Read-only, no-fork loopback resolver controls, externally bounded to 5 s.
 * Design evidence only, not a match to the installed Libinfo binary:
 * apple-oss-distributions/Libinfo@39b70c515baee5b609e7e91693edbd934b6845a1
 * lookup.subproj/mdns_module.c: mdns_hostbyaddr and _mdns_query_start.
 */
#define _DARWIN_C_SOURCE 1
#include <arpa/inet.h>
#include <dns_sd.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define QUESTION "1.0.0.127.in-addr.arpa."
#define CALLBACK_LIMIT 16

struct observations {
    unsigned count;
    bool done;
    bool overflow;
    bool loopback;
    int32_t error;
};

static bool image_uuid(const void *symbol, char output[33]) {
    Dl_info image;
    if (!dladdr(symbol, &image) || !image.dli_fbase) return false;
    const struct mach_header_64 *header = image.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->ncmds > 1024 || header->sizeofcmds > 1024 * 1024) return false;
    const unsigned char *cursor = (const unsigned char *)(header + 1);
    const unsigned char *end = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) return false;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor)) return false;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize < sizeof(struct uuid_command)) return false;
            const struct uuid_command *uuid = (const struct uuid_command *)command;
            for (unsigned byte = 0; byte < 16; byte++) snprintf(output + 2 * byte, 3, "%02x", uuid->uuid[byte]);
            return true;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static bool local_name(const char *value) {
    return value && (!strcasecmp(value, "localhost") || !strcasecmp(value, "localhost.") ||
                     !strcasecmp(value, "127.0.0.1") ||
                     !strcasecmp(value, "hol-guard-qualification.localhost") ||
                     !strcasecmp(value, "hol-guard-qualification.localhost."));
}

static bool local_ptr(const void *data, uint16_t length) {
    static const unsigned char localhost[] = {9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0};
    /* Only the expected fixed wire value is classified; no RDATA is printed. */
    return data && length == sizeof(localhost) && !memcmp(data, localhost, sizeof(localhost));
}

static void DNSSD_API callback(DNSServiceRef reference, DNSServiceFlags flags, uint32_t interface_index,
                              DNSServiceErrorType error, const char *name, uint16_t type, uint16_t dns_class,
                              uint16_t length, const void *data, uint32_t ttl, void *context) {
    (void)reference;
    (void)ttl;
    struct observations *state = context;
    if (state->count == CALLBACK_LIMIT) {
        state->overflow = true;
        state->done = true;
        return;
    }
    /* DNS-SD documents the other callback arguments as undefined on error. */
    if (error) { flags = 0; interface_index = 0; type = 0; dns_class = 0; length = 0; }
    bool question_matches = !error && name && !strcasecmp(name, QUESTION);
    bool loopback = error == 0 && (flags & kDNSServiceFlagsAdd) && question_matches &&
                    type == kDNSServiceType_PTR && dns_class == kDNSServiceClass_IN && local_ptr(data, length);
    state->count++;
    state->loopback |= loopback;
    if (error) state->error = error;
    printf("{\"kind\":\"callback\",\"sequence\":%u,\"flags\":%" PRIu32
           ",\"interface_index\":%" PRIu32 ",\"error\":%" PRId32
           ",\"type\":%u,\"class\":%u,\"data_bytes\":%u,\"question_matches\":%s,\"loopback_label\":%s}\n",
           state->count, flags, interface_index, error, (unsigned)type, (unsigned)dns_class, (unsigned)length,
           question_matches ? "true" : "false", loopback ? "true" : "false");
    /* Observe the finite currently available batch, not a sustained query. */
    if (error || !(flags & kDNSServiceFlagsMoreComing)) state->done = true;
}

static int dns_query(bool shared) {
    DNSServiceRef connection = NULL, query = NULL;
    DNSServiceFlags flags = 0;
    DNSServiceErrorType error = kDNSServiceErr_NoError;
    struct observations state = {0};
    if (shared) {
        error = DNSServiceCreateConnection(&connection);
        flags = kDNSServiceFlagsShareConnection | kDNSServiceFlagsReturnIntermediates | kDNSServiceFlagsTimeout;
        query = connection;
    }
    if (!error) error = DNSServiceQueryRecord(&query, flags, 0, QUESTION, kDNSServiceType_PTR,
                                            kDNSServiceClass_IN, callback, &state);
    printf("{\"kind\":\"query\",\"shared\":%s,\"requested_flags\":%" PRIu32 ",\"error\":%" PRId32 "}\n",
           shared ? "true" : "false", flags, error);
    DNSServiceRef event_source = shared ? connection : query;
    if (!error) {
        int descriptor = DNSServiceRefSockFD(event_source);
        if (descriptor < 0) error = kDNSServiceErr_BadReference;
        while (!error && !state.done) {
            struct pollfd descriptor_event = {.fd = descriptor, .events = POLLIN, .revents = 0};
            int ready = poll(&descriptor_event, 1, -1);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || !(descriptor_event.revents & POLLIN)) {
                error = kDNSServiceErr_Unknown;
                break;
            }
            error = DNSServiceProcessResult(event_source);
        }
    }
    if (shared && query && query != connection) DNSServiceRefDeallocate(query);
    if (event_source) DNSServiceRefDeallocate(event_source);
    printf("{\"kind\":\"result\",\"error\":%" PRId32
           ",\"callback_error\":%" PRId32 ",\"callbacks\":%u,\"overflow\":%s,\"loopback_label\":%s}\n",
           error, state.error, state.count, state.overflow ? "true" : "false", state.loopback ? "true" : "false");
    return error || state.error || state.overflow ? 2 : 0;
}

static int libc_query(bool nameinfo) {
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) return 3;
    int error;
    bool loopback;
    if (nameinfo) {
        char hostname[NI_MAXHOST];
        error = getnameinfo((const struct sockaddr *)&address, sizeof(address), hostname, sizeof(hostname),
                            NULL, 0, NI_NAMEREQD | NI_NUMERICSERV);
        loopback = !error && local_name(hostname);
    } else {
        struct hostent *host = gethostbyaddr(&address.sin_addr, sizeof(address.sin_addr), AF_INET);
        error = host ? 0 : h_errno;
        loopback = host && local_name(host->h_name);
    }
    printf("{\"kind\":\"result\",\"error\":%d,\"loopback_label\":%s}\n", error, loopback ? "true" : "false");
    return error ? 2 : 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "dns_simple") && strcmp(argv[1], "dns_shared") &&
                      strcmp(argv[1], "libc_addr") && strcmp(argv[1], "libc_name"))) return 64;
    setvbuf(stdout, NULL, _IONBF, 0);
    char libinfo[33], dnssd[33];
    if (!image_uuid((const void *)(uintptr_t)&gethostbyaddr, libinfo) ||
        !image_uuid((const void *)(uintptr_t)&DNSServiceQueryRecord, dnssd)) return 3;
    const struct mach_header *self = _dyld_get_image_header(0);
    if (!self) return 3;
    printf("{\"kind\":\"identity\",\"mode\":\"%s\",\"pid\":%ld,\"libinfo_uuid\":\"%s\","
           "\"dnssd_uuid\":\"%s\",\"cpu_type\":%d,\"cpu_subtype\":%d}\n",
           argv[1], (long)getpid(), libinfo, dnssd, self->cputype, self->cpusubtype);
    if (!strcmp(argv[1], "dns_simple")) return dns_query(false);
    if (!strcmp(argv[1], "dns_shared")) return dns_query(true);
    return libc_query(!strcmp(argv[1], "libc_name"));
}
