/* Load the same held observer image as Python and make the same unsigned C call. */
#define _DARWIN_C_SOURCE 1
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*configure_fn)(unsigned, int);
typedef int (*query_fn)(unsigned);
typedef int (*identity_fn)(char *, char *, char *, unsigned);

static int emit(const char *format, ...) {
    char data[1024];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(data, sizeof(data), format, arguments);
    va_end(arguments);
    if (length <= 0 || (unsigned)length >= sizeof(data)) return 3;
    return write(STDOUT_FILENO, data, (size_t)length) == length ? 0 : 3;
}

static int failure(const char *stage, void *handle) {
    (void)emit("{\"kind\":\"native_host_failure\",\"stage\":\"%s\"}\n", stage);
    if (handle) dlclose(handle);
    return 3;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[2], "dns_simple") && strcmp(argv[2], "dns_shared"))) return 64;
    int flags = RTLD_NOW | RTLD_LOCAL;
    /* Use the descriptor, not stdout's FILE, before the unchanged main sets buffering. */
    if (emit("{\"kind\":\"native_host\",\"phase\":\"load_enter\",\"pid\":%ld,\"mode\":\"%s\","
             "\"loader_flags\":%d}\n", (long)getpid(), argv[2], flags)) return 3;
    void *handle = dlopen(argv[1], flags);
    if (!handle) return failure("load", NULL);
    configure_fn configure = (configure_fn)dlsym(handle, "hol_guard_endpoint_configure");
    query_fn query = (query_fn)dlsym(handle, "hol_guard_dnssd_python_call");
    identity_fn identity = (identity_fn)dlsym(handle, "hol_guard_resolver_bridge_identity");
    if (!configure || !query || !identity) return failure("symbol", handle);
    if (configure(1, flags)) return failure("configure", handle);
    char bridge[33] = {0}, libinfo[33] = {0}, dnssd[33] = {0};
    if (identity(bridge, libinfo, dnssd, 33)) return failure("identity_before", handle);
    if (emit("{\"kind\":\"native_host\",\"phase\":\"call_enter\",\"bridge_uuid\":\"%s\","
             "\"libinfo_uuid\":\"%s\",\"dnssd_uuid\":\"%s\"}\n", bridge, libinfo, dnssd))
        return failure("output_before", handle);
    int code = query((unsigned)!strcmp(argv[2], "dns_shared"));
    char bridge_after[33] = {0}, libinfo_after[33] = {0}, dnssd_after[33] = {0};
    if (identity(bridge_after, libinfo_after, dnssd_after, 33) ||
        strcmp(bridge, bridge_after) || strcmp(libinfo, libinfo_after) || strcmp(dnssd, dnssd_after))
        return failure("identity_after", handle);
    if (emit("{\"kind\":\"native_host\",\"phase\":\"complete\",\"return_code\":%d,"
             "\"bridge_uuid\":\"%s\",\"libinfo_uuid\":\"%s\",\"dnssd_uuid\":\"%s\"}\n",
             code, bridge_after, libinfo_after, dnssd_after)) return failure("output_after", handle);
    /* Keep the exact dlopen handle alive through query return and final image observation. */
    if (dlclose(handle)) return failure("unload", NULL);
    return code;
}
