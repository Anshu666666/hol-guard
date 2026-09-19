/* Load the exact standalone probe implementation into the Python process. */
#define main hol_guard_original_resolver_main
#include "native_macos_resolver_probe.c"
#undef main

int hol_guard_resolver_call(unsigned operation) {
    if (operation > 1) return 64;
    char *arguments[] = {"resolver-bridge", operation ? "libc_name" : "libc_addr"};
    return hol_guard_original_resolver_main(2, arguments);
}

int hol_guard_resolver_bridge_identity(char *bridge, char *libinfo, char *dnssd, unsigned capacity) {
    if (!bridge || !libinfo || !dnssd || capacity != 33 ||
        !image_uuid((const void *)(uintptr_t)&hol_guard_resolver_call, bridge) ||
        !image_uuid((const void *)(uintptr_t)&gethostbyaddr, libinfo) ||
        !image_uuid((const void *)(uintptr_t)&DNSServiceQueryRecord, dnssd)) return 3;
    return 0;
}
