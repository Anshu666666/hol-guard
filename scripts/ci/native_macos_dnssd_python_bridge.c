/* Additional controls only: preserve both included source files verbatim. */
#include "native_macos_python_resolver_bridge.c"

int hol_guard_dnssd_python_call(unsigned operation) {
    if (operation > 1) return 64;
    char *arguments[] = {"resolver-probe", operation ? "dns_shared" : "dns_simple", NULL};
    return hol_guard_original_resolver_main(2, arguments);
}
