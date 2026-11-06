/*
 * PROFINET SNMP agent fuzzer (pn_snmp_handle, UDP 161 payload).
 *
 * Byte 0 picks the response buffer size (1..1021 bytes) so the tooBig and
 * short-buffer paths run as well as the normal GetResponse. The buffer is
 * heap-allocated at exactly that size, so ASan sees any write past it.
 */
#include "pn_internal.h"
#include "pn_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pn_stack_t *g_s;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_s) {
        pn_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.iface, sizeof(cfg.iface), "mock");
        snprintf(cfg.station_name, sizeof(cfg.station_name), "fuzz");
        cfg.mac_set = 1;
        cfg.mac[0] = 0x02;
        g_s = pn_stack_create(&cfg);
        if (!g_s) {
            abort();
        }
    }
    if (size < 1) {
        return 0;
    }
    size_t cap = (size_t)data[0] * 4u + 1u;
    uint8_t *resp = malloc(cap);
    if (!resp) {
        return 0;
    }
    size_t out = 0;
    (void)pn_snmp_handle(g_s, data + 1, size - 1, resp, cap, &out);
    if (out > cap) {
        abort();
    }
    free(resp);
    return 0;
}
