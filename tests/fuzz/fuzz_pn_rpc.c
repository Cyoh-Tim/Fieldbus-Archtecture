#include "pn_stack.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static pn_stack_t *s;
    if (!s) {
        pn_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.iface, sizeof(cfg.iface), "mock");
        snprintf(cfg.station_name, sizeof(cfg.station_name), "fuzz");
        cfg.security_class = 0;
        cfg.input_len = 32;
        cfg.output_len = 8;
        s = pn_stack_create(&cfg);
        if (!s) {
            return 0;
        }
    }
    uint8_t resp[2048];
    size_t rlen = 0;
    (void)pn_stack_handle_rpc(s, data, size, resp, sizeof(resp), &rlen);
    return 0;
}
