#include "pn_endian.h"
#include "pn_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int g_run = 1;

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <iface>\n", argv[0]);
        return 1;
    }
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "%s", argv[1]);
    snprintf(cfg.station_name, sizeof(cfg.station_name), "sensor-line1");
    cfg.security_class = 0;
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 1;
    cfg.ip = (192 << 24) | (168 << 16) | 10;
    cfg.netmask = 0xFFFFFF00u;
    cfg.cycle_us = 8000;

    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s || pn_stack_start(s) != 0) {
        fprintf(stderr, "stack start failed on %s\n", argv[1]);
        return 1;
    }
    fprintf(stderr, "device up on %s name=%s\n", argv[1],
            pn_stack_cfg(s)->station_name);
    for (int i = 0; i < 250 && g_run; i++) {
        pn_stack_poll(s);
        usleep(20000);
    }
    pn_stack_destroy(s);
    return 0;
}
