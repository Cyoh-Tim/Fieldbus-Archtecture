#include "pn_endian.h"
#include "pn_stack.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int g_run = 1;

static void on_sig(int sig)
{
    (void)sig;
    g_run = 0;
}

static uint32_t parse_ipv4(const char *s)
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <iface> [ipv4] [seconds]\n", argv[0]);
        return 1;
    }
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "%s", argv[1]);
    snprintf(cfg.station_name, sizeof(cfg.station_name), "sensor-line1");
    cfg.security_class = 0;
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 1;
    cfg.ip = argc > 2 ? parse_ipv4(argv[2]) : ((192 << 24) | (168 << 16) | 10);
    cfg.netmask = 0xFFFFFF00u;
    cfg.cycle_us = 8000;
    int seconds = argc > 3 ? atoi(argv[3]) : 8;

    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s || pn_stack_start(s) != 0) {
        fprintf(stderr, "stack start failed on %s\n", argv[1]);
        return 1;
    }
    fprintf(stderr, "device up on %s name=%s ip=%s\n", argv[1],
            pn_stack_cfg(s)->station_name, argc > 2 ? argv[2] : "192.168.0.10");
    int inject = getenv("PN_INJECT_DIAG") != NULL;
    int beta_io = getenv("PN_BETA_IO") != NULL;
    int injected = 0;
    static const uint8_t k_beta_in[32] = {
        'B', 'E', 'T', 'A', '-', 'P', 'N', '-', 'I', 'N', '-',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F', '!', '!', '!', '!', '!'};
    int loops = seconds * 1000;
    for (int i = 0; i < loops && g_run; i++) {
        if (beta_io) {
            pn_stack_write_input(s, 0, k_beta_in, sizeof(k_beta_in));
        }
        pn_stack_poll(s);
        if (inject && !injected && pn_stack_ar_up(s)) {
            pn_stack_diag_appear(s);
            injected = 1;
        }
        usleep(1000);
    }
    pn_stack_destroy(s);
    return 0;
}
