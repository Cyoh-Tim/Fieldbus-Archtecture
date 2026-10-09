/*
 * PROFINET oracle DUT for the veth lab tests (tests/oracle/test_pn_lab.py).
 *
 *   pn_oracle_lab <iface> <ipv4> [seconds]
 *
 * Unlike pn_oracle_pipe (mock Ethernet), this runs the stack's real transport:
 * AF_PACKET on <iface> for DCP/LLDP/RTC1/alarms and UDP 34964 for DCE/RPC, so
 * it needs root (or CAP_NET_RAW) and <ipv4> configured on <iface>. Same device
 * shape as pn_oracle_pipe: station "oracle-dut", vendor 0xABCD, device 0x0001,
 * input/output 32 bytes, cycle 8 ms. The input image is 0x10 0x11 ... 0x2F.
 * Prints "READY" on stdout once started. Not a product binary.
 */
#define _POSIX_C_SOURCE 200809L

#include "pn_stack.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t g_stop;

static void on_sig(int sig)
{
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <iface> <ipv4> [seconds]\n", argv[0]);
        return 2;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, argv[2], &a) != 1) {
        fprintf(stderr, "bad ipv4 %s\n", argv[2]);
        return 2;
    }
    const int seconds = argc > 3 ? atoi(argv[3]) : 10;

    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "%s", argv[1]);
    snprintf(cfg.station_name, sizeof(cfg.station_name), "oracle-dut");
    snprintf(cfg.device_type, sizeof(cfg.device_type), "FieldbusOracle");
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 0x0001;
    cfg.ip = ntohl(a.s_addr);
    cfg.netmask = 0xFFFFFF00u;
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 32;
    cfg.cycle_us = 8000;

    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s || pn_stack_start(s) != 0) {
        fprintf(stderr, "pn stack start failed on %s\n", argv[1]);
        return 1;
    }
    uint8_t in[32];
    for (int i = 0; i < 32; i++) {
        in[i] = (uint8_t)(0x10 + i);
    }
    pn_stack_write_input(s, 0, in, sizeof(in));
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    printf("READY\n");
    fflush(stdout);

    struct timespec start, now, nap = {0, 500000L};
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!g_stop) {
        pn_stack_poll(s);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= seconds) {
            break;
        }
        nanosleep(&nap, NULL);
    }
    pn_stack_destroy(s);
    return 0;
}
