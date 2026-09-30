/*
 * SLMP oracle DUT (tests/oracle): Binary 3E client.
 *
 *   slmp_oracle_client --port N --count K [--interval-ms I]
 *
 * Reads D1..DK one word at a time from 127.0.0.1:N and prints one line per
 * read: "READ <head> <rc> <value-hex>". The independent fake PLC in
 * test_slmp_oracle.py decides whether the values are right. Not a product
 * binary.
 */
#define _POSIX_C_SOURCE 200809L

#include "slmp_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    int port = 15601;
    int count = 8;
    long interval_ms = 300;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            interval_ms = atol(argv[++i]);
        }
    }

    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_CLIENT;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    snprintf(cfg.plc_ip, sizeof(cfg.plc_ip), "127.0.0.1");
    cfg.port = port;
    cfg.pc_no = 0xFF;
    cfg.timeout_ms = 1000;

    slmp_stack_t *s = slmp_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "slmp_stack_create failed\n");
        return 1;
    }
    slmp_stack_start(s);

    struct timespec nap = {interval_ms / 1000, (interval_ms % 1000) * 1000000L};
    for (int i = 1; i <= count; i++) {
        slmp_range_t r;
        memset(&r, 0, sizeof(r));
        r.addr.device_code = 0xA8; /* D */
        r.addr.head = (uint32_t)i;
        r.addr.unit = SLMP_ACCESS_WORD;
        r.quantity = 1;
        uint8_t raw[8];
        size_t n = 0;
        int rc = slmp_stack_client_batch_read(s, &r, raw, sizeof(raw), &n);
        /* batch_read returns words as canonical big-endian bytes */
        unsigned v = (rc == 0 && n >= 2) ? (unsigned)(raw[0] << 8 | raw[1]) : 0;
        printf("READ %d %d %04x\n", i, rc, v);
        fflush(stdout);
        nanosleep(&nap, NULL);
    }
    slmp_stack_destroy(s);
    return 0;
}
