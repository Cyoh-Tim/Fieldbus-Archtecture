/*
 * SLMP oracle DUT (tests/oracle): Binary 3E client.
 *
 *   slmp_oracle_client --port N --count K [--interval-ms I]
 *                      [--start H] [--dev CODE] [--bit] [--write V]
 *
 * Reads <dev>H..<dev>(H+K-1) (default D1..DK) one point at a time from
 * 127.0.0.1:N and prints one line per read: "READ <head> <rc> <value-hex>".
 * --dev takes the binary device code (default 0xA8 = D), --bit uses bit
 * units (subcommand 0001), --write V batch-writes V to each point instead
 * and prints "WRITE <head> <rc>". The independent fake PLC in
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
    long start = 1;
    unsigned dev = 0xA8; /* D */
    int bit = 0;
    int do_write = 0;
    unsigned long wval = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            interval_ms = atol(argv[++i]);
        } else if (strcmp(argv[i], "--start") == 0 && i + 1 < argc) {
            start = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--dev") == 0 && i + 1 < argc) {
            dev = (unsigned)strtoul(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--bit") == 0) {
            bit = 1;
        } else if (strcmp(argv[i], "--write") == 0 && i + 1 < argc) {
            do_write = 1;
            wval = strtoul(argv[++i], NULL, 16);
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
    for (long i = start; i < start + count; i++) {
        slmp_range_t r;
        memset(&r, 0, sizeof(r));
        r.addr.device_code = (uint8_t)dev;
        r.addr.head = (uint32_t)i;
        r.addr.unit = bit ? SLMP_ACCESS_BIT : SLMP_ACCESS_WORD;
        r.quantity = 1;
        uint8_t raw[8];
        size_t n = 0;
        if (do_write) {
            /* word: canonical big-endian bytes; bit: one byte per point */
            raw[0] = bit ? (uint8_t)(wval != 0) : (uint8_t)(wval >> 8);
            raw[1] = (uint8_t)wval;
            int rc = slmp_stack_client_batch_write(s, &r, raw, bit ? 1u : 2u);
            printf("WRITE %ld %d\n", i, rc);
        } else {
            int rc = slmp_stack_client_batch_read(s, &r, raw, sizeof(raw), &n);
            /* word: canonical big-endian bytes; bit: one byte per point */
            unsigned v = 0;
            if (rc == 0 && n >= 1) {
                v = bit ? raw[0] : (n >= 2 ? (unsigned)(raw[0] << 8 | raw[1]) : 0);
            }
            printf("READ %ld %d %04x\n", i, rc, v);
        }
        fflush(stdout);
        nanosleep(&nap, NULL);
    }
    slmp_stack_destroy(s);
    return 0;
}
