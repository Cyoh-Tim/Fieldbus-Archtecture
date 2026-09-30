/*
 * PROFINET oracle DUT pipe (tests/oracle).
 *
 * Runs the stack with mock Ethernet and speaks a line protocol on
 * stdin/stdout so an independent implementation (scapy pnio) can build
 * requests and dissect responses. Not a product binary.
 *
 *   ETH <hex>    inject one Ethernet frame, poll ~50 ms
 *   RPC <hex>    inject one DCE/RPC UDP payload (port 34964)
 *   POLL <ms>    poll for <ms> milliseconds
 *   TAKE         pull a Device-originated RPC (ApplicationReady)
 *   INPUT <hex>  write the input image from offset 0
 *   SNMP <hex>   inject one SNMP UDP payload (port 161)
 *   ALARM <fid>  send one alarm (hex FrameID FC01 High / FE01 Low)
 *   QUIT
 *
 * Every command answers with zero or more lines, then "END":
 *   TX <hex>     Ethernet frame the stack sent
 *   RSP <hex>    RPC / SNMP response payload (RPC, SNMP command)
 *   RPCTX <hex>  Device-originated RPC payload (TAKE command)
 *   ERR <rc>     negative return code from the stack call
 */
#define _POSIX_C_SOURCE 200809L

#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LINE_MAX_BYTES 65536
#define FRAME_MAX 2048

static int mock_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    printf("TX ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", frame[i]);
    }
    printf("\n");
    return (int)len;
}

static int mock_recv(void *ctx, uint8_t *frame, size_t cap, int timeout_ms)
{
    (void)ctx;
    (void)frame;
    (void)cap;
    (void)timeout_ms;
    return -EAGAIN;
}

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) {
            break;
        }
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static void print_hex(const char *tag, const uint8_t *b, size_t n)
{
    printf("%s ", tag);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static void poll_for_ms(pn_stack_t *s, long ms)
{
    struct timespec start, now, nap = {0, 1000000L};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        pn_stack_poll(s);
        clock_gettime(CLOCK_MONOTONIC, &now);
        long el = (now.tv_sec - start.tv_sec) * 1000L +
                  (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (el >= ms) {
            break;
        }
        nanosleep(&nap, NULL);
    }
}

int main(int argc, char **argv)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.station_name, sizeof(cfg.station_name), "%s",
             argc > 1 ? argv[1] : "oracle-dut");
    snprintf(cfg.device_type, sizeof(cfg.device_type), "FieldbusOracle");
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 0x0001;
    cfg.ip = (192u << 24) | (168u << 16) | (0u << 8) | 50u;
    cfg.netmask = 0xFFFFFF00u;
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 32;
    cfg.cycle_us = 8000;

    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "pn_stack_create failed\n");
        return 1;
    }
    pn_eth_ops_t ops = {mock_send, mock_recv, NULL};
    pn_stack_set_eth_ops(s, ops);
    if (pn_stack_start(s) != 0) {
        fprintf(stderr, "pn_stack_start failed\n");
        return 1;
    }
    printf("READY\nEND\n");
    fflush(stdout);

    static char line[LINE_MAX_BYTES];
    static uint8_t buf[FRAME_MAX];
    static uint8_t resp[FRAME_MAX];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "ETH ", 4) == 0) {
            size_t n = unhex(line + 4, buf, sizeof(buf));
            int rc = pn_stack_handle_eth(s, buf, n);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            }
            poll_for_ms(s, 50);
        } else if (strncmp(line, "RPC ", 4) == 0) {
            size_t n = unhex(line + 4, buf, sizeof(buf));
            size_t rlen = 0;
            int rc = pn_stack_handle_rpc(s, buf, n, resp, sizeof(resp), &rlen);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            } else if (rlen > 0) {
                print_hex("RSP", resp, rlen);
            }
        } else if (strncmp(line, "POLL ", 5) == 0) {
            poll_for_ms(s, strtol(line + 5, NULL, 10));
        } else if (strcmp(line, "TAKE") == 0) {
            size_t rlen = 0;
            int rc = pn_stack_take_rpc_tx(s, resp, sizeof(resp), &rlen);
            if (rc == 0 && rlen > 0) {
                print_hex("RPCTX", resp, rlen);
            } else if (rc != -EAGAIN) {
                printf("ERR %d\n", rc);
            }
        } else if (strncmp(line, "INPUT ", 6) == 0) {
            size_t n = unhex(line + 6, buf, sizeof(buf));
            int rc = pn_stack_write_input(s, 0, buf, n);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            }
        } else if (strncmp(line, "SNMP ", 5) == 0) {
            size_t n = unhex(line + 5, buf, sizeof(buf));
            size_t rlen = 0;
            int rc = pn_stack_handle_snmp(s, buf, n, resp, sizeof(resp), &rlen);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            } else if (rlen > 0) {
                print_hex("RSP", resp, rlen);
            }
        } else if (strncmp(line, "ALARM ", 6) == 0) {
            unsigned long fid = strtoul(line + 6, NULL, 16);
            int rc = pn_stack_send_alarm_ex(s, (uint16_t)fid);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            }
        } else if (strcmp(line, "QUIT") == 0) {
            break;
        }
        printf("END\n");
        fflush(stdout);
    }
    pn_stack_destroy(s);
    return 0;
}
