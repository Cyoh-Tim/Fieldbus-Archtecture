/*
 * PROFINET oracle DUT: adapter level (tests/oracle).
 *
 * Opens a config through fb_api (core + adapters/profinet + pn_stack), so
 * the adapter builds pn_cfg_t and the point mapping from the JSON exactly
 * as the product does. The stack instance the adapter creates is captured
 * by linking with -Wl,--wrap=pn_stack_create and given mock Ethernet ops
 * (public pn_stack_set_eth_ops) before the adapter starts it. Nothing else
 * of the adapter or stack is touched. Not a product binary.
 *
 *   usage: pn_oracle_app <config.json>
 *
 * Startup prints "READY" or "ERR <fb_err>" (fb_open failed; process exits),
 * then "END". Commands (same line protocol as pn_oracle_pipe):
 *   ETH <hex>          inject one Ethernet frame, poll ~50 ms
 *   RPC <hex>          inject one DCE/RPC UDP payload (port 34964)
 *   POLL <ms>          fb_poll() for <ms> milliseconds
 *   WU32 <name> <u32>  fb_write_u32
 *   WF32 <name> <f>    fb_write_f32
 *   RF32 <name>        fb_read_f32 -> "F32 <IEEE754 BE hex>"
 *   QUIT
 * Output lines: TX <hex>, RSP <hex>, F32 <hex>, ERR <rc>, then END.
 */
#define _POSIX_C_SOURCE 200809L

#include "fb_api.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LINE_MAX_BYTES 65536
#define FRAME_MAX 2048

static pn_stack_t *g_stack;

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

pn_stack_t *__real_pn_stack_create(const pn_cfg_t *cfg);

pn_stack_t *__wrap_pn_stack_create(const pn_cfg_t *cfg)
{
    pn_stack_t *s = __real_pn_stack_create(cfg);
    if (s) {
        pn_eth_ops_t ops = {mock_send, mock_recv, NULL};
        pn_stack_set_eth_ops(s, ops);
        g_stack = s;
    }
    return s;
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

static void poll_for_ms(fb_runtime_t *rt, long ms)
{
    struct timespec start, now, nap = {0, 1000000L};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        fb_poll(rt);
        clock_gettime(CLOCK_MONOTONIC, &now);
        long el = (now.tv_sec - start.tv_sec) * 1000L +
                  (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (el >= ms) {
            break;
        }
        nanosleep(&nap, NULL);
    }
}

/* "<name> <value>" -> name (NUL-terminated in place), value string */
static char *split_arg(char *s)
{
    char *sp = strchr(s, ' ');
    if (!sp) {
        return NULL;
    }
    *sp = '\0';
    return sp + 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: pn_oracle_app <config.json>\n");
        return 2;
    }
    fb_runtime_t *rt = NULL;
    int orc = fb_open(argv[1], &rt);
    if (orc != FB_OK || !g_stack) {
        printf("ERR %d\nEND\n", orc != FB_OK ? orc : -1);
        fflush(stdout);
        fb_close(rt);
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
            int rc = pn_stack_handle_eth(g_stack, buf, n);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            }
            poll_for_ms(rt, 50);
        } else if (strncmp(line, "RPC ", 4) == 0) {
            size_t n = unhex(line + 4, buf, sizeof(buf));
            size_t rlen = 0;
            int rc = pn_stack_handle_rpc(g_stack, buf, n, resp, sizeof(resp),
                                         &rlen);
            if (rc < 0) {
                printf("ERR %d\n", rc);
            } else if (rlen > 0) {
                print_hex("RSP", resp, rlen);
            }
        } else if (strncmp(line, "POLL ", 5) == 0) {
            poll_for_ms(rt, strtol(line + 5, NULL, 10));
        } else if (strncmp(line, "WU32 ", 5) == 0) {
            char *val = split_arg(line + 5);
            int rc = val ? fb_write_u32(rt, line + 5,
                                        (uint32_t)strtoul(val, NULL, 10))
                         : FB_ERR_INVAL;
            if (rc != FB_OK) {
                printf("ERR %d\n", rc);
            }
        } else if (strncmp(line, "WF32 ", 5) == 0) {
            char *val = split_arg(line + 5);
            int rc = val ? fb_write_f32(rt, line + 5, strtof(val, NULL))
                         : FB_ERR_INVAL;
            if (rc != FB_OK) {
                printf("ERR %d\n", rc);
            }
        } else if (strncmp(line, "RF32 ", 5) == 0) {
            float f = 0.0f;
            int rc = fb_read_f32(rt, line + 5, &f);
            if (rc != FB_OK) {
                printf("ERR %d\n", rc);
            } else {
                uint32_t u;
                memcpy(&u, &f, sizeof(u));
                uint8_t be[4] = {(uint8_t)(u >> 24), (uint8_t)(u >> 16),
                                 (uint8_t)(u >> 8), (uint8_t)u};
                print_hex("F32", be, sizeof(be));
            }
        } else if (strcmp(line, "QUIT") == 0) {
            break;
        }
        printf("END\n");
        fflush(stdout);
    }
    fb_close(rt);
    return 0;
}
