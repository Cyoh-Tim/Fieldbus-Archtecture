/*
 * Modbus TCP oracle DUT (tests/oracle): client-role stack driven by a line
 * protocol on stdin/stdout. The fake server in test_modbus_oracle.py decides
 * whether what the client did is right. Not a product binary.
 *
 * Commands (one per line, answer is one line):
 *   NEW <port> <timeout_ms>          -> "NEW <i>"        (create client i, not started)
 *   START <i>                        -> "START <i> <rc> <ms>"
 *   POLL <i>                         -> "POLL <i> <ms>"
 *   READ <i> <h|i|c|d> <addr> <qty>  -> "READ <i> <rc> <ms> <v0> <v1> ..."
 *                                       (values from the local mirror, hex)
 *   WREGS <i> <addr> <v0> [v1 ...]   -> "WREGS <i> <rc> <ms>"
 *   WBITS <i> <addr> <b0> [b1 ...]   -> "WBITS <i> <rc> <ms>"
 *   SLEEP <ms>                       -> "SLEEP"
 *   QUIT
 * Unknown/invalid input -> "ERR ...".
 */
#define _POSIX_C_SOURCE 200809L

#include "mb_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_INST 8
#define MAX_VALS 125

static mb_stack_t *g_inst[MAX_INST];
static int g_count;

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static mb_stack_t *inst(const char *tok)
{
    if (!tok) {
        return NULL;
    }
    int i = atoi(tok);
    if (i < 0 || i >= g_count) {
        return NULL;
    }
    return g_inst[i];
}

static int parse_type(const char *t, mb_reg_type_t *out)
{
    if (!t) {
        return -1;
    }
    switch (t[0]) {
    case 'h':
        *out = MB_REG_HOLDING;
        return 0;
    case 'i':
        *out = MB_REG_INPUT;
        return 0;
    case 'c':
        *out = MB_REG_COIL;
        return 0;
    case 'd':
        *out = MB_REG_DISCRETE;
        return 0;
    default:
        return -1;
    }
}

int main(void)
{
    char line[2048];
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (fgets(line, sizeof(line), stdin)) {
        char *save = NULL;
        char *cmd = strtok_r(line, " \t\r\n", &save);
        if (!cmd) {
            continue;
        }
        if (strcmp(cmd, "QUIT") == 0) {
            break;
        } else if (strcmp(cmd, "NEW") == 0) {
            char *p = strtok_r(NULL, " \t\r\n", &save);
            char *t = strtok_r(NULL, " \t\r\n", &save);
            if (!p || !t || g_count >= MAX_INST) {
                printf("ERR NEW\n");
                continue;
            }
            mb_cfg_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            cfg.role = MB_ROLE_CLIENT;
            snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
            cfg.port = atoi(p);
            cfg.unit_id = 1;
            cfg.client_timeout_ms = atoi(t);
            cfg.n_holding = 1000;
            cfg.n_input = 1000;
            cfg.n_coil = 1000;
            cfg.n_discrete = 1000;
            mb_stack_t *s = mb_stack_create(&cfg);
            if (!s) {
                printf("ERR NEW create\n");
                continue;
            }
            g_inst[g_count] = s;
            printf("NEW %d\n", g_count);
            g_count++;
        } else if (strcmp(cmd, "START") == 0) {
            char *it = strtok_r(NULL, " \t\r\n", &save);
            mb_stack_t *s = inst(it);
            if (!s) {
                printf("ERR START\n");
                continue;
            }
            double t0 = now_ms();
            int rc = mb_stack_start(s);
            printf("START %s %d %.1f\n", it, rc, now_ms() - t0);
        } else if (strcmp(cmd, "POLL") == 0) {
            char *it = strtok_r(NULL, " \t\r\n", &save);
            mb_stack_t *s = inst(it);
            if (!s) {
                printf("ERR POLL\n");
                continue;
            }
            double t0 = now_ms();
            mb_stack_poll(s);
            printf("POLL %s %.1f\n", it, now_ms() - t0);
        } else if (strcmp(cmd, "READ") == 0) {
            char *it = strtok_r(NULL, " \t\r\n", &save);
            char *ty = strtok_r(NULL, " \t\r\n", &save);
            char *ad = strtok_r(NULL, " \t\r\n", &save);
            char *qt = strtok_r(NULL, " \t\r\n", &save);
            mb_stack_t *s = inst(it);
            mb_reg_type_t type;
            if (!s || !ad || !qt || parse_type(ty, &type) != 0) {
                printf("ERR READ\n");
                continue;
            }
            uint16_t addr = (uint16_t)atoi(ad);
            uint16_t qty = (uint16_t)atoi(qt);
            if (qty > MAX_VALS) {
                printf("ERR READ qty\n");
                continue;
            }
            double t0 = now_ms();
            int rc = mb_stack_client_read(s, type, addr, qty);
            double dt = now_ms() - t0;
            printf("READ %s %d %.1f", it, rc, dt);
            if (rc == 0) {
                if (type == MB_REG_HOLDING || type == MB_REG_INPUT) {
                    uint16_t v[MAX_VALS];
                    if (mb_stack_read_regs(s, type, addr, v, qty) == 0) {
                        for (uint16_t k = 0; k < qty; k++) {
                            printf(" %04x", v[k]);
                        }
                    }
                } else {
                    uint8_t b[MAX_VALS];
                    if (mb_stack_read_bits(s, type, addr, b, qty) == 0) {
                        for (uint16_t k = 0; k < qty; k++) {
                            printf(" %x", b[k] ? 1 : 0);
                        }
                    }
                }
            }
            printf("\n");
        } else if (strcmp(cmd, "WREGS") == 0 || strcmp(cmd, "WBITS") == 0) {
            int regs = strcmp(cmd, "WREGS") == 0;
            char *it = strtok_r(NULL, " \t\r\n", &save);
            char *ad = strtok_r(NULL, " \t\r\n", &save);
            mb_stack_t *s = inst(it);
            if (!s || !ad) {
                printf("ERR %s\n", cmd);
                continue;
            }
            uint16_t v[MAX_VALS];
            uint8_t b[MAX_VALS];
            uint16_t n = 0;
            char *tok;
            while (n < MAX_VALS &&
                   (tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
                unsigned long x = strtoul(tok, NULL, 16);
                v[n] = (uint16_t)x;
                b[n] = x ? 1 : 0;
                n++;
            }
            double t0 = now_ms();
            int rc = regs ? mb_stack_client_write_regs(s, (uint16_t)atoi(ad),
                                                       v, n)
                          : mb_stack_client_write_bits(s, (uint16_t)atoi(ad),
                                                       b, n);
            printf("%s %s %d %.1f\n", cmd, it, rc, now_ms() - t0);
        } else if (strcmp(cmd, "SLEEP") == 0) {
            char *ms = strtok_r(NULL, " \t\r\n", &save);
            long v = ms ? atol(ms) : 0;
            struct timespec nap = {v / 1000, (v % 1000) * 1000000L};
            nanosleep(&nap, NULL);
            printf("SLEEP\n");
        } else {
            printf("ERR unknown %s\n", cmd);
        }
    }
    for (int i = 0; i < g_count; i++) {
        mb_stack_destroy(g_inst[i]);
    }
    return 0;
}
