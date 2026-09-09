/*
 * Seeded Modbus TCP server for reliability testing.
 * Preloads holding/input/coil/discrete then serves forever (or --seconds N).
 */
#include "mb_stack.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile int g_stop;

static void on_sig(int s)
{
    (void)s;
    g_stop = 1;
}

int main(int argc, char **argv)
{
    int port = 1502;
    int seconds = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
        }
    }

    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.max_clients = 8;
    cfg.n_holding = 1000;
    cfg.n_input = 1000;
    cfg.n_coil = 1000;
    cfg.n_discrete = 1000;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");

    mb_stack_t *s = mb_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "create failed\n");
        return 1;
    }

    /* Deterministic seed pattern for verification. */
    for (uint16_t i = 0; i < 256; i++) {
        uint16_t hv = (uint16_t)(0xA000 + i);
        uint16_t iv = (uint16_t)(0xB000 + i);
        mb_stack_write_regs(s, MB_REG_HOLDING, i, &hv, 1);
        mb_stack_write_regs(s, MB_REG_INPUT, i, &iv, 1);
        uint8_t cb = (uint8_t)(i & 1);
        uint8_t db = (uint8_t)((i >> 1) & 1);
        mb_stack_write_bits(s, MB_REG_COIL, i, &cb, 1);
        mb_stack_write_bits(s, MB_REG_DISCRETE, i, &db, 1);
    }
    /* Known floats at holding 300/301 as ABCD big-endian IEEE 1.5f = 0x3FC00000 */
    uint16_t fregs[2] = {0x3FC0, 0x0000};
    mb_stack_write_regs(s, MB_REG_HOLDING, 300, fregs, 2);
    /* String "ABCD" at holding 400 (2 chars/reg) */
    uint8_t str[4] = {'A', 'B', 'C', 'D'};
    mb_stack_write_bytes(s, MB_REG_HOLDING, 400, str, 4);

    if (mb_stack_start(s) != 0) {
        fprintf(stderr, "start failed\n");
        mb_stack_destroy(s);
        return 1;
    }
    fprintf(stderr, "mb_seeded_server ready on 127.0.0.1:%d\n", port);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    time_t end = seconds > 0 ? time(NULL) + seconds : 0;
    while (!g_stop) {
        mb_stack_poll(s);
        if (end && time(NULL) >= end) {
            break;
        }
        usleep(1000);
    }
    mb_stack_stop(s);
    mb_stack_destroy(s);
    return 0;
}
