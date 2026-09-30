/*
 * SLMP oracle DUT (tests/oracle): Binary 3E server/simulator on loopback.
 *
 *   slmp_oracle_server --port N [--seconds S]
 *
 * Seeds D0..D9 = 0x1000 + n so a read-only probe has known values.
 * The independent client (pymcprotocol) drives it over real TCP.
 * Not a product binary.
 */
#define _POSIX_C_SOURCE 200809L

#include "slmp_stack.h"

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
    int port = 15600;
    int seconds = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
        }
    }

    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.port = port;
    cfg.pc_no = 0xFF;
    cfg.max_clients = 4;

    slmp_stack_t *s = slmp_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "slmp_stack_create failed\n");
        return 1;
    }
    for (uint16_t n = 0; n < 10; n++) {
        uint16_t v = (uint16_t)(0x1000 + n);
        slmp_stack_write_words(s, SLMP_DEV_D, n, &v, 1);
    }
    if (slmp_stack_start(s) != 0) {
        fprintf(stderr, "slmp_stack_start failed\n");
        slmp_stack_destroy(s);
        return 1;
    }
    fprintf(stderr, "slmp_oracle_server ready on 127.0.0.1:%d\n", port);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    time_t end = seconds > 0 ? time(NULL) + seconds : 0;
    struct timespec nap = {0, 1000000L};
    while (!g_stop) {
        slmp_stack_poll(s);
        if (end && time(NULL) >= end) {
            break;
        }
        nanosleep(&nap, NULL);
    }
    slmp_stack_destroy(s);
    return 0;
}
