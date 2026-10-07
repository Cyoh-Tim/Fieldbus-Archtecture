/*
 * EtherNet/IP oracle DUT (tests/oracle): Adapter on loopback, real sockets.
 *
 *   eip_oracle_adapter --tcp-port N --udp-port M [--seconds S]
 *                      [--input-size B] [--config-size B] [--acd]
 *                      [--bind-ip A] [--report-output]
 *
 * Assemblies: input 150 (8 bytes by default, seeded 01 02 03 ...; byte i =
 * (i+1) & 0xFF), output 101 (4 bytes), config 100 (0 bytes by default).
 * rpi_us = 8000 (the device's minimum RPI for T5 tests). Security class 0.
 * --acd arms ACD (acd_enable = 1; default off). Independent clients
 * (pycomm3, raw spec encoders in Python) drive it. Not a product binary.
 * --bind-ip binds TCP/UDP to that address (default 127.0.0.1; the veth lab
 * tests run it inside a network namespace). --report-output prints
 * "OUT up=<class1_up> <hex>" to stderr whenever the output image or the
 * Class 1 state changes (lab tests read it).
 */
#define _POSIX_C_SOURCE 200809L

#include "eip_stack.h"

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
    int tcp_port = 15644;
    int udp_port = 15622;
    int seconds = 0;
    int input_size = 8;
    int config_size = 0;
    int acd = 0;
    int report_output = 0;
    const char *bind_ip = "127.0.0.1";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tcp-port") == 0 && i + 1 < argc) {
            tcp_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--udp-port") == 0 && i + 1 < argc) {
            udp_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--input-size") == 0 && i + 1 < argc) {
            input_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--config-size") == 0 && i + 1 < argc) {
            config_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bind-ip") == 0 && i + 1 < argc) {
            bind_ip = argv[++i];
        } else if (strcmp(argv[i], "--report-output") == 0) {
            report_output = 1;
        } else if (strcmp(argv[i], "--acd") == 0) {
            acd = 1;
        }
    }

    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", bind_ip);
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_port;
    cfg.vendor_id = 0xABCD;
    cfg.device_type = 12;
    cfg.product_code = 1;
    cfg.major_rev = 1;
    cfg.minor_rev = 1;
    cfg.serial_number = 0x12345678u;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "FieldbusOracle");
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.input_size = (uint16_t)input_size;
    cfg.output_size = 4;
    cfg.config_size = (uint16_t)config_size;
    cfg.rpi_us = 8000;
    cfg.security_class = 0;
    cfg.lldp_enable = 0;
    cfg.acd_enable = acd;

    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "eip_stack_create failed\n");
        return 1;
    }
    if (eip_stack_start(s) != 0) {
        fprintf(stderr, "eip_stack_start failed\n");
        eip_stack_destroy(s);
        return 1;
    }
    for (int i = 0; i < input_size; i++) {
        const uint8_t b = (uint8_t)((i + 1) & 0xFF);
        eip_stack_write_input(s, (size_t)i, &b, 1);
    }
    fprintf(stderr, "eip_oracle_adapter ready tcp=%d udp=%d\n", tcp_port,
            udp_port);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    time_t end = seconds > 0 ? time(NULL) + seconds : 0;
    struct timespec nap = {0, 1000000L};
    uint8_t last_out[4] = {0};
    int last_up = -1;
    while (!g_stop) {
        eip_stack_poll(s);
        if (report_output) {
            uint8_t o[4];
            const int up = eip_stack_class1_up(s);
            if (eip_stack_read_output(s, 0, o, sizeof(o)) == (int)sizeof(o) &&
                (memcmp(o, last_out, sizeof(o)) != 0 || up != last_up)) {
                fprintf(stderr, "OUT up=%d %02x%02x%02x%02x\n", up, o[0], o[1],
                        o[2], o[3]);
                memcpy(last_out, o, sizeof(o));
                last_up = up;
            }
        }
        if (end && time(NULL) >= end) {
            break;
        }
        nanosleep(&nap, NULL);
    }
    eip_stack_destroy(s);
    return 0;
}
