/*
 * Modbus/SLMP oracle DUT (tests/oracle): an application that uses only the
 * public fb_api.h, driven by a line protocol on stdin/stdout. It lets the
 * oracle tests exercise adapter-level behaviour (config parsing, point
 * mapping, client-mode cycle timing) while pymodbus / pymcprotocol / a
 * spec-based fake peer judge what reached the wire. Not a product binary.
 *
 *   mb_slmp_oracle_app <config.json>      -> first line "OPEN <rc>"
 *
 * Commands (one per line, answer is one line):
 *   START | STOP                         -> "START <rc>" | "STOP <rc>"
 *   POLL                                 -> "POLL <rc> <ms>"
 *   LOOP <total_ms> <period_ms>          -> "LOOP <n> <max_ms> <sum_ms>"
 *   WU32|WI32|WF32|WBOOL <name> <value>  -> "W <rc>"
 *   WSTR <name> <text>                   -> "W <rc>"
 *   RU32|RI32|RBOOL <name>               -> "R <rc> <value>"
 *   RF32 <name>                          -> "R <rc> <value %.6g>"
 *   RSTR <name>                          -> "R <rc> <hex of text>"
 *   QUIT
 */
#define _POSIX_C_SOURCE 200809L

#include "fb_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void nap_ms(double ms)
{
    if (ms <= 0) {
        return;
    }
    long us = (long)(ms * 1000.0);
    struct timespec ts = {us / 1000000L, (us % 1000000L) * 1000L};
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) {
        printf("OPEN %d\n", FB_ERR_INVAL);
        return 1;
    }
    fb_runtime_t *rt = NULL;
    int rc = fb_open(argv[1], &rt);
    printf("OPEN %d\n", rc);
    if (rc != FB_OK) {
        return 1;
    }

    char line[2048];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        char *save = NULL;
        char *cmd = strtok_r(line, " ", &save);
        if (!cmd) {
            continue;
        }
        char *name = NULL;
        if (strcmp(cmd, "QUIT") == 0) {
            break;
        } else if (strcmp(cmd, "START") == 0) {
            printf("START %d\n", fb_start(rt));
        } else if (strcmp(cmd, "STOP") == 0) {
            printf("STOP %d\n", fb_stop(rt));
        } else if (strcmp(cmd, "POLL") == 0) {
            double t0 = now_ms();
            int prc = fb_poll(rt);
            printf("POLL %d %.1f\n", prc, now_ms() - t0);
        } else if (strcmp(cmd, "LOOP") == 0) {
            char *a = strtok_r(NULL, " ", &save);
            char *b = strtok_r(NULL, " ", &save);
            double total = a ? atof(a) : 0;
            double period = b ? atof(b) : 10;
            double start = now_ms();
            double worst = 0, sum = 0;
            int n = 0;
            while (now_ms() - start < total) {
                double t0 = now_ms();
                (void)fb_poll(rt);
                double dt = now_ms() - t0;
                sum += dt;
                if (dt > worst) {
                    worst = dt;
                }
                n++;
                nap_ms(period - dt);
            }
            printf("LOOP %d %.1f %.1f\n", n, worst, sum);
        } else if (strcmp(cmd, "WU32") == 0 || strcmp(cmd, "WI32") == 0 ||
                   strcmp(cmd, "WF32") == 0 || strcmp(cmd, "WBOOL") == 0) {
            name = strtok_r(NULL, " ", &save);
            char *v = strtok_r(NULL, " ", &save);
            if (!name || !v) {
                printf("ERR %s\n", cmd);
                continue;
            }
            int wrc;
            if (cmd[1] == 'U') {
                wrc = fb_write_u32(rt, name, (uint32_t)strtoul(v, NULL, 0));
            } else if (cmd[1] == 'I') {
                wrc = fb_write_i32(rt, name, (int32_t)strtol(v, NULL, 0));
            } else if (cmd[1] == 'F') {
                wrc = fb_write_f32(rt, name, strtof(v, NULL));
            } else {
                wrc = fb_write_bool(rt, name, atoi(v) != 0);
            }
            printf("W %d\n", wrc);
        } else if (strcmp(cmd, "WSTR") == 0) {
            name = strtok_r(NULL, " ", &save);
            char *text = save ? save : "";
            if (!name) {
                printf("ERR WSTR\n");
                continue;
            }
            printf("W %d\n", fb_write_string(rt, name, text));
        } else if (strcmp(cmd, "RU32") == 0) {
            name = strtok_r(NULL, " ", &save);
            uint32_t v = 0;
            int r = name ? fb_read_u32(rt, name, &v) : FB_ERR_INVAL;
            printf("R %d %lu\n", r, (unsigned long)v);
        } else if (strcmp(cmd, "RI32") == 0) {
            name = strtok_r(NULL, " ", &save);
            int32_t v = 0;
            int r = name ? fb_read_i32(rt, name, &v) : FB_ERR_INVAL;
            printf("R %d %ld\n", r, (long)v);
        } else if (strcmp(cmd, "RBOOL") == 0) {
            name = strtok_r(NULL, " ", &save);
            int v = 0;
            int r = name ? fb_read_bool(rt, name, &v) : FB_ERR_INVAL;
            printf("R %d %d\n", r, v);
        } else if (strcmp(cmd, "RF32") == 0) {
            name = strtok_r(NULL, " ", &save);
            float v = 0;
            int r = name ? fb_read_f32(rt, name, &v) : FB_ERR_INVAL;
            printf("R %d %.6g\n", r, (double)v);
        } else if (strcmp(cmd, "RSTR") == 0) {
            name = strtok_r(NULL, " ", &save);
            char buf[512];
            memset(buf, 0, sizeof(buf));
            int r = name ? fb_read_string(rt, name, buf, sizeof(buf))
                         : FB_ERR_INVAL;
            printf("R %d ", r);
            for (size_t i = 0; buf[i]; i++) {
                printf("%02x", (unsigned char)buf[i]);
            }
            printf("\n");
        } else {
            printf("ERR unknown %s\n", cmd);
        }
    }
    fb_close(rt);
    return 0;
}
