/*
 * EtherNet/IP oracle DUT (tests/oracle): application path through fb_api
 * and adapters/ethernetip (T1, T2, T11-2 adapter part).
 *
 *   eip_oracle_fbapi <config.json>
 *
 * fb_open + fb_start (cycle thread polls the adapter on real loopback
 * sockets), prints "READY", then reads one command per stdin line:
 *
 *   W <point> u32|i32|f32 <value>   -> "OK <rc>"
 *   R <point> u32|i32|f32           -> "VAL <rc> <value>"
 *   Q                               -> exit
 *
 * The scanner side (independent encoders in test_eip_oracle.py) reads and
 * writes the Assembly bytes on the wire and decides. Not a product binary.
 */
#define _POSIX_C_SOURCE 200809L

#include "fb_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: eip_oracle_fbapi <config.json>\n");
        return 2;
    }
    fb_runtime_t *rt = NULL;
    int rc = fb_open(argv[1], &rt);
    if (rc != FB_OK) {
        printf("OPEN %d\n", rc);
        fflush(stdout);
        return 1;
    }
    rc = fb_start(rt);
    if (rc != FB_OK) {
        printf("START %d\n", rc);
        fflush(stdout);
        fb_close(rt);
        return 1;
    }
    printf("READY\n");
    fflush(stdout);

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        char cmd[4] = {0}, name[128] = {0}, type[8] = {0}, val[64] = {0};
        int n = sscanf(line, "%3s %127s %7s %63s", cmd, name, type, val);
        if (n < 1 || cmd[0] == 'Q') {
            break;
        }
        if (cmd[0] == 'W' && n == 4) {
            if (strcmp(type, "u32") == 0) {
                rc = fb_write_u32(rt, name, (uint32_t)strtoul(val, NULL, 0));
            } else if (strcmp(type, "i32") == 0) {
                rc = fb_write_i32(rt, name, (int32_t)strtol(val, NULL, 0));
            } else {
                rc = fb_write_f32(rt, name, strtof(val, NULL));
            }
            printf("OK %d\n", rc);
        } else if (cmd[0] == 'R' && n >= 3) {
            if (strcmp(type, "u32") == 0) {
                uint32_t v = 0;
                rc = fb_read_u32(rt, name, &v);
                printf("VAL %d %u\n", rc, v);
            } else if (strcmp(type, "i32") == 0) {
                int32_t v = 0;
                rc = fb_read_i32(rt, name, &v);
                printf("VAL %d %d\n", rc, v);
            } else {
                float v = 0;
                rc = fb_read_f32(rt, name, &v);
                printf("VAL %d %.6g\n", rc, (double)v);
            }
        } else {
            printf("ERR\n");
        }
        fflush(stdout);
    }
    fb_stop(rt);
    fb_close(rt);
    return 0;
}
