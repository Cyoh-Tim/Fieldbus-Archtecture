#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "eip_stack.h"
#include "mb_stack.h"
#include "slmp_stack.h"

/*
 * CODESYS-style protocol master used in the pool test.
 * Speaks the same client roles a Control SL IEC app would:
 *   Modbus TCP master, EtherNet/IP originator (UCMM), SLMP 3E client.
 * PROFINET Controller is tests/pn_codesys_beta.c (same CM order as CODESYS).
 */

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int contains(const uint8_t *p, size_t n, const char *s)
{
    size_t m = strlen(s);
    if (m == 0 || m > n) {
        return 0;
    }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(p + i, s, m) == 0) {
            return 1;
        }
    }
    return 0;
}

static int parse_state(const char *path, uint16_t *seq, uint16_t *temp)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    unsigned s = 0, t = 0;
    char *ps = strstr(line, "\"seq\":");
    char *pt = strstr(line, "\"temperature_x10\":");
    if (!ps || !pt) {
        return -1;
    }
    s = (unsigned)atoi(ps + (int)strlen("\"seq\":"));
    t = (unsigned)atoi(pt + (int)strlen("\"temperature_x10\":"));
    *seq = (uint16_t)s;
    *temp = (uint16_t)t;
    return 0;
}

typedef struct {
    int saw_barcode;
    int seq_increased;
    uint16_t last_seq;
    uint16_t last_temp;
    int samples;
    int match_state;
} sample_acc_t;

static void acc_feed(sample_acc_t *a, const uint8_t *bar, size_t bar_len,
                     uint16_t temp, uint16_t seq, const char *state_path)
{
    a->samples++;
    if (contains(bar, bar_len, "BETA-PN-IN")) {
        a->saw_barcode = 1;
    }
    if (a->samples > 1 && seq != a->last_seq) {
        a->seq_increased = 1;
    }
    a->last_seq = seq;
    a->last_temp = temp;
    if (state_path) {
        uint16_t st_seq = 0, st_temp = 0;
        if (parse_state(state_path, &st_seq, &st_temp) == 0) {
            int ds = (int)seq - (int)st_seq;
            if (ds < 0) {
                ds = -ds;
            }
            int dt = (int)temp - (int)st_temp;
            if (dt < 0) {
                dt = -dt;
            }
            if (ds <= 80 && dt <= 80) {
                a->match_state = 1;
            }
        }
    }
    fprintf(stderr, "  sample barcode='%.16s' temp=%u seq=%u\n", bar,
            (unsigned)temp, (unsigned)seq);
}

static int acc_ok(const sample_acc_t *a, const char *proto)
{
    int ok = a->saw_barcode && a->seq_increased && a->samples >= 3 &&
             a->last_temp >= 200 && a->last_temp <= 350;
    if (!ok) {
        fprintf(stderr,
                "FAIL %s barcode=%d seq_move=%d samples=%d temp=%u\n", proto,
                a->saw_barcode, a->seq_increased, a->samples,
                (unsigned)a->last_temp);
        return 0;
    }
    fprintf(stderr, "PASS %s samples=%d last_seq=%u temp=%u state_match=%d\n",
            proto, a->samples, (unsigned)a->last_seq, (unsigned)a->last_temp,
            a->match_state);
    return 1;
}

static int run_modbus(const char *host, int port, int seconds,
                      const char *state_path)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_CLIENT;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "%s", host);
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.client_timeout_ms = 500;
    cfg.n_holding = 64;
    cfg.n_input = 16;
    cfg.n_coil = 16;
    cfg.n_discrete = 16;

    mb_stack_t *s = mb_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "modbus create failed\n");
        return 1;
    }
    int rc = mb_stack_start(s);
    if (rc != 0) {
        fprintf(stderr, "modbus connect %s:%d failed (%d)\n", host, port, rc);
        mb_stack_destroy(s);
        return 1;
    }

    sample_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) {
        rc = mb_stack_client_read(s, MB_REG_HOLDING, 0, 19);
        if (rc != 0) {
            fprintf(stderr, "modbus read failed (%d)\n", rc);
            usleep(200000);
            continue;
        }
        uint8_t buf[40];
        memset(buf, 0, sizeof(buf));
        if (mb_stack_read_bytes(s, MB_REG_HOLDING, 0, buf, 38) != 0) {
            usleep(200000);
            continue;
        }
        acc_feed(&acc, buf, 16, rd_be16(buf + 32), rd_be16(buf + 36),
                 state_path);
        usleep(200000);
    }
    mb_stack_destroy(s);
    return acc_ok(&acc, "modbus") ? 0 : 1;
}

static int run_eip(const char *host, int port, int seconds,
                   const char *state_path)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ORIGINATOR;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "%s", host);
    cfg.remote_port = port;
    cfg.security_class = 0;
    cfg.mock = 0;
    cfg.input_size = 64;
    cfg.output_size = 8;

    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "eip create failed\n");
        return 1;
    }
    int rc = eip_stack_start(s);
    if (rc != 0) {
        fprintf(stderr, "eip connect %s:%d failed (%d)\n", host, port, rc);
        eip_stack_destroy(s);
        return 1;
    }

    sample_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) {
        uint8_t buf[128];
        size_t n = sizeof(buf);
        rc = eip_stack_explicit_get(s, CIP_CLASS_ASSEMBLY, 150, 3, buf, &n);
        if (rc != 0 || n < 38) {
            fprintf(stderr, "eip GetAttribute assembly 150 failed rc=%d n=%zu\n",
                    rc, n);
            usleep(200000);
            continue;
        }
        acc_feed(&acc, buf, 16, rd_be16(buf + 32), rd_be16(buf + 36),
                 state_path);
        usleep(200000);
    }
    eip_stack_destroy(s);
    return acc_ok(&acc, "ethernetip") ? 0 : 1;
}

static int run_slmp(const char *host, int port, int seconds,
                    const char *state_path)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_CLIENT;
    snprintf(cfg.plc_ip, sizeof(cfg.plc_ip), "%s", host);
    cfg.port = port;
    cfg.network_no = 0;
    cfg.pc_no = 255;
    cfg.dest_module_io = 0x03FF;
    cfg.monitoring_timer = 16;
    cfg.timeout_ms = 1000;
    cfg.frame = SLMP_FRAME_3E_BINARY;

    slmp_stack_t *s = slmp_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "slmp create failed\n");
        return 1;
    }
    int rc = slmp_stack_start(s);
    if (rc != 0) {
        fprintf(stderr, "slmp connect %s:%d failed (%d)\n", host, port, rc);
        slmp_stack_destroy(s);
        return 1;
    }

    sample_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) {
        slmp_range_t range;
        memset(&range, 0, sizeof(range));
        range.addr.device_code = SLMP_DEV_D;
        range.addr.head = 100;
        range.addr.unit = SLMP_ACCESS_WORD;
        range.quantity = 19;
        uint8_t buf[64];
        size_t n = 0;
        rc = slmp_stack_client_batch_read(s, &range, buf, sizeof(buf), &n);
        if (rc != 0 || n < 38) {
            fprintf(stderr, "slmp batch read D100 failed rc=%d n=%zu\n", rc, n);
            usleep(200000);
            continue;
        }
        acc_feed(&acc, buf, 16, rd_be16(buf + 32), rd_be16(buf + 36),
                 state_path);
        usleep(200000);
    }
    slmp_stack_destroy(s);
    return acc_ok(&acc, "slmp") ? 0 : 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "사용법: %s --proto modbus|ethernetip|slmp [--host IP] [--port N] "
            "[--seconds N] [--state FILE]\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *proto = NULL;
    const char *host = "127.0.0.1";
    const char *state = getenv("SENSOR_STATE");
    int port = 0;
    int seconds = 3;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--proto") == 0 && i + 1 < argc) {
            proto = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--state") == 0 && i + 1 < argc) {
            state = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }
    if (!proto) {
        usage(argv[0]);
        return 2;
    }
    if (seconds < 1) {
        seconds = 1;
    }
    if (strcmp(proto, "modbus") == 0) {
        return run_modbus(host, port ? port : 1502, seconds, state);
    }
    if (strcmp(proto, "ethernetip") == 0 || strcmp(proto, "eip") == 0) {
        return run_eip(host, port ? port : 44818, seconds, state);
    }
    if (strcmp(proto, "slmp") == 0) {
        return run_slmp(host, port ? port : 15000, seconds, state);
    }
    fprintf(stderr, "unknown proto %s\n", proto);
    return 2;
}
