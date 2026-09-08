#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "adapter_registry.h"
#include "config_loader.h"
#include "logger.h"
#include "protocol_adapter.h"

/*
 * Live sensor demo for the fieldbus daemon.
 *
 * Same config.json as multiproto_daemon. Each cycle publishes a changing
 * process image through write_point() so a PLC (CODESYS or the in-repo
 * pool_master) can observe real data on the wire.
 *
 * Process image (sensor → PLC, access=read points):
 *   barcode         32 ASCII  "BETA-PN-IN/NNNNNN" + pad
 *   temperature     uint16 BE, 0.1 °C (200..350)
 *   humidity        uint16 BE, 0.1 %RH (300..700)
 *   seq             uint16 BE, increments every publish
 *
 * State snapshot (for the pool tester to compare) is written atomically
 * to SENSOR_STATE (default /tmp/fieldbus-sensor-demo.json).
 */

static volatile int g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static int write_named(protocol_adapter_t *a, const char *name,
                       const uint8_t *data, size_t len)
{
    point_value_t v;
    v.data = (uint8_t *)data;
    v.len = len;
    int rc = a->write_point(a, name, &v);
    if (rc == -ENOENT) {
        return 0; /* point not in this protocol config */
    }
    return rc;
}

static int write_state_file(const char *path, const char *barcode,
                            uint16_t temp_x10, uint16_t hum_x10, uint16_t seq)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        return -errno;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long ms =
        (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
    fprintf(f,
            "{\"barcode\":\"%s\",\"temperature_x10\":%u,\"humidity_x10\":%u,"
            "\"seq\":%u,\"unix_ms\":%lld}\n",
            barcode, (unsigned)temp_x10, (unsigned)hum_x10, (unsigned)seq, ms);
    fclose(f);
    if (rename(tmp, path) != 0) {
        return -errno;
    }
    return 0;
}

static void timespec_add_ms(struct timespec *t, long ms)
{
    t->tv_sec += ms / 1000;
    t->tv_nsec += (ms % 1000) * 1000000L;
    if (t->tv_nsec >= 1000000000L) {
        t->tv_nsec -= 1000000000L;
        t->tv_sec += 1;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <config.json>\n", argv[0]);
        return 1;
    }

    const char *state_path = getenv("SENSOR_STATE");
    if (!state_path || !state_path[0]) {
        state_path = "/tmp/fieldbus-sensor-demo.json";
    }

    daemon_config_t cfg;
    if (config_load(argv[1], &cfg) != 0) {
        LOG_ERROR("sensor", "설정 로드 실패: %s", argv[1]);
        return 1;
    }

    adapter_ctor_fn ctor = adapter_registry_lookup(cfg.protocol);
    if (!ctor) {
        LOG_ERROR("sensor", "알 수 없는 protocol: \"%s\"", cfg.protocol);
        config_free(&cfg);
        return 1;
    }

    protocol_adapter_t *adapter = ctor();
    if (!adapter) {
        LOG_ERROR("sensor", "어댑터 생성 실패: %s", cfg.protocol);
        config_free(&cfg);
        return 1;
    }

    int exit_code = 0;
    if (adapter->init(adapter, cfg.protocol_params_json, cfg.points_json) !=
        0) {
        LOG_ERROR("sensor", "어댑터 init 실패: %s", cfg.protocol);
        exit_code = 1;
        goto cleanup;
    }
    if (adapter->connect(adapter) != 0) {
        LOG_ERROR("sensor", "어댑터 connect 실패: %s", cfg.protocol);
        exit_code = 1;
        goto cleanup;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    LOG_INFO("sensor",
             "demo start device=%s protocol=%s cycle_ms=%d state=%s",
             cfg.device_name, cfg.protocol, cfg.cycle_ms, state_path);

    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    uint16_t seq = 0;
    int cycle_ms = cfg.cycle_ms > 0 ? cfg.cycle_ms : 8;

    while (!g_stop) {
        seq++;
        /* ~20.0 + 15.0 * triangle on seq, 0.1 °C units */
        uint16_t temp_x10 = (uint16_t)(200 + (seq % 151));
        uint16_t hum_x10 = (uint16_t)(300 + ((seq * 3) % 401));

        char barcode[33];
        memset(barcode, 0, sizeof(barcode));
        snprintf(barcode, sizeof(barcode), "BETA-PN-IN/%06u",
                 (unsigned)(seq % 1000000u));

        uint8_t bar_raw[32];
        memset(bar_raw, 0, sizeof(bar_raw));
        memcpy(bar_raw, barcode, strnlen(barcode, 32));

        uint8_t tbytes[2], hbytes[2], sbytes[2];
        wr_be16(tbytes, temp_x10);
        wr_be16(hbytes, hum_x10);
        wr_be16(sbytes, seq);

        (void)write_named(adapter, "barcode_value", bar_raw, sizeof(bar_raw));
        (void)write_named(adapter, "temperature", tbytes, sizeof(tbytes));
        (void)write_named(adapter, "humidity", hbytes, sizeof(hbytes));
        (void)write_named(adapter, "seq", sbytes, sizeof(sbytes));
        (void)write_named(adapter, "status_word", sbytes, sizeof(sbytes));

        if ((seq % 4) == 0) {
            write_state_file(state_path, barcode, temp_x10, hum_x10, seq);
        }

        adapter->poll_cycle(adapter);

        timespec_add_ms(&next, cycle_ms);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec < next.tv_sec ||
            (now.tv_sec == next.tv_sec && now.tv_nsec < next.tv_nsec)) {
            int rc;
            do {
                rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next,
                                     NULL);
            } while (rc == EINTR && !g_stop);
        } else {
            next = now;
        }
    }

    LOG_INFO("sensor", "종료 중 seq=%u", (unsigned)seq);
    adapter->disconnect(adapter);

cleanup:
    adapter->destroy(adapter);
    config_free(&cfg);
    return exit_code;
}
