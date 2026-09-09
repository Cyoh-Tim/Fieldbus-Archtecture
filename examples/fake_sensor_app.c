#include "fb_api.h"

#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Equipment-free fake sensor using only include/fb_api.h.
 *
 * Publishes PLC-read points (barcode + temperature) with fb_write_*,
 * then reads them back with fb_read_* so the values are visibly stored.
 * Default config is a Modbus TCP server on loopback — no PLC, no NIC,
 * no CAP_NET_RAW.
 *
 * Usage:
 *   fake_sensor_app [--once | --seconds N | --cycles N] [config.json]
 */

static volatile int g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--once | --seconds N | --cycles N] [config.json]\n"
            "  --once       publish + readback once, then exit (script/CI)\n"
            "  --seconds N  publish every 1s for N seconds (SIGINT also stops)\n"
            "  --cycles N   publish every cycle_ms for N cycles\n"
            "  default config: config/example.fake_sensor.json\n",
            argv0);
}

static const char *access_name(fb_access_t a)
{
    switch (a) {
    case FB_ACCESS_PLC_READ:
        return "PLC_READ (app publishes)";
    case FB_ACCESS_PLC_WRITE:
        return "PLC_WRITE (app read-only)";
    case FB_ACCESS_READWRITE:
        return "READWRITE";
    default:
        return "UNKNOWN";
    }
}

static void sleep_ms(int ms)
{
    if (ms <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0) {
        if (g_stop) {
            return;
        }
    }
}

static int publish_and_readback(fb_runtime_t *rt, unsigned seq, int do_poll)
{
    char barcode[32];
    char got_barcode[64];
    float temp;
    float got_temp = 0.0f;
    int rc;

    snprintf(barcode, sizeof(barcode), "LOT-A-%04u", seq);
    /* Tenths so scale 0.1 round-trips exactly (same as tests/test_fb_api.c). */
    temp = 25.5f + (float)(seq % 5);

    printf("write barcode_value=\"%s\" temperature=%.1f\n", barcode,
           (double)temp);

    rc = fb_write_string(rt, "barcode_value", barcode);
    if (rc != FB_OK) {
        fprintf(stderr, "fb_write_string(barcode_value): %s\n",
                fb_strerror(rc));
        return 1;
    }
    rc = fb_write_f32(rt, "temperature", temp);
    if (rc != FB_OK) {
        fprintf(stderr, "fb_write_f32(temperature): %s\n", fb_strerror(rc));
        return 1;
    }

    if (do_poll) {
        rc = fb_poll(rt);
        if (rc != FB_OK) {
            fprintf(stderr, "fb_poll: %s\n", fb_strerror(rc));
            return 1;
        }
    }

    memset(got_barcode, 0, sizeof(got_barcode));
    rc = fb_read_string(rt, "barcode_value", got_barcode, sizeof(got_barcode));
    if (rc != FB_OK) {
        fprintf(stderr, "fb_read_string(barcode_value): %s\n", fb_strerror(rc));
        return 1;
    }
    rc = fb_read_f32(rt, "temperature", &got_temp);
    if (rc != FB_OK) {
        fprintf(stderr, "fb_read_f32(temperature): %s\n", fb_strerror(rc));
        return 1;
    }

    printf("read  barcode_value=\"%s\" temperature=%.1f  (same session)\n",
           got_barcode, (double)got_temp);

    if (strcmp(got_barcode, barcode) != 0) {
        fprintf(stderr, "readback mismatch: barcode expected \"%s\" got \"%s\"\n",
                barcode, got_barcode);
        return 1;
    }
    if (fabsf(got_temp - temp) > 0.05f) {
        fprintf(stderr, "readback mismatch: temperature expected %.1f got %.1f\n",
                (double)temp, (double)got_temp);
        return 1;
    }
    printf("ok    values are readable via fb_read_*\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *config = "config/example.fake_sensor.json";
    int once = 0;
    int seconds = 0;
    int cycles = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--once") == 0) {
            once = 1;
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
            if (seconds <= 0) {
                fprintf(stderr, "--seconds needs a positive integer\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--cycles") == 0 && i + 1 < argc) {
            cycles = atoi(argv[++i]);
            if (cycles <= 0) {
                fprintf(stderr, "--cycles needs a positive integer\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        } else {
            config = argv[i];
        }
    }

    printf("=== fake sensor (no PLC, no NIC) ===\n");
    printf("config=%s\n", config);
    printf("access: app writes PLC-read points; PLC would FC03 them.\n");
    printf("this is not PI / ODVA / Modbus.org certification.\n");

    fb_runtime_t *rt = NULL;
    int rc = fb_open(config, &rt);
    if (rc != FB_OK) {
        fprintf(stderr, "fb_open: %s\n", fb_strerror(rc));
        return 1;
    }

    fb_health_t h;
    memset(&h, 0, sizeof(h));
    if (fb_health(rt, &h) == FB_OK) {
        printf("protocol=%s device=%s cycle_ms=%d connected=%d gen=%u\n",
               h.protocol, h.device_name, h.cycle_ms, h.connected,
               h.generation);
    }

    size_t n = 0;
    (void)fb_list_points(rt, NULL, 0, &n);
    if (n > 0) {
        fb_point_info_t *pts = calloc(n, sizeof(*pts));
        if (pts) {
            (void)fb_list_points(rt, pts, n, &n);
            printf("points=%zu\n", n);
            for (size_t p = 0; p < n; p++) {
                printf("  %s access=%s type=%s native=%d\n", pts[p].name,
                       access_name(pts[p].access), pts[p].data_type,
                       (int)pts[p].native_type);
            }
            free(pts);
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int cycle_ms = h.cycle_ms > 0 ? h.cycle_ms : 8;
    unsigned seq = 1;
    int failed = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (once) {
        failed = publish_and_readback(rt, seq, 1);
        fb_close(rt);
        return failed;
    }

    /* Background cycle thread; main publishes and readbacks. */
    rc = fb_start(rt);
    if (rc != FB_OK) {
        fprintf(stderr, "fb_start: %s\n", fb_strerror(rc));
        fb_close(rt);
        return 1;
    }

    printf("running (Ctrl+C to stop)");
    if (seconds > 0) {
        printf(" for %d s", seconds);
    }
    if (cycles > 0) {
        printf(" for %d cycles", cycles);
    }
    printf("\n");

    int interval_ms = (cycles > 0) ? cycle_ms : 1000;
    unsigned done = 0;
    while (!g_stop) {
        if (publish_and_readback(rt, seq, 0) != 0) {
            failed = 1;
            break;
        }
        seq++;
        done++;
        if (cycles > 0 && (int)done >= cycles) {
            break;
        }
        if (seconds > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            int elapsed = (int)(now.tv_sec - t0.tv_sec);
            if (elapsed >= seconds) {
                break;
            }
        }
        sleep_ms(interval_ms);
    }

    (void)fb_stop(rt);
    fb_close(rt);
    printf("shutdown clean\n");
    return failed;
}
