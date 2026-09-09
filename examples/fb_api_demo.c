#include "fb_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Minimal app using only include/fb_api.h (no adapter headers).
 * Usage: fb_api_demo <config.json>
 */
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <config.json>\n", argv[0]);
        return 1;
    }

    fb_runtime_t *rt = NULL;
    int rc = fb_open(argv[1], &rt);
    if (rc != FB_OK) {
        fprintf(stderr, "fb_open: %s\n", fb_strerror(rc));
        return 1;
    }

    fb_health_t h;
    if (fb_health(rt, &h) == FB_OK) {
        printf("protocol=%s device=%s cycle_ms=%d connected=%d gen=%u\n",
               h.protocol, h.device_name, h.cycle_ms, h.connected,
               h.generation);
    }

    size_t n = 0;
    (void)fb_list_points(rt, NULL, 0, &n);
    fb_point_info_t *pts = NULL;
    if (n > 0) {
        pts = calloc(n, sizeof(*pts));
        if (!pts) {
            fb_close(rt);
            return 1;
        }
        (void)fb_list_points(rt, pts, n, &n);
        printf("points=%zu\n", n);
        for (size_t i = 0; i < n; i++) {
            printf("  %s access=%d type=%s native=%d\n", pts[i].name,
                   (int)pts[i].access, pts[i].data_type, (int)pts[i].native_type);
        }
    }

    if (argc >= 3) {
        const char *name = argv[2];
        if (argc >= 4) {
            rc = fb_write_string(rt, name, argv[3]);
            if (rc != FB_OK) {
                float f = (float)atof(argv[3]);
                rc = fb_write_f32(rt, name, f);
            }
            printf("write %s -> %s\n", name, fb_strerror(rc));
        }
        char buf[128];
        rc = fb_read_string(rt, name, buf, sizeof(buf));
        if (rc == FB_OK) {
            printf("read %s = \"%s\"\n", name, buf);
        } else {
            float f = 0;
            rc = fb_read_f32(rt, name, &f);
            if (rc == FB_OK) {
                printf("read %s = %f\n", name, (double)f);
            } else {
                printf("read %s -> %s\n", name, fb_strerror(rc));
            }
        }
    }

    (void)fb_poll(rt);
    free(pts);
    fb_close(rt);
    return 0;
}
