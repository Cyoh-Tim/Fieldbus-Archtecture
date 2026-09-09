#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "fb_api.h"
#include "logger.h"

static volatile int g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <config.json>\n", argv[0]);
        return 1;
    }

    fb_runtime_t *rt = NULL;
    int rc = fb_open(argv[1], &rt);
    if (rc != FB_OK) {
        LOG_ERROR("main", "설정/세션 시작 실패: %s (%s)", argv[1],
                  fb_strerror(rc));
        return 1;
    }

    fb_health_t h;
    if (fb_health(rt, &h) == FB_OK) {
        LOG_INFO("main", "device=%s protocol=%s cycle_ms=%d", h.device_name,
                 h.protocol, h.cycle_ms);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    LOG_INFO("main", "데몬 시작 (Ctrl+C 로 종료)");
    fb_run(rt, &g_stop);

    LOG_INFO("main", "종료 중...");
    fb_close(rt);
    return 0;
}
