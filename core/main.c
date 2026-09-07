#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "adapter_registry.h"
#include "config_loader.h"
#include "logger.h"
#include "protocol_adapter.h"
#include "scheduler.h"

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

    daemon_config_t cfg;
    if (config_load(argv[1], &cfg) != 0) {
        LOG_ERROR("main", "설정 로드 실패: %s", argv[1]);
        return 1;
    }

    LOG_INFO("main", "device=%s protocol=%s cycle_ms=%d", cfg.device_name,
              cfg.protocol, cfg.cycle_ms);

    adapter_ctor_fn ctor = adapter_registry_lookup(cfg.protocol);
    if (!ctor) {
        LOG_ERROR("main", "알 수 없는 protocol: \"%s\" (레지스트리에 없음)",
                   cfg.protocol);
        config_free(&cfg);
        return 1;
    }

    protocol_adapter_t *adapter = ctor();
    if (!adapter) {
        LOG_ERROR("main", "어댑터 생성 실패: %s", cfg.protocol);
        config_free(&cfg);
        return 1;
    }

    int exit_code = 0;

    if (adapter->init(adapter, cfg.protocol_params_json, cfg.points_json) != 0) {
        LOG_ERROR("main", "어댑터 init 실패: %s", cfg.protocol);
        exit_code = 1;
        goto cleanup;
    }

    if (adapter->connect(adapter) != 0) {
        LOG_ERROR("main", "어댑터 connect 실패: %s", cfg.protocol);
        exit_code = 1;
        goto cleanup;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    LOG_INFO("main", "데몬 시작 (Ctrl+C 로 종료)");
    scheduler_run(adapter, cfg.cycle_ms, &g_stop);

    LOG_INFO("main", "종료 중...");
    adapter->disconnect(adapter);

cleanup:
    adapter->destroy(adapter);
    config_free(&cfg);
    return exit_code;
}
