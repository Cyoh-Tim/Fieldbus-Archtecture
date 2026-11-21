#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

typedef struct daemon_config {
    char protocol[64];   /* 예: "modbus_tcp" */
    char device_name[128];
    char role[32];       /* "server" | "client" 등, 어댑터가 해석 */
    int cycle_ms;
    /* 지터 편차가 이 값(µs)보다 크면 초과로 센다. 키를 생략하면 100.
     * 음수는 0. 지터 로그는 1초에 한 번 요약한다. 마감 놓침
     * (wake + elapsed > cycle) 은 이 값과 상관없이 사이클마다 경고한다. */
    int cycle_warn_us;

    /* 아래 두 필드는 cJSON_PrintUnformatted 로 직렬화된 원본 JSON 문자열.
     * 코어는 내용을 해석하지 않고 그대로 adapter->init() 에 전달한다.
     * 호출자가 config_free() 로 해제해야 한다. */
    char *protocol_params_json;
    char *points_json;
} daemon_config_t;

/* 성공 0, 실패 시 음수. 실패 시 LOG_ERROR("config", ...) 로
 * stderr 에 [timestamp][ERROR][config] 원인 로그를 출력한다. */
int config_load(const char *path, daemon_config_t *out);
void config_free(daemon_config_t *cfg);

#endif /* CONFIG_LOADER_H */
