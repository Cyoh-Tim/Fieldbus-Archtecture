#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

typedef struct daemon_config {
    char protocol[64];   /* 예: "modbus_tcp" */
    char device_name[128];
    char role[32];       /* "server" | "client" 등, 어댑터가 해석 */
    int cycle_ms;

    /* 아래 두 필드는 cJSON_PrintUnformatted 로 직렬화된 원본 JSON 문자열.
     * 코어는 내용을 해석하지 않고 그대로 adapter->init() 에 전달한다.
     * 호출자가 config_free() 로 해제해야 한다. */
    char *protocol_params_json;
    char *points_json;
} daemon_config_t;

/* 성공 0, 실패 시 음수. 실패 시 stderr 에 원인(누락 필드 등) 로그 출력 */
int config_load(const char *path, daemon_config_t *out);
void config_free(daemon_config_t *cfg);

#endif /* CONFIG_LOADER_H */
