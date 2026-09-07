#include "config_loader.h"

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

static char *read_whole_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[read] = '\0';
    return buf;
}

int config_load(const char *path, daemon_config_t *out)
{
    memset(out, 0, sizeof(*out));
    out->cycle_ms = 8; /* 기본값 */

    char *raw = read_whole_file(path);
    if (!raw) {
        fprintf(stderr, "[config] 파일을 열 수 없음: %s\n", path);
        return -1;
    }

    cJSON *root = cJSON_Parse(raw);
    free(raw);
    if (!root) {
        fprintf(stderr, "[config] JSON 파싱 실패: %s\n", cJSON_GetErrorPtr());
        return -1;
    }

    cJSON *protocol = cJSON_GetObjectItemCaseSensitive(root, "protocol");
    if (!cJSON_IsString(protocol) || !protocol->valuestring[0]) {
        fprintf(stderr, "[config] \"protocol\" 필드가 없거나 문자열이 아님\n");
        cJSON_Delete(root);
        return -1;
    }
    snprintf(out->protocol, sizeof(out->protocol), "%s", protocol->valuestring);

    cJSON *device = cJSON_GetObjectItemCaseSensitive(root, "device");
    if (cJSON_IsObject(device)) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(device, "name");
        if (cJSON_IsString(name)) {
            snprintf(out->device_name, sizeof(out->device_name), "%s",
                     name->valuestring);
        }
        cJSON *role = cJSON_GetObjectItemCaseSensitive(device, "role");
        if (cJSON_IsString(role)) {
            snprintf(out->role, sizeof(out->role), "%s", role->valuestring);
        }
    }

    cJSON *cycle_ms = cJSON_GetObjectItemCaseSensitive(root, "cycle_ms");
    if (cJSON_IsNumber(cycle_ms)) {
        out->cycle_ms = cycle_ms->valueint;
    }

    cJSON *protocol_params =
        cJSON_GetObjectItemCaseSensitive(root, "protocol_params");
    cJSON *points = cJSON_GetObjectItemCaseSensitive(root, "points");

    /* protocol_params / points 는 없어도 파싱 자체는 성공시키고,
     * 어댑터의 init()이 필요한 필드 누락을 자체적으로 검증/보고하게 한다. */
    out->protocol_params_json =
        protocol_params ? cJSON_PrintUnformatted(protocol_params)
                         : strdup("{}");
    out->points_json = points ? cJSON_PrintUnformatted(points) : strdup("[]");

    cJSON_Delete(root);
    return 0;
}

void config_free(daemon_config_t *cfg)
{
    if (!cfg) {
        return;
    }
    free(cfg->protocol_params_json);
    free(cfg->points_json);
    cfg->protocol_params_json = NULL;
    cfg->points_json = NULL;
}
