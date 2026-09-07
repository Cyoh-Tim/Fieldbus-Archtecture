#include "modbus_adapter.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>
#include <modbus.h>

#include "logger.h"

#define MAX_POINTS 128
#define MAX_NAME 64

typedef enum {
    REG_HOLDING,
    REG_INPUT,
    REG_COIL,
    REG_DISCRETE,
} modbus_reg_type_t;

typedef struct {
    char name[MAX_NAME];
    modbus_reg_type_t reg_type;
    int start;
    char access[8]; /* "read" | "write" */
} modbus_point_t;

typedef struct {
    modbus_t *mb;
    char ip[64];
    int port;
    int unit_id;

    modbus_point_t points[MAX_POINTS];
    int point_count;

    int connected;
    char last_error[128];
} modbus_ctx_t;

static modbus_reg_type_t parse_reg_type(const char *s)
{
    if (!s) return REG_HOLDING;
    if (strcmp(s, "input") == 0) return REG_INPUT;
    if (strcmp(s, "coil") == 0) return REG_COIL;
    if (strcmp(s, "discrete") == 0) return REG_DISCRETE;
    return REG_HOLDING;
}

static int mb_init(protocol_adapter_t *self, const char *protocol_params_json,
                    const char *points_json)
{
    modbus_ctx_t *ctx = calloc(1, sizeof(modbus_ctx_t));
    if (!ctx) return -ENOMEM;
    ctx->port = 502;
    ctx->unit_id = 1;

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(params, "ip");
        if (cJSON_IsString(ip)) {
            snprintf(ctx->ip, sizeof(ctx->ip), "%s", ip->valuestring);
        }
        cJSON *port = cJSON_GetObjectItemCaseSensitive(params, "port");
        if (cJSON_IsNumber(port)) ctx->port = port->valueint;
        cJSON *unit_id = cJSON_GetObjectItemCaseSensitive(params, "unit_id");
        if (cJSON_IsNumber(unit_id)) ctx->unit_id = unit_id->valueint;
        cJSON_Delete(params);
    }

    if (!ctx->ip[0]) {
        LOG_ERROR("modbus", "protocol_params.ip 누락");
        free(ctx);
        return -EINVAL;
    }

    cJSON *points = cJSON_Parse(points_json);
    if (cJSON_IsArray(points)) {
        cJSON *p;
        cJSON_ArrayForEach(p, points)
        {
            if (ctx->point_count >= MAX_POINTS) break;
            cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
            cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
            cJSON *address = cJSON_GetObjectItemCaseSensitive(p, "address");
            cJSON *mb_addr =
                address ? cJSON_GetObjectItemCaseSensitive(address, "modbus")
                        : NULL;
            if (!cJSON_IsString(name) || !mb_addr) {
                LOG_WARN("modbus",
                         "포인트 정의 누락(name/address.modbus) - 건너뜀");
                continue;
            }
            modbus_point_t *pt = &ctx->points[ctx->point_count++];
            snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
            snprintf(pt->access, sizeof(pt->access), "%s",
                     cJSON_IsString(access) ? access->valuestring : "read");
            cJSON *reg_type =
                cJSON_GetObjectItemCaseSensitive(mb_addr, "register_type");
            cJSON *start = cJSON_GetObjectItemCaseSensitive(mb_addr, "start");
            pt->reg_type = parse_reg_type(
                cJSON_IsString(reg_type) ? reg_type->valuestring : NULL);
            pt->start = cJSON_IsNumber(start) ? start->valueint : 0;
        }
        cJSON_Delete(points);
    }

    LOG_INFO("modbus", "init 완료: %s:%d unit_id=%d points=%d", ctx->ip,
              ctx->port, ctx->unit_id, ctx->point_count);

    self->ctx = ctx;
    return 0;
}

static int mb_connect(protocol_adapter_t *self)
{
    modbus_ctx_t *ctx = self->ctx;
    ctx->mb = modbus_new_tcp(ctx->ip, ctx->port);
    if (!ctx->mb) {
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "modbus_new_tcp 실패");
        return -1;
    }
    modbus_set_slave(ctx->mb, ctx->unit_id);
    if (modbus_connect(ctx->mb) == -1) {
        snprintf(ctx->last_error, sizeof(ctx->last_error), "connect 실패: %s",
                 modbus_strerror(errno));
        LOG_ERROR("modbus", "%s", ctx->last_error);
        return -1;
    }
    ctx->connected = 1;
    LOG_INFO("modbus", "연결 성공 %s:%d", ctx->ip, ctx->port);
    return 0;
}

static void mb_disconnect(protocol_adapter_t *self)
{
    modbus_ctx_t *ctx = self->ctx;
    if (ctx->mb) {
        modbus_close(ctx->mb);
        modbus_free(ctx->mb);
        ctx->mb = NULL;
    }
    ctx->connected = 0;
}

static void mb_poll_cycle(protocol_adapter_t *self)
{
    /* TODO: 여기서 등록된 read 포인트를 주기적으로 스캔해 캐시에 반영.
     * 지금은 요청 시점에 read_point 에서 직접 읽는 방식으로 단순화되어 있음.
     * 실제 배포 시 사이클마다 일괄 read 후 캐싱하도록 확장 권장. */
    (void)self;
}

static modbus_point_t *find_point(modbus_ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->point_count; i++) {
        if (strcmp(ctx->points[i].name, name) == 0) return &ctx->points[i];
    }
    return NULL;
}

static int mb_read_point(protocol_adapter_t *self, const char *point_name,
                          point_value_t *out)
{
    modbus_ctx_t *ctx = self->ctx;
    modbus_point_t *pt = find_point(ctx, point_name);
    if (!pt || !ctx->mb) return -ENOENT;

    int rc = -1;
    switch (pt->reg_type) {
    case REG_HOLDING: {
        uint16_t reg;
        rc = modbus_read_registers(ctx->mb, pt->start, 1, &reg);
        if (rc == 1) {
            out->data = malloc(2);
            out->data[0] = reg >> 8;
            out->data[1] = reg & 0xff;
            out->len = 2;
        }
        break;
    }
    case REG_INPUT: {
        uint16_t reg;
        rc = modbus_read_input_registers(ctx->mb, pt->start, 1, &reg);
        if (rc == 1) {
            out->data = malloc(2);
            out->data[0] = reg >> 8;
            out->data[1] = reg & 0xff;
            out->len = 2;
        }
        break;
    }
    case REG_COIL: {
        uint8_t bit;
        rc = modbus_read_bits(ctx->mb, pt->start, 1, &bit);
        if (rc == 1) {
            out->data = malloc(1);
            out->data[0] = bit;
            out->len = 1;
        }
        break;
    }
    case REG_DISCRETE: {
        uint8_t bit;
        rc = modbus_read_input_bits(ctx->mb, pt->start, 1, &bit);
        if (rc == 1) {
            out->data = malloc(1);
            out->data[0] = bit;
            out->len = 1;
        }
        break;
    }
    }
    return rc < 0 ? -1 : 0;
}

static int mb_write_point(protocol_adapter_t *self, const char *point_name,
                           const point_value_t *value)
{
    modbus_ctx_t *ctx = self->ctx;
    modbus_point_t *pt = find_point(ctx, point_name);
    if (!pt || !ctx->mb) return -ENOENT;

    if (pt->reg_type == REG_HOLDING && value->len >= 2) {
        uint16_t reg = (value->data[0] << 8) | value->data[1];
        return modbus_write_register(ctx->mb, pt->start, reg) == 1 ? 0 : -1;
    }
    if (pt->reg_type == REG_COIL && value->len >= 1) {
        return modbus_write_bit(ctx->mb, pt->start,
                                 value->data[0] ? 1 : 0) == 1
                   ? 0
                   : -1;
    }
    LOG_WARN("modbus", "point %s 는 write 대상이 아니거나 값 크기 불일치",
             point_name);
    return -EINVAL;
}

static int mb_health(protocol_adapter_t *self, int *connected, char *err_buf,
                      size_t err_buf_len)
{
    modbus_ctx_t *ctx = self->ctx;
    *connected = ctx->connected;
    snprintf(err_buf, err_buf_len, "%s", ctx->last_error);
    return 0;
}

static void mb_destroy(protocol_adapter_t *self)
{
    if (!self) return;
    modbus_ctx_t *ctx = self->ctx;
    if (ctx) {
        if (ctx->mb) {
            modbus_close(ctx->mb);
            modbus_free(ctx->mb);
        }
        free(ctx);
    }
    free(self);
}

protocol_adapter_t *modbus_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(protocol_adapter_t));
    if (!a) return NULL;
    a->name = "modbus_tcp";
    a->init = mb_init;
    a->connect = mb_connect;
    a->disconnect = mb_disconnect;
    a->poll_cycle = mb_poll_cycle;
    a->read_point = mb_read_point;
    a->write_point = mb_write_point;
    a->health = mb_health;
    a->destroy = mb_destroy;
    return a;
}
