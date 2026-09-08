#include "modbus_adapter.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
#include "mb_stack.h"

#define MAX_POINTS 128
#define MAX_NAME 64

typedef struct {
    char name[MAX_NAME];
    char access[8]; /* "read" | "write" — PLC 관점 (PROFINET과 동일) */
    mb_reg_type_t reg_type;
    uint16_t start;    /* 0-based protocol address */
    uint16_t quantity; /* registers or bits */
    size_t byte_len;   /* raw bytes exposed to core */
} modbus_point_t;

typedef struct {
    mb_stack_t *stack;
    mb_role_t role;
    modbus_point_t points[MAX_POINTS];
    int point_count;
    char last_error[128];
} modbus_ctx_t;

static mb_reg_type_t parse_reg_type(const char *s)
{
    if (!s) {
        return MB_REG_HOLDING;
    }
    if (strcmp(s, "input") == 0) {
        return MB_REG_INPUT;
    }
    if (strcmp(s, "coil") == 0) {
        return MB_REG_COIL;
    }
    if (strcmp(s, "discrete") == 0) {
        return MB_REG_DISCRETE;
    }
    return MB_REG_HOLDING;
}

/*
 * 통신 가이드 주소 → 0-based protocol address.
 * 비전문가가 문서의 40001 / 30001 / 10001 / 00001 를 그대로 넣어도 된다.
 */
static uint16_t normalize_start(mb_reg_type_t type, int start)
{
    if (start < 0) {
        return 0;
    }
    switch (type) {
    case MB_REG_HOLDING:
        if (start >= 40001) {
            return (uint16_t)(start - 40001);
        }
        if (start >= 4000 && start < 5000) {
            return (uint16_t)(start - 4000);
        }
        break;
    case MB_REG_INPUT:
        if (start >= 30001) {
            return (uint16_t)(start - 30001);
        }
        if (start >= 3000 && start < 4000) {
            return (uint16_t)(start - 3000);
        }
        break;
    case MB_REG_DISCRETE:
        if (start >= 10001) {
            return (uint16_t)(start - 10001);
        }
        if (start >= 1000 && start < 2000) {
            return (uint16_t)(start - 1000);
        }
        break;
    case MB_REG_COIL:
        if (start >= 1 && start < 10000) {
            /* 1-based coil numbering common in manuals */
            return (uint16_t)(start - 1);
        }
        break;
    }
    return (uint16_t)start;
}

static uint16_t default_quantity(mb_reg_type_t type, const char *data_type,
                                 int length, int quantity_field)
{
    if (quantity_field > 0) {
        return (uint16_t)quantity_field;
    }
    if (type == MB_REG_COIL || type == MB_REG_DISCRETE) {
        return 1;
    }
    if (data_type && strcmp(data_type, "string") == 0) {
        int len = length > 0 ? length : 2;
        return (uint16_t)((len + 1) / 2);
    }
    if (data_type && (strcmp(data_type, "uint32") == 0 ||
                      strcmp(data_type, "int32") == 0 ||
                      strcmp(data_type, "float32") == 0)) {
        return 2;
    }
    if (data_type && strcmp(data_type, "bool") == 0) {
        return 1;
    }
    if (length > 0) {
        return (uint16_t)((length + 1) / 2);
    }
    return 1;
}

static size_t point_byte_len(mb_reg_type_t type, uint16_t quantity, int length,
                             const char *data_type)
{
    if (type == MB_REG_COIL || type == MB_REG_DISCRETE) {
        return quantity;
    }
    if (length > 0) {
        return (size_t)length;
    }
    if (data_type && strcmp(data_type, "string") == 0) {
        return (size_t)quantity * 2u;
    }
    return (size_t)quantity * 2u;
}

static int parse_points(modbus_ctx_t *ctx, const char *points_json)
{
    cJSON *arr = cJSON_Parse(points_json);
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return 0;
    }
    cJSON *p;
    cJSON_ArrayForEach(p, arr)
    {
        if (ctx->point_count >= MAX_POINTS) {
            break;
        }
        cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        cJSON *data_type = cJSON_GetObjectItemCaseSensitive(p, "data_type");
        cJSON *length = cJSON_GetObjectItemCaseSensitive(p, "length");
        cJSON *address = cJSON_GetObjectItemCaseSensitive(p, "address");
        cJSON *mb =
            address ? cJSON_GetObjectItemCaseSensitive(address, "modbus")
                    : NULL;
        if (!cJSON_IsString(name) || !cJSON_IsObject(mb)) {
            LOG_WARN("modbus",
                     "포인트 정의 누락(name/address.modbus) - 건너뜀");
            continue;
        }
        modbus_point_t *pt = &ctx->points[ctx->point_count];
        memset(pt, 0, sizeof(*pt));
        snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
        snprintf(pt->access, sizeof(pt->access), "%s",
                 cJSON_IsString(access) ? access->valuestring : "read");

        cJSON *reg_type = cJSON_GetObjectItemCaseSensitive(mb, "register_type");
        cJSON *start = cJSON_GetObjectItemCaseSensitive(mb, "start");
        cJSON *qty = cJSON_GetObjectItemCaseSensitive(mb, "quantity");
        pt->reg_type = parse_reg_type(
            cJSON_IsString(reg_type) ? reg_type->valuestring : NULL);
        int start_raw = cJSON_IsNumber(start) ? start->valueint : 0;
        pt->start = normalize_start(pt->reg_type, start_raw);
        pt->quantity = default_quantity(
            pt->reg_type,
            cJSON_IsString(data_type) ? data_type->valuestring : NULL,
            cJSON_IsNumber(length) ? length->valueint : 0,
            cJSON_IsNumber(qty) ? qty->valueint : 0);
        pt->byte_len = point_byte_len(
            pt->reg_type, pt->quantity,
            cJSON_IsNumber(length) ? length->valueint : 0,
            cJSON_IsString(data_type) ? data_type->valuestring : NULL);
        ctx->point_count++;
    }
    cJSON_Delete(arr);
    return 0;
}

static int mb_init(protocol_adapter_t *self, const char *protocol_params_json,
                   const char *points_json)
{
    modbus_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -ENOMEM;
    }

    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.port = MB_TCP_DEFAULT_PORT;
    cfg.unit_id = MB_UNIT_ID_DEFAULT;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "0.0.0.0");

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        cJSON *role = cJSON_GetObjectItemCaseSensitive(params, "role");
        if (cJSON_IsString(role) && strcmp(role->valuestring, "client") == 0) {
            cfg.role = MB_ROLE_CLIENT;
        }
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(params, "ip");
        if (cJSON_IsString(ip)) {
            if (cfg.role == MB_ROLE_CLIENT) {
                snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "%s",
                         ip->valuestring);
            } else {
                snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s",
                         ip->valuestring);
            }
        }
        cJSON *bind_ip = cJSON_GetObjectItemCaseSensitive(params, "bind_ip");
        if (cJSON_IsString(bind_ip) && cfg.role == MB_ROLE_SERVER) {
            snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s",
                     bind_ip->valuestring);
        }
        cJSON *port = cJSON_GetObjectItemCaseSensitive(params, "port");
        if (cJSON_IsNumber(port)) {
            cfg.port = port->valueint;
        }
        cJSON *unit_id = cJSON_GetObjectItemCaseSensitive(params, "unit_id");
        if (cJSON_IsNumber(unit_id)) {
            cfg.unit_id = unit_id->valueint;
        }
        cJSON_Delete(params);
    }

    if (cfg.role == MB_ROLE_CLIENT && !cfg.remote_ip[0]) {
        LOG_ERROR("modbus",
                  "client 역할이면 protocol_params.ip (원격 슬레이브) 필요");
        free(ctx);
        return -EINVAL;
    }

    parse_points(ctx, points_json);
    ctx->role = cfg.role;
    ctx->stack = mb_stack_create(&cfg);
    if (!ctx->stack) {
        free(ctx);
        return -ENOMEM;
    }
    self->ctx = ctx;
    LOG_INFO("modbus", "init %s port=%d unit_id=%d points=%d (자체 스택)",
             cfg.role == MB_ROLE_SERVER ? "server" : "client", cfg.port,
             cfg.unit_id, ctx->point_count);
    return 0;
}

static int mb_connect(protocol_adapter_t *self)
{
    modbus_ctx_t *ctx = self->ctx;
    int rc = mb_stack_start(ctx->stack);
    if (rc != 0) {
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "stack start failed (%d)", rc);
        LOG_ERROR("modbus", "%s", ctx->last_error);
        return rc;
    }
    return 0;
}

static void mb_disconnect(protocol_adapter_t *self)
{
    modbus_ctx_t *ctx = self->ctx;
    if (ctx && ctx->stack) {
        mb_stack_stop(ctx->stack);
    }
}

static void mb_poll_cycle(protocol_adapter_t *self)
{
    modbus_ctx_t *ctx = self->ctx;
    if (!ctx || !ctx->stack) {
        return;
    }
    mb_stack_poll(ctx->stack);

    /* Client: batch-refresh all PLC-readable ("read") and PLC-writable
     * ("write") points into the local cache each cycle. */
    if (ctx->role != MB_ROLE_CLIENT) {
        return;
    }
    for (int i = 0; i < ctx->point_count; i++) {
        modbus_point_t *pt = &ctx->points[i];
        int rc =
            mb_stack_client_read(ctx->stack, pt->reg_type, pt->start,
                                 pt->quantity);
        if (rc != 0) {
            snprintf(ctx->last_error, sizeof(ctx->last_error),
                     "poll %s failed (%d)", pt->name, rc);
            LOG_WARN("modbus", "%s", ctx->last_error);
        }
    }
}

static modbus_point_t *find_point(modbus_ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->point_count; i++) {
        if (strcmp(ctx->points[i].name, name) == 0) {
            return &ctx->points[i];
        }
    }
    return NULL;
}

static int mb_read_point(protocol_adapter_t *self, const char *point_name,
                         point_value_t *out)
{
    modbus_ctx_t *ctx = self->ctx;
    modbus_point_t *pt = find_point(ctx, point_name);
    if (!pt || !out) {
        return -ENOENT;
    }

    /* Framework rule (same as PROFINET):
     * access=write → PLC writes into our map → app reads it here.
     * access=read  → also readable (app may inspect what it published). */
    size_t n = pt->byte_len;
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (!buf) {
        return -ENOMEM;
    }
    int rc = mb_stack_read_bytes(ctx->stack, pt->reg_type, pt->start, buf, n);
    if (rc != 0) {
        free(buf);
        return rc;
    }
    out->data = buf;
    out->len = n;
    return 0;
}

static int mb_write_point(protocol_adapter_t *self, const char *point_name,
                          const point_value_t *value)
{
    modbus_ctx_t *ctx = self->ctx;
    modbus_point_t *pt = find_point(ctx, point_name);
    if (!pt || !value || !value->data) {
        return -ENOENT;
    }

    size_t n = value->len;
    if (n > pt->byte_len) {
        n = pt->byte_len;
    }

    if (ctx->role == MB_ROLE_CLIENT) {
        if (pt->reg_type == MB_REG_HOLDING) {
            uint16_t qty = (uint16_t)((n + 1) / 2);
            uint16_t *regs = calloc(qty, sizeof(uint16_t));
            if (!regs) {
                return -ENOMEM;
            }
            for (uint16_t i = 0; i < qty; i++) {
                size_t off = (size_t)i * 2u;
                uint8_t hi = (off < n) ? value->data[off] : 0;
                uint8_t lo = (off + 1 < n) ? value->data[off + 1] : 0;
                regs[i] = (uint16_t)((hi << 8) | lo);
            }
            int rc = mb_stack_client_write_regs(ctx->stack, pt->start, regs, qty);
            free(regs);
            return rc;
        }
        if (pt->reg_type == MB_REG_COIL) {
            return mb_stack_client_write_bits(ctx->stack, pt->start, value->data,
                                              (uint16_t)n);
        }
        LOG_WARN("modbus", "client write 는 holding/coil 만 지원: %s",
                 point_name);
        return -EINVAL;
    }

    /* Server: publish into local map for the PLC/master to read. */
    return mb_stack_write_bytes(ctx->stack, pt->reg_type, pt->start, value->data,
                                n);
}

static int mb_health(protocol_adapter_t *self, int *connected, char *err_buf,
                     size_t err_buf_len)
{
    modbus_ctx_t *ctx = self->ctx;
    *connected = mb_stack_connected(ctx->stack);
    snprintf(err_buf, err_buf_len, "%s", ctx->last_error);
    return 0;
}

static void mb_destroy(protocol_adapter_t *self)
{
    if (!self) {
        return;
    }
    modbus_ctx_t *ctx = self->ctx;
    if (ctx) {
        mb_stack_destroy(ctx->stack);
        free(ctx);
    }
    free(self);
}

protocol_adapter_t *modbus_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
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
