#include "modbus_adapter.h"

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
#include "mb_stack.h"

#define MAX_POINTS 128
#define MAX_NAME 64

typedef enum {
    MB_DT_UINT16 = 0,
    MB_DT_INT16,
    MB_DT_UINT32,
    MB_DT_INT32,
    MB_DT_FLOAT32,
    MB_DT_BOOL,
    MB_DT_STRING,
} mb_data_type_t;

typedef struct {
    char name[MAX_NAME];
    char access[8];
    mb_reg_type_t reg_type;
    mb_data_type_t data_type;
    uint16_t start;      /* 0-based protocol address (start+offset 반영) */
    uint16_t quantity;   /* registers or bits spanning the value */
    size_t byte_offset;  /* within the multi-byte window */
    size_t byte_len;     /* app-facing raw length */
    int bit;             /* -1 = n/a; else bit in holding/input */
    int byte_order_le;   /* 1 = little-endian bytes inside value */
    int word_order_ba;   /* 1 = swap 16-bit words for 32-bit types */
    double scale;        /* eng = raw * scale + eng_offset */
    double eng_offset;
    int apply_scale;     /* scale!=1 or eng_offset!=0 */
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

static mb_data_type_t parse_data_type(const char *s)
{
    if (!s) {
        return MB_DT_UINT16;
    }
    if (strcmp(s, "int16") == 0) {
        return MB_DT_INT16;
    }
    if (strcmp(s, "uint32") == 0) {
        return MB_DT_UINT32;
    }
    if (strcmp(s, "int32") == 0) {
        return MB_DT_INT32;
    }
    if (strcmp(s, "float32") == 0) {
        return MB_DT_FLOAT32;
    }
    if (strcmp(s, "bool") == 0) {
        return MB_DT_BOOL;
    }
    if (strcmp(s, "string") == 0) {
        return MB_DT_STRING;
    }
    return MB_DT_UINT16;
}

/*
 * 통신 가이드 주소 → 0-based.
 * zero_based=1 이면 start 를 그대로 쓴다.
 */
static uint16_t normalize_start(mb_reg_type_t type, int start, int zero_based)
{
    if (start < 0) {
        return 0;
    }
    if (zero_based) {
        return (uint16_t)start;
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
            return (uint16_t)(start - 1);
        }
        break;
    }
    return (uint16_t)start;
}

static uint16_t default_quantity(mb_reg_type_t type, mb_data_type_t dt,
                                 int length, int quantity_field, int bit)
{
    if (quantity_field > 0) {
        return (uint16_t)quantity_field;
    }
    if (type == MB_REG_COIL || type == MB_REG_DISCRETE) {
        return 1;
    }
    if (bit >= 0) {
        return 1;
    }
    switch (dt) {
    case MB_DT_STRING: {
        int len = length > 0 ? length : 2;
        return (uint16_t)((len + 1) / 2);
    }
    case MB_DT_UINT32:
    case MB_DT_INT32:
    case MB_DT_FLOAT32:
        return 2;
    case MB_DT_BOOL:
    case MB_DT_UINT16:
    case MB_DT_INT16:
    default:
        return 1;
    }
}

static size_t native_byte_len(mb_data_type_t dt, uint16_t quantity, int length,
                              mb_reg_type_t reg_type)
{
    if (reg_type == MB_REG_COIL || reg_type == MB_REG_DISCRETE) {
        return quantity;
    }
    switch (dt) {
    case MB_DT_BOOL:
        return 1;
    case MB_DT_UINT16:
    case MB_DT_INT16:
        return 2;
    case MB_DT_UINT32:
    case MB_DT_INT32:
    case MB_DT_FLOAT32:
        return 4;
    case MB_DT_STRING:
        if (length > 0) {
            return (size_t)length;
        }
        return (size_t)quantity * 2u;
    }
    return (size_t)quantity * 2u;
}

static void swap_bytes(uint8_t *p, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint8_t t = p[i];
        p[i] = p[i + 1];
        p[i + 1] = t;
    }
}

static void swap_words32(uint8_t *p)
{
    uint8_t t0 = p[0], t1 = p[1];
    p[0] = p[2];
    p[1] = p[3];
    p[2] = t0;
    p[3] = t1;
}

/* Canonical host buffer (big-endian numeric layout) <-> wire register bytes. */
static void wire_to_canonical(const modbus_point_t *pt, uint8_t *buf, size_t n)
{
    if (pt->word_order_ba && n >= 4) {
        swap_words32(buf);
    }
    if (pt->byte_order_le) {
        swap_bytes(buf, n);
    }
}

static void canonical_to_wire(const modbus_point_t *pt, uint8_t *buf, size_t n)
{
    if (pt->byte_order_le) {
        swap_bytes(buf, n);
    }
    if (pt->word_order_ba && n >= 4) {
        swap_words32(buf);
    }
}

static uint16_t be_u16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void put_be_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint32_t be_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static double decode_raw_number(const modbus_point_t *pt, const uint8_t *canon,
                                size_t n)
{
    switch (pt->data_type) {
    case MB_DT_UINT16:
        return (n >= 2) ? (double)be_u16(canon) : 0.0;
    case MB_DT_INT16:
        return (n >= 2) ? (double)(int16_t)be_u16(canon) : 0.0;
    case MB_DT_UINT32:
        return (n >= 4) ? (double)be_u32(canon) : 0.0;
    case MB_DT_INT32:
        return (n >= 4) ? (double)(int32_t)be_u32(canon) : 0.0;
    case MB_DT_FLOAT32: {
        if (n < 4) {
            return 0.0;
        }
        uint32_t u = be_u32(canon);
        float f;
        memcpy(&f, &u, sizeof(f));
        return (double)f;
    }
    case MB_DT_BOOL:
        return (n >= 1 && canon[0]) ? 1.0 : 0.0;
    default:
        return 0.0;
    }
}

static void encode_raw_number(const modbus_point_t *pt, double raw, uint8_t *canon,
                              size_t n)
{
    memset(canon, 0, n);
    switch (pt->data_type) {
    case MB_DT_UINT16:
        if (n >= 2) {
            put_be_u16(canon, (uint16_t)lround(raw));
        }
        break;
    case MB_DT_INT16:
        if (n >= 2) {
            put_be_u16(canon, (uint16_t)(int16_t)lround(raw));
        }
        break;
    case MB_DT_UINT32:
        if (n >= 4) {
            put_be_u32(canon, (uint32_t)llround(raw));
        }
        break;
    case MB_DT_INT32:
        if (n >= 4) {
            put_be_u32(canon, (uint32_t)(int32_t)llround(raw));
        }
        break;
    case MB_DT_FLOAT32:
        if (n >= 4) {
            float f = (float)raw;
            uint32_t u;
            memcpy(&u, &f, sizeof(u));
            put_be_u32(canon, u);
        }
        break;
    case MB_DT_BOOL:
        if (n >= 1) {
            canon[0] = (raw != 0.0) ? 1 : 0;
        }
        break;
    default:
        break;
    }
}

static int map_window_bytes(const modbus_point_t *pt)
{
    if (pt->reg_type == MB_REG_COIL || pt->reg_type == MB_REG_DISCRETE) {
        return (int)pt->quantity;
    }
    return (int)pt->quantity * 2;
}

static int read_map_window(mb_stack_t *stack, const modbus_point_t *pt,
                           uint8_t *wire, size_t wire_cap)
{
    size_t need = (size_t)map_window_bytes(pt);
    if (need > wire_cap) {
        return -ENOSPC;
    }
    if (pt->bit >= 0 &&
        (pt->reg_type == MB_REG_HOLDING || pt->reg_type == MB_REG_INPUT)) {
        uint16_t reg = 0;
        int rc = mb_stack_read_regs(stack, pt->reg_type, pt->start, &reg, 1);
        if (rc != 0) {
            return rc;
        }
        wire[0] = (uint8_t)((reg >> (pt->bit & 15)) & 1);
        return 0;
    }
    return mb_stack_read_bytes(stack, pt->reg_type, pt->start, wire, need);
}

static int write_map_window(mb_stack_t *stack, const modbus_point_t *pt,
                            const uint8_t *wire, size_t wire_len)
{
    if (pt->bit >= 0 && pt->reg_type == MB_REG_HOLDING) {
        uint16_t reg = 0;
        int rc = mb_stack_read_regs(stack, MB_REG_HOLDING, pt->start, &reg, 1);
        if (rc != 0) {
            return rc;
        }
        uint16_t mask = (uint16_t)(1u << (pt->bit & 15));
        if (wire_len > 0 && wire[0]) {
            reg = (uint16_t)(reg | mask);
        } else {
            reg = (uint16_t)(reg & (uint16_t)~mask);
        }
        return mb_stack_write_regs(stack, MB_REG_HOLDING, pt->start, &reg, 1);
    }
    size_t need = (size_t)map_window_bytes(pt);
    if (wire_len < need) {
        uint8_t tmp[256];
        if (need > sizeof(tmp)) {
            return -ENOSPC;
        }
        memset(tmp, 0, need);
        memcpy(tmp, wire, wire_len);
        return mb_stack_write_bytes(stack, pt->reg_type, pt->start, tmp, need);
    }
    return mb_stack_write_bytes(stack, pt->reg_type, pt->start, wire, need);
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
        cJSON *scale = cJSON_GetObjectItemCaseSensitive(p, "scale");
        cJSON *eng_off = cJSON_GetObjectItemCaseSensitive(p, "offset");
        cJSON *byte_order = cJSON_GetObjectItemCaseSensitive(p, "byte_order");
        cJSON *word_order = cJSON_GetObjectItemCaseSensitive(p, "word_order");
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
        pt->bit = -1;
        pt->scale = 1.0;
        snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
        snprintf(pt->access, sizeof(pt->access), "%s",
                 cJSON_IsString(access) ? access->valuestring : "read");
        pt->data_type = parse_data_type(
            cJSON_IsString(data_type) ? data_type->valuestring : NULL);

        if (cJSON_IsNumber(scale)) {
            pt->scale = scale->valuedouble;
        }
        if (cJSON_IsNumber(eng_off)) {
            pt->eng_offset = eng_off->valuedouble;
        }
        pt->apply_scale =
            (pt->scale != 1.0) || (pt->eng_offset != 0.0);
        if (cJSON_IsString(byte_order) &&
            strcmp(byte_order->valuestring, "little") == 0) {
            pt->byte_order_le = 1;
        }
        if (cJSON_IsString(word_order) &&
            (strcmp(word_order->valuestring, "ba") == 0 ||
             strcmp(word_order->valuestring, "BA") == 0 ||
             strcmp(word_order->valuestring, "cdab") == 0)) {
            pt->word_order_ba = 1;
        }

        cJSON *reg_type = cJSON_GetObjectItemCaseSensitive(mb, "register_type");
        cJSON *start = cJSON_GetObjectItemCaseSensitive(mb, "start");
        cJSON *addr_off = cJSON_GetObjectItemCaseSensitive(mb, "offset");
        cJSON *byte_off = cJSON_GetObjectItemCaseSensitive(mb, "byte_offset");
        cJSON *qty = cJSON_GetObjectItemCaseSensitive(mb, "quantity");
        cJSON *bit = cJSON_GetObjectItemCaseSensitive(mb, "bit");
        cJSON *zero_based = cJSON_GetObjectItemCaseSensitive(mb, "zero_based");

        pt->reg_type = parse_reg_type(
            cJSON_IsString(reg_type) ? reg_type->valuestring : NULL);
        int zb = cJSON_IsTrue(zero_based) ? 1 : 0;
        int start_raw = cJSON_IsNumber(start) ? start->valueint : 0;
        int add = cJSON_IsNumber(addr_off) ? addr_off->valueint : 0;
        uint32_t abs_addr =
            (uint32_t)normalize_start(pt->reg_type, start_raw, zb) +
            (uint32_t)add;
        if (abs_addr > 0xFFFF) {
            LOG_WARN("modbus", "point %s address overflow - 건너뜀", pt->name);
            continue;
        }
        pt->start = (uint16_t)abs_addr;
        pt->byte_offset =
            cJSON_IsNumber(byte_off) ? (size_t)byte_off->valueint : 0;
        if (cJSON_IsNumber(bit)) {
            pt->bit = bit->valueint;
        }
        pt->quantity = default_quantity(
            pt->reg_type, pt->data_type,
            cJSON_IsNumber(length) ? length->valueint : 0,
            cJSON_IsNumber(qty) ? qty->valueint : 0, pt->bit);
        pt->byte_len = native_byte_len(
            pt->data_type, pt->quantity,
            cJSON_IsNumber(length) ? length->valueint : 0, pt->reg_type);

        /* If byte_offset slices a window, expose the remaining bytes. */
        size_t win = (size_t)map_window_bytes(pt);
        if (pt->byte_offset > 0 && pt->data_type == MB_DT_STRING) {
            if (pt->byte_offset >= win) {
                LOG_WARN("modbus", "point %s byte_offset 과다 - 건너뜀",
                         pt->name);
                continue;
            }
            size_t rem = win - pt->byte_offset;
            if (pt->byte_len > rem) {
                pt->byte_len = rem;
            }
        }
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

    if (ctx->role != MB_ROLE_CLIENT) {
        return;
    }
    for (int i = 0; i < ctx->point_count; i++) {
        modbus_point_t *pt = &ctx->points[i];
        int rc = mb_stack_client_read(ctx->stack, pt->reg_type, pt->start,
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

static int extract_app_bytes(const modbus_point_t *pt, uint8_t *wire,
                             size_t wire_len, uint8_t *out, size_t out_len)
{
    size_t win = (size_t)map_window_bytes(pt);
    if (wire_len < win) {
        return -EINVAL;
    }
    if (pt->bit >= 0) {
        if (out_len < 1) {
            return -EINVAL;
        }
        out[0] = wire[0] ? 1 : 0;
        return 0;
    }
    size_t off = pt->byte_offset;
    if (off >= win) {
        return -EINVAL;
    }
    size_t avail = win - off;
    size_t n = out_len < avail ? out_len : avail;
    memcpy(out, wire + off, n);
    if (n < out_len) {
        memset(out + n, 0, out_len - n);
    }
    wire_to_canonical(pt, out, out_len);
    return 0;
}

static int merge_app_bytes(const modbus_point_t *pt, const uint8_t *app,
                           size_t app_len, uint8_t *wire, size_t wire_cap)
{
    size_t win = (size_t)map_window_bytes(pt);
    if (win > wire_cap) {
        return -ENOSPC;
    }
    memset(wire, 0, win);
    if (pt->bit >= 0) {
        wire[0] = (app_len > 0 && app[0]) ? 1 : 0;
        return 0;
    }
    uint8_t tmp[256];
    if (pt->byte_len > sizeof(tmp)) {
        return -ENOSPC;
    }
    memset(tmp, 0, pt->byte_len);
    size_t n = app_len < pt->byte_len ? app_len : pt->byte_len;
    memcpy(tmp, app, n);
    canonical_to_wire(pt, tmp, pt->byte_len);
    if (pt->byte_offset + pt->byte_len > win) {
        return -EINVAL;
    }
    memcpy(wire + pt->byte_offset, tmp, pt->byte_len);
    return 0;
}

static int mb_read_point(protocol_adapter_t *self, const char *point_name,
                         point_value_t *out)
{
    modbus_ctx_t *ctx = self->ctx;
    modbus_point_t *pt = find_point(ctx, point_name);
    if (!pt || !out) {
        return -ENOENT;
    }

    uint8_t wire[256];
    int rc = read_map_window(ctx->stack, pt, wire, sizeof(wire));
    if (rc != 0) {
        return rc;
    }

    size_t n = pt->byte_len;
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (!buf) {
        return -ENOMEM;
    }
    rc = extract_app_bytes(pt, wire, (size_t)map_window_bytes(pt), buf, n);
    if (rc != 0) {
        free(buf);
        return rc;
    }

    if (pt->apply_scale && pt->data_type != MB_DT_STRING) {
        double raw = decode_raw_number(pt, buf, n);
        double eng = raw * pt->scale + pt->eng_offset;
        /* Engineering value always returned as float32 when scale/offset set. */
        free(buf);
        buf = malloc(4);
        if (!buf) {
            return -ENOMEM;
        }
        float f = (float)eng;
        uint32_t u;
        memcpy(&u, &f, sizeof(u));
        put_be_u32(buf, u);
        n = 4;
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

    uint8_t app[256];
    size_t app_len = pt->byte_len;
    if (app_len > sizeof(app)) {
        return -ENOSPC;
    }
    memset(app, 0, app_len);

    if (pt->apply_scale && pt->data_type != MB_DT_STRING) {
        /* Accept engineering float32 (4 bytes) or native raw. */
        double eng;
        if (value->len >= 4) {
            uint32_t u = be_u32(value->data);
            float f;
            memcpy(&f, &u, sizeof(f));
            eng = (double)f;
        } else {
            uint8_t tmp[8];
            memset(tmp, 0, sizeof(tmp));
            size_t n = value->len < app_len ? value->len : app_len;
            memcpy(tmp, value->data, n);
            eng = decode_raw_number(pt, tmp, app_len);
        }
        double raw = (eng - pt->eng_offset) / (pt->scale != 0.0 ? pt->scale : 1.0);
        encode_raw_number(pt, raw, app, app_len);
    } else {
        size_t n = value->len < app_len ? value->len : app_len;
        memcpy(app, value->data, n);
    }

    uint8_t wire[256];
    int rc = merge_app_bytes(pt, app, app_len, wire, sizeof(wire));
    if (rc != 0) {
        return rc;
    }

    if (ctx->role == MB_ROLE_CLIENT) {
        if (pt->reg_type == MB_REG_HOLDING) {
            if (pt->bit >= 0) {
                uint16_t reg = 0;
                /* Read-modify-write remotely: pull, patch, push. */
                rc = mb_stack_client_read(ctx->stack, MB_REG_HOLDING, pt->start,
                                          1);
                if (rc != 0) {
                    return rc;
                }
                mb_stack_read_regs(ctx->stack, MB_REG_HOLDING, pt->start, &reg,
                                   1);
                uint16_t mask = (uint16_t)(1u << (pt->bit & 15));
                if (wire[0]) {
                    reg = (uint16_t)(reg | mask);
                } else {
                    reg = (uint16_t)(reg & (uint16_t)~mask);
                }
                return mb_stack_client_write_regs(ctx->stack, pt->start, &reg,
                                                  1);
            }
            uint16_t qty = pt->quantity;
            uint16_t *regs = calloc(qty, sizeof(uint16_t));
            if (!regs) {
                return -ENOMEM;
            }
            for (uint16_t i = 0; i < qty; i++) {
                size_t off = (size_t)i * 2u;
                uint8_t hi = wire[off];
                uint8_t lo = wire[off + 1];
                regs[i] = (uint16_t)((hi << 8) | lo);
            }
            rc = mb_stack_client_write_regs(ctx->stack, pt->start, regs, qty);
            free(regs);
            return rc;
        }
        if (pt->reg_type == MB_REG_COIL) {
            return mb_stack_client_write_bits(ctx->stack, pt->start, wire,
                                              pt->quantity);
        }
        LOG_WARN("modbus", "client write 는 holding/coil 만 지원: %s",
                 point_name);
        return -EINVAL;
    }

    return write_map_window(ctx->stack, pt, wire, (size_t)map_window_bytes(pt));
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
