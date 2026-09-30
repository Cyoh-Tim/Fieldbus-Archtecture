#include "modbus_adapter.h"

#include "modbus_codec.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
#include "mb_stack.h"

#define MAX_POINTS 256
#define MAX_NAME 64
#define WIRE_CAP 512

typedef struct {
    char name[MAX_NAME];
    char access[12];
    mb_reg_type_t reg_type;
    mb_data_type_t data_type;
    mb_endian_t endian;
    uint16_t start;
    uint16_t quantity;
    size_t byte_offset;
    size_t byte_len;
    int bit;
    int bit_count;
    int chars_per_reg;
    int string_swap;
    int trim_null;
    double scale;
    double eng_offset;
    int apply_scale;
} modbus_point_t;

typedef struct {
    mb_stack_t *stack;
    mb_role_t role;
    modbus_point_t points[MAX_POINTS];
    int point_count;
    char last_error[128];
} modbus_ctx_t;

static int eqi(const char *a, const char *b)
{
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static int parse_reg_type(const char *s, int *known)
{
    if (known) {
        *known = 1;
    }
    if (!s) {
        return MB_REG_HOLDING;
    }
    if (eqi(s, "input") || eqi(s, "ir") || eqi(s, "3x") || eqi(s, "3") ||
        eqi(s, "input_register") || eqi(s, "input_registers") ||
        eqi(s, "analog_input")) {
        return MB_REG_INPUT;
    }
    if (eqi(s, "coil") || eqi(s, "coils") || eqi(s, "0x") || eqi(s, "0") ||
        eqi(s, "do") || eqi(s, "digital_output")) {
        return MB_REG_COIL;
    }
    if (eqi(s, "discrete") || eqi(s, "di") || eqi(s, "1x") || eqi(s, "1") ||
        eqi(s, "discrete_input") || eqi(s, "digital_input")) {
        return MB_REG_DISCRETE;
    }
    if (eqi(s, "holding") || eqi(s, "hr") || eqi(s, "4x") || eqi(s, "4") ||
        eqi(s, "holding_register") || eqi(s, "holding_registers") ||
        eqi(s, "register") || eqi(s, "registers")) {
        return MB_REG_HOLDING;
    }
    if (known) {
        *known = 0;
    }
    return MB_REG_HOLDING;
}

static int json_get_int(const cJSON *obj, const char *k1, const char *k2,
                        const char *k3, int def, int *found)
{
    const char *keys[3] = {k1, k2, k3};
    for (int i = 0; i < 3; i++) {
        if (!keys[i]) {
            continue;
        }
        const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, keys[i]);
        if (cJSON_IsNumber(it)) {
            if (found) {
                *found = 1;
            }
            return it->valueint;
        }
        if (cJSON_IsString(it) && it->valuestring) {
            const char *s = it->valuestring;
            const char *body = s;
            int base = 10;
            if (*body == '+' || *body == '-') {
                body++;
            }
            /* Decimal by default. strtol(..., 0) treats a leading 0 as octal
             * ("00010" → 8, "00009" → 0, "040001" → 16385). Hex only with
             * an explicit 0x/0X prefix. */
            if (body[0] == '0' && (body[1] == 'x' || body[1] == 'X') &&
                isxdigit((unsigned char)body[2])) {
                base = 16;
            }
            char *end = NULL;
            long v = strtol(s, &end, base);
            if (end != s && *end == '\0') {
                if (found) {
                    *found = 1;
                }
                return (int)v;
            }
        }
    }
    if (found) {
        *found = 0;
    }
    return def;
}

static double json_get_double(const cJSON *obj, const char *k1, const char *k2,
                              double def)
{
    const char *keys[2] = {k1, k2};
    for (int i = 0; i < 2; i++) {
        if (!keys[i]) {
            continue;
        }
        const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, keys[i]);
        if (cJSON_IsNumber(it)) {
            return it->valuedouble;
        }
    }
    return def;
}

static const char *json_get_str(const cJSON *obj, const char *k1,
                                const char *k2)
{
    const char *keys[2] = {k1, k2};
    for (int i = 0; i < 2; i++) {
        if (!keys[i]) {
            continue;
        }
        const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, keys[i]);
        if (cJSON_IsString(it)) {
            return it->valuestring;
        }
    }
    return NULL;
}

static uint16_t normalize_start(mb_reg_type_t type, int start, int mode_zero)
{
    if (start < 0) {
        return 0;
    }
    if (mode_zero) {
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
        /* 00001..09999 and plain 1..9999 → 0-based */
        if (start >= 1 && start <= 9999) {
            return (uint16_t)(start - 1);
        }
        break;
    }
    return (uint16_t)start;
}

static int address_mode_zero(const cJSON *mb)
{
    const cJSON *z = cJSON_GetObjectItemCaseSensitive(mb, "zero_based");
    if (cJSON_IsTrue(z)) {
        return 1;
    }
    if (cJSON_IsBool(z) && cJSON_IsFalse(z)) {
        return 0;
    }
    const char *base = json_get_str(mb, "address_base", "addr_base");
    if (base && (eqi(base, "zero") || eqi(base, "pdu") || eqi(base, "0"))) {
        return 1;
    }
    return 0;
}

static uint16_t infer_quantity(const modbus_point_t *pt, int length,
                               int qty_field)
{
    if (qty_field > 0) {
        return (uint16_t)qty_field;
    }
    if (pt->reg_type == MB_REG_COIL || pt->reg_type == MB_REG_DISCRETE) {
        return (pt->bit_count > 1) ? (uint16_t)pt->bit_count : 1;
    }
    if (pt->bit >= 0) {
        /* bit field inside register(s) */
        int bits = pt->bit_count > 0 ? pt->bit_count : 1;
        return (uint16_t)((pt->bit + bits + 15) / 16);
    }
    switch (pt->data_type) {
    case MB_DT_STRING: {
        int len = length > 0 ? length : 2;
        int cpr = pt->chars_per_reg == 1 ? 1 : 2;
        return (uint16_t)((len + cpr - 1) / cpr);
    }
    case MB_DT_RAW:
        if (length > 0) {
            return (uint16_t)((length + 1) / 2);
        }
        return 1;
    case MB_DT_UINT8:
    case MB_DT_INT8:
        return 1;
    case MB_DT_UINT16:
    case MB_DT_INT16:
    case MB_DT_BCD16:
    case MB_DT_BOOL:
        return 1;
    case MB_DT_UINT32:
    case MB_DT_INT32:
    case MB_DT_FLOAT32:
    case MB_DT_BCD32:
        return 2;
    case MB_DT_UINT64:
    case MB_DT_INT64:
    case MB_DT_FLOAT64:
        return 4;
    }
    return 1;
}

static size_t map_window_bytes(const modbus_point_t *pt)
{
    if (pt->reg_type == MB_REG_COIL || pt->reg_type == MB_REG_DISCRETE) {
        return pt->quantity;
    }
    return (size_t)pt->quantity * 2u;
}

static int parse_points(modbus_ctx_t *ctx, const char *points_json)
{
    cJSON *arr = cJSON_Parse(points_json);
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        if (points_json && points_json[0] && strcmp(points_json, "[]") != 0) {
            LOG_ERROR("modbus", "points 가 JSON 배열이 아님");
            return -EINVAL;
        }
        return 0;
    }
    cJSON *p;
    cJSON_ArrayForEach(p, arr)
    {
        if (ctx->point_count >= MAX_POINTS) {
            LOG_WARN("modbus", "points 상한(%d) 초과", MAX_POINTS);
            break;
        }
        cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        cJSON *address = cJSON_GetObjectItemCaseSensitive(p, "address");
        cJSON *mb =
            address ? cJSON_GetObjectItemCaseSensitive(address, "modbus")
                    : NULL;
        if (!cJSON_IsString(name) || !cJSON_IsObject(mb)) {
            LOG_WARN("modbus", "포인트 누락(name/address.modbus) - 건너뜀");
            continue;
        }

        modbus_point_t *pt = &ctx->points[ctx->point_count];
        memset(pt, 0, sizeof(*pt));
        pt->bit = -1;
        pt->bit_count = 1;
        pt->scale = 1.0;
        pt->chars_per_reg = 2;
        pt->trim_null = 1;
        snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
        snprintf(pt->access, sizeof(pt->access), "%s",
                 cJSON_IsString(access) ? access->valuestring : "read");

        const char *dt = json_get_str(p, "data_type", "datatype");
        pt->data_type = mb_parse_data_type(dt);
        pt->scale = json_get_double(p, "scale", "gain", 1.0);
        pt->eng_offset = json_get_double(p, "offset", NULL, 0.0);
        pt->apply_scale = (pt->scale != 1.0) || (pt->eng_offset != 0.0);

        const char *bo = json_get_str(p, "byte_order", "byteOrder");
        const char *wo = json_get_str(p, "word_order", "wordOrder");
        const char *en = json_get_str(p, "endian", "endianness");
        /* Also allow endian under address.modbus */
        if (!en) {
            en = json_get_str(mb, "endian", "endianness");
        }
        if (!bo) {
            bo = json_get_str(mb, "byte_order", "byteOrder");
        }
        if (!wo) {
            wo = json_get_str(mb, "word_order", "wordOrder");
        }
        pt->endian = mb_parse_endian(bo, wo, en);

        int found = 0;
        int cpr = json_get_int(p, "chars_per_register", "chars_per_reg",
                               "char_per_register", 2, &found);
        if (!found) {
            cpr = json_get_int(mb, "chars_per_register", "chars_per_reg", NULL,
                               2, &found);
        }
        pt->chars_per_reg = (cpr == 1) ? 1 : 2;

        const cJSON *ss = cJSON_GetObjectItemCaseSensitive(p, "string_swap");
        if (!ss) {
            ss = cJSON_GetObjectItemCaseSensitive(mb, "string_swap");
        }
        pt->string_swap = cJSON_IsTrue(ss) ? 1 : 0;
        const cJSON *tn = cJSON_GetObjectItemCaseSensitive(p, "trim_null");
        if (cJSON_IsBool(tn)) {
            pt->trim_null = cJSON_IsTrue(tn) ? 1 : 0;
        }

        const char *rts = json_get_str(mb, "register_type", "type");
        if (!rts) {
            rts = json_get_str(mb, "area", "table");
        }
        int known_type = 1;
        pt->reg_type = parse_reg_type(rts, &known_type);
        if (rts && !known_type) {
            LOG_WARN("modbus", "point %s 알 수 없는 register_type \"%s\" → holding",
                     pt->name, rts);
        }

        int start_raw =
            json_get_int(mb, "start", "address", "register", 0, &found);
        if (!found) {
            start_raw = json_get_int(mb, "addr", "reg", NULL, 0, &found);
        }
        int add =
            json_get_int(mb, "offset", "reg_offset", "register_offset", 0, NULL);
        int mode_zero = address_mode_zero(mb);
        uint32_t abs_addr =
            (uint32_t)normalize_start(pt->reg_type, start_raw, mode_zero) +
            (uint32_t)add;
        if (abs_addr > 0xFFFF) {
            LOG_WARN("modbus", "point %s address overflow - 건너뜀", pt->name);
            continue;
        }
        pt->start = (uint16_t)abs_addr;
        pt->byte_offset = (size_t)json_get_int(mb, "byte_offset", "byteOffset",
                                               "data_offset", 0, NULL);

        int bit_found = 0;
        int bit = json_get_int(mb, "bit", "bit_offset", "bit_index", -1,
                               &bit_found);
        pt->bit = bit_found ? bit : -1;
        pt->bit_count =
            json_get_int(mb, "bit_count", "bits", "bit_length", 1, NULL);
        if (pt->bit_count < 1) {
            pt->bit_count = 1;
        }
        if (pt->bit_count > 32) {
            LOG_WARN("modbus", "point %s bit_count=%d > 32, clamp", pt->name,
                     pt->bit_count);
            pt->bit_count = 32;
        }

        int length = json_get_int(p, "length", "len", "size", 0, NULL);
        int qty = json_get_int(mb, "quantity", "count", "qty", 0, NULL);
        pt->quantity = infer_quantity(pt, length, qty);
        pt->byte_len = mb_type_native_size(pt->data_type, length, pt->quantity,
                                           pt->chars_per_reg);
        if (pt->data_type == MB_DT_BOOL && pt->bit_count > 1) {
            pt->byte_len = (size_t)((pt->bit_count + 7) / 8);
            if (pt->byte_len < 1) {
                pt->byte_len = 1;
            }
        }

        size_t win = map_window_bytes(pt);
        if (pt->byte_offset > 0 && pt->byte_offset >= win &&
            pt->reg_type != MB_REG_COIL && pt->reg_type != MB_REG_DISCRETE &&
            pt->bit < 0) {
            LOG_WARN("modbus", "point %s byte_offset 과다 - 건너뜀", pt->name);
            continue;
        }
        if (pt->byte_offset > 0 &&
            (pt->data_type == MB_DT_STRING || pt->data_type == MB_DT_RAW ||
             pt->data_type == MB_DT_UINT8 || pt->data_type == MB_DT_INT8)) {
            size_t rem = win > pt->byte_offset ? win - pt->byte_offset : 0;
            if (pt->byte_len > rem && rem > 0) {
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
    cfg.client_timeout_ms = 200;
    cfg.max_clients = 4;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "0.0.0.0");

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        const char *role = json_get_str(params, "role", NULL);
        if (role && (eqi(role, "client") || eqi(role, "master"))) {
            cfg.role = MB_ROLE_CLIENT;
        }
        const char *ip = json_get_str(params, "ip", "host");
        if (!ip) {
            ip = json_get_str(params, "remote_ip", "slave_ip");
        }
        if (ip) {
            if (cfg.role == MB_ROLE_CLIENT) {
                snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "%s", ip);
            } else {
                snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", ip);
            }
        }
        const char *bind = json_get_str(params, "bind_ip", "listen_ip");
        if (bind && cfg.role == MB_ROLE_SERVER) {
            snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", bind);
        }
        int f = 0;
        cfg.port = json_get_int(params, "port", NULL, NULL, cfg.port, &f);
        cfg.unit_id =
            json_get_int(params, "unit_id", "slave_id", "device_id", cfg.unit_id,
                         &f);
        cfg.client_timeout_ms = json_get_int(params, "client_timeout_ms",
                                             "timeout_ms", "timeout", 200, &f);
        cfg.max_clients =
            json_get_int(params, "max_clients", "max_masters", NULL, 4, &f);
        cfg.idle_timeout_ms = json_get_int(params, "idle_timeout_ms",
                                           "idle_timeout", NULL, 0, &f);
        cfg.max_conn_per_ip = json_get_int(params, "max_conn_per_ip",
                                           "max_connections_per_ip", NULL, 0,
                                           &f);
        cfg.n_holding =
            (uint16_t)json_get_int(params, "n_holding", "holding_count", NULL,
                                   0, &f);
        cfg.n_input =
            (uint16_t)json_get_int(params, "n_input", "input_count", NULL, 0,
                                   &f);
        cfg.n_coil =
            (uint16_t)json_get_int(params, "n_coil", "coil_count", NULL, 0, &f);
        cfg.n_discrete =
            (uint16_t)json_get_int(params, "n_discrete", "discrete_count", NULL,
                                   0, &f);
        const cJSON *any =
            cJSON_GetObjectItemCaseSensitive(params, "unit_id_any");
        if (!any) {
            any = cJSON_GetObjectItemCaseSensitive(params, "accept_any_unit");
        }
        cfg.unit_id_any = cJSON_IsTrue(any) ? 1 : 0;
        cJSON_Delete(params);
    }

    if (cfg.role == MB_ROLE_CLIENT && !cfg.remote_ip[0]) {
        LOG_ERROR("modbus", "client 이면 protocol_params.ip 필요");
        free(ctx);
        return -EINVAL;
    }

    if (parse_points(ctx, points_json) != 0) {
        free(ctx);
        return -EINVAL;
    }
    ctx->role = cfg.role;
    ctx->stack = mb_stack_create(&cfg);
    if (!ctx->stack) {
        free(ctx);
        return -ENOMEM;
    }
    self->ctx = ctx;
    LOG_INFO("modbus",
             "init %s port=%d unit_id=%d points=%d (범용 매핑, 자체 스택)",
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

static int read_map_window(mb_stack_t *stack, const modbus_point_t *pt,
                           uint8_t *wire, size_t wire_cap)
{
    size_t need = map_window_bytes(pt);
    if (need > wire_cap) {
        return -ENOSPC;
    }
    if (pt->bit >= 0 &&
        (pt->reg_type == MB_REG_HOLDING || pt->reg_type == MB_REG_INPUT)) {
        uint16_t regs[4];
        uint16_t nreg = pt->quantity < 4 ? pt->quantity : 4;
        int rc = mb_stack_read_regs(stack, pt->reg_type, pt->start, regs, nreg);
        if (rc != 0) {
            return rc;
        }
        uint64_t word = 0;
        for (uint16_t i = 0; i < nreg; i++) {
            word |= (uint64_t)regs[i] << (16 * i);
        }
        uint64_t v = mb_extract_bits(word, pt->bit, pt->bit_count);
        if (pt->bit_count <= 8) {
            wire[0] = (uint8_t)v;
        } else if (pt->bit_count <= 16) {
            wire[0] = (uint8_t)(v >> 8);
            wire[1] = (uint8_t)v;
        } else {
            wire[0] = (uint8_t)(v >> 24);
            wire[1] = (uint8_t)(v >> 16);
            wire[2] = (uint8_t)(v >> 8);
            wire[3] = (uint8_t)v;
        }
        return 0;
    }
    return mb_stack_read_bytes(stack, pt->reg_type, pt->start, wire, need);
}

static int write_map_window(mb_stack_t *stack, const modbus_point_t *pt,
                            const uint8_t *wire, size_t wire_len)
{
    if (pt->bit >= 0 &&
        (pt->reg_type == MB_REG_HOLDING || pt->reg_type == MB_REG_INPUT)) {
        uint16_t regs[4];
        uint16_t nreg = pt->quantity < 4 ? pt->quantity : 4;
        memset(regs, 0, sizeof(regs));
        int rc = mb_stack_read_regs(stack, pt->reg_type, pt->start, regs, nreg);
        if (rc != 0) {
            return rc;
        }
        uint64_t word = 0;
        for (uint16_t i = 0; i < nreg; i++) {
            word |= (uint64_t)regs[i] << (16 * i);
        }
        uint64_t v = 0;
        if (pt->bit_count <= 8) {
            v = wire_len ? wire[0] : 0;
        } else if (pt->bit_count <= 16) {
            v = ((uint64_t)(wire_len > 0 ? wire[0] : 0) << 8) |
                (wire_len > 1 ? wire[1] : 0);
        } else {
            v = ((uint64_t)(wire_len > 0 ? wire[0] : 0) << 24) |
                ((uint64_t)(wire_len > 1 ? wire[1] : 0) << 16) |
                ((uint64_t)(wire_len > 2 ? wire[2] : 0) << 8) |
                (wire_len > 3 ? wire[3] : 0);
        }
        word = mb_insert_bits(word, pt->bit, pt->bit_count, v);
        for (uint16_t i = 0; i < nreg; i++) {
            regs[i] = (uint16_t)((word >> (16 * i)) & 0xFFFF);
        }
        return mb_stack_write_regs(stack, pt->reg_type, pt->start, regs, nreg);
    }
    size_t need = map_window_bytes(pt);
    if (wire_len < need) {
        uint8_t tmp[WIRE_CAP];
        if (need > sizeof(tmp)) {
            return -ENOSPC;
        }
        memset(tmp, 0, need);
        memcpy(tmp, wire, wire_len);
        return mb_stack_write_bytes(stack, pt->reg_type, pt->start, tmp, need);
    }
    return mb_stack_write_bytes(stack, pt->reg_type, pt->start, wire, need);
}

static int app_from_wire(const modbus_point_t *pt, const uint8_t *wire,
                         size_t wire_len, uint8_t *app, size_t app_len)
{
    size_t win = map_window_bytes(pt);
    if (wire_len < win && pt->bit < 0) {
        return -EINVAL;
    }
    memset(app, 0, app_len);

    if (pt->bit >= 0) {
        size_t n = app_len < 4 ? app_len : 4;
        memcpy(app, wire, n);
        return 0;
    }

    if (pt->data_type == MB_DT_STRING) {
        uint8_t tmp[WIRE_CAP];
        if (win > sizeof(tmp)) {
            return -ENOSPC;
        }
        memcpy(tmp, wire, win);
        /* string packing is independent of numeric endian; optional swap */
        mb_unpack_string(app, app_len, tmp + pt->byte_offset,
                         win > pt->byte_offset ? win - pt->byte_offset : 0,
                         pt->chars_per_reg, pt->string_swap, pt->trim_null);
        return 0;
    }

    size_t off = pt->byte_offset;
    if (off >= win) {
        return -EINVAL;
    }
    size_t avail = win - off;
    size_t n = app_len < avail ? app_len : avail;
    memcpy(app, wire + off, n);
    mb_wire_to_canonical(app, app_len, pt->endian);
    return 0;
}

static int wire_from_app(const modbus_point_t *pt, const uint8_t *app,
                         size_t app_len, uint8_t *wire, size_t wire_cap)
{
    size_t win = map_window_bytes(pt);
    if (win > wire_cap) {
        return -ENOSPC;
    }
    memset(wire, 0, win);

    if (pt->bit >= 0) {
        size_t n = app_len < 4 ? app_len : 4;
        memcpy(wire, app, n);
        return 0;
    }

    if (pt->data_type == MB_DT_STRING) {
        mb_pack_string(wire + pt->byte_offset,
                       win > pt->byte_offset ? win - pt->byte_offset : 0, app,
                       app_len, pt->chars_per_reg, pt->string_swap);
        return 0;
    }

    uint8_t tmp[WIRE_CAP];
    if (pt->byte_len > sizeof(tmp)) {
        return -ENOSPC;
    }
    memset(tmp, 0, pt->byte_len);
    size_t n = app_len < pt->byte_len ? app_len : pt->byte_len;
    memcpy(tmp, app, n);
    mb_canonical_to_wire(tmp, pt->byte_len, pt->endian);
    if (pt->byte_offset + pt->byte_len > win) {
        /* allow uint8 at byte_offset inside a register window */
        if (pt->byte_offset >= win) {
            return -EINVAL;
        }
        size_t rem = win - pt->byte_offset;
        memcpy(wire + pt->byte_offset, tmp, rem < n ? rem : n);
        return 0;
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

    uint8_t wire[WIRE_CAP];
    int rc = read_map_window(ctx->stack, pt, wire, sizeof(wire));
    if (rc != 0) {
        return rc;
    }

    size_t n = pt->byte_len;
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (!buf) {
        return -ENOMEM;
    }
    rc = app_from_wire(pt, wire, map_window_bytes(pt), buf, n);
    if (rc != 0) {
        free(buf);
        return rc;
    }

    if (pt->apply_scale && pt->data_type != MB_DT_STRING &&
        pt->data_type != MB_DT_RAW) {
        double raw = mb_decode_number(pt->data_type, buf, n);
        if (pt->bit >= 0) {
            /* bit-field already extracted as small integer in wire/app */
            raw = 0;
            for (size_t i = 0; i < n; i++) {
                raw = raw * 256.0 + buf[i];
            }
        }
        double eng = raw * pt->scale + pt->eng_offset;
        free(buf);
        buf = malloc(4);
        if (!buf) {
            return -ENOMEM;
        }
        float f = (float)eng;
        uint32_t u;
        memcpy(&u, &f, sizeof(u));
        buf[0] = (uint8_t)(u >> 24);
        buf[1] = (uint8_t)(u >> 16);
        buf[2] = (uint8_t)(u >> 8);
        buf[3] = (uint8_t)u;
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

    uint8_t app[WIRE_CAP];
    size_t app_len = pt->byte_len;
    if (app_len > sizeof(app)) {
        return -ENOSPC;
    }
    memset(app, 0, app_len);

    if (pt->apply_scale && pt->data_type != MB_DT_STRING &&
        pt->data_type != MB_DT_RAW) {
        double eng;
        if (value->len >= 4) {
            uint32_t u = ((uint32_t)value->data[0] << 24) |
                         ((uint32_t)value->data[1] << 16) |
                         ((uint32_t)value->data[2] << 8) |
                         (uint32_t)value->data[3];
            float f;
            memcpy(&f, &u, sizeof(f));
            eng = (double)f;
        } else {
            uint8_t tmp[16];
            memset(tmp, 0, sizeof(tmp));
            size_t n = value->len < app_len ? value->len : app_len;
            memcpy(tmp, value->data, n);
            eng = mb_decode_number(pt->data_type, tmp, app_len);
        }
        double raw =
            (eng - pt->eng_offset) / (pt->scale != 0.0 ? pt->scale : 1.0);
        if (pt->bit >= 0) {
            uint64_t iv = (uint64_t)llround(raw);
            if (pt->bit_count <= 8) {
                app[0] = (uint8_t)iv;
            } else if (pt->bit_count <= 16) {
                app[0] = (uint8_t)(iv >> 8);
                app[1] = (uint8_t)iv;
            } else {
                app[0] = (uint8_t)(iv >> 24);
                app[1] = (uint8_t)(iv >> 16);
                app[2] = (uint8_t)(iv >> 8);
                app[3] = (uint8_t)iv;
            }
        } else {
            mb_encode_number(pt->data_type, raw, app, app_len);
        }
    } else {
        size_t n = value->len < app_len ? value->len : app_len;
        memcpy(app, value->data, n);
    }

    uint8_t wire[WIRE_CAP];
    int rc = wire_from_app(pt, app, app_len, wire, sizeof(wire));
    if (rc != 0) {
        return rc;
    }

    if (ctx->role == MB_ROLE_CLIENT) {
        if (pt->reg_type == MB_REG_HOLDING || pt->reg_type == MB_REG_INPUT) {
            if (pt->bit >= 0) {
                rc = mb_stack_client_read(ctx->stack, pt->reg_type, pt->start,
                                          pt->quantity);
                if (rc != 0) {
                    return rc;
                }
            }
            /* Always write through local map update + client holding write. */
            rc = write_map_window(ctx->stack, pt, wire, map_window_bytes(pt));
            if (rc != 0) {
                return rc;
            }
            if (pt->reg_type != MB_REG_HOLDING) {
                LOG_WARN("modbus", "client 는 input 원격 쓰기 불가: %s",
                         point_name);
                return -EINVAL;
            }
            uint16_t qty = pt->quantity;
            if (qty > 123) {
                LOG_ERROR("modbus", "client write quantity %u > 123: %s", qty,
                          point_name);
                return -EINVAL;
            }
            uint16_t *regs = calloc(qty, sizeof(uint16_t));
            if (!regs) {
                return -ENOMEM;
            }
            mb_stack_read_regs(ctx->stack, MB_REG_HOLDING, pt->start, regs,
                               qty);
            rc = mb_stack_client_write_regs(ctx->stack, pt->start, regs, qty);
            free(regs);
            return rc;
        }
        if (pt->reg_type == MB_REG_COIL) {
            return mb_stack_client_write_bits(ctx->stack, pt->start, wire,
                                              pt->quantity);
        }
        LOG_WARN("modbus", "client write 미지원 영역: %s", point_name);
        return -EINVAL;
    }

    return write_map_window(ctx->stack, pt, wire, map_window_bytes(pt));
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
