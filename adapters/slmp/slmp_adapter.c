#include "slmp_adapter.h"

#include "slmp_codec.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
#include "slmp_stack.h"

#define MAX_POINTS 256
#define MAX_NAME 64
#define WIRE_CAP 512

typedef struct {
    char name[MAX_NAME];
    char access[12];
    uint8_t device_code;
    int is_bit_device;
    slmp_access_unit_t unit;
    slmp_data_type_t data_type;
    slmp_endian_t endian;
    uint32_t start;
    uint16_t quantity;
    size_t byte_offset;
    size_t byte_len;
    int bit;
    int bit_count;
    int chars_per_word;
    int string_swap;
    int trim_null;
    double scale;
    double eng_offset;
    int apply_scale;
} slmp_point_t;

typedef struct {
    slmp_stack_t *stack;
    slmp_role_t role;
    slmp_point_t points[MAX_POINTS];
    int point_count;
    char last_error[128];
} slmp_ctx_t;

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
            char *end = NULL;
            long v = strtol(it->valuestring, &end, 0);
            if (end != it->valuestring) {
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

/* Parse "D100", "X1A", "100", "0x1A" into device + head.
 * device_hint may be NULL; if present used when start has no prefix. */
static int parse_device_head(const char *device_hint, const char *start_str,
                             int start_num, int have_num, uint8_t *code_out,
                             uint32_t *head_out, int *is_bit_out)
{
    uint8_t code = SLMP_DEV_D;
    int is_bit = 0;
    uint32_t head = 0;

    if (device_hint && device_hint[0]) {
        if (slmp_device_code_from_name(device_hint, &code, &is_bit) != 0) {
            LOG_WARN("slmp", "unknown device_code '%s'", device_hint);
            return -EINVAL;
        }
    }

    if (start_str && start_str[0]) {
        /* Optional leading device letters then number */
        size_t i = 0;
        while (start_str[i] && isalpha((unsigned char)start_str[i])) {
            i++;
        }
        if (i > 0) {
            char dname[8];
            if (i >= sizeof(dname)) {
                return -EINVAL;
            }
            memcpy(dname, start_str, i);
            dname[i] = 0;
            if (slmp_device_code_from_name(dname, &code, &is_bit) != 0) {
                return -EINVAL;
            }
        }
        const char *num = start_str + i;
        if (!num[0]) {
            return -EINVAL;
        }
        int base = 10;
        if (slmp_device_is_hex_addr(code) ||
            (num[0] == '0' && (num[1] == 'x' || num[1] == 'X'))) {
            base = 0; /* auto hex if 0x, else if hex device use 16 */
            if (!(num[0] == '0' && (num[1] == 'x' || num[1] == 'X')) &&
                slmp_device_is_hex_addr(code)) {
                base = 16;
            }
        }
        char *end = NULL;
        unsigned long v = strtoul(num, &end, base);
        if (end == num) {
            return -EINVAL;
        }
        head = (uint32_t)v;
    } else if (have_num) {
        head = (uint32_t)start_num;
    }

    *code_out = code;
    *head_out = head;
    if (is_bit_out) {
        *is_bit_out = is_bit;
    }
    return 0;
}

static uint16_t infer_quantity(const slmp_point_t *pt, int length, int qty_field)
{
    if (qty_field > 0) {
        return (uint16_t)qty_field;
    }
    if (pt->unit == SLMP_ACCESS_BIT) {
        return (pt->bit_count > 1) ? (uint16_t)pt->bit_count : 1;
    }
    if (pt->bit >= 0) {
        int bits = pt->bit_count > 0 ? pt->bit_count : 1;
        return (uint16_t)((pt->bit + bits + 15) / 16);
    }
    switch (pt->data_type) {
    case SLMP_DT_STRING: {
        int len = length > 0 ? length : 2;
        int cpw = pt->chars_per_word == 1 ? 1 : 2;
        return (uint16_t)((len + cpw - 1) / cpw);
    }
    case SLMP_DT_RAW:
        if (length > 0) {
            return (uint16_t)((length + 1) / 2);
        }
        return 1;
    case SLMP_DT_UINT8:
    case SLMP_DT_INT8:
    case SLMP_DT_UINT16:
    case SLMP_DT_INT16:
    case SLMP_DT_BCD16:
    case SLMP_DT_BOOL:
        return 1;
    case SLMP_DT_UINT32:
    case SLMP_DT_INT32:
    case SLMP_DT_FLOAT32:
    case SLMP_DT_BCD32:
        return 2;
    case SLMP_DT_UINT64:
    case SLMP_DT_INT64:
    case SLMP_DT_FLOAT64:
        return 4;
    }
    return 1;
}

static size_t map_window_bytes(const slmp_point_t *pt)
{
    if (pt->unit == SLMP_ACCESS_BIT) {
        return pt->quantity;
    }
    return (size_t)pt->quantity * 2u;
}

static int access_is_plc_read(const char *access)
{
    return !access || eqi(access, "read") || eqi(access, "readwrite") ||
           eqi(access, "rw");
}

static int access_is_plc_write(const char *access)
{
    return access && (eqi(access, "write") || eqi(access, "readwrite") ||
                      eqi(access, "rw"));
}

static int parse_points(slmp_ctx_t *ctx, const char *points_json)
{
    cJSON *arr = cJSON_Parse(points_json);
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        if (points_json && points_json[0] && strcmp(points_json, "[]") != 0) {
            LOG_ERROR("slmp", "points 가 JSON 배열이 아님");
            return -EINVAL;
        }
        return 0;
    }
    cJSON *p;
    cJSON_ArrayForEach(p, arr)
    {
        if (ctx->point_count >= MAX_POINTS) {
            LOG_WARN("slmp", "points 상한(%d) 초과", MAX_POINTS);
            break;
        }
        cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        cJSON *address = cJSON_GetObjectItemCaseSensitive(p, "address");
        cJSON *sa =
            address ? cJSON_GetObjectItemCaseSensitive(address, "slmp") : NULL;
        if (!cJSON_IsString(name) || !cJSON_IsObject(sa)) {
            LOG_WARN("slmp", "포인트 누락(name/address.slmp) - 건너뜀");
            continue;
        }

        slmp_point_t *pt = &ctx->points[ctx->point_count];
        memset(pt, 0, sizeof(*pt));
        pt->bit = -1;
        pt->bit_count = 1;
        pt->scale = 1.0;
        pt->chars_per_word = 2;
        pt->trim_null = 1;
        snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
        snprintf(pt->access, sizeof(pt->access), "%s",
                 cJSON_IsString(access) ? access->valuestring : "read");

        const char *dt = json_get_str(p, "data_type", "datatype");
        pt->data_type = slmp_parse_data_type(dt);
        pt->scale = json_get_double(p, "scale", "gain", 1.0);
        pt->eng_offset = json_get_double(p, "offset", NULL, 0.0);
        pt->apply_scale = (pt->scale != 1.0) || (pt->eng_offset != 0.0);

        const char *bo = json_get_str(p, "byte_order", "byteOrder");
        const char *wo = json_get_str(p, "word_order", "wordOrder");
        const char *en = json_get_str(p, "endian", "endianness");
        if (!en) {
            en = json_get_str(sa, "endian", "endianness");
        }
        if (!bo) {
            bo = json_get_str(sa, "byte_order", "byteOrder");
        }
        if (!wo) {
            wo = json_get_str(sa, "word_order", "wordOrder");
        }
        pt->endian = slmp_parse_endian(bo, wo, en);

        int found = 0;
        int cpw = json_get_int(p, "chars_per_word", "chars_per_register",
                               "char_per_register", 2, &found);
        if (!found) {
            cpw = json_get_int(sa, "chars_per_word", "chars_per_register", NULL,
                               2, &found);
        }
        pt->chars_per_word = (cpw == 1) ? 1 : 2;

        const cJSON *ss = cJSON_GetObjectItemCaseSensitive(p, "string_swap");
        if (!ss) {
            ss = cJSON_GetObjectItemCaseSensitive(sa, "string_swap");
        }
        pt->string_swap = cJSON_IsTrue(ss) ? 1 : 0;
        const cJSON *tn = cJSON_GetObjectItemCaseSensitive(p, "trim_null");
        if (cJSON_IsBool(tn)) {
            pt->trim_null = cJSON_IsTrue(tn) ? 1 : 0;
        }

        const char *dev = json_get_str(sa, "device_code", "device");
        if (!dev) {
            dev = json_get_str(sa, "dev", "soft_device");
        }

        int have_num = 0;
        int start_num =
            json_get_int(sa, "start", "address", "head", 0, &have_num);
        if (!have_num) {
            start_num = json_get_int(sa, "addr", "register", NULL, 0, &have_num);
        }
        const char *start_str = NULL;
        const cJSON *st = cJSON_GetObjectItemCaseSensitive(sa, "start");
        if (!cJSON_IsString(st)) {
            st = cJSON_GetObjectItemCaseSensitive(sa, "address");
        }
        if (!cJSON_IsString(st)) {
            st = cJSON_GetObjectItemCaseSensitive(sa, "head");
        }
        if (cJSON_IsString(st)) {
            start_str = st->valuestring;
            have_num = 0;
        }

        if (parse_device_head(dev, start_str, start_num, have_num,
                              &pt->device_code, &pt->start,
                              &pt->is_bit_device) != 0) {
            LOG_WARN("slmp", "point %s 주소 파싱 실패 - 건너뜀", pt->name);
            continue;
        }

        int off = json_get_int(sa, "offset", "reg_offset", NULL, 0, &found);
        if (found && off != 0) {
            pt->start += (uint32_t)off;
        }

        pt->byte_offset = (size_t)json_get_int(sa, "byte_offset", "byteOffset",
                                               "data_offset", 0, &found);

        int bit = json_get_int(sa, "bit", "bit_offset", "bit_index", -1, &found);
        pt->bit = found ? bit : -1;
        pt->bit_count =
            json_get_int(sa, "bit_count", "bits", "bit_length", 1, &found);

        const char *unit = json_get_str(sa, "unit", "access_unit");
        if (unit && eqi(unit, "bit")) {
            pt->unit = SLMP_ACCESS_BIT;
        } else if (unit && eqi(unit, "word")) {
            pt->unit = SLMP_ACCESS_WORD;
        } else if (pt->data_type == SLMP_DT_BOOL && pt->is_bit_device &&
                   pt->bit < 0) {
            pt->unit = SLMP_ACCESS_BIT;
        } else {
            pt->unit = SLMP_ACCESS_WORD;
        }

        int length = json_get_int(p, "length", "len", "size", 0, &found);
        int qty = json_get_int(sa, "quantity", "count", "qty", 0, &found);
        pt->quantity = infer_quantity(pt, length, qty);
        pt->byte_len = slmp_type_native_size(pt->data_type, length, pt->quantity,
                                             pt->chars_per_word);
        if (pt->data_type == SLMP_DT_BOOL && pt->bit_count > 1) {
            pt->byte_len = (size_t)((pt->bit_count + 7) / 8);
            if (pt->byte_len < 1) {
                pt->byte_len = 1;
            }
        }

        if (slmp_stack_map_ensure(ctx->stack, pt->device_code,
                                  pt->is_bit_device ||
                                      pt->unit == SLMP_ACCESS_BIT) != 0) {
            LOG_WARN("slmp", "point %s map_ensure 실패", pt->name);
        }

        ctx->point_count++;
    }
    cJSON_Delete(arr);
    return 0;
}

static int slmp_init(protocol_adapter_t *self, const char *protocol_params_json,
                     const char *points_json)
{
    slmp_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -ENOMEM;
    }

    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_CLIENT;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    cfg.port = SLMP_TCP_DEFAULT_PORT;
    cfg.network_no = 0;
    cfg.pc_no = SLMP_PC_OWN_STATION;
    cfg.dest_module_io = SLMP_DEST_MODULE_CPU;
    cfg.dest_multidrop = 0;
    cfg.monitoring_timer = 0x0010;
    cfg.timeout_ms = 1000;
    cfg.max_clients = 4;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "0.0.0.0");

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        const char *role = json_get_str(params, "role", NULL);
        if (role && (eqi(role, "server") || eqi(role, "slave") ||
                     eqi(role, "simulator"))) {
            cfg.role = SLMP_ROLE_SERVER;
        }
        const char *ip = json_get_str(params, "plc_ip", "ip");
        if (!ip) {
            ip = json_get_str(params, "host", "remote_ip");
        }
        if (ip) {
            if (cfg.role == SLMP_ROLE_CLIENT) {
                snprintf(cfg.plc_ip, sizeof(cfg.plc_ip), "%s", ip);
            } else {
                snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", ip);
            }
        }
        const char *bind = json_get_str(params, "bind_ip", "listen_ip");
        if (bind && cfg.role == SLMP_ROLE_SERVER) {
            snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", bind);
        }
        int f = 0;
        cfg.port = json_get_int(params, "port", NULL, NULL, cfg.port, &f);
        cfg.network_no = (uint8_t)json_get_int(params, "network_no", "network",
                                               NULL, cfg.network_no, &f);
        cfg.pc_no = (uint8_t)json_get_int(params, "pc_no", "pc", "station",
                                          cfg.pc_no, &f);
        cfg.dest_module_io = (uint16_t)json_get_int(
            params, "dest_module_io", "io_no", "module_io", cfg.dest_module_io,
            &f);
        cfg.dest_multidrop = (uint8_t)json_get_int(
            params, "dest_multidrop", "station_no", "multidrop", 0, &f);
        cfg.monitoring_timer = (uint16_t)json_get_int(
            params, "monitoring_timer", "monitor_timer", NULL,
            cfg.monitoring_timer, &f);
        cfg.timeout_ms = json_get_int(params, "timeout_ms", "timeout",
                                      "client_timeout_ms", cfg.timeout_ms, &f);
        cfg.max_clients =
            json_get_int(params, "max_clients", NULL, NULL, cfg.max_clients, &f);
        cfg.idle_timeout_ms = json_get_int(params, "idle_timeout_ms",
                                           "idle_timeout", NULL, 0, &f);
        cfg.max_conn_per_ip = json_get_int(params, "max_conn_per_ip",
                                           "max_connections_per_ip", NULL, 0,
                                           &f);
        cfg.map_words = (uint32_t)json_get_int(params, "map_words",
                                               "word_map_size", NULL, 0, &f);
        cfg.map_bits = (uint32_t)json_get_int(params, "map_bits",
                                              "bit_map_size", NULL, 0, &f);

        const char *frame = json_get_str(params, "frame", "frame_type");
        if (frame) {
            if (eqi(frame, "3E") || eqi(frame, "3E_binary") ||
                eqi(frame, "binary") || eqi(frame, "3e")) {
                cfg.frame = SLMP_FRAME_3E_BINARY;
            } else {
                LOG_ERROR("slmp", "미지원 frame '%s' (Binary 3E 만)", frame);
                cJSON_Delete(params);
                free(ctx);
                return -EINVAL;
            }
        }
        cJSON_Delete(params);
    }

    if (cfg.role == SLMP_ROLE_CLIENT && !cfg.plc_ip[0]) {
        LOG_ERROR("slmp", "client 이면 protocol_params.plc_ip 필요");
        free(ctx);
        return -EINVAL;
    }

    ctx->stack = slmp_stack_create(&cfg);
    if (!ctx->stack) {
        free(ctx);
        return -ENOMEM;
    }
    ctx->role = cfg.role;

    if (parse_points(ctx, points_json) != 0) {
        slmp_stack_destroy(ctx->stack);
        free(ctx);
        return -EINVAL;
    }

    self->ctx = ctx;
    LOG_INFO("slmp",
             "init %s %s:%d points=%d (Binary 3E, 범용 매핑)",
             cfg.role == SLMP_ROLE_CLIENT ? "client" : "server",
             cfg.role == SLMP_ROLE_CLIENT ? cfg.plc_ip : cfg.bind_ip, cfg.port,
             ctx->point_count);
    return 0;
}

static int slmp_connect(protocol_adapter_t *self)
{
    slmp_ctx_t *ctx = self->ctx;
    int rc = slmp_stack_start(ctx->stack);
    if (rc != 0) {
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "stack start failed (%d)", rc);
        LOG_ERROR("slmp", "%s", ctx->last_error);
        return rc;
    }
    return 0;
}

static void slmp_disconnect(protocol_adapter_t *self)
{
    slmp_ctx_t *ctx = self->ctx;
    if (ctx && ctx->stack) {
        slmp_stack_stop(ctx->stack);
    }
}

static slmp_point_t *find_point(slmp_ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->point_count; i++) {
        if (strcmp(ctx->points[i].name, name) == 0) {
            return &ctx->points[i];
        }
    }
    return NULL;
}

static slmp_range_t point_range(const slmp_point_t *pt)
{
    slmp_range_t r;
    memset(&r, 0, sizeof(r));
    r.addr.device_code = pt->device_code;
    r.addr.head = pt->start;
    r.addr.unit = pt->unit;
    r.quantity = pt->quantity;
    return r;
}

static int read_map_window(slmp_ctx_t *ctx, const slmp_point_t *pt,
                           uint8_t *wire, size_t wire_cap)
{
    size_t need = map_window_bytes(pt);
    if (need > wire_cap) {
        return -ENOSPC;
    }
    if (pt->bit >= 0 && pt->unit == SLMP_ACCESS_WORD) {
        uint16_t regs[4];
        uint16_t nreg = pt->quantity < 4 ? pt->quantity : 4;
        int rc = slmp_stack_read_words(ctx->stack, pt->device_code, pt->start,
                                       regs, nreg);
        if (rc != 0) {
            return rc;
        }
        uint64_t word = 0;
        for (uint16_t i = 0; i < nreg; i++) {
            word |= (uint64_t)regs[i] << (16 * i);
        }
        uint64_t v = slmp_extract_bits(word, pt->bit, pt->bit_count);
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
    if (pt->unit == SLMP_ACCESS_BIT) {
        return slmp_stack_read_bits(ctx->stack, pt->device_code, pt->start, wire,
                                    pt->quantity);
    }
    return slmp_stack_read_bytes(ctx->stack, pt->device_code, pt->start, wire,
                                 need);
}

static int write_map_window(slmp_ctx_t *ctx, const slmp_point_t *pt,
                            const uint8_t *wire, size_t wire_len)
{
    if (pt->bit >= 0 && pt->unit == SLMP_ACCESS_WORD) {
        uint16_t regs[4];
        uint16_t nreg = pt->quantity < 4 ? pt->quantity : 4;
        memset(regs, 0, sizeof(regs));
        int rc = slmp_stack_read_words(ctx->stack, pt->device_code, pt->start,
                                       regs, nreg);
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
        word = slmp_insert_bits(word, pt->bit, pt->bit_count, v);
        for (uint16_t i = 0; i < nreg; i++) {
            regs[i] = (uint16_t)((word >> (16 * i)) & 0xFFFF);
        }
        return slmp_stack_write_words(ctx->stack, pt->device_code, pt->start,
                                      regs, nreg);
    }
    size_t need = map_window_bytes(pt);
    if (pt->unit == SLMP_ACCESS_BIT) {
        return slmp_stack_write_bits(ctx->stack, pt->device_code, pt->start,
                                     wire, pt->quantity);
    }
    if (wire_len < need) {
        uint8_t tmp[WIRE_CAP];
        if (need > sizeof(tmp)) {
            return -ENOSPC;
        }
        memset(tmp, 0, need);
        memcpy(tmp, wire, wire_len);
        return slmp_stack_write_bytes(ctx->stack, pt->device_code, pt->start,
                                      tmp, need);
    }
    return slmp_stack_write_bytes(ctx->stack, pt->device_code, pt->start, wire,
                                  need);
}

static int remote_sync_write(slmp_ctx_t *ctx, const slmp_point_t *pt)
{
    if (ctx->role != SLMP_ROLE_CLIENT) {
        return 0;
    }
    slmp_range_t range = point_range(pt);
    uint8_t wire[WIRE_CAP];
    size_t need = map_window_bytes(pt);
    if (need > sizeof(wire)) {
        return -ENOSPC;
    }
    int rc = read_map_window(ctx, pt, wire, sizeof(wire));
    if (rc != 0) {
        return rc;
    }
    /* For bit-in-word, quantity already covers the word window */
    return slmp_stack_client_batch_write(ctx->stack, &range, wire, need);
}

static int remote_sync_read(slmp_ctx_t *ctx, const slmp_point_t *pt)
{
    if (ctx->role != SLMP_ROLE_CLIENT) {
        return 0;
    }
    slmp_range_t range = point_range(pt);
    uint8_t wire[WIRE_CAP];
    size_t got = 0;
    return slmp_stack_client_batch_read(ctx->stack, &range, wire, sizeof(wire),
                                        &got);
}

static void slmp_poll_cycle(protocol_adapter_t *self)
{
    slmp_ctx_t *ctx = self->ctx;
    if (!ctx || !ctx->stack) {
        return;
    }
    slmp_stack_poll(ctx->stack);
    if (ctx->role != SLMP_ROLE_CLIENT) {
        return;
    }
    /* Cache PLC→sensor points (access=write from PLC perspective). */
    for (int i = 0; i < ctx->point_count; i++) {
        slmp_point_t *pt = &ctx->points[i];
        if (!access_is_plc_write(pt->access)) {
            continue;
        }
        int rc = remote_sync_read(ctx, pt);
        if (rc != 0) {
            snprintf(ctx->last_error, sizeof(ctx->last_error),
                     "poll %s failed (%d)", pt->name, rc);
            LOG_WARN("slmp", "%s", ctx->last_error);
        }
    }
}

static int app_from_wire(const slmp_point_t *pt, const uint8_t *wire,
                         size_t wire_len, uint8_t *app, size_t app_len)
{
    size_t win = map_window_bytes(pt);
    if (wire_len < win && pt->bit < 0 && pt->unit != SLMP_ACCESS_BIT) {
        return -EINVAL;
    }
    memset(app, 0, app_len);

    if (pt->bit >= 0 || pt->unit == SLMP_ACCESS_BIT) {
        size_t n = app_len < wire_len ? app_len : wire_len;
        if (n > 4 && pt->bit >= 0) {
            n = 4;
        }
        memcpy(app, wire, n < app_len ? n : app_len);
        return 0;
    }

    if (pt->data_type == SLMP_DT_STRING) {
        uint8_t tmp[WIRE_CAP];
        if (win > sizeof(tmp)) {
            return -ENOSPC;
        }
        memcpy(tmp, wire, win);
        slmp_unpack_string(app, app_len, tmp + pt->byte_offset,
                           win > pt->byte_offset ? win - pt->byte_offset : 0,
                           pt->chars_per_word, pt->string_swap, pt->trim_null);
        return 0;
    }

    size_t off = pt->byte_offset;
    if (off >= win) {
        return -EINVAL;
    }
    size_t avail = win - off;
    size_t n = app_len < avail ? app_len : avail;
    memcpy(app, wire + off, n);
    slmp_wire_to_canonical(app, app_len, pt->endian);
    return 0;
}

static int wire_from_app(const slmp_point_t *pt, const uint8_t *app,
                         size_t app_len, uint8_t *wire, size_t wire_cap)
{
    size_t win = map_window_bytes(pt);
    if (win > wire_cap) {
        return -ENOSPC;
    }
    memset(wire, 0, win);

    if (pt->bit >= 0 || pt->unit == SLMP_ACCESS_BIT) {
        size_t n = app_len < win ? app_len : win;
        memcpy(wire, app, n);
        return 0;
    }

    if (pt->data_type == SLMP_DT_STRING) {
        slmp_pack_string(wire + pt->byte_offset,
                         win > pt->byte_offset ? win - pt->byte_offset : 0, app,
                         app_len, pt->chars_per_word, pt->string_swap);
        return 0;
    }

    uint8_t tmp[WIRE_CAP];
    if (pt->byte_len > sizeof(tmp)) {
        return -ENOSPC;
    }
    memset(tmp, 0, pt->byte_len);
    size_t n = app_len < pt->byte_len ? app_len : pt->byte_len;
    memcpy(tmp, app, n);
    slmp_canonical_to_wire(tmp, pt->byte_len, pt->endian);
    if (pt->byte_offset + pt->byte_len > win) {
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

static int slmp_read_point(protocol_adapter_t *self, const char *point_name,
                           point_value_t *out)
{
    slmp_ctx_t *ctx = self->ctx;
    slmp_point_t *pt = find_point(ctx, point_name);
    if (!pt || !out) {
        return -ENOENT;
    }

    if (ctx->role == SLMP_ROLE_CLIENT && access_is_plc_write(pt->access)) {
        int rc = remote_sync_read(ctx, pt);
        if (rc != 0) {
            return rc;
        }
    }

    uint8_t wire[WIRE_CAP];
    int rc = read_map_window(ctx, pt, wire, sizeof(wire));
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

    if (pt->apply_scale && pt->data_type != SLMP_DT_STRING &&
        pt->data_type != SLMP_DT_RAW) {
        double raw = slmp_decode_number(pt->data_type, buf, n);
        if (pt->bit >= 0 || pt->unit == SLMP_ACCESS_BIT) {
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

static int slmp_write_point(protocol_adapter_t *self, const char *point_name,
                            const point_value_t *value)
{
    slmp_ctx_t *ctx = self->ctx;
    slmp_point_t *pt = find_point(ctx, point_name);
    if (!pt || !value || !value->data) {
        return -ENOENT;
    }

    uint8_t app[WIRE_CAP];
    size_t app_len = pt->byte_len;
    if (app_len > sizeof(app)) {
        return -ENOSPC;
    }
    memset(app, 0, app_len);

    if (pt->apply_scale && pt->data_type != SLMP_DT_STRING &&
        pt->data_type != SLMP_DT_RAW) {
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
            eng = slmp_decode_number(pt->data_type, tmp, app_len);
        }
        double raw =
            (eng - pt->eng_offset) / (pt->scale != 0.0 ? pt->scale : 1.0);
        if (pt->bit >= 0 || pt->unit == SLMP_ACCESS_BIT) {
            uint64_t iv = (uint64_t)llround(raw);
            if (pt->bit_count <= 8 || pt->unit == SLMP_ACCESS_BIT) {
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
            slmp_encode_number(pt->data_type, raw, app, app_len);
        }
    } else {
        size_t n = value->len < app_len ? value->len : app_len;
        memcpy(app, value->data, n);
    }

    if (ctx->role == SLMP_ROLE_CLIENT && pt->bit >= 0 &&
        pt->unit == SLMP_ACCESS_WORD) {
        int rc = remote_sync_read(ctx, pt);
        if (rc != 0) {
            return rc;
        }
    }

    uint8_t wire[WIRE_CAP];
    int rc = wire_from_app(pt, app, app_len, wire, sizeof(wire));
    if (rc != 0) {
        return rc;
    }
    rc = write_map_window(ctx, pt, wire, map_window_bytes(pt));
    if (rc != 0) {
        return rc;
    }

    if (ctx->role == SLMP_ROLE_CLIENT && access_is_plc_read(pt->access)) {
        return remote_sync_write(ctx, pt);
    }
    return 0;
}

static int slmp_health(protocol_adapter_t *self, int *connected, char *err_buf,
                       size_t err_buf_len)
{
    slmp_ctx_t *ctx = self->ctx;
    *connected = ctx && ctx->stack ? slmp_stack_connected(ctx->stack) : 0;
    snprintf(err_buf, err_buf_len, "%s", ctx ? ctx->last_error : "");
    return 0;
}

static void slmp_destroy(protocol_adapter_t *self)
{
    if (!self) {
        return;
    }
    slmp_ctx_t *ctx = self->ctx;
    if (ctx) {
        slmp_stack_destroy(ctx->stack);
        free(ctx);
    }
    free(self);
}

protocol_adapter_t *slmp_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(protocol_adapter_t));
    if (!a) {
        return NULL;
    }
    a->name = "slmp";
    a->init = slmp_init;
    a->connect = slmp_connect;
    a->disconnect = slmp_disconnect;
    a->poll_cycle = slmp_poll_cycle;
    a->read_point = slmp_read_point;
    a->write_point = slmp_write_point;
    a->health = slmp_health;
    a->destroy = slmp_destroy;
    return a;
}
