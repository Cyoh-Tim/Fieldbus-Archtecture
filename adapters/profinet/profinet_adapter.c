#include "profinet_adapter.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
#include "pn_stack.h"

#define PN_ADAPTER_POINTS_MAX 64

/* 스케일된 숫자의 IO 이미지 표현. 문자열/raw 는 복사만 한다. */
typedef enum {
    PN_DT_UINT8 = 0,
    PN_DT_INT8,
    PN_DT_UINT16,
    PN_DT_INT16,
    PN_DT_UINT32,
    PN_DT_INT32,
    PN_DT_UINT64,
    PN_DT_INT64,
    PN_DT_FLOAT32,
    PN_DT_FLOAT64,
    PN_DT_BOOL,
    PN_DT_STRING,
    PN_DT_RAW
} pn_dt_t;

typedef struct {
    char name[64];
    char access[8];
    int slot;
    int subslot;
    int index;
    int byte_offset;
    int length;
    pn_dt_t data_type;
    double scale;
    double eng_offset;
    int apply_scale;
} pn_point_t;

typedef struct {
    pn_stack_t *stack;
    pn_point_t points[PN_ADAPTER_POINTS_MAX];
    int point_count;
    char last_error[128];
} pn_ctx_t;

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_psk(const char *hex, uint8_t out[PN_PSK_LEN])
{
    size_t n = strlen(hex);
    if (n != PN_PSK_LEN * 2) {
        return -EINVAL;
    }
    for (int i = 0; i < PN_PSK_LEN; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -EINVAL;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static uint32_t parse_ipv4(const char *s)
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}

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

static pn_dt_t pn_parse_dt(const char *s)
{
    if (!s || !s[0]) {
        return PN_DT_UINT16;
    }
    if (eqi(s, "uint8") || eqi(s, "u8") || eqi(s, "byte")) {
        return PN_DT_UINT8;
    }
    if (eqi(s, "int8") || eqi(s, "i8") || eqi(s, "sbyte")) {
        return PN_DT_INT8;
    }
    if (eqi(s, "uint16") || eqi(s, "u16") || eqi(s, "word") ||
        eqi(s, "ushort")) {
        return PN_DT_UINT16;
    }
    if (eqi(s, "int16") || eqi(s, "i16") || eqi(s, "short")) {
        return PN_DT_INT16;
    }
    if (eqi(s, "uint32") || eqi(s, "u32") || eqi(s, "dword") ||
        eqi(s, "uint")) {
        return PN_DT_UINT32;
    }
    if (eqi(s, "int32") || eqi(s, "i32") || eqi(s, "int") || eqi(s, "long")) {
        return PN_DT_INT32;
    }
    if (eqi(s, "uint64") || eqi(s, "u64") || eqi(s, "qword")) {
        return PN_DT_UINT64;
    }
    if (eqi(s, "int64") || eqi(s, "i64")) {
        return PN_DT_INT64;
    }
    if (eqi(s, "float32") || eqi(s, "float") || eqi(s, "real") ||
        eqi(s, "single")) {
        return PN_DT_FLOAT32;
    }
    if (eqi(s, "float64") || eqi(s, "double")) {
        return PN_DT_FLOAT64;
    }
    if (eqi(s, "bool") || eqi(s, "boolean") || eqi(s, "bit")) {
        return PN_DT_BOOL;
    }
    if (eqi(s, "string") || eqi(s, "ascii") || eqi(s, "str")) {
        return PN_DT_STRING;
    }
    if (eqi(s, "raw") || eqi(s, "bytes") || eqi(s, "blob")) {
        return PN_DT_RAW;
    }
    return PN_DT_UINT16;
}

/* 스케일 적용 시 IO 에 쓰는 정수/실수 크기. 문자열은 length 를 쓴다. */
static int pn_type_wire_len(pn_dt_t dt, int length)
{
    switch (dt) {
    case PN_DT_UINT8:
    case PN_DT_INT8:
    case PN_DT_BOOL:
        return 1;
    case PN_DT_UINT16:
    case PN_DT_INT16:
        return 2;
    case PN_DT_UINT32:
    case PN_DT_INT32:
    case PN_DT_FLOAT32:
        return 4;
    case PN_DT_UINT64:
    case PN_DT_INT64:
    case PN_DT_FLOAT64:
        return 8;
    case PN_DT_STRING:
    case PN_DT_RAW:
        return length > 0 ? length : 0;
    }
    return length > 0 ? length : 2;
}

static uint16_t ld_be16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static uint32_t ld_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t ld_be64(const uint8_t *p)
{
    return ((uint64_t)ld_be32(p) << 32) | ld_be32(p + 4);
}

static void st_be16(uint8_t *d, uint16_t v)
{
    d[0] = (uint8_t)(v >> 8);
    d[1] = (uint8_t)v;
}

static void st_be32(uint8_t *d, uint32_t v)
{
    d[0] = (uint8_t)(v >> 24);
    d[1] = (uint8_t)(v >> 16);
    d[2] = (uint8_t)(v >> 8);
    d[3] = (uint8_t)v;
}

static void st_be64(uint8_t *d, uint64_t v)
{
    st_be32(d, (uint32_t)(v >> 32));
    st_be32(d + 4, (uint32_t)v);
}

static float ld_f32_be(const uint8_t *p)
{
    uint32_t u = ld_be32(p);
    float f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static double ld_f64_be(const uint8_t *p)
{
    uint64_t u = ld_be64(p);
    double d;
    memcpy(&d, &u, sizeof(d));
    return d;
}

static void st_f32_be(uint8_t *d, float f)
{
    uint32_t u;
    memcpy(&u, &f, sizeof(u));
    st_be32(d, u);
}

static void st_f64_be(uint8_t *d, double v)
{
    uint64_t u;
    memcpy(&u, &v, sizeof(u));
    st_be64(d, u);
}

/* llround 와 같이 0.5 는 0 에서 먼 쪽으로. libm 에 의존하지 않는다. */
static int64_t pn_iround(double x)
{
    if (x >= 0.0) {
        return (int64_t)(x + 0.5);
    }
    return (int64_t)(x - 0.5);
}

static double pn_decode_number(pn_dt_t dt, const uint8_t *b, size_t n)
{
    switch (dt) {
    case PN_DT_UINT8:
        return n >= 1 ? (double)b[0] : 0.0;
    case PN_DT_INT8:
        return n >= 1 ? (double)(int8_t)b[0] : 0.0;
    case PN_DT_UINT16:
        return n >= 2 ? (double)ld_be16(b) : 0.0;
    case PN_DT_INT16:
        return n >= 2 ? (double)(int16_t)ld_be16(b) : 0.0;
    case PN_DT_UINT32:
        return n >= 4 ? (double)ld_be32(b) : 0.0;
    case PN_DT_INT32:
        return n >= 4 ? (double)(int32_t)ld_be32(b) : 0.0;
    case PN_DT_UINT64:
        return n >= 8 ? (double)ld_be64(b) : 0.0;
    case PN_DT_INT64:
        return n >= 8 ? (double)(int64_t)ld_be64(b) : 0.0;
    case PN_DT_FLOAT32:
        return n >= 4 ? (double)ld_f32_be(b) : 0.0;
    case PN_DT_FLOAT64:
        return n >= 8 ? ld_f64_be(b) : 0.0;
    case PN_DT_BOOL:
        return (n >= 1 && b[0]) ? 1.0 : 0.0;
    default:
        return 0.0;
    }
}

static void pn_encode_number(pn_dt_t dt, double raw, uint8_t *b, size_t n)
{
    memset(b, 0, n);
    switch (dt) {
    case PN_DT_UINT8:
        if (n >= 1) {
            b[0] = (uint8_t)pn_iround(raw);
        }
        break;
    case PN_DT_INT8:
        if (n >= 1) {
            b[0] = (uint8_t)(int8_t)pn_iround(raw);
        }
        break;
    case PN_DT_UINT16:
        if (n >= 2) {
            st_be16(b, (uint16_t)pn_iround(raw));
        }
        break;
    case PN_DT_INT16:
        if (n >= 2) {
            st_be16(b, (uint16_t)(int16_t)pn_iround(raw));
        }
        break;
    case PN_DT_UINT32:
        if (n >= 4) {
            st_be32(b, (uint32_t)pn_iround(raw));
        }
        break;
    case PN_DT_INT32:
        if (n >= 4) {
            st_be32(b, (uint32_t)(int32_t)pn_iround(raw));
        }
        break;
    case PN_DT_UINT64:
        if (n >= 8) {
            st_be64(b, (uint64_t)pn_iround(raw));
        }
        break;
    case PN_DT_INT64:
        if (n >= 8) {
            st_be64(b, (uint64_t)pn_iround(raw));
        }
        break;
    case PN_DT_FLOAT32:
        if (n >= 4) {
            st_f32_be(b, (float)raw);
        }
        break;
    case PN_DT_FLOAT64:
        if (n >= 8) {
            st_f64_be(b, raw);
        }
        break;
    case PN_DT_BOOL:
        if (n >= 1) {
            b[0] = (raw != 0.0) ? 1 : 0;
        }
        break;
    default:
        break;
    }
}

static int parse_points(pn_ctx_t *ctx, const char *points_json)
{
    cJSON *arr = cJSON_Parse(points_json);
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return 0;
    }
    cJSON *p;
    cJSON_ArrayForEach(p, arr)
    {
        if (ctx->point_count >= PN_ADAPTER_POINTS_MAX) {
            break;
        }
        pn_point_t *pt = &ctx->points[ctx->point_count];
        memset(pt, 0, sizeof(*pt));
        cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        cJSON *length = cJSON_GetObjectItemCaseSensitive(p, "length");
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(p, "address");
        cJSON *pn = addr ? cJSON_GetObjectItemCaseSensitive(addr, "profinet")
                         : NULL;
        if (!cJSON_IsString(name) || !cJSON_IsObject(pn)) {
            continue;
        }
        snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
        snprintf(pt->access, sizeof(pt->access), "%s",
                 cJSON_IsString(access) ? access->valuestring : "read");
        pt->length = cJSON_IsNumber(length) ? length->valueint : 1;
        cJSON *dt = cJSON_GetObjectItemCaseSensitive(p, "data_type");
        if (!cJSON_IsString(dt)) {
            dt = cJSON_GetObjectItemCaseSensitive(p, "datatype");
        }
        pt->data_type = pn_parse_dt(cJSON_IsString(dt) ? dt->valuestring : NULL);
        cJSON *sc = cJSON_GetObjectItemCaseSensitive(p, "scale");
        if (!cJSON_IsNumber(sc)) {
            sc = cJSON_GetObjectItemCaseSensitive(p, "gain");
        }
        pt->scale = cJSON_IsNumber(sc) ? sc->valuedouble : 1.0;
        cJSON *eoff = cJSON_GetObjectItemCaseSensitive(p, "offset");
        pt->eng_offset = cJSON_IsNumber(eoff) ? eoff->valuedouble : 0.0;
        pt->apply_scale = pt->data_type != PN_DT_STRING &&
                          pt->data_type != PN_DT_RAW &&
                          (pt->scale != 1.0 || pt->eng_offset != 0.0);
        cJSON *slot = cJSON_GetObjectItemCaseSensitive(pn, "slot");
        cJSON *sub = cJSON_GetObjectItemCaseSensitive(pn, "subslot");
        cJSON *idx = cJSON_GetObjectItemCaseSensitive(pn, "index");
        cJSON *off = cJSON_GetObjectItemCaseSensitive(pn, "byte_offset");
        pt->slot = cJSON_IsNumber(slot) ? slot->valueint : 1;
        pt->subslot = cJSON_IsNumber(sub) ? sub->valueint : 1;
        pt->index = cJSON_IsNumber(idx) ? idx->valueint : 1;
        pt->byte_offset = cJSON_IsNumber(off) ? off->valueint : 0;
        ctx->point_count++;
    }
    cJSON_Delete(arr);
    return 0;
}

static int pn_init(protocol_adapter_t *self, const char *protocol_params_json,
                   const char *points_json)
{
    pn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -ENOMEM;
    }

    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* Vendor integrity extension stays off. PI Security Class 1 does not
     * put HMAC on frames; a standard controller must be able to Connect
     * and set the station name. protocol_params.security_class still
     * turns the extension on. */
    cfg.security_class = 0;
    cfg.cycle_us = 8000;
    cfg.input_len = 32;
    cfg.output_len = 8;
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        cJSON *iface = cJSON_GetObjectItemCaseSensitive(params, "iface");
        if (cJSON_IsString(iface)) {
            snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface->valuestring);
        }
        cJSON *dn = cJSON_GetObjectItemCaseSensitive(params, "device_name");
        if (cJSON_IsString(dn)) {
            snprintf(cfg.station_name, sizeof(cfg.station_name), "%s",
                     dn->valuestring);
        }
        cJSON *vid = cJSON_GetObjectItemCaseSensitive(params, "vendor_id");
        if (cJSON_IsNumber(vid)) {
            cfg.vendor_id = (uint16_t)vid->valueint;
        }
        cJSON *did = cJSON_GetObjectItemCaseSensitive(params, "device_id");
        if (cJSON_IsNumber(did)) {
            cfg.device_id = (uint16_t)did->valueint;
        }
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(params, "ip");
        if (cJSON_IsString(ip)) {
            cfg.ip = parse_ipv4(ip->valuestring);
        }
        cJSON *mask = cJSON_GetObjectItemCaseSensitive(params, "netmask");
        if (cJSON_IsString(mask)) {
            cfg.netmask = parse_ipv4(mask->valuestring);
        }
        cJSON *gw = cJSON_GetObjectItemCaseSensitive(params, "gateway");
        if (cJSON_IsString(gw)) {
            cfg.gateway = parse_ipv4(gw->valuestring);
        }
        cJSON *sc = cJSON_GetObjectItemCaseSensitive(params, "security_class");
        if (cJSON_IsNumber(sc)) {
            cfg.security_class = sc->valueint;
        }
        cJSON *enf =
            cJSON_GetObjectItemCaseSensitive(params, "enforce_security_class");
        if (cJSON_IsBool(enf)) {
            cfg.enforce_security_class = cJSON_IsTrue(enf);
        } else if (cJSON_IsNumber(enf)) {
            cfg.enforce_security_class = enf->valueint != 0;
        }
        cJSON *psk = cJSON_GetObjectItemCaseSensitive(params, "psk_hex");
        if (cJSON_IsString(psk)) {
            if (parse_psk(psk->valuestring, cfg.psk) == 0) {
                cfg.psk_set = 1;
            } else {
                LOG_ERROR("profinet",
                          "psk_hex 는 64 hex chars (32 bytes) 여야 함");
                cJSON_Delete(params);
                free(ctx);
                return -EINVAL;
            }
        }
        cJSON *ilen = cJSON_GetObjectItemCaseSensitive(params, "input_len");
        if (cJSON_IsNumber(ilen)) {
            cfg.input_len = (uint16_t)ilen->valueint;
        }
        cJSON *olen = cJSON_GetObjectItemCaseSensitive(params, "output_len");
        if (cJSON_IsNumber(olen)) {
            cfg.output_len = (uint16_t)olen->valueint;
        }
        cJSON *cycle = cJSON_GetObjectItemCaseSensitive(params, "cycle_us");
        if (cJSON_IsNumber(cycle)) {
            cfg.cycle_us = (uint32_t)cycle->valueint;
        }
        cJSON_Delete(params);
    }

    if (cfg.security_class >= PN_VENDOR_INTEGRITY && !cfg.psk_set) {
        LOG_ERROR("profinet",
                  "security_class>=1 (vendor integrity extension) 이면 "
                  "protocol_params.psk_hex 가 필요함");
        free(ctx);
        return -EINVAL;
    }

    parse_points(ctx, points_json);
    ctx->stack = pn_stack_create(&cfg);
    if (!ctx->stack) {
        free(ctx);
        return -ENOMEM;
    }
    self->ctx = ctx;
    LOG_INFO("profinet",
             "init CC-B/RT1 device=%s points=%d vendor_integrity=%d (IRT 없음)",
             cfg.station_name, ctx->point_count, cfg.security_class);
    return 0;
}

static int pn_connect(protocol_adapter_t *self)
{
    pn_ctx_t *ctx = self->ctx;
    int rc = pn_stack_start(ctx->stack);
    if (rc != 0) {
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "stack start failed (%d)", rc);
        LOG_ERROR("profinet", "%s", ctx->last_error);
        return rc;
    }
    return 0;
}

static void pn_disconnect(protocol_adapter_t *self)
{
    pn_ctx_t *ctx = self->ctx;
    if (ctx && ctx->stack) {
        pn_stack_stop(ctx->stack);
    }
}

static void pn_poll_cycle(protocol_adapter_t *self)
{
    pn_ctx_t *ctx = self->ctx;
    if (ctx && ctx->stack) {
        pn_stack_poll(ctx->stack);
    }
}

static pn_point_t *find_point(pn_ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->point_count; i++) {
        if (strcmp(ctx->points[i].name, name) == 0) {
            return &ctx->points[i];
        }
    }
    return NULL;
}

static int pn_read_image(pn_ctx_t *ctx, const pn_point_t *pt, uint8_t *dst,
                         size_t n)
{
    if (strcmp(pt->access, "write") == 0) {
        return pn_stack_read_output(ctx->stack, (size_t)pt->byte_offset, dst,
                                    n);
    }
    return pn_stack_read_input(ctx->stack, (size_t)pt->byte_offset, dst, n);
}

static int pn_read_point(protocol_adapter_t *self, const char *point_name,
                         point_value_t *out)
{
    pn_ctx_t *ctx = self->ctx;
    pn_point_t *pt = find_point(ctx, point_name);
    if (!pt || !out || !out->data) {
        return -EINVAL;
    }
    /* T0 A안: wire 정수 → eng = raw*scale+offset → float32(BE) 4바이트. */
    if (pt->apply_scale) {
        int wlen = pn_type_wire_len(pt->data_type, pt->length);
        if (wlen <= 0 || wlen > 8) {
            return -EINVAL;
        }
        if (out->len < 4) {
            return -ENOSPC;
        }
        uint8_t wire[8];
        memset(wire, 0, sizeof(wire));
        int rc = pn_read_image(ctx, pt, wire, (size_t)wlen);
        if (rc != 0) {
            return rc;
        }
        double raw = pn_decode_number(pt->data_type, wire, (size_t)wlen);
        double eng = raw * pt->scale + pt->eng_offset;
        st_f32_be(out->data, (float)eng);
        out->len = 4;
        return 0;
    }
    size_t n = (size_t)pt->length;
    if (n > out->len) {
        n = out->len;
    }
    int rc = pn_read_image(ctx, pt, out->data, n);
    if (rc == 0) {
        out->len = n;
    }
    return rc;
}

static int pn_write_point(protocol_adapter_t *self, const char *point_name,
                          const point_value_t *value)
{
    pn_ctx_t *ctx = self->ctx;
    pn_point_t *pt = find_point(ctx, point_name);
    if (!pt || !value || !value->data) {
        return -EINVAL;
    }
    /* T0 A안: float32(BE) 공학값 → raw = (eng-offset)/scale → data_type 크기, BE. */
    if (pt->apply_scale) {
        int wlen = pn_type_wire_len(pt->data_type, pt->length);
        if (wlen <= 0 || wlen > 8) {
            return -EINVAL;
        }
        double eng;
        if (value->len >= 4) {
            eng = (double)ld_f32_be(value->data);
        } else {
            uint8_t tmp[8];
            memset(tmp, 0, sizeof(tmp));
            size_t n = value->len < (size_t)wlen ? value->len : (size_t)wlen;
            if (n > 0) {
                memcpy(tmp, value->data, n);
            }
            eng = pn_decode_number(pt->data_type, tmp, (size_t)wlen);
        }
        double denom = pt->scale != 0.0 ? pt->scale : 1.0;
        double raw = (eng - pt->eng_offset) / denom;
        uint8_t wire[8];
        pn_encode_number(pt->data_type, raw, wire, (size_t)wlen);
        return pn_stack_write_input(ctx->stack, (size_t)pt->byte_offset, wire,
                                    (size_t)wlen);
    }
    size_t n = value->len;
    if ((int)n > pt->length) {
        n = (size_t)pt->length;
    }
    return pn_stack_write_input(ctx->stack, (size_t)pt->byte_offset, value->data,
                                n);
}

static int pn_health(protocol_adapter_t *self, int *connected, char *err_buf,
                     size_t err_buf_len)
{
    pn_ctx_t *ctx = self->ctx;
    *connected = pn_stack_ar_up(ctx->stack);
    snprintf(err_buf, err_buf_len, "%s", ctx->last_error);
    return 0;
}

static void pn_destroy(protocol_adapter_t *self)
{
    if (!self) {
        return;
    }
    pn_ctx_t *ctx = self->ctx;
    if (ctx) {
        pn_stack_destroy(ctx->stack);
        free(ctx);
    }
    free(self);
}

protocol_adapter_t *profinet_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
    a->name = "profinet";
    a->init = pn_init;
    a->connect = pn_connect;
    a->disconnect = pn_disconnect;
    a->poll_cycle = pn_poll_cycle;
    a->read_point = pn_read_point;
    a->write_point = pn_write_point;
    a->health = pn_health;
    a->destroy = pn_destroy;
    return a;
}
