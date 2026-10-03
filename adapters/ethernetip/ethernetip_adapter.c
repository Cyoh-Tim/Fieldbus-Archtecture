#include "ethernetip_adapter.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "eip_stack.h"
#include "logger.h"

/*
 * Point capacity is intentionally high and heap-backed so one daemon image
 * can map large multi-sensor process images without recompiling.
 */
#define EIP_ADAPTER_POINTS_INITIAL 256
#define EIP_ADAPTER_NAME_MAX 128
#define EIP_ADAPTER_TAG_MAX EIP_TAG_NAME_MAX

typedef enum {
    EIP_ADDR_ASSEMBLY = 0,
    EIP_ADDR_TAG = 1,
    EIP_ADDR_CIP_PATH = 2,
} eip_addr_kind_t;

/* 스케일된 숫자의 Assembly 표현. 문자열/raw/bool 은 복사만 한다.
 * bcd16/bcd32 는 T1 과 같이 그 폭의 정수(엔디안만 변환)로 다룬다. */
typedef enum {
    EIP_DT_NONE = 0, /* 누락·미인식: 변환 없음 */
    EIP_DT_UINT8,
    EIP_DT_INT8,
    EIP_DT_UINT16,
    EIP_DT_INT16,
    EIP_DT_UINT32,
    EIP_DT_INT32,
    EIP_DT_UINT64,
    EIP_DT_INT64,
    EIP_DT_FLOAT32,
    EIP_DT_FLOAT64,
    EIP_DT_BOOL,
    EIP_DT_STRING,
    EIP_DT_RAW,
} eip_dt_t;

typedef struct {
    char name[EIP_ADAPTER_NAME_MAX];
    char access[8]; /* read | write */
    eip_addr_kind_t kind;
    char tag[EIP_ADAPTER_TAG_MAX];
    uint16_t class_id;
    uint16_t instance;
    uint16_t attribute;
    uint16_t assembly;
    int byte_offset;
    int length;
    eip_dt_t data_type;
    double scale;
    double eng_offset;
    int apply_scale;
    /* 0 = no endian conversion (bool/string/bytes/uint8/missing/unknown).
     * 2/4/8 = numeric width; app boundary is canonical big-endian, CIP wire
     * is little-endian. */
    size_t endian_width;
} eip_point_t;

typedef struct {
    eip_stack_t *stack; /* first field: tests peek the stack through ctx */
    eip_point_t *points;
    int point_count;
    int point_cap;
    eip_role_t role;
    char last_error[128];
} eip_ctx_t;

static int ensure_point_cap(eip_ctx_t *ctx, int need)
{
    if (need <= ctx->point_cap) {
        return 0;
    }
    int cap = ctx->point_cap ? ctx->point_cap : EIP_ADAPTER_POINTS_INITIAL;
    while (cap < need) {
        if (cap > 65536 / 2) {
            return -ENOMEM;
        }
        cap *= 2;
    }
    eip_point_t *n =
        realloc(ctx->points, (size_t)cap * sizeof(eip_point_t));
    if (!n) {
        return -ENOMEM;
    }
    ctx->points = n;
    ctx->point_cap = cap;
    return 0;
}

static int eqi(const char *a, const char *b)
{
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (tolower(ca) != tolower(cb)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

/* 0 = recognized (including empty). -1 = data_type string was not recognized. */
static int eip_parse_dt(const char *s, eip_dt_t *out)
{
    if (!s || !s[0]) {
        *out = EIP_DT_NONE;
        return 0;
    }
    if (eqi(s, "bool") || eqi(s, "boolean") || eqi(s, "bit")) {
        *out = EIP_DT_BOOL;
        return 0;
    }
    if (eqi(s, "string") || eqi(s, "ascii") || eqi(s, "str")) {
        *out = EIP_DT_STRING;
        return 0;
    }
    if (eqi(s, "raw") || eqi(s, "bytes") || eqi(s, "blob")) {
        *out = EIP_DT_RAW;
        return 0;
    }
    if (eqi(s, "uint8") || eqi(s, "u8") || eqi(s, "byte")) {
        *out = EIP_DT_UINT8;
        return 0;
    }
    if (eqi(s, "int8") || eqi(s, "i8") || eqi(s, "sbyte")) {
        *out = EIP_DT_INT8;
        return 0;
    }
    if (eqi(s, "uint16") || eqi(s, "u16") || eqi(s, "word") || eqi(s, "ushort") ||
        eqi(s, "bcd16") || eqi(s, "bcd")) {
        *out = EIP_DT_UINT16;
        return 0;
    }
    if (eqi(s, "int16") || eqi(s, "i16") || eqi(s, "short")) {
        *out = EIP_DT_INT16;
        return 0;
    }
    if (eqi(s, "uint32") || eqi(s, "u32") || eqi(s, "dword") || eqi(s, "uint") ||
        eqi(s, "bcd32")) {
        *out = EIP_DT_UINT32;
        return 0;
    }
    if (eqi(s, "int32") || eqi(s, "i32") || eqi(s, "int") || eqi(s, "long")) {
        *out = EIP_DT_INT32;
        return 0;
    }
    if (eqi(s, "float32") || eqi(s, "float") || eqi(s, "real") ||
        eqi(s, "single")) {
        *out = EIP_DT_FLOAT32;
        return 0;
    }
    if (eqi(s, "uint64") || eqi(s, "u64") || eqi(s, "qword")) {
        *out = EIP_DT_UINT64;
        return 0;
    }
    if (eqi(s, "int64") || eqi(s, "i64")) {
        *out = EIP_DT_INT64;
        return 0;
    }
    if (eqi(s, "float64") || eqi(s, "double")) {
        *out = EIP_DT_FLOAT64;
        return 0;
    }
    *out = EIP_DT_NONE;
    return -1;
}

static size_t eip_endian_width(eip_dt_t dt)
{
    switch (dt) {
    case EIP_DT_UINT16:
    case EIP_DT_INT16:
        return 2;
    case EIP_DT_UINT32:
    case EIP_DT_INT32:
    case EIP_DT_FLOAT32:
        return 4;
    case EIP_DT_UINT64:
    case EIP_DT_INT64:
    case EIP_DT_FLOAT64:
        return 8;
    default:
        return 0;
    }
}

static int eip_dt_is_numeric(eip_dt_t dt)
{
    return eip_endian_width(dt) > 0 || dt == EIP_DT_UINT8 || dt == EIP_DT_INT8;
}

static int eip_type_wire_len(eip_dt_t dt)
{
    switch (dt) {
    case EIP_DT_UINT8:
    case EIP_DT_INT8:
        return 1;
    case EIP_DT_UINT16:
    case EIP_DT_INT16:
        return 2;
    case EIP_DT_UINT32:
    case EIP_DT_INT32:
    case EIP_DT_FLOAT32:
        return 4;
    case EIP_DT_UINT64:
    case EIP_DT_INT64:
    case EIP_DT_FLOAT64:
        return 8;
    default:
        return 0;
    }
}

static void eip_swap_elems(uint8_t *buf, size_t n, size_t width)
{
    if (!buf || width < 2 || n < width) {
        return;
    }
    size_t elems = n / width;
    for (size_t e = 0; e < elems; e++) {
        uint8_t *p = buf + e * width;
        size_t i = 0;
        size_t j = width - 1;
        while (i < j) {
            uint8_t t = p[i];
            p[i] = p[j];
            p[j] = t;
            i++;
            j--;
        }
    }
}

/* Numeric points: API boundary is canonical big-endian, including fb_read_bytes.
 * CIP wire stays little-endian (canon_to_wire / wire_to_canon). */
static void wire_to_canon(const eip_point_t *pt, uint8_t *buf, size_t n)
{
    if (!pt || pt->endian_width < 2 || !buf || n < pt->endian_width) {
        return;
    }
    eip_swap_elems(buf, n, pt->endian_width);
}

static int canon_to_wire(const eip_point_t *pt, uint8_t *dst, size_t dst_cap,
                         const uint8_t *src, size_t n)
{
    if (n > dst_cap) {
        return -ENOSPC;
    }
    if (n > 0) {
        memcpy(dst, src, n);
    }
    if (pt && pt->endian_width >= 2) {
        eip_swap_elems(dst, n, pt->endian_width);
    }
    return 0;
}

static uint16_t eip_ld_be16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static uint32_t eip_ld_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t eip_ld_be64(const uint8_t *p)
{
    return ((uint64_t)eip_ld_be32(p) << 32) | eip_ld_be32(p + 4);
}

static void eip_st_be16(uint8_t *d, uint16_t v)
{
    d[0] = (uint8_t)(v >> 8);
    d[1] = (uint8_t)v;
}

static void eip_st_be32(uint8_t *d, uint32_t v)
{
    d[0] = (uint8_t)(v >> 24);
    d[1] = (uint8_t)(v >> 16);
    d[2] = (uint8_t)(v >> 8);
    d[3] = (uint8_t)v;
}

static void eip_st_be64(uint8_t *d, uint64_t v)
{
    eip_st_be32(d, (uint32_t)(v >> 32));
    eip_st_be32(d + 4, (uint32_t)v);
}

static float eip_ld_f32_be(const uint8_t *p)
{
    uint32_t u = eip_ld_be32(p);
    float f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static double eip_ld_f64_be(const uint8_t *p)
{
    uint64_t u = eip_ld_be64(p);
    double d;
    memcpy(&d, &u, sizeof(d));
    return d;
}

static void eip_st_f32_be(uint8_t *d, float f)
{
    uint32_t u;
    memcpy(&u, &f, sizeof(u));
    eip_st_be32(d, u);
}

static void eip_st_f64_be(uint8_t *d, double v)
{
    uint64_t u;
    memcpy(&u, &v, sizeof(u));
    eip_st_be64(d, u);
}

/* 0.5 는 0 에서 먼 쪽으로. libm 에 의존하지 않는다. */
static int64_t eip_iround(double x)
{
    if (x >= 0.0) {
        return (int64_t)(x + 0.5);
    }
    return (int64_t)(x - 0.5);
}

static double eip_decode_number(eip_dt_t dt, const uint8_t *b, size_t n)
{
    switch (dt) {
    case EIP_DT_UINT8:
        return n >= 1 ? (double)b[0] : 0.0;
    case EIP_DT_INT8:
        return n >= 1 ? (double)(int8_t)b[0] : 0.0;
    case EIP_DT_UINT16:
        return n >= 2 ? (double)eip_ld_be16(b) : 0.0;
    case EIP_DT_INT16:
        return n >= 2 ? (double)(int16_t)eip_ld_be16(b) : 0.0;
    case EIP_DT_UINT32:
        return n >= 4 ? (double)eip_ld_be32(b) : 0.0;
    case EIP_DT_INT32:
        return n >= 4 ? (double)(int32_t)eip_ld_be32(b) : 0.0;
    case EIP_DT_UINT64:
        return n >= 8 ? (double)eip_ld_be64(b) : 0.0;
    case EIP_DT_INT64:
        return n >= 8 ? (double)(int64_t)eip_ld_be64(b) : 0.0;
    case EIP_DT_FLOAT32:
        return n >= 4 ? (double)eip_ld_f32_be(b) : 0.0;
    case EIP_DT_FLOAT64:
        return n >= 8 ? eip_ld_f64_be(b) : 0.0;
    default:
        return 0.0;
    }
}

static void eip_encode_number(eip_dt_t dt, double raw, uint8_t *b, size_t n)
{
    memset(b, 0, n);
    switch (dt) {
    case EIP_DT_UINT8:
        if (n >= 1) {
            b[0] = (uint8_t)eip_iround(raw);
        }
        break;
    case EIP_DT_INT8:
        if (n >= 1) {
            b[0] = (uint8_t)(int8_t)eip_iround(raw);
        }
        break;
    case EIP_DT_UINT16:
        if (n >= 2) {
            eip_st_be16(b, (uint16_t)eip_iround(raw));
        }
        break;
    case EIP_DT_INT16:
        if (n >= 2) {
            eip_st_be16(b, (uint16_t)(int16_t)eip_iround(raw));
        }
        break;
    case EIP_DT_UINT32:
        if (n >= 4) {
            eip_st_be32(b, (uint32_t)eip_iround(raw));
        }
        break;
    case EIP_DT_INT32:
        if (n >= 4) {
            eip_st_be32(b, (uint32_t)(int32_t)eip_iround(raw));
        }
        break;
    case EIP_DT_UINT64:
        if (n >= 8) {
            eip_st_be64(b, (uint64_t)eip_iround(raw));
        }
        break;
    case EIP_DT_INT64:
        if (n >= 8) {
            eip_st_be64(b, (uint64_t)eip_iround(raw));
        }
        break;
    case EIP_DT_FLOAT32:
        if (n >= 4) {
            eip_st_f32_be(b, (float)raw);
        }
        break;
    case EIP_DT_FLOAT64:
        if (n >= 8) {
            eip_st_f64_be(b, raw);
        }
        break;
    default:
        break;
    }
}

static int parse_points(eip_ctx_t *ctx, const char *points_json)
{
    cJSON *arr = cJSON_Parse(points_json);
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return 0;
    }
    int idx = 0;
    cJSON *p;
    cJSON_ArrayForEach(p, arr)
    {
        if (ensure_point_cap(ctx, idx + 1) != 0) {
            LOG_ERROR("ethernetip", "points 할당 실패 (확장 한도)");
            break;
        }
        cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        cJSON *length = cJSON_GetObjectItemCaseSensitive(p, "length");
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(p, "address");
        cJSON *eip =
            addr ? cJSON_GetObjectItemCaseSensitive(addr, "ethernetip") : NULL;
        if (!cJSON_IsString(name) || !cJSON_IsObject(eip)) {
            LOG_WARN("ethernetip",
                     "포인트 정의 누락(name/address.ethernetip) - 건너뜀");
            continue;
        }
        eip_point_t *pt = &ctx->points[idx];
        memset(pt, 0, sizeof(*pt));
        pt->scale = 1.0;
        snprintf(pt->name, sizeof(pt->name), "%s", name->valuestring);
        snprintf(pt->access, sizeof(pt->access), "%s",
                 cJSON_IsString(access) ? access->valuestring : "read");
        pt->length = cJSON_IsNumber(length) ? length->valueint : 1;
        cJSON *dtype = cJSON_GetObjectItemCaseSensitive(p, "data_type");
        if (!cJSON_IsString(dtype)) {
            dtype = cJSON_GetObjectItemCaseSensitive(p, "datatype");
        }
        if (cJSON_IsString(dtype)) {
            eip_dt_t dt = EIP_DT_NONE;
            if (eip_parse_dt(dtype->valuestring, &dt) != 0) {
                LOG_WARN("ethernetip",
                         "point %s data_type '%s' 미인식 - 바이트 순서 변환 없음",
                         pt->name, dtype->valuestring);
                dt = EIP_DT_NONE;
            }
            pt->data_type = dt;
            pt->endian_width = eip_endian_width(dt);
        }
        cJSON *sc = cJSON_GetObjectItemCaseSensitive(p, "scale");
        if (!cJSON_IsNumber(sc)) {
            sc = cJSON_GetObjectItemCaseSensitive(p, "gain");
        }
        pt->scale = cJSON_IsNumber(sc) ? sc->valuedouble : 1.0;
        cJSON *eoff = cJSON_GetObjectItemCaseSensitive(p, "offset");
        pt->eng_offset = cJSON_IsNumber(eoff) ? eoff->valuedouble : 0.0;
        pt->apply_scale = eip_dt_is_numeric(pt->data_type) &&
                          (pt->scale != 1.0 || pt->eng_offset != 0.0);
        if (!eip_dt_is_numeric(pt->data_type) &&
            (pt->scale != 1.0 || pt->eng_offset != 0.0)) {
            LOG_WARN("ethernetip",
                     "point %s scale/offset 는 숫자 data_type 에만 적용",
                     pt->name);
        }

        cJSON *tag = cJSON_GetObjectItemCaseSensitive(eip, "tag");
        cJSON *asm_id = cJSON_GetObjectItemCaseSensitive(eip, "assembly");
        cJSON *off = cJSON_GetObjectItemCaseSensitive(eip, "byte_offset");
        cJSON *cls = cJSON_GetObjectItemCaseSensitive(eip, "class_id");
        cJSON *inst = cJSON_GetObjectItemCaseSensitive(eip, "instance");
        cJSON *attr = cJSON_GetObjectItemCaseSensitive(eip, "attribute");
        cJSON *alen = cJSON_GetObjectItemCaseSensitive(eip, "length");
        if (cJSON_IsNumber(alen)) {
            pt->length = alen->valueint;
        }
        pt->byte_offset = cJSON_IsNumber(off) ? off->valueint : 0;

        if (cJSON_IsString(tag) && tag->valuestring[0]) {
            pt->kind = EIP_ADDR_TAG;
            snprintf(pt->tag, sizeof(pt->tag), "%s", tag->valuestring);
        } else if (cJSON_IsNumber(cls) && cJSON_IsNumber(inst)) {
            pt->kind = EIP_ADDR_CIP_PATH;
            pt->class_id = (uint16_t)cls->valueint;
            pt->instance = (uint16_t)inst->valueint;
            pt->attribute =
                cJSON_IsNumber(attr) ? (uint16_t)attr->valueint : 3;
        } else {
            pt->kind = EIP_ADDR_ASSEMBLY;
            pt->assembly =
                cJSON_IsNumber(asm_id) ? (uint16_t)asm_id->valueint : 0;
        }
        idx++;
    }
    ctx->point_count = idx;
    cJSON_Delete(arr);
    return 0;
}

static int eip_init(protocol_adapter_t *self, const char *protocol_params_json,
                    const char *points_json)
{
    eip_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -ENOMEM;
    }
    ctx->role = EIP_ROLE_ADAPTER;

    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.tcp_port = EIP_TCP_PORT_DEFAULT;
    cfg.udp_io_port = EIP_UDP_IO_PORT_DEFAULT;
    cfg.input_assembly = EIP_ASM_INPUT_DEFAULT;
    cfg.output_assembly = EIP_ASM_OUTPUT_DEFAULT;
    cfg.config_assembly = EIP_ASM_CONFIG_DEFAULT;
    cfg.input_size = 256;  /* scalable default process image */
    cfg.output_size = 256;
    cfg.config_size = 1;
    cfg.rpi_us = 8000;
    cfg.vendor_id = 0xABCD;
    cfg.device_type = 0x0C;
    cfg.product_code = 1;
    cfg.major_rev = 1;
    cfg.minor_rev = 0;
    cfg.lldp_enable = 1;
    cfg.acd_enable = 1;
    cfg.lldp_tx_interval_sec = 30;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "FieldbusSensor");

    cJSON *params = cJSON_Parse(protocol_params_json);
    if (params) {
        cJSON *role = cJSON_GetObjectItemCaseSensitive(params, "role");
        if (cJSON_IsString(role) &&
            strcmp(role->valuestring, "client") == 0) {
            cfg.role = EIP_ROLE_ORIGINATOR;
            ctx->role = EIP_ROLE_ORIGINATOR;
        }
        cJSON *bind = cJSON_GetObjectItemCaseSensitive(params, "bind_ip");
        if (cJSON_IsString(bind)) {
            snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", bind->valuestring);
        }
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(params, "ip");
        if (cJSON_IsString(ip)) {
            /* adapter: optional bind; originator: remote peer */
            if (cfg.role == EIP_ROLE_ORIGINATOR) {
                snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "%s",
                         ip->valuestring);
            } else if (!cfg.bind_ip[0]) {
                snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s",
                         ip->valuestring);
            }
        }
        cJSON *rip = cJSON_GetObjectItemCaseSensitive(params, "remote_ip");
        if (cJSON_IsString(rip)) {
            snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "%s",
                     rip->valuestring);
        }
        cJSON *port = cJSON_GetObjectItemCaseSensitive(params, "port");
        if (cJSON_IsNumber(port)) {
            cfg.tcp_port = port->valueint;
            cfg.remote_port = port->valueint;
        }
        cJSON *udp = cJSON_GetObjectItemCaseSensitive(params, "udp_io_port");
        if (cJSON_IsNumber(udp)) {
            cfg.udp_io_port = udp->valueint;
        }
        cJSON *vid = cJSON_GetObjectItemCaseSensitive(params, "vendor_id");
        if (cJSON_IsNumber(vid)) {
            cfg.vendor_id = (uint16_t)vid->valueint;
        }
        cJSON *dt = cJSON_GetObjectItemCaseSensitive(params, "device_type");
        if (cJSON_IsNumber(dt)) {
            cfg.device_type = (uint16_t)dt->valueint;
        }
        cJSON *pc = cJSON_GetObjectItemCaseSensitive(params, "product_code");
        if (cJSON_IsNumber(pc)) {
            cfg.product_code = (uint16_t)pc->valueint;
        }
        cJSON *sn = cJSON_GetObjectItemCaseSensitive(params, "serial_number");
        if (cJSON_IsNumber(sn)) {
            cfg.serial_number = (uint32_t)sn->valuedouble;
        }
        cJSON *pn = cJSON_GetObjectItemCaseSensitive(params, "product_name");
        if (cJSON_IsString(pn)) {
            snprintf(cfg.product_name, sizeof(cfg.product_name), "%s",
                     pn->valuestring);
        }
        cJSON *ia = cJSON_GetObjectItemCaseSensitive(params, "input_assembly");
        if (cJSON_IsNumber(ia)) {
            cfg.input_assembly = (uint16_t)ia->valueint;
        }
        cJSON *oa = cJSON_GetObjectItemCaseSensitive(params, "output_assembly");
        if (cJSON_IsNumber(oa)) {
            cfg.output_assembly = (uint16_t)oa->valueint;
        }
        cJSON *ca = cJSON_GetObjectItemCaseSensitive(params, "config_assembly");
        if (cJSON_IsNumber(ca)) {
            cfg.config_assembly = (uint16_t)ca->valueint;
        }
        /* design.md legacy key */
        cJSON *ai =
            cJSON_GetObjectItemCaseSensitive(params, "assembly_instance");
        if (cJSON_IsNumber(ai)) {
            cfg.input_assembly = (uint16_t)ai->valueint;
        }
        cJSON *ilen = cJSON_GetObjectItemCaseSensitive(params, "input_size");
        if (cJSON_IsNumber(ilen)) {
            cfg.input_size = (uint16_t)ilen->valueint;
        }
        cJSON *olen = cJSON_GetObjectItemCaseSensitive(params, "output_size");
        if (cJSON_IsNumber(olen)) {
            cfg.output_size = (uint16_t)olen->valueint;
        }
        cJSON *rpi = cJSON_GetObjectItemCaseSensitive(params, "rpi_us");
        if (cJSON_IsNumber(rpi)) {
            cfg.rpi_us = (uint32_t)rpi->valueint;
        }
        cJSON *sc = cJSON_GetObjectItemCaseSensitive(params, "security_class");
        if (cJSON_IsNumber(sc)) {
            cfg.security_class = sc->valueint;
        }
        cJSON *pm = cJSON_GetObjectItemCaseSensitive(params, "protection_mode");
        if (cJSON_IsNumber(pm)) {
            cfg.protection_mode = (uint32_t)pm->valuedouble;
        }
        cJSON *idle = cJSON_GetObjectItemCaseSensitive(params, "idle_timeout_ms");
        if (cJSON_IsNumber(idle)) {
            cfg.idle_timeout_ms = idle->valueint;
        }
        cJSON *perip =
            cJSON_GetObjectItemCaseSensitive(params, "max_conn_per_ip");
        if (cJSON_IsNumber(perip)) {
            cfg.max_conn_per_ip = perip->valueint;
        }
        cJSON *sp = cJSON_GetObjectItemCaseSensitive(params, "secure_tcp_port");
        if (cJSON_IsNumber(sp)) {
            cfg.secure_tcp_port = sp->valueint;
        }
        cJSON *iface = cJSON_GetObjectItemCaseSensitive(params, "iface");
        if (cJSON_IsString(iface)) {
            snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface->valuestring);
        }
        cJSON *lldp = cJSON_GetObjectItemCaseSensitive(params, "lldp_enable");
        if (cJSON_IsBool(lldp)) {
            cfg.lldp_enable = cJSON_IsTrue(lldp);
        } else if (cJSON_IsNumber(lldp)) {
            cfg.lldp_enable = lldp->valueint != 0;
        }
        cJSON *li = cJSON_GetObjectItemCaseSensitive(params, "lldp_tx_interval_sec");
        if (cJSON_IsNumber(li)) {
            cfg.lldp_tx_interval_sec = (uint16_t)li->valueint;
        }
        cJSON *acd = cJSON_GetObjectItemCaseSensitive(params, "acd_enable");
        if (cJSON_IsBool(acd)) {
            cfg.acd_enable = cJSON_IsTrue(acd);
        } else if (cJSON_IsNumber(acd)) {
            cfg.acd_enable = acd->valueint != 0;
        }
        cJSON *psk = cJSON_GetObjectItemCaseSensitive(params, "psk_hex");
        if (cJSON_IsString(psk)) {
            const char *hex = psk->valuestring;
            size_t n = strlen(hex);
            if (n != EIP_PSK_LEN * 2) {
                LOG_ERROR("ethernetip",
                          "psk_hex 는 64 hex chars (32 bytes) 여야 함");
                cJSON_Delete(params);
                free(ctx);
                return -EINVAL;
            }
            for (int i = 0; i < EIP_PSK_LEN; i++) {
                unsigned int b;
                if (sscanf(hex + i * 2, "%2x", &b) != 1) {
                    LOG_ERROR("ethernetip", "psk_hex 파싱 실패");
                    cJSON_Delete(params);
                    free(ctx);
                    return -EINVAL;
                }
                cfg.psk[i] = (uint8_t)b;
            }
            cfg.psk_set = 1;
        }
        cJSON *mock = cJSON_GetObjectItemCaseSensitive(params, "mock");
        if (cJSON_IsBool(mock)) {
            cfg.mock = cJSON_IsTrue(mock);
        }
        cJSON_Delete(params);
    }

    if (cfg.security_class >= EIP_SECURITY_CLASS_1 && !cfg.psk_set) {
        LOG_ERROR("ethernetip",
                  "security_class>=1 이면 protocol_params.psk_hex 가 필요함");
        free(ctx);
        return -EINVAL;
    }

    if (cfg.role == EIP_ROLE_ORIGINATOR && !cfg.remote_ip[0]) {
        LOG_ERROR("ethernetip", "originator 모드에는 ip/remote_ip 필요");
        free(ctx);
        return -EINVAL;
    }

    parse_points(ctx, points_json);

    /* Auto-expand process image if points need more room */
    for (int i = 0; i < ctx->point_count; i++) {
        eip_point_t *pt = &ctx->points[i];
        int end = pt->byte_offset + pt->length;
        if (pt->kind == EIP_ADDR_ASSEMBLY || pt->kind == EIP_ADDR_TAG) {
            int is_out = (strcmp(pt->access, "write") == 0);
            if (is_out && end > (int)cfg.output_size &&
                end <= EIP_ASSEMBLY_SIZE_MAX) {
                cfg.output_size = (uint16_t)end;
            }
            if (!is_out && end > (int)cfg.input_size &&
                end <= EIP_ASSEMBLY_SIZE_MAX) {
                cfg.input_size = (uint16_t)end;
            }
        }
        if (pt->kind == EIP_ADDR_ASSEMBLY && pt->assembly == 0) {
            pt->assembly = (strcmp(pt->access, "write") == 0)
                               ? cfg.output_assembly
                               : cfg.input_assembly;
        }
    }

    ctx->stack = eip_stack_create(&cfg);
    if (!ctx->stack) {
        free(ctx->points);
        free(ctx);
        return -ENOMEM;
    }
    self->ctx = ctx;
    LOG_INFO("ethernetip",
             "init role=%s points=%d in_asm=%u/%u out_asm=%u/%u sec=%d (자체 스택)",
             cfg.role == EIP_ROLE_ORIGINATOR ? "originator" : "adapter",
             ctx->point_count, cfg.input_assembly, cfg.input_size,
             cfg.output_assembly, cfg.output_size, cfg.security_class);
    return 0;
}

static int eip_connect(protocol_adapter_t *self)
{
    eip_ctx_t *ctx = self->ctx;
    int rc = eip_stack_start(ctx->stack);
    if (rc != 0) {
        snprintf(ctx->last_error, sizeof(ctx->last_error),
                 "stack start failed (%d)", rc);
        LOG_ERROR("ethernetip", "%s", ctx->last_error);
        return rc;
    }
    return 0;
}

static void eip_disconnect(protocol_adapter_t *self)
{
    eip_ctx_t *ctx = self->ctx;
    if (ctx && ctx->stack) {
        eip_stack_stop(ctx->stack);
    }
}

static void eip_poll_cycle(protocol_adapter_t *self)
{
    eip_ctx_t *ctx = self->ctx;
    if (ctx && ctx->stack) {
        eip_stack_poll(ctx->stack);
    }
}

static eip_point_t *find_point(eip_ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->point_count; i++) {
        if (strcmp(ctx->points[i].name, name) == 0) {
            return &ctx->points[i];
        }
    }
    return NULL;
}

static int eip_read_wire(eip_ctx_t *ctx, const eip_point_t *pt, uint8_t *dst,
                         size_t n, size_t *got)
{
    int rc;
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_TAG) {
        size_t g = n;
        rc = eip_stack_tag_read(ctx->stack, pt->tag, dst, &g);
        if (rc == 0 && got) {
            *got = g;
        }
        return rc;
    }
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_CIP_PATH) {
        size_t g = n;
        rc = eip_stack_explicit_get(ctx->stack, pt->class_id, pt->instance,
                                    pt->attribute, dst, &g);
        if (rc == 0 && got) {
            *got = g;
        }
        return rc;
    }
    if (strcmp(pt->access, "write") == 0) {
        rc = eip_stack_read_output(ctx->stack, (size_t)pt->byte_offset, dst, n);
    } else {
        rc = eip_stack_read_input(ctx->stack, (size_t)pt->byte_offset, dst, n);
    }
    if (rc > 0) {
        if (got) {
            *got = (size_t)rc;
        }
        return 0;
    }
    return rc;
}

static int eip_write_wire(eip_ctx_t *ctx, const eip_point_t *pt,
                          const uint8_t *src, size_t n)
{
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_TAG) {
        return eip_stack_tag_write(ctx->stack, pt->tag, src, n);
    }
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_CIP_PATH) {
        return eip_stack_explicit_set(ctx->stack, pt->class_id, pt->instance,
                                      pt->attribute, src, n);
    }
    /* Adapter: sensor publishes into input (T->O) image */
    int rc = eip_stack_write_input(ctx->stack, (size_t)pt->byte_offset, src, n);
    return rc < 0 ? rc : 0;
}

static int eip_read_point(protocol_adapter_t *self, const char *point_name,
                          point_value_t *out)
{
    eip_ctx_t *ctx = self->ctx;
    eip_point_t *pt = find_point(ctx, point_name);
    if (!pt || !out || !out->data) {
        return -EINVAL;
    }
    /* T0 A안: wire 정수 → eng = raw*scale+offset → float32(BE) 4바이트.
     * CIP wire 는 리틀 엔디안이므로 디코드 전에 빅 엔디안으로 되돌린다. */
    if (pt->apply_scale) {
        int wlen = eip_type_wire_len(pt->data_type);
        if (wlen <= 0 || wlen > 8) {
            LOG_ERROR("ethernetip",
                      "point %s 스케일 data_type 크기를 알 수 없음",
                      point_name);
            return -EINVAL;
        }
        if (out->len < 4) {
            LOG_ERROR("ethernetip",
                      "point %s 스케일 읽기는 4바이트 버퍼가 필요",
                      point_name);
            return -ENOSPC;
        }
        uint8_t wire[8];
        memset(wire, 0, sizeof(wire));
        size_t got = 0;
        int rc = eip_read_wire(ctx, pt, wire, (size_t)wlen, &got);
        if (rc != 0) {
            return rc;
        }
        wire_to_canon(pt, wire, got);
        double raw = eip_decode_number(pt->data_type, wire, (size_t)wlen);
        double eng = raw * pt->scale + pt->eng_offset;
        eip_st_f32_be(out->data, (float)eng);
        out->len = 4;
        return 0;
    }
    size_t n = (size_t)pt->length;
    if (n > out->len) {
        n = out->len;
    }

    int rc = -1;
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_TAG) {
        size_t got = n;
        rc = eip_stack_tag_read(ctx->stack, pt->tag, out->data, &got);
        if (rc == 0) {
            wire_to_canon(pt, out->data, got);
            out->len = got;
        }
        return rc;
    }
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_CIP_PATH) {
        size_t got = n;
        rc = eip_stack_explicit_get(ctx->stack, pt->class_id, pt->instance,
                                    pt->attribute, out->data, &got);
        if (rc == 0) {
            wire_to_canon(pt, out->data, got);
            out->len = got;
        }
        return rc;
    }
    if (strcmp(pt->access, "write") == 0) {
        rc = eip_stack_read_output(ctx->stack, (size_t)pt->byte_offset,
                                   out->data, n);
    } else {
        rc = eip_stack_read_input(ctx->stack, (size_t)pt->byte_offset,
                                  out->data, n);
    }
    if (rc > 0) {
        wire_to_canon(pt, out->data, (size_t)rc);
        out->len = (size_t)rc;
        return 0;
    }
    return rc;
}

static int eip_write_point(protocol_adapter_t *self, const char *point_name,
                           const point_value_t *value)
{
    eip_ctx_t *ctx = self->ctx;
    eip_point_t *pt = find_point(ctx, point_name);
    if (!pt || !value || !value->data) {
        return -EINVAL;
    }
    /* T0 A안: float32(BE) 공학값 → raw = (eng-offset)/scale → data_type 크기 → LE. */
    if (pt->apply_scale) {
        int wlen = eip_type_wire_len(pt->data_type);
        if (wlen <= 0 || wlen > 8) {
            LOG_ERROR("ethernetip",
                      "point %s 스케일 data_type 크기를 알 수 없음",
                      point_name);
            return -EINVAL;
        }
        double eng;
        if (value->len >= 4) {
            eng = (double)eip_ld_f32_be(value->data);
        } else {
            uint8_t tmp[8];
            memset(tmp, 0, sizeof(tmp));
            size_t n = value->len < (size_t)wlen ? value->len : (size_t)wlen;
            if (n > 0) {
                memcpy(tmp, value->data, n);
            }
            eng = eip_decode_number(pt->data_type, tmp, (size_t)wlen);
        }
        double denom = pt->scale != 0.0 ? pt->scale : 1.0;
        double raw = (eng - pt->eng_offset) / denom;
        uint8_t wire[8];
        eip_encode_number(pt->data_type, raw, wire, (size_t)wlen);
        eip_swap_elems(wire, (size_t)wlen, pt->endian_width);
        return eip_write_wire(ctx, pt, wire, (size_t)wlen);
    }
    size_t n = value->len;
    if ((int)n > pt->length) {
        n = (size_t)pt->length;
    }

    uint8_t wire[EIP_ASSEMBLY_SIZE_MAX];
    int sc = canon_to_wire(pt, wire, sizeof wire, value->data, n);
    if (sc != 0) {
        LOG_ERROR("ethernetip", "point %s 값 길이 %zu 가 변환 버퍼를 넘음",
                  point_name, n);
        return sc;
    }

    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_TAG) {
        return eip_stack_tag_write(ctx->stack, pt->tag, wire, n);
    }
    if (ctx->role == EIP_ROLE_ORIGINATOR && pt->kind == EIP_ADDR_CIP_PATH) {
        return eip_stack_explicit_set(ctx->stack, pt->class_id, pt->instance,
                                      pt->attribute, wire, n);
    }
    /* Adapter: sensor publishes into input (T->O) image */
    int rc = eip_stack_write_input(ctx->stack, (size_t)pt->byte_offset, wire, n);
    return rc < 0 ? rc : 0;
}

static int eip_health(protocol_adapter_t *self, int *connected, char *err_buf,
                      size_t err_buf_len)
{
    eip_ctx_t *ctx = self->ctx;
    int up = eip_stack_class1_up(ctx->stack) || eip_stack_session_up(ctx->stack);
    *connected = up;
    snprintf(err_buf, err_buf_len, "%s", ctx->last_error);
    return 0;
}

static void eip_destroy(protocol_adapter_t *self)
{
    if (!self) {
        return;
    }
    eip_ctx_t *ctx = self->ctx;
    if (ctx) {
        eip_stack_destroy(ctx->stack);
        free(ctx->points);
        free(ctx);
    }
    free(self);
}

protocol_adapter_t *ethernetip_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) {
        return NULL;
    }
    a->name = "ethernetip";
    a->init = eip_init;
    a->connect = eip_connect;
    a->disconnect = eip_disconnect;
    a->poll_cycle = eip_poll_cycle;
    a->read_point = eip_read_point;
    a->write_point = eip_write_point;
    a->health = eip_health;
    a->destroy = eip_destroy;
    return a;
}
