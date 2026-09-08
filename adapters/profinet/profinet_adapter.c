#include "profinet_adapter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>

#include "logger.h"
#include "pn_stack.h"

#define PN_ADAPTER_POINTS_MAX 64

typedef struct {
    char name[64];
    char access[8];
    int slot;
    int subslot;
    int index;
    int byte_offset;
    int length;
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
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return 0;
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
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
        cJSON *slot = cJSON_GetObjectItemCaseSensitive(pn, "slot");
        cJSON *sub = cJSON_GetObjectItemCaseSensitive(pn, "subslot");
        cJSON *idx = cJSON_GetObjectItemCaseSensitive(pn, "index");
        cJSON *off = cJSON_GetObjectItemCaseSensitive(pn, "byte_offset");
        pt->slot = cJSON_IsNumber(slot) ? slot->valueint : 1;
        pt->subslot = cJSON_IsNumber(sub) ? sub->valueint : 1;
        pt->index = cJSON_IsNumber(idx) ? idx->valueint : 1;
        pt->byte_offset = cJSON_IsNumber(off) ? off->valueint : 0;
        if (pt->byte_offset < 0 || pt->length <= 0) {
            LOG_WARN("profinet", "point %s skipped (offset/length)", pt->name);
            continue;
        }
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
    cfg.security_class = 0; /* lab default: unsigned */
    cfg.cycle_us = PN_CYCLE_MIN_US;
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
        } else {
            cJSON *cycle_ms = cJSON_GetObjectItemCaseSensitive(params, "cycle_ms");
            if (cJSON_IsNumber(cycle_ms) && cycle_ms->valueint > 0) {
                cfg.cycle_us = (uint32_t)cycle_ms->valueint * 1000u;
            }
        }
        cJSON *apply_ip = cJSON_GetObjectItemCaseSensitive(params, "apply_os_ip");
        if (cJSON_IsBool(apply_ip)) {
            cfg.apply_os_ip = cJSON_IsTrue(apply_ip) ? 1 : 0;
        } else if (cJSON_IsNumber(apply_ip)) {
            cfg.apply_os_ip = apply_ip->valueint ? 1 : 0;
        }
        cJSON_Delete(params);
    }

    if (cfg.security_class >= PN_SECURITY_CLASS_1 && !cfg.psk_set) {
        LOG_ERROR("profinet",
                  "security_class>=1 이면 protocol_params.psk_hex 가 필요함");
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
    LOG_INFO("profinet", "init RT1 device=%s points=%d sec=%d (IRT 없음)",
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

static int pn_read_point(protocol_adapter_t *self, const char *point_name,
                         point_value_t *out)
{
    pn_ctx_t *ctx = self->ctx;
    pn_point_t *pt = find_point(ctx, point_name);
    if (!pt || !out || !out->data) {
        return -EINVAL;
    }
    size_t n = (size_t)pt->length;
    if (n > out->len) {
        n = out->len;
    }
    if (strcmp(pt->access, "write") == 0) {
        return pn_stack_read_output(ctx->stack, (size_t)pt->byte_offset,
                                    out->data, n);
    }
    return pn_stack_read_input(ctx->stack, (size_t)pt->byte_offset, out->data,
                               n);
}

static int pn_write_point(protocol_adapter_t *self, const char *point_name,
                          const point_value_t *value)
{
    pn_ctx_t *ctx = self->ctx;
    pn_point_t *pt = find_point(ctx, point_name);
    if (!pt || !value || !value->data) {
        return -EINVAL;
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
