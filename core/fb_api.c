#define _POSIX_C_SOURCE 200809L

#include "fb_api.h"

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cJSON.h>

#include "adapter_registry.h"
#include "config_loader.h"
#include "logger.h"
#include "protocol_adapter.h"

#define FB_MAX_POINTS 256
#define FB_WIRE_CAP 1024
#define FB_PATH_MAX 4096

typedef enum {
    FB_KIND_BOOL = 0,
    FB_KIND_U8,
    FB_KIND_I8,
    FB_KIND_U16,
    FB_KIND_I16,
    FB_KIND_U32,
    FB_KIND_I32,
    FB_KIND_U64,
    FB_KIND_I64,
    FB_KIND_F32,
    FB_KIND_F64,
    FB_KIND_STRING,
    FB_KIND_BYTES,
    FB_KIND_BCD16,
    FB_KIND_BCD32
} fb_kind_t;

typedef struct {
    char name[FB_POINT_NAME_MAX];
    char data_type[FB_POINT_TYPE_MAX];
    fb_access_t access;
    fb_kind_t kind;
    int scaled;
    size_t native_size;
} fb_point_meta_t;

typedef struct {
    daemon_config_t cfg;
    protocol_adapter_t *adapter;
    fb_point_meta_t points[FB_MAX_POINTS];
    int point_count;
} fb_session_t;

struct fb_runtime {
    pthread_mutex_t mu;
    fb_session_t session;
    uint32_t generation;
    int have_session;
    int thread_on;
    pthread_t thread;
    volatile int thread_stop;
    char last_error[FB_ERROR_MSG_MAX];
    char config_path[FB_PATH_MAX];
};

static int eqi(const char *a, const char *b)
{
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static void set_err(char *buf, size_t buflen, const char *msg)
{
    if (!buf || buflen == 0) {
        return;
    }
    snprintf(buf, buflen, "%s", msg ? msg : "");
}

static void rt_set_err(fb_runtime_t *rt, const char *msg)
{
    if (rt) {
        set_err(rt->last_error, sizeof(rt->last_error), msg);
    }
}

static int map_errno(int rc)
{
    if (rc >= 0) {
        return FB_OK;
    }
    switch (rc) {
    case -ENOENT:
        return FB_ERR_NOENT;
    case -EINVAL:
        return FB_ERR_INVAL;
    case -ENOMEM:
        return FB_ERR_NOMEM;
    case -ENOSPC:
    case -ENOBUFS:
        return FB_ERR_NOSPC;
    case -EPERM:
    case -EACCES:
        return FB_ERR_PERM;
    case -ENOSYS:
    case -ENOTSUP:
        return FB_ERR_UNSUPPORTED;
    case -EBUSY:
        return FB_ERR_BUSY;
    default:
        return FB_ERR_IO;
    }
}

static fb_kind_t parse_kind(const char *s)
{
    if (!s || !s[0]) {
        return FB_KIND_U16;
    }
    if (eqi(s, "uint8") || eqi(s, "u8") || eqi(s, "byte")) {
        return FB_KIND_U8;
    }
    if (eqi(s, "int8") || eqi(s, "i8") || eqi(s, "sbyte")) {
        return FB_KIND_I8;
    }
    if (eqi(s, "uint16") || eqi(s, "u16") || eqi(s, "word") ||
        eqi(s, "ushort")) {
        return FB_KIND_U16;
    }
    if (eqi(s, "int16") || eqi(s, "i16") || eqi(s, "short")) {
        return FB_KIND_I16;
    }
    if (eqi(s, "uint32") || eqi(s, "u32") || eqi(s, "dword") ||
        eqi(s, "uint")) {
        return FB_KIND_U32;
    }
    if (eqi(s, "int32") || eqi(s, "i32") || eqi(s, "int") || eqi(s, "long")) {
        return FB_KIND_I32;
    }
    if (eqi(s, "uint64") || eqi(s, "u64") || eqi(s, "qword")) {
        return FB_KIND_U64;
    }
    if (eqi(s, "int64") || eqi(s, "i64")) {
        return FB_KIND_I64;
    }
    if (eqi(s, "float32") || eqi(s, "float") || eqi(s, "real") ||
        eqi(s, "single")) {
        return FB_KIND_F32;
    }
    if (eqi(s, "float64") || eqi(s, "double")) {
        return FB_KIND_F64;
    }
    if (eqi(s, "bool") || eqi(s, "boolean") || eqi(s, "bit")) {
        return FB_KIND_BOOL;
    }
    if (eqi(s, "string") || eqi(s, "ascii") || eqi(s, "str")) {
        return FB_KIND_STRING;
    }
    if (eqi(s, "raw") || eqi(s, "bytes") || eqi(s, "blob")) {
        return FB_KIND_BYTES;
    }
    if (eqi(s, "bcd16") || eqi(s, "bcd")) {
        return FB_KIND_BCD16;
    }
    if (eqi(s, "bcd32")) {
        return FB_KIND_BCD32;
    }
    return FB_KIND_U16;
}

static size_t kind_native_size(fb_kind_t k, int length)
{
    switch (k) {
    case FB_KIND_BOOL:
    case FB_KIND_U8:
    case FB_KIND_I8:
        return 1;
    case FB_KIND_U16:
    case FB_KIND_I16:
    case FB_KIND_BCD16:
        return 2;
    case FB_KIND_U32:
    case FB_KIND_I32:
    case FB_KIND_F32:
    case FB_KIND_BCD32:
        return 4;
    case FB_KIND_U64:
    case FB_KIND_I64:
    case FB_KIND_F64:
        return 8;
    case FB_KIND_STRING:
    case FB_KIND_BYTES:
        return length > 0 ? (size_t)length : 0;
    }
    return 0;
}

static fb_type_t native_type_of(const fb_point_meta_t *m)
{
    if (!m) {
        return FB_TYPE_BYTES;
    }
    if (m->kind == FB_KIND_STRING) {
        return FB_TYPE_STRING;
    }
    if (m->kind == FB_KIND_BYTES) {
        return FB_TYPE_BYTES;
    }
    if (m->kind == FB_KIND_BOOL) {
        return FB_TYPE_BOOL;
    }
    if (m->scaled || m->kind == FB_KIND_F32) {
        return FB_TYPE_F32;
    }
    if (m->kind == FB_KIND_F64) {
        return FB_TYPE_F64;
    }
    if (m->kind == FB_KIND_I8 || m->kind == FB_KIND_I16 ||
        m->kind == FB_KIND_I32) {
        return FB_TYPE_I32;
    }
    if (m->kind == FB_KIND_I64) {
        return FB_TYPE_I64;
    }
    if (m->kind == FB_KIND_U64) {
        return FB_TYPE_U64;
    }
    return FB_TYPE_U32;
}

static int app_may_write(fb_access_t a)
{
    return a == FB_ACCESS_PLC_READ || a == FB_ACCESS_READWRITE ||
           a == FB_ACCESS_UNKNOWN;
}

static fb_access_t parse_access(const char *s)
{
    if (!s || !s[0] || eqi(s, "read") || eqi(s, "r")) {
        return FB_ACCESS_PLC_READ;
    }
    if (eqi(s, "write") || eqi(s, "w")) {
        return FB_ACCESS_PLC_WRITE;
    }
    if (eqi(s, "readwrite") || eqi(s, "rw") || eqi(s, "read_write")) {
        return FB_ACCESS_READWRITE;
    }
    return FB_ACCESS_PLC_READ;
}

static const fb_point_meta_t *find_meta(const fb_session_t *s, const char *name)
{
    if (!s || !name) {
        return NULL;
    }
    for (int i = 0; i < s->point_count; i++) {
        if (strcmp(s->points[i].name, name) == 0) {
            return &s->points[i];
        }
    }
    return NULL;
}

static void fill_point_info(const fb_point_meta_t *m, fb_point_info_t *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->name, sizeof(out->name), "%s", m->name);
    snprintf(out->data_type, sizeof(out->data_type), "%s", m->data_type);
    out->access = m->access;
    out->native_type = native_type_of(m);
    out->flags = m->scaled ? FB_POINT_F_SCALED : 0;
    out->wire_size = m->scaled && m->kind != FB_KIND_STRING &&
                             m->kind != FB_KIND_BYTES
                         ? 4
                         : m->native_size;
}

static int parse_points_meta(fb_session_t *s, const char *points_json)
{
    s->point_count = 0;
    if (!points_json) {
        return 0;
    }
    cJSON *arr = cJSON_Parse(points_json);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return 0;
    }
    const cJSON *p;
    cJSON_ArrayForEach(p, arr)
    {
        if (!cJSON_IsObject(p) || s->point_count >= FB_MAX_POINTS) {
            continue;
        }
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        if (!cJSON_IsString(name) || !name->valuestring ||
            !name->valuestring[0]) {
            continue;
        }
        fb_point_meta_t *m = &s->points[s->point_count];
        memset(m, 0, sizeof(*m));
        snprintf(m->name, sizeof(m->name), "%s", name->valuestring);
        const cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        m->access = parse_access(
            cJSON_IsString(access) ? access->valuestring : NULL);
        const cJSON *dt = cJSON_GetObjectItemCaseSensitive(p, "data_type");
        if (!cJSON_IsString(dt)) {
            dt = cJSON_GetObjectItemCaseSensitive(p, "datatype");
        }
        snprintf(m->data_type, sizeof(m->data_type), "%s",
                 cJSON_IsString(dt) && dt->valuestring ? dt->valuestring
                                                       : "uint16");
        m->kind = parse_kind(m->data_type);
        int length = 0;
        const cJSON *len = cJSON_GetObjectItemCaseSensitive(p, "length");
        if (cJSON_IsNumber(len)) {
            length = len->valueint;
        }
        m->native_size = kind_native_size(m->kind, length);
        double scale = 1.0;
        double offset = 0.0;
        const cJSON *sc = cJSON_GetObjectItemCaseSensitive(p, "scale");
        if (!cJSON_IsNumber(sc)) {
            sc = cJSON_GetObjectItemCaseSensitive(p, "gain");
        }
        if (cJSON_IsNumber(sc)) {
            scale = sc->valuedouble;
        }
        const cJSON *off = cJSON_GetObjectItemCaseSensitive(p, "offset");
        if (cJSON_IsNumber(off)) {
            offset = off->valuedouble;
        }
        m->scaled = (m->kind != FB_KIND_STRING && m->kind != FB_KIND_BYTES &&
                     m->kind != FB_KIND_BOOL) &&
                    (fabs(scale - 1.0) > 1e-12 || fabs(offset) > 1e-12);
        s->point_count++;
    }
    cJSON_Delete(arr);
    return 0;
}

static void session_clear(fb_session_t *s)
{
    if (!s) {
        return;
    }
    memset(s, 0, sizeof(*s));
}

static void session_teardown(fb_session_t *s, int do_disconnect)
{
    if (!s) {
        return;
    }
    if (s->adapter) {
        if (do_disconnect && s->adapter->disconnect) {
            s->adapter->disconnect(s->adapter);
        }
        if (s->adapter->destroy) {
            s->adapter->destroy(s->adapter);
        }
        s->adapter = NULL;
    }
    config_free(&s->cfg);
    session_clear(s);
}

static int session_build(const char *path, fb_session_t *s, char *err,
                         size_t errlen)
{
    memset(s, 0, sizeof(*s));
    if (config_load(path, &s->cfg) != 0) {
        set_err(err, errlen, "config_load failed");
        session_clear(s);
        return FB_ERR_CONFIG;
    }
    adapter_ctor_fn ctor = adapter_registry_lookup(s->cfg.protocol);
    if (!ctor) {
        set_err(err, errlen, "unknown protocol");
        config_free(&s->cfg);
        session_clear(s);
        return FB_ERR_CONFIG;
    }
    s->adapter = ctor();
    if (!s->adapter) {
        set_err(err, errlen, "adapter create failed");
        config_free(&s->cfg);
        session_clear(s);
        return FB_ERR_NOMEM;
    }
    int rc = s->adapter->init(s->adapter, s->cfg.protocol_params_json,
                              s->cfg.points_json);
    if (rc != 0) {
        set_err(err, errlen, "adapter init failed");
        int mapped = map_errno(rc);
        if (mapped == FB_ERR_INVAL) {
            mapped = FB_ERR_CONFIG;
        }
        session_teardown(s, 0);
        return mapped;
    }
    parse_points_meta(s, s->cfg.points_json);
    return FB_OK;
}

static int session_connect(fb_session_t *s, char *err, size_t errlen)
{
    if (!s || !s->adapter || !s->adapter->connect) {
        set_err(err, errlen, "no adapter");
        return FB_ERR_STATE;
    }
    int rc = s->adapter->connect(s->adapter);
    if (rc != 0) {
        set_err(err, errlen, "adapter connect failed");
        return map_errno(rc) == FB_ERR_INVAL ? FB_ERR_IO : map_errno(rc);
    }
    return FB_OK;
}

static uint32_t be_load_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t be_load_uint(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void be_store_uint(uint8_t *p, size_t n, uint64_t v)
{
    for (size_t i = 0; i < n; i++) {
        p[n - 1 - i] = (uint8_t)(v >> (8 * i));
    }
}

static float be_load_f32(const uint8_t *p)
{
    uint32_t u = be_load_u32(p);
    float f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

static void be_store_f32(uint8_t *p, float f)
{
    uint32_t u;
    memcpy(&u, &f, sizeof(u));
    p[0] = (uint8_t)(u >> 24);
    p[1] = (uint8_t)(u >> 16);
    p[2] = (uint8_t)(u >> 8);
    p[3] = (uint8_t)u;
}

static double be_load_f64(const uint8_t *p)
{
    uint64_t u = be_load_uint(p, 8);
    double d;
    memcpy(&d, &u, sizeof(d));
    return d;
}

static void be_store_f64(uint8_t *p, double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof(u));
    be_store_uint(p, 8, u);
}

static int64_t sign_extend(uint64_t v, size_t nbytes)
{
    if (nbytes >= 8) {
        return (int64_t)v;
    }
    size_t bits = nbytes * 8;
    uint64_t sign = 1ull << (bits - 1);
    if (v & sign) {
        v |= ~((1ull << bits) - 1);
    }
    return (int64_t)v;
}

static int adapter_read_copy(protocol_adapter_t *a, const char *name,
                             uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    uint8_t scratch[FB_WIRE_CAP];
    point_value_t pv;
    memset(&pv, 0, sizeof(pv));
    pv.data = scratch;
    pv.len = sizeof(scratch);
    int rc = a->read_point(a, name, &pv);
    if (rc != 0) {
        return rc;
    }
    uint8_t *src = pv.data ? pv.data : scratch;
    size_t n = pv.len;
    if (n > dst_cap) {
        n = dst_cap;
    }
    if (n > 0 && src) {
        memcpy(dst, src, n);
    }
    *out_len = n;
    if (pv.data && pv.data != scratch) {
        free(pv.data);
    }
    return 0;
}

static int adapter_write_bytes(protocol_adapter_t *a, const char *name,
                               const uint8_t *data, size_t len)
{
    point_value_t pv;
    pv.data = (uint8_t *)(uintptr_t)data;
    pv.len = len;
    return a->write_point(a, name, &pv);
}

static int is_signed_kind(fb_kind_t k)
{
    return k == FB_KIND_I8 || k == FB_KIND_I16 || k == FB_KIND_I32 ||
           k == FB_KIND_I64;
}

static int decode_numeric(const fb_point_meta_t *m, const uint8_t *raw,
                          size_t n, double *out)
{
    if (!raw || n == 0) {
        *out = 0;
        return FB_OK;
    }
    /* Adapter-applied scale: native size != 4 but payload is BE float32. */
    if (m->scaled && n == 4 && m->native_size != 4) {
        *out = (double)be_load_f32(raw);
        return FB_OK;
    }
    switch (m->kind) {
    case FB_KIND_BOOL:
        *out = raw[0] ? 1.0 : 0.0;
        return FB_OK;
    case FB_KIND_F32:
        if (n < 4) {
            return FB_ERR_TYPE;
        }
        *out = (double)be_load_f32(raw);
        return FB_OK;
    case FB_KIND_F64:
        if (n < 8) {
            return FB_ERR_TYPE;
        }
        *out = be_load_f64(raw);
        return FB_OK;
    case FB_KIND_STRING:
    case FB_KIND_BYTES:
        return FB_ERR_TYPE;
    default:
        break;
    }
    size_t use = n;
    if (m->native_size > 0 && use > m->native_size) {
        use = m->native_size;
    }
    if (use > 8) {
        use = 8;
    }
    uint64_t u = be_load_uint(raw, use);
    if (is_signed_kind(m->kind)) {
        *out = (double)sign_extend(u, use);
    } else {
        *out = (double)u;
    }
    return FB_OK;
}

static int encode_numeric(const fb_point_meta_t *m, double eng, uint8_t *out,
                          size_t *out_len)
{
    if (m->kind == FB_KIND_STRING || m->kind == FB_KIND_BYTES) {
        return FB_ERR_TYPE;
    }
    if (m->scaled) {
        be_store_f32(out, (float)eng);
        *out_len = 4;
        return FB_OK;
    }
    if (m->kind == FB_KIND_BOOL) {
        out[0] = eng != 0.0 ? 1 : 0;
        *out_len = 1;
        return FB_OK;
    }
    if (m->kind == FB_KIND_F32) {
        be_store_f32(out, (float)eng);
        *out_len = 4;
        return FB_OK;
    }
    if (m->kind == FB_KIND_F64) {
        be_store_f64(out, eng);
        *out_len = 8;
        return FB_OK;
    }
    size_t n = m->native_size ? m->native_size : 2;
    if (n > 8) {
        n = 8;
    }
    if (is_signed_kind(m->kind)) {
        be_store_uint(out, n, (uint64_t)(int64_t)llround(eng));
    } else {
        double r = eng < 0 ? 0 : eng;
        be_store_uint(out, n, (uint64_t)llround(r));
    }
    *out_len = n;
    return FB_OK;
}

static int value_as_double(const fb_value_t *v, double *out)
{
    switch (v->type) {
    case FB_TYPE_BOOL:
        *out = v->v.b ? 1.0 : 0.0;
        return FB_OK;
    case FB_TYPE_I32:
        *out = (double)v->v.i32;
        return FB_OK;
    case FB_TYPE_U32:
        *out = (double)v->v.u32;
        return FB_OK;
    case FB_TYPE_I64:
        *out = (double)v->v.i64;
        return FB_OK;
    case FB_TYPE_U64:
        *out = (double)v->v.u64;
        return FB_OK;
    case FB_TYPE_F32:
        *out = (double)v->v.f32;
        return FB_OK;
    case FB_TYPE_F64:
        *out = v->v.f64;
        return FB_OK;
    default:
        return FB_ERR_TYPE;
    }
}

static int store_numeric(fb_value_t *v, fb_type_t want, double x)
{
    switch (want) {
    case FB_TYPE_BOOL:
        v->type = FB_TYPE_BOOL;
        v->v.b = (x != 0.0);
        return FB_OK;
    case FB_TYPE_I32:
        v->type = FB_TYPE_I32;
        v->v.i32 = (int32_t)llround(x);
        return FB_OK;
    case FB_TYPE_U32:
        if (x < 0) {
            return FB_ERR_TYPE;
        }
        v->type = FB_TYPE_U32;
        v->v.u32 = (uint32_t)llround(x);
        return FB_OK;
    case FB_TYPE_I64:
        v->type = FB_TYPE_I64;
        v->v.i64 = (int64_t)llround(x);
        return FB_OK;
    case FB_TYPE_U64:
        if (x < 0) {
            return FB_ERR_TYPE;
        }
        v->type = FB_TYPE_U64;
        v->v.u64 = (uint64_t)llround(x);
        return FB_OK;
    case FB_TYPE_F32:
        v->type = FB_TYPE_F32;
        v->v.f32 = (float)x;
        return FB_OK;
    case FB_TYPE_F64:
        v->type = FB_TYPE_F64;
        v->v.f64 = x;
        return FB_OK;
    default:
        return FB_ERR_TYPE;
    }
}

static long timespec_diff_ms(const struct timespec *a, const struct timespec *b)
{
    long sec_diff = a->tv_sec - b->tv_sec;
    long nsec_diff = a->tv_nsec - b->tv_nsec;
    return sec_diff * 1000 + nsec_diff / 1000000;
}

static void timespec_add_ms(struct timespec *t, long ms)
{
    t->tv_sec += ms / 1000;
    t->tv_nsec += (ms % 1000) * 1000000L;
    if (t->tv_nsec >= 1000000000L) {
        t->tv_nsec -= 1000000000L;
        t->tv_sec += 1;
    }
}

static int poll_locked(fb_runtime_t *rt)
{
    protocol_adapter_t *a = rt->session.adapter;
    if (!a || !a->poll_cycle) {
        return FB_ERR_STATE;
    }
    a->poll_cycle(a);
    return FB_OK;
}

static int run_cycle_loop(fb_runtime_t *rt, volatile int *stop_flag)
{
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    while (1) {
        if ((stop_flag && *stop_flag) || rt->thread_stop) {
            break;
        }
        int cycle_ms;
        struct timespec before;
        clock_gettime(CLOCK_MONOTONIC, &before);
        pthread_mutex_lock(&rt->mu);
        cycle_ms = rt->session.cfg.cycle_ms;
        if (cycle_ms <= 0) {
            cycle_ms = 8;
        }
        int prc = poll_locked(rt);
        pthread_mutex_unlock(&rt->mu);
        if (prc != FB_OK) {
            return prc;
        }

        struct timespec after;
        clock_gettime(CLOCK_MONOTONIC, &after);
        long elapsed_ms = timespec_diff_ms(&after, &before);
        if (elapsed_ms > cycle_ms) {
            LOG_WARN("fb_api", "cycle 초과: elapsed=%ldms > cycle_ms=%d",
                     elapsed_ms, cycle_ms);
        }

        timespec_add_ms(&next, cycle_ms);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (timespec_diff_ms(&next, &now) > 0) {
            struct timespec rem;
            int rc;
            do {
                rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next,
                                     &rem);
            } while (rc == EINTR);
        } else {
            next = now;
        }
    }
    return FB_OK;
}

static void *cycle_thread_main(void *arg)
{
    fb_runtime_t *rt = arg;
    (void)run_cycle_loop(rt, NULL);
    return NULL;
}

static int stop_thread_unlocked_prep(fb_runtime_t *rt)
{
    if (!rt->thread_on) {
        return 0;
    }
    rt->thread_stop = 1;
    return 1;
}

static void join_thread(fb_runtime_t *rt)
{
    if (!rt->thread_on) {
        return;
    }
    pthread_join(rt->thread, NULL);
    rt->thread_on = 0;
    rt->thread_stop = 0;
}

uint32_t fb_api_version(void)
{
    return FB_API_VERSION;
}

const char *fb_strerror(int err)
{
    switch (err) {
    case FB_OK:
        return "ok";
    case FB_ERR_INVAL:
        return "invalid argument";
    case FB_ERR_NOENT:
        return "point not found";
    case FB_ERR_IO:
        return "i/o error";
    case FB_ERR_TYPE:
        return "type mismatch";
    case FB_ERR_PERM:
        return "permission denied";
    case FB_ERR_STATE:
        return "bad state";
    case FB_ERR_NOMEM:
        return "out of memory";
    case FB_ERR_NOSPC:
        return "buffer too small";
    case FB_ERR_CONFIG:
        return "config error";
    case FB_ERR_UNSUPPORTED:
        return "not supported";
    case FB_ERR_BUSY:
        return "busy";
    default:
        return "unknown error";
    }
}

int fb_open(const char *config_path, fb_runtime_t **out)
{
    if (out) {
        *out = NULL;
    }
    if (!config_path || !config_path[0] || !out) {
        return FB_ERR_INVAL;
    }
    if (strlen(config_path) >= FB_PATH_MAX) {
        return FB_ERR_INVAL;
    }

    fb_runtime_t *rt = calloc(1, sizeof(*rt));
    if (!rt) {
        return FB_ERR_NOMEM;
    }
    if (pthread_mutex_init(&rt->mu, NULL) != 0) {
        free(rt);
        return FB_ERR_NOMEM;
    }
    snprintf(rt->config_path, sizeof(rt->config_path), "%s", config_path);

    fb_session_t sess;
    int rc = session_build(config_path, &sess, rt->last_error,
                           sizeof(rt->last_error));
    if (rc != FB_OK) {
        pthread_mutex_destroy(&rt->mu);
        free(rt);
        return rc;
    }
    rc = session_connect(&sess, rt->last_error, sizeof(rt->last_error));
    if (rc != FB_OK) {
        session_teardown(&sess, 0);
        pthread_mutex_destroy(&rt->mu);
        free(rt);
        return rc;
    }

    rt->session = sess;
    rt->have_session = 1;
    rt->generation = 1;
    LOG_INFO("fb_api", "open device=%s protocol=%s cycle_ms=%d points=%d",
             rt->session.cfg.device_name, rt->session.cfg.protocol,
             rt->session.cfg.cycle_ms, rt->session.point_count);
    *out = rt;
    return FB_OK;
}

int fb_close(fb_runtime_t *rt)
{
    if (!rt) {
        return FB_OK;
    }
    rt->thread_stop = 1;
    if (rt->thread_on) {
        pthread_join(rt->thread, NULL);
        rt->thread_on = 0;
    }
    pthread_mutex_lock(&rt->mu);
    if (rt->have_session) {
        session_teardown(&rt->session, 1);
        rt->have_session = 0;
    }
    pthread_mutex_unlock(&rt->mu);
    pthread_mutex_destroy(&rt->mu);
    free(rt);
    return FB_OK;
}

int fb_reload(fb_runtime_t *rt, const char *config_path)
{
    if (!rt || !config_path || !config_path[0]) {
        return FB_ERR_INVAL;
    }
    if (strlen(config_path) >= FB_PATH_MAX) {
        return FB_ERR_INVAL;
    }

    char err[FB_ERROR_MSG_MAX];
    err[0] = '\0';
    fb_session_t neu;
    int rc = session_build(config_path, &neu, err, sizeof(err));
    if (rc != FB_OK) {
        pthread_mutex_lock(&rt->mu);
        rt_set_err(rt, err[0] ? err : "reload validate failed");
        pthread_mutex_unlock(&rt->mu);
        LOG_ERROR("fb_api", "reload aborted (old session kept): %s",
                  err[0] ? err : fb_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session || !rt->session.adapter) {
        pthread_mutex_unlock(&rt->mu);
        session_teardown(&neu, 0);
        return FB_ERR_STATE;
    }

    if (rt->session.adapter->disconnect) {
        rt->session.adapter->disconnect(rt->session.adapter);
    }
    rc = session_connect(&neu, err, sizeof(err));
    if (rc != FB_OK) {
        char rec_err[FB_ERROR_MSG_MAX];
        rec_err[0] = '\0';
        int rec = session_connect(&rt->session, rec_err, sizeof(rec_err));
        rt_set_err(rt, err[0] ? err : "reload connect failed");
        pthread_mutex_unlock(&rt->mu);
        session_teardown(&neu, 0);
        LOG_ERROR("fb_api",
                  "reload connect failed (attempted restore old): %s restore=%d",
                  err[0] ? err : fb_strerror(rc), rec);
        return rc;
    }

    fb_session_t old = rt->session;
    rt->session = neu;
    rt->generation++;
    snprintf(rt->config_path, sizeof(rt->config_path), "%s", config_path);
    rt->last_error[0] = '\0';
    pthread_mutex_unlock(&rt->mu);

    session_teardown(&old, 0);
    LOG_INFO("fb_api", "reload ok generation=%u protocol=%s points=%d",
             rt->generation, rt->session.cfg.protocol, rt->session.point_count);
    return FB_OK;
}

int fb_read_point(fb_runtime_t *rt, const char *name, fb_value_t *value)
{
    if (!rt || !name || !name[0] || !value) {
        return FB_ERR_INVAL;
    }
    if (strlen(name) >= FB_POINT_NAME_MAX) {
        return FB_ERR_INVAL;
    }

    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session || !rt->session.adapter ||
        !rt->session.adapter->read_point) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    const fb_point_meta_t *m = find_meta(&rt->session, name);
    if (!m) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_NOENT;
    }

    uint8_t raw[FB_WIRE_CAP];
    size_t n = 0;
    int arc = adapter_read_copy(rt->session.adapter, name, raw, sizeof(raw), &n);
    if (arc != 0) {
        int mapped = map_errno(arc);
        rt_set_err(rt, mapped == FB_ERR_NOENT ? "point not found"
                                              : "read_point failed");
        pthread_mutex_unlock(&rt->mu);
        return mapped == FB_ERR_INVAL ? FB_ERR_NOENT : mapped;
    }

    fb_type_t want = value->type == FB_TYPE_AUTO ? native_type_of(m)
                                                 : value->type;
    int rc = FB_OK;
    if (want == FB_TYPE_BYTES) {
        if (!value->buf || value->cap == 0) {
            rc = FB_ERR_INVAL;
        } else if (n > value->cap) {
            rc = FB_ERR_NOSPC;
        } else {
            memcpy(value->buf, raw, n);
            value->len = n;
            value->type = FB_TYPE_BYTES;
        }
    } else if (want == FB_TYPE_STRING || m->kind == FB_KIND_STRING) {
        if (want != FB_TYPE_STRING && want != FB_TYPE_AUTO) {
            rc = FB_ERR_TYPE;
        } else if (!value->buf || value->cap == 0) {
            rc = FB_ERR_INVAL;
        } else {
            size_t copy = n;
            if (copy + 1 > value->cap) {
                rc = FB_ERR_NOSPC;
            } else {
                memcpy(value->buf, raw, copy);
                ((char *)value->buf)[copy] = '\0';
                /* trim trailing NULs already in payload */
                value->len = strlen((char *)value->buf);
                value->type = FB_TYPE_STRING;
            }
        }
    } else {
        double x;
        rc = decode_numeric(m, raw, n, &x);
        if (rc == FB_OK) {
            rc = store_numeric(value, want, x);
        }
    }
    pthread_mutex_unlock(&rt->mu);
    return rc;
}

int fb_write_point(fb_runtime_t *rt, const char *name, const fb_value_t *value)
{
    if (!rt || !name || !name[0] || !value) {
        return FB_ERR_INVAL;
    }
    if (strlen(name) >= FB_POINT_NAME_MAX) {
        return FB_ERR_INVAL;
    }

    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session || !rt->session.adapter ||
        !rt->session.adapter->write_point) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    const fb_point_meta_t *m = find_meta(&rt->session, name);
    if (!m) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_NOENT;
    }
    if (!app_may_write(m->access)) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_PERM;
    }

    uint8_t wire[FB_WIRE_CAP];
    size_t wlen = 0;
    int rc = FB_OK;
    if (value->type == FB_TYPE_BYTES) {
        if (!value->buf) {
            rc = FB_ERR_INVAL;
        } else if (value->len > sizeof(wire)) {
            rc = FB_ERR_NOSPC;
        } else {
            memcpy(wire, value->buf, value->len);
            wlen = value->len;
        }
    } else if (value->type == FB_TYPE_STRING) {
        if (m->kind != FB_KIND_STRING && m->kind != FB_KIND_BYTES) {
            rc = FB_ERR_TYPE;
        } else if (!value->buf) {
            rc = FB_ERR_INVAL;
        } else {
            size_t slen = value->len;
            if (slen == 0) {
                size_t bound = value->cap ? value->cap : FB_WIRE_CAP;
                slen = strnlen((const char *)value->buf, bound);
            }
            if (slen > sizeof(wire)) {
                rc = FB_ERR_NOSPC;
            } else {
                memcpy(wire, value->buf, slen);
                wlen = slen;
            }
        }
    } else {
        double x;
        rc = value_as_double(value, &x);
        if (rc == FB_OK) {
            rc = encode_numeric(m, x, wire, &wlen);
        }
    }

    if (rc == FB_OK) {
        int arc = adapter_write_bytes(rt->session.adapter, name, wire, wlen);
        if (arc != 0) {
            rc = map_errno(arc);
            if (rc == FB_ERR_INVAL) {
                rc = FB_ERR_IO;
            }
            rt_set_err(rt, "write_point failed");
        }
    }
    pthread_mutex_unlock(&rt->mu);
    return rc;
}

int fb_read_bool(fb_runtime_t *rt, const char *name, int *out)
{
    if (!out) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_BOOL;
    int rc = fb_read_point(rt, name, &v);
    if (rc == FB_OK) {
        *out = v.v.b;
    }
    return rc;
}

int fb_write_bool(fb_runtime_t *rt, const char *name, int v)
{
    fb_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = FB_TYPE_BOOL;
    val.v.b = v ? 1 : 0;
    return fb_write_point(rt, name, &val);
}

int fb_read_i32(fb_runtime_t *rt, const char *name, int32_t *out)
{
    if (!out) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_I32;
    int rc = fb_read_point(rt, name, &v);
    if (rc == FB_OK) {
        *out = v.v.i32;
    }
    return rc;
}

int fb_write_i32(fb_runtime_t *rt, const char *name, int32_t v)
{
    fb_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = FB_TYPE_I32;
    val.v.i32 = v;
    return fb_write_point(rt, name, &val);
}

int fb_read_u32(fb_runtime_t *rt, const char *name, uint32_t *out)
{
    if (!out) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_U32;
    int rc = fb_read_point(rt, name, &v);
    if (rc == FB_OK) {
        *out = v.v.u32;
    }
    return rc;
}

int fb_write_u32(fb_runtime_t *rt, const char *name, uint32_t v)
{
    fb_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = FB_TYPE_U32;
    val.v.u32 = v;
    return fb_write_point(rt, name, &val);
}

int fb_read_f32(fb_runtime_t *rt, const char *name, float *out)
{
    if (!out) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_F32;
    int rc = fb_read_point(rt, name, &v);
    if (rc == FB_OK) {
        *out = v.v.f32;
    }
    return rc;
}

int fb_write_f32(fb_runtime_t *rt, const char *name, float v)
{
    fb_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = FB_TYPE_F32;
    val.v.f32 = v;
    return fb_write_point(rt, name, &val);
}

int fb_read_string(fb_runtime_t *rt, const char *name, char *buf, size_t cap)
{
    if (!buf || cap == 0) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_STRING;
    v.buf = buf;
    v.cap = cap;
    return fb_read_point(rt, name, &v);
}

int fb_write_string(fb_runtime_t *rt, const char *name, const char *s)
{
    if (!s) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_STRING;
    v.buf = (void *)(uintptr_t)s;
    v.len = strlen(s);
    v.cap = v.len;
    return fb_write_point(rt, name, &v);
}

int fb_read_bytes(fb_runtime_t *rt, const char *name, void *buf, size_t cap,
                  size_t *out_len)
{
    if (!buf || cap == 0) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_BYTES;
    v.buf = buf;
    v.cap = cap;
    int rc = fb_read_point(rt, name, &v);
    if (rc == FB_OK && out_len) {
        *out_len = v.len;
    }
    return rc;
}

int fb_write_bytes(fb_runtime_t *rt, const char *name, const void *buf,
                   size_t len)
{
    if (!buf && len > 0) {
        return FB_ERR_INVAL;
    }
    fb_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = FB_TYPE_BYTES;
    v.buf = (void *)(uintptr_t)buf;
    v.len = len;
    v.cap = len;
    return fb_write_point(rt, name, &v);
}

int fb_list_points(fb_runtime_t *rt, fb_point_info_t *out, size_t cap,
                   size_t *out_count)
{
    if (!rt || !out_count) {
        return FB_ERR_INVAL;
    }
    if (out && cap == 0) {
        /* allowed: treat as count-only if out is ignored; keep simple */
    }
    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    *out_count = (size_t)rt->session.point_count;
    size_t n = *out_count;
    if (out && cap < n) {
        n = cap;
    }
    if (out) {
        for (size_t i = 0; i < n; i++) {
            fill_point_info(&rt->session.points[i], &out[i]);
        }
    }
    pthread_mutex_unlock(&rt->mu);
    return FB_OK;
}

int fb_point_info(fb_runtime_t *rt, const char *name, fb_point_info_t *out)
{
    if (!rt || !name || !name[0] || !out) {
        return FB_ERR_INVAL;
    }
    pthread_mutex_lock(&rt->mu);
    const fb_point_meta_t *m = find_meta(&rt->session, name);
    if (!m) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_NOENT;
    }
    fill_point_info(m, out);
    pthread_mutex_unlock(&rt->mu);
    return FB_OK;
}

int fb_health(fb_runtime_t *rt, fb_health_t *out)
{
    if (!rt || !out) {
        return FB_ERR_INVAL;
    }
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session || !rt->session.adapter) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    out->cycle_ms = rt->session.cfg.cycle_ms;
    out->generation = rt->generation;
    snprintf(out->protocol, sizeof(out->protocol), "%s",
             rt->session.cfg.protocol);
    snprintf(out->device_name, sizeof(out->device_name), "%s",
             rt->session.cfg.device_name);
    snprintf(out->last_error, sizeof(out->last_error), "%s", rt->last_error);
    int connected = 0;
    char errbuf[FB_ERROR_MSG_MAX];
    errbuf[0] = '\0';
    if (rt->session.adapter->health) {
        (void)rt->session.adapter->health(rt->session.adapter, &connected,
                                          errbuf, sizeof(errbuf));
    }
    out->connected = connected ? 1 : 0;
    if (errbuf[0] && !out->last_error[0]) {
        snprintf(out->last_error, sizeof(out->last_error), "%s", errbuf);
    }
    pthread_mutex_unlock(&rt->mu);
    return FB_OK;
}

int fb_poll(fb_runtime_t *rt)
{
    if (!rt) {
        return FB_ERR_INVAL;
    }
    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    int rc = poll_locked(rt);
    pthread_mutex_unlock(&rt->mu);
    return rc;
}

int fb_run(fb_runtime_t *rt, volatile int *stop_flag)
{
    if (!rt || !stop_flag) {
        return FB_ERR_INVAL;
    }
    if (rt->thread_on) {
        return FB_ERR_STATE;
    }
    return run_cycle_loop(rt, stop_flag);
}

int fb_start(fb_runtime_t *rt)
{
    if (!rt) {
        return FB_ERR_INVAL;
    }
    pthread_mutex_lock(&rt->mu);
    if (!rt->have_session) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    if (rt->thread_on) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_STATE;
    }
    rt->thread_stop = 0;
    if (pthread_create(&rt->thread, NULL, cycle_thread_main, rt) != 0) {
        pthread_mutex_unlock(&rt->mu);
        return FB_ERR_NOMEM;
    }
    rt->thread_on = 1;
    pthread_mutex_unlock(&rt->mu);
    return FB_OK;
}

int fb_stop(fb_runtime_t *rt)
{
    if (!rt) {
        return FB_ERR_INVAL;
    }
    int need_join = 0;
    pthread_mutex_lock(&rt->mu);
    need_join = stop_thread_unlocked_prep(rt);
    pthread_mutex_unlock(&rt->mu);
    if (need_join) {
        join_thread(rt);
    }
    return FB_OK;
}
