#ifndef FB_API_H
#define FB_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Application-facing Fieldbus runtime API (point-oriented).
 *
 * Apps include only this header. They do not talk Modbus / SLMP /
 * EtherNet/IP / PROFINET types, and they must not include adapter or
 * stack headers. One config JSON selects one protocol for the process.
 *
 * ABI: bump FB_API_VERSION_MINOR for compatible additions, MAJOR for
 * breaking changes. fb_health_t / fb_point_info_t have reserved[] tails.
 */

#define FB_API_VERSION_MAJOR 1
#define FB_API_VERSION_MINOR 0
#define FB_API_VERSION_PATCH 0
#define FB_API_VERSION                                                 \
    ((uint32_t)(((FB_API_VERSION_MAJOR) << 16) |                       \
                ((FB_API_VERSION_MINOR) << 8) | (FB_API_VERSION_PATCH)))

#define FB_POINT_NAME_MAX 64
#define FB_POINT_TYPE_MAX 32
#define FB_PROTOCOL_MAX 64
#define FB_DEVICE_NAME_MAX 128
#define FB_ERROR_MSG_MAX 160

typedef struct fb_runtime fb_runtime_t;

typedef enum fb_err {
    FB_OK = 0,
    FB_ERR_INVAL = -1,        /* NULL / empty / malformed argument */
    FB_ERR_NOENT = -2,        /* unknown point name */
    FB_ERR_IO = -3,           /* adapter/stack I/O or connect */
    FB_ERR_TYPE = -4,         /* value type not usable for this point */
    FB_ERR_PERM = -5,         /* write to an app-read-only point */
    FB_ERR_STATE = -6,        /* lifecycle / thread state */
    FB_ERR_NOMEM = -7,        /* allocation failed */
    FB_ERR_NOSPC = -8,        /* caller buffer too small */
    FB_ERR_CONFIG = -9,       /* config path / JSON / unknown protocol */
    FB_ERR_UNSUPPORTED = -10, /* stub protocol or unimplemented op */
    FB_ERR_BUSY = -11         /* reserved (reload/thread contention) */
} fb_err_t;

/*
 * Logical type used at the API boundary (not a protocol wire type).
 * Numeric payloads from Modbus/SLMP adapters are canonical big-endian
 * (and engineering float32 when the adapter applied scale/offset).
 */
typedef enum fb_type {
    FB_TYPE_AUTO = 0, /* read: fill native type from config */
    FB_TYPE_BOOL,
    FB_TYPE_I32,
    FB_TYPE_U32,
    FB_TYPE_I64,
    FB_TYPE_U64,
    FB_TYPE_F32,
    FB_TYPE_F64,
    FB_TYPE_STRING, /* UTF-8/ASCII bytes; read always NUL-terminates */
    FB_TYPE_BYTES   /* opaque; length in .len */
} fb_type_t;

/*
 * access in config.json is PLC-centric (same as adapters):
 *   "read"      — PLC reads  → app publishes (fb_write_point)
 *   "write"     — PLC writes → app consumes (fb_read_point only)
 *   "readwrite" — both
 * FB_ERR_PERM is returned when the app writes a PLC-write-only point.
 */
typedef enum fb_access {
    FB_ACCESS_UNKNOWN = 0,
    FB_ACCESS_PLC_READ = 1,
    FB_ACCESS_PLC_WRITE = 2,
    FB_ACCESS_READWRITE = 3
} fb_access_t;

#define FB_POINT_F_SCALED 1u

typedef struct fb_value {
    fb_type_t type;
    union {
        int b; /* 0 or 1 */
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f32;
        double f64;
    } v;
    /* STRING/BYTES: caller-owned buffer. cap is capacity; len is used. */
    void *buf;
    size_t cap;
    size_t len;
} fb_value_t;

typedef struct fb_point_info {
    char name[FB_POINT_NAME_MAX];
    char data_type[FB_POINT_TYPE_MAX]; /* config string, truncated */
    fb_access_t access;
    fb_type_t native_type;
    uint32_t flags;   /* FB_POINT_F_SCALED */
    size_t wire_size; /* expected app bytes; 0 if unknown */
    uint32_t reserved[4];
} fb_point_info_t;

typedef struct fb_health {
    int connected; /* 1 connected, 0 not */
    int cycle_ms;
    uint32_t generation; /* 1 after open; ++ on successful reload */
    char protocol[FB_PROTOCOL_MAX];
    char device_name[FB_DEVICE_NAME_MAX];
    char last_error[FB_ERROR_MSG_MAX];
    uint32_t reserved[8];
} fb_health_t;

uint32_t fb_api_version(void);
const char *fb_strerror(int err);

/*
 * Load config JSON, construct the selected adapter, init + connect.
 * On failure *out is NULL (if out != NULL) and the process has no session.
 */
int fb_open(const char *config_path, fb_runtime_t **out);

/* NULL rt is a no-op (FB_OK). Stops an internal cycle thread if any. */
int fb_close(fb_runtime_t *rt);

/*
 * Reload policy: in-process restart-of-session.
 * New config is loaded and adapter init is completed before the live
 * session is touched. On init failure the old session is unchanged.
 * Connect of the new adapter happens after disconnecting the old one
 * (same bind port). If new connect fails, the old adapter is started
 * again; generation is not incremented.
 */
int fb_reload(fb_runtime_t *rt, const char *config_path);

int fb_read_point(fb_runtime_t *rt, const char *name, fb_value_t *value);
int fb_write_point(fb_runtime_t *rt, const char *name, const fb_value_t *value);

int fb_read_bool(fb_runtime_t *rt, const char *name, int *out);
int fb_write_bool(fb_runtime_t *rt, const char *name, int v);
int fb_read_i32(fb_runtime_t *rt, const char *name, int32_t *out);
int fb_write_i32(fb_runtime_t *rt, const char *name, int32_t v);
int fb_read_u32(fb_runtime_t *rt, const char *name, uint32_t *out);
int fb_write_u32(fb_runtime_t *rt, const char *name, uint32_t v);
int fb_read_f32(fb_runtime_t *rt, const char *name, float *out);
int fb_write_f32(fb_runtime_t *rt, const char *name, float v);
int fb_read_string(fb_runtime_t *rt, const char *name, char *buf, size_t cap);
int fb_write_string(fb_runtime_t *rt, const char *name, const char *s);
int fb_read_bytes(fb_runtime_t *rt, const char *name, void *buf, size_t cap,
                  size_t *out_len);
int fb_write_bytes(fb_runtime_t *rt, const char *name, const void *buf,
                   size_t len);

/*
 * If out == NULL, only *out_count is written (total points).
 * If cap < total, the first cap entries are filled and *out_count is still
 * the total. Return FB_OK.
 */
int fb_list_points(fb_runtime_t *rt, fb_point_info_t *out, size_t cap,
                   size_t *out_count);
int fb_point_info(fb_runtime_t *rt, const char *name, fb_point_info_t *out);

int fb_health(fb_runtime_t *rt, fb_health_t *out);

/*
 * Cycle driving (pick one):
 *   Default / embedded: the library does not start a thread. Call
 *   fb_poll() each cycle, or fb_run() to block like the daemon.
 *   Optional: fb_start() spawns a CLOCK_MONOTONIC cycle thread.
 * Adapter calls are mutex-protected, so poll/thread + app read/write
 * may run concurrently. Do not call fb_run() while fb_start() is active.
 */
int fb_poll(fb_runtime_t *rt);
int fb_run(fb_runtime_t *rt, volatile int *stop_flag);
int fb_start(fb_runtime_t *rt);
int fb_stop(fb_runtime_t *rt); /* join cycle thread; session stays open */

#ifdef __cplusplus
}
#endif

#endif /* FB_API_H */
