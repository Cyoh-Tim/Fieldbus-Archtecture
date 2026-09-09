#include "pcap.h"
#include "ctt.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logger.h"

#define PCAP_MAGIC 0xa1b2c3d4u

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void wr_le16(FILE *f, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    fwrite(b, 1, 2, f);
}

static void wr_le32(FILE *f, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16),
                    (uint8_t)(v >> 24)};
    fwrite(b, 1, 4, f);
}

static int ext_is(const char *path, const char *ext)
{
    size_t n = strlen(path);
    size_t m = strlen(ext);
    if (n < m) {
        return 0;
    }
    return strcmp(path + n - m, ext) == 0;
}

int ctt_pcap_write_one(const char *path, const uint8_t *frame, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        LOG_ERROR("ctt", "pcap write %s: %s", path, strerror(errno));
        return -errno;
    }
    wr_le32(f, PCAP_MAGIC);
    wr_le16(f, 2);
    wr_le16(f, 4);
    wr_le32(f, 0);
    wr_le32(f, 0);
    wr_le32(f, 65535);
    wr_le32(f, 1); /* LINKTYPE_ETHERNET */
    wr_le32(f, 0); /* ts_sec */
    wr_le32(f, 0); /* ts_usec */
    wr_le32(f, (uint32_t)len);
    wr_le32(f, (uint32_t)len);
    fwrite(frame, 1, len, f);
    fclose(f);
    return 0;
}

int ctt_pcap_read_first(const char *path, uint8_t *frame, size_t cap,
                        size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -errno;
    }
    uint8_t gh[24];
    if (fread(gh, 1, 24, f) != 24) {
        fclose(f);
        return -EINVAL;
    }
    uint32_t magic = rd_le32(gh);
    if (magic != PCAP_MAGIC) {
        fclose(f);
        return -EINVAL;
    }
    uint8_t ph[16];
    if (fread(ph, 1, 16, f) != 16) {
        fclose(f);
        return -EINVAL;
    }
    uint32_t incl = rd_le32(ph + 8);
    if (incl > cap) {
        fclose(f);
        return -ENOSPC;
    }
    if (fread(frame, 1, incl, f) != incl) {
        fclose(f);
        return -EINVAL;
    }
    fclose(f);
    *out_len = incl;
    return 0;
}

int ctt_bin_write(const char *path, const uint8_t *frame, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        LOG_ERROR("ctt", "bin write %s: %s", path, strerror(errno));
        return -errno;
    }
    fwrite(frame, 1, len, f);
    fclose(f);
    return 0;
}

int ctt_bin_read(const char *path, uint8_t *frame, size_t cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -errno;
    }
    size_t n = fread(frame, 1, cap, f);
    fclose(f);
    if (n == 0) {
        return -EINVAL;
    }
    *out_len = n;
    return 0;
}

int ctt_golden_load(const char *path, uint8_t *frame, size_t cap, size_t *out_len)
{
    if (ext_is(path, ".pcap")) {
        return ctt_pcap_read_first(path, frame, cap, out_len);
    }
    return ctt_bin_read(path, frame, cap, out_len);
}

int ctt_resolve_path(const char *scenario_path, const char *rel, char *out,
                     size_t cap)
{
    if (!rel || !rel[0] || !out || cap < 2) {
        return -EINVAL;
    }
    if (rel[0] == '/') {
        snprintf(out, cap, "%s", rel);
        return access(out, R_OK) == 0 ? 0 : -ENOENT;
    }
    if (access(rel, R_OK) == 0) {
        snprintf(out, cap, "%s", rel);
        return 0;
    }
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", scenario_path ? scenario_path : ".");
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
    } else {
        snprintf(dir, sizeof(dir), ".");
    }
    for (int i = 0; i < 10; i++) {
        snprintf(out, cap, "%s/%s", dir, rel);
        if (access(out, R_OK) == 0) {
            return 0;
        }
        slash = strrchr(dir, '/');
        if (!slash || slash == dir) {
            break;
        }
        *slash = '\0';
    }
    snprintf(out, cap, "%s", rel);
    return -ENOENT;
}

static int ensure_dir(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -ENOTDIR;
    }
    if (mkdir(dir, 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    return -errno;
}

static int capture_is_dir(const char *p)
{
    size_t n = strlen(p);
    if (n == 0) {
        return 0;
    }
    if (p[n - 1] == '/') {
        return 1;
    }
    struct stat st;
    if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1;
    }
    return !ext_is(p, ".pcap") && !ext_is(p, ".bin");
}

int ctt_capture_step_frame(ctt_run_t *run, int step, const char *action,
                           const uint8_t *frame, size_t len)
{
    if (!run || !run->opts.capture[0] || !frame || len == 0) {
        return 0;
    }
    char path[640];
    if (capture_is_dir(run->opts.capture)) {
        if (ensure_dir(run->opts.capture) != 0) {
            LOG_ERROR("ctt", "capture dir %s: %s", run->opts.capture,
                      strerror(errno));
            return -1;
        }
        const char *nm = run->name ? run->name : "scenario";
        snprintf(path, sizeof(path), "%s/%s-%d-%s.pcap", run->opts.capture, nm,
                 step, action ? action : "step");
    } else {
        snprintf(path, sizeof(path), "%s", run->opts.capture);
    }
    int rc = ext_is(path, ".bin") ? ctt_bin_write(path, frame, len)
                                   : ctt_pcap_write_one(path, frame, len);
    if (rc == 0) {
        LOG_INFO("ctt", "captured step=%d action=%s bytes=%zu file=%s", step,
                 action ? action : "?", len, path);
    }
    return rc;
}

static void hex_preview(const uint8_t *p, size_t n, char *out, size_t cap)
{
    size_t show = n < 24 ? n : 24;
    size_t off = 0;
    out[0] = '\0';
    for (size_t i = 0; i < show && off + 4 < cap; i++) {
        off += (size_t)snprintf(out + off, cap - off, "%s%02x", i ? " " : "",
                               p[i]);
    }
    if (n > show && off + 4 < cap) {
        snprintf(out + off, cap - off, " …");
    }
}

int ctt_golden_check(ctt_run_t *run, int step, const char *action,
                      const uint8_t *frame, size_t len, const char *rel)
{
    if (!rel || !rel[0]) {
        return 0;
    }
    if (run->opts.capture[0]) {
        LOG_INFO("ctt", "skip golden check while --capture is set");
        return 0;
    }
    if (run->opts.transport != CTT_TRANSPORT_MOCK) {
        LOG_INFO("ctt",
                 "skip golden replay on transport=af_packet (wire padding/"
                 "MAC); field asserts still apply");
        return 0;
    }
    char path[640];
    if (ctt_resolve_path(run->path, rel, path, sizeof(path)) != 0) {
        ctt_failf(run, step, action, "golden not found: %s", rel);
        return -1;
    }
    uint8_t want[CTT_FRAME_MAX];
    size_t wlen = 0;
    if (ctt_golden_load(path, want, sizeof(want), &wlen) != 0) {
        ctt_failf(run, step, action, "golden load failed: %s", path);
        return -1;
    }
    if (len != wlen || memcmp(frame, want, wlen) != 0) {
        char a[96], b[96];
        hex_preview(want, wlen, a, sizeof(a));
        hex_preview(frame, len, b, sizeof(b));
        ctt_failf(run, step, action,
                  "golden mismatch file=%s expect_len=%zu actual_len=%zu "
                  "expect[%s] actual[%s]",
                  path, wlen, len, a, b);
        return -1;
    }
    LOG_INFO("ctt", "golden OK step=%d action=%s file=%s bytes=%zu", step,
             action ? action : "?", path, wlen);
    return 0;
}
