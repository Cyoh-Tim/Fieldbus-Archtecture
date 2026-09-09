#include "ctt.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logger.h"
#include "slmp_stack.h"

typedef struct {
    slmp_stack_t *stack;
    slmp_cfg_t cfg;
} slmp_priv_t;

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static slmp_access_unit_t unit_from_str(const char *s)
{
    if (s && (strcmp(s, "bit") == 0 || strcmp(s, "bit_unit") == 0)) {
        return SLMP_ACCESS_BIT;
    }
    return SLMP_ACCESS_WORD;
}

static slmp_frame_type_t frame_from_str(const char *s)
{
    if (!s) {
        return SLMP_FRAME_3E_BINARY;
    }
    if (strcmp(s, "3e_ascii") == 0 || strcmp(s, "3E_ASCII") == 0) {
        return SLMP_FRAME_3E_ASCII;
    }
    if (strcmp(s, "4e_binary") == 0 || strcmp(s, "4E_BINARY") == 0) {
        return SLMP_FRAME_4E_BINARY;
    }
    return SLMP_FRAME_3E_BINARY;
}

static int resolve_device(const yaml_node_t *map, uint8_t *code, int *is_bit)
{
    const char *name = yaml_cstr(map, "device", NULL);
    if (!name || !name[0]) {
        if (yaml_has(map, "device_code")) {
            *code = (uint8_t)yaml_ulong(map, "device_code", 0);
            if (is_bit) {
                *is_bit = 0;
                (void)slmp_device_name_from_code(*code);
            }
            return 0;
        }
        return -EINVAL;
    }
    return slmp_device_code_from_name(name, code, is_bit);
}

static int load_u16s(const yaml_node_t *map, const char *key, uint16_t *out,
                     int cap)
{
    long tmp[128];
    int n = yaml_longs(map, key, tmp, cap < 128 ? cap : 128);
    if (n < 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        out[i] = (uint16_t)tmp[i];
    }
    return n;
}

static int load_u8s(const yaml_node_t *map, const char *key, uint8_t *out,
                    int cap)
{
    long tmp[256];
    int n = yaml_longs(map, key, tmp, cap < 256 ? cap : 256);
    if (n < 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        out[i] = (uint8_t)tmp[i];
    }
    return n;
}

static int fill_range(const yaml_node_t *step, slmp_range_t *range)
{
    memset(range, 0, sizeof(*range));
    int is_bit = 0;
    if (resolve_device(step, &range->addr.device_code, &is_bit) != 0) {
        return -EINVAL;
    }
    range->addr.head = (uint32_t)yaml_ulong(step, "head", 0);
    const char *unit = yaml_cstr(step, "unit", NULL);
    if (unit) {
        range->addr.unit = unit_from_str(unit);
    } else {
        range->addr.unit = is_bit ? SLMP_ACCESS_BIT : SLMP_ACCESS_WORD;
    }
    range->quantity = (uint16_t)yaml_ulong(step, "quantity", 1);
    return 0;
}

static int words_to_be(const uint16_t *vals, int n, uint8_t *raw)
{
    for (int i = 0; i < n; i++) {
        raw[i * 2] = (uint8_t)(vals[i] >> 8);
        raw[i * 2 + 1] = (uint8_t)(vals[i] & 0xff);
    }
    return n * 2;
}

static int step_device_lookup(ctt_run_t *run, const yaml_node_t *step, int idx)
{
    const char *name = yaml_cstr(step, "name", "");
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    uint8_t code = 0;
    int is_bit = 0;
    int rc = slmp_device_code_from_name(name, &code, &is_bit);
    if (expect && yaml_bool(expect, "unknown", 0)) {
        return ctt_check(run, idx, "device_lookup", rc != 0,
                          "expected unknown device %s rc=%d", name, rc);
    }
    if (ctt_check(run, idx, "device_lookup", rc == 0, "lookup %s rc=%d", name,
                  rc) != 0) {
        return -1;
    }
    if (expect && yaml_has(expect, "code")) {
        unsigned long want = yaml_ulong(expect, "code", 0);
        if (ctt_check(run, idx, "device_lookup", code == (uint8_t)want,
                      "%s code want=0x%02lX got=0x%02X", name, want,
                      code) != 0) {
            return -1;
        }
    }
    if (expect && yaml_has(expect, "is_bit")) {
        int want = yaml_bool(expect, "is_bit", 0);
        if (ctt_check(run, idx, "device_lookup", is_bit == want,
                      "%s is_bit want=%d got=%d", name, want, is_bit) != 0) {
            return -1;
        }
    }
    if (expect && yaml_has(expect, "hex_addr")) {
        int want = yaml_bool(expect, "hex_addr", 0);
        int got = slmp_device_is_hex_addr(code);
        return ctt_check(run, idx, "device_lookup", got == want,
                          "%s hex_addr want=%d got=%d", name, want, got);
    }
    return 0;
}

static int step_create_stack(ctt_run_t *run, slmp_priv_t *priv,
                              const yaml_node_t *step, int idx)
{
    slmp_cfg_t cfg = priv->cfg;
    cfg.frame = frame_from_str(yaml_cstr(step, "frame", "3e_binary"));
    slmp_stack_t *s = slmp_stack_create(&cfg);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *want = expect ? yaml_cstr(expect, "result", "ok") : "ok";
    if (strcmp(want, "reject") == 0) {
        int rc = ctt_check(run, idx, "create_stack", s == NULL,
                          "frame=%d expected reject", (int)cfg.frame);
        if (s) {
            slmp_stack_destroy(s);
        }
        return rc;
    }
    if (ctt_check(run, idx, "create_stack", s != NULL, "create failed") != 0) {
        return -1;
    }
    slmp_stack_destroy(s);
    return 0;
}

static int check_encode_read(ctt_run_t *run, slmp_priv_t *priv,
                            const yaml_node_t *step, int idx,
                            const uint8_t *frame, size_t len)
{
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    if (!expect) {
        return 0;
    }
    if (yaml_has(expect, "length")) {
        unsigned long want = yaml_ulong(expect, "length", 0);
        if (ctt_check(run, idx, "encode_batch_read", len == want,
                      "len want=%lu got=%zu", want, len) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "subheader")) {
        unsigned long want = yaml_ulong(expect, "subheader", 0);
        if (ctt_check(run, idx, "encode_batch_read",
                      rd_le16(frame) == (uint16_t)want,
                      "subheader want=0x%04lX got=0x%04X", want,
                      rd_le16(frame)) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "cmd")) {
        unsigned long want = yaml_ulong(expect, "cmd", 0);
        if (ctt_check(run, idx, "encode_batch_read",
                      rd_le16(frame + 11) == (uint16_t)want,
                      "cmd want=0x%04lX got=0x%04X", want,
                      rd_le16(frame + 11)) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "device_code")) {
        unsigned long want = yaml_ulong(expect, "device_code", 0);
        if (ctt_check(run, idx, "encode_batch_read", frame[18] == (uint8_t)want,
                      "dev want=0x%02lX got=0x%02X", want, frame[18]) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "quantity")) {
        unsigned long want = yaml_ulong(expect, "quantity", 0);
        if (ctt_check(run, idx, "encode_batch_read",
                      rd_le16(frame + 19) == (uint16_t)want,
                      "qty want=%lu got=%u", want, rd_le16(frame + 19)) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "pc_no")) {
        unsigned long want = yaml_ulong(expect, "pc_no", 0);
        if (ctt_check(run, idx, "encode_batch_read", frame[3] == (uint8_t)want,
                      "pc_no want=0x%02lX got=0x%02X", want, frame[3]) != 0) {
            return -1;
        }
    }
    (void)priv;
    return 0;
}

static int step_encode_read(ctt_run_t *run, slmp_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    slmp_range_t range;
    if (fill_range(step, &range) != 0) {
        ctt_failf(run, idx, "encode_batch_read", "bad device/head");
        return -1;
    }
    uint8_t frame[64];
    size_t len = 0;
    int rc = slmp_encode_batch_read(&priv->cfg, &range, frame, sizeof(frame),
                                    &len);
    if (ctt_check(run, idx, "encode_batch_read", rc == 0, "encode rc=%d",
                  rc) != 0) {
        return -1;
    }
    return check_encode_read(run, priv, step, idx, frame, len);
}

static int step_encode_write(ctt_run_t *run, slmp_priv_t *priv,
                             const yaml_node_t *step, int idx)
{
    slmp_range_t range;
    if (fill_range(step, &range) != 0) {
        ctt_failf(run, idx, "encode_batch_write", "bad device/head");
        return -1;
    }
    uint8_t raw[256];
    size_t raw_len = 0;
    if (range.addr.unit == SLMP_ACCESS_BIT) {
        int n = load_u8s(step, "bits", raw, 256);
        if (n <= 0) {
            ctt_failf(run, idx, "encode_batch_write", "bits required");
            return -1;
        }
        range.quantity = (uint16_t)n;
        raw_len = (size_t)n;
    } else {
        uint16_t vals[64];
        int n = load_u16s(step, "values", vals, 64);
        if (n <= 0) {
            ctt_failf(run, idx, "encode_batch_write", "values required");
            return -1;
        }
        range.quantity = (uint16_t)n;
        raw_len = (size_t)words_to_be(vals, n, raw);
    }
    uint8_t frame[SLMP_FRAME_MAX];
    size_t len = 0;
    int rc = slmp_encode_batch_write(&priv->cfg, &range, raw, raw_len, frame,
                                     sizeof(frame), &len);
    if (ctt_check(run, idx, "encode_batch_write", rc == 0, "encode rc=%d",
                  rc) != 0) {
        return -1;
    }
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    if (expect && yaml_has(expect, "length")) {
        unsigned long want = yaml_ulong(expect, "length", 0);
        if (ctt_check(run, idx, "encode_batch_write", len == want,
                      "len want=%lu got=%zu", want, len) != 0) {
            return -1;
        }
    }
    if (expect && yaml_has(expect, "cmd")) {
        unsigned long want = yaml_ulong(expect, "cmd", 0);
        return ctt_check(run, idx, "encode_batch_write",
                          rd_le16(frame + 11) == (uint16_t)want,
                          "cmd want=0x%04lX got=0x%04X", want,
                          rd_le16(frame + 11));
    }
    return 0;
}

static int step_seed_words(ctt_run_t *run, slmp_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    uint8_t code = 0;
    if (resolve_device(step, &code, NULL) != 0) {
        ctt_failf(run, idx, "seed_words", "device required");
        return -1;
    }
    uint32_t head = (uint32_t)yaml_ulong(step, "head", 0);
    const char *ascii = yaml_cstr(step, "ascii", NULL);
    if (ascii && ascii[0]) {
        int rc = slmp_stack_write_bytes(priv->stack, code, head,
                                        (const uint8_t *)ascii, strlen(ascii));
        return ctt_check(run, idx, "seed_words", rc == 0,
                          "write_bytes rc=%d", rc);
    }
    uint16_t vals[128];
    int n = load_u16s(step, "values", vals, 128);
    if (n <= 0) {
        ctt_failf(run, idx, "seed_words", "values required");
        return -1;
    }
    int rc = slmp_stack_write_words(priv->stack, code, head, vals, (uint16_t)n);
    return ctt_check(run, idx, "seed_words", rc == 0, "write_words rc=%d", rc);
}

static int step_seed_bits(ctt_run_t *run, slmp_priv_t *priv,
                          const yaml_node_t *step, int idx)
{
    uint8_t code = 0;
    if (resolve_device(step, &code, NULL) != 0) {
        ctt_failf(run, idx, "seed_bits", "device required");
        return -1;
    }
    uint32_t head = (uint32_t)yaml_ulong(step, "head", 0);
    uint8_t bits[256];
    int n = load_u8s(step, "bits", bits, 256);
    if (n <= 0) {
        ctt_failf(run, idx, "seed_bits", "bits required");
        return -1;
    }
    int rc = slmp_stack_write_bits(priv->stack, code, head, bits, (uint16_t)n);
    return ctt_check(run, idx, "seed_bits", rc == 0, "write_bits rc=%d", rc);
}

static int check_end_and_values(ctt_run_t *run, int idx, const char *action,
                                const yaml_node_t *expect, const uint8_t *resp,
                                size_t resp_len)
{
    uint16_t end = 0xFFFF;
    const uint8_t *data = NULL;
    size_t dlen = 0;
    int rc = slmp_decode_response(resp, resp_len, &end, &data, &dlen);
    if (ctt_check(run, idx, action, rc == 0, "decode rc=%d", rc) != 0) {
        return -1;
    }
    if (!expect) {
        return 0;
    }
    if (yaml_has(expect, "end_code")) {
        unsigned long want = yaml_ulong(expect, "end_code", 0);
        if (ctt_check(run, idx, action, end == (uint16_t)want,
                      "end_code want=0x%04lX got=0x%04X", want, end) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "subheader")) {
        unsigned long want = yaml_ulong(expect, "subheader", 0);
        if (ctt_check(run, idx, action, rd_le16(resp) == (uint16_t)want,
                      "subheader want=0x%04lX got=0x%04X", want,
                      rd_le16(resp)) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "data_len")) {
        unsigned long want = yaml_ulong(expect, "data_len", 0);
        if (ctt_check(run, idx, action, dlen == want, "data_len want=%lu got=%zu",
                      want, dlen) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "values") && data) {
        uint16_t want[64];
        int n = load_u16s(expect, "values", want, 64);
        if (n < 0) {
            ctt_failf(run, idx, action, "bad expect.values");
            return -1;
        }
        if (ctt_check(run, idx, action, dlen >= (size_t)n * 2u,
                      "payload short dlen=%zu n=%d", dlen, n) != 0) {
            return -1;
        }
        for (int i = 0; i < n; i++) {
            uint16_t got = rd_le16(data + i * 2);
            if (ctt_check(run, idx, action, got == want[i],
                          "word[%d] want=0x%04X got=0x%04X", i, want[i],
                          got) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int step_batch_read(ctt_run_t *run, slmp_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    slmp_range_t range;
    if (fill_range(step, &range) != 0) {
        ctt_failf(run, idx, "batch_read", "bad device/head");
        return -1;
    }
    uint8_t req[64];
    size_t req_len = 0;
    int rc = slmp_encode_batch_read(&priv->cfg, &range, req, sizeof(req),
                                     &req_len);
    if (ctt_check(run, idx, "batch_read", rc == 0, "encode rc=%d", rc) != 0) {
        return -1;
    }
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    rc = slmp_stack_handle_request(priv->stack, req, req_len, resp,
                                    sizeof(resp), &resp_len);
    if (ctt_check(run, idx, "batch_read", rc == 0, "handle rc=%d", rc) != 0) {
        return -1;
    }
    return check_end_and_values(run, idx, "batch_read",
                                yaml_map_get(step, "expect"), resp, resp_len);
}

static int step_batch_write(ctt_run_t *run, slmp_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    slmp_range_t range;
    if (fill_range(step, &range) != 0) {
        ctt_failf(run, idx, "batch_write", "bad device/head");
        return -1;
    }
    uint8_t raw[256];
    size_t raw_len = 0;
    if (range.addr.unit == SLMP_ACCESS_BIT) {
        int n = load_u8s(step, "bits", raw, 256);
        if (n <= 0) {
            ctt_failf(run, idx, "batch_write", "bits required");
            return -1;
        }
        range.quantity = (uint16_t)n;
        raw_len = (size_t)n;
    } else {
        uint16_t vals[64];
        int n = load_u16s(step, "values", vals, 64);
        if (n <= 0) {
            ctt_failf(run, idx, "batch_write", "values required");
            return -1;
        }
        range.quantity = (uint16_t)n;
        raw_len = (size_t)words_to_be(vals, n, raw);
    }
    uint8_t req[SLMP_FRAME_MAX];
    size_t req_len = 0;
    int rc = slmp_encode_batch_write(&priv->cfg, &range, raw, raw_len, req,
                                     sizeof(req), &req_len);
    if (ctt_check(run, idx, "batch_write", rc == 0, "encode rc=%d", rc) != 0) {
        return -1;
    }
    uint8_t resp[128];
    size_t resp_len = 0;
    rc = slmp_stack_handle_request(priv->stack, req, req_len, resp,
                                    sizeof(resp), &resp_len);
    if (ctt_check(run, idx, "batch_write", rc == 0, "handle rc=%d", rc) != 0) {
        return -1;
    }
    return check_end_and_values(run, idx, "batch_write",
                                yaml_map_get(step, "expect"), resp, resp_len);
}

static int step_map_check_words(ctt_run_t *run, slmp_priv_t *priv,
                                const yaml_node_t *step, int idx)
{
    uint8_t code = 0;
    if (resolve_device(step, &code, NULL) != 0) {
        ctt_failf(run, idx, "map_check_words", "device required");
        return -1;
    }
    uint32_t head = (uint32_t)yaml_ulong(step, "head", 0);
    const char *ascii = yaml_cstr(step, "ascii", NULL);
    if (ascii && ascii[0]) {
        size_t n = strlen(ascii);
        uint8_t buf[128];
        int rc = slmp_stack_read_bytes(priv->stack, code, head, buf, n);
        if (ctt_check(run, idx, "map_check_words", rc == 0, "read_bytes rc=%d",
                      rc) != 0) {
            return -1;
        }
        return ctt_check(run, idx, "map_check_words", memcmp(buf, ascii, n) == 0,
                          "ascii mismatch");
    }
    uint16_t want[64];
    int n = load_u16s(step, "values", want, 64);
    if (n <= 0) {
        ctt_failf(run, idx, "map_check_words", "values required");
        return -1;
    }
    uint16_t got[128];
    int rc = slmp_stack_read_words(priv->stack, code, head, got, (uint16_t)n);
    if (ctt_check(run, idx, "map_check_words", rc == 0, "read_words rc=%d",
                  rc) != 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (ctt_check(run, idx, "map_check_words", got[i] == want[i],
                      "word[%u] want=0x%04X got=0x%04X", head + i, want[i],
                      got[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int step_map_check_bits(ctt_run_t *run, slmp_priv_t *priv,
                               const yaml_node_t *step, int idx)
{
    uint8_t code = 0;
    if (resolve_device(step, &code, NULL) != 0) {
        ctt_failf(run, idx, "map_check_bits", "device required");
        return -1;
    }
    uint32_t head = (uint32_t)yaml_ulong(step, "head", 0);
    uint8_t want[256];
    int n = load_u8s(step, "bits", want, 256);
    if (n <= 0) {
        ctt_failf(run, idx, "map_check_bits", "bits required");
        return -1;
    }
    uint8_t got[256];
    int rc = slmp_stack_read_bits(priv->stack, code, head, got, (uint16_t)n);
    if (ctt_check(run, idx, "map_check_bits", rc == 0, "read_bits rc=%d",
                  rc) != 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (ctt_check(run, idx, "map_check_bits", got[i] == want[i],
                      "bit[%d] want=%u got=%u", i, want[i], got[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int step_inject(ctt_run_t *run, slmp_priv_t *priv, const yaml_node_t *step,
                       int idx)
{
    uint8_t req[32];
    memset(req, 0, sizeof(req));
    uint16_t sub = (uint16_t)yaml_ulong(step, "subheader", SLMP_SUBHEADER_REQ_3E);
    wr_le16(req, sub);
    req[3] = 0xFF;
    wr_le16(req + 4, 0x03FF);
    wr_le16(req + 7, 12);
    wr_le16(req + 9, 0x0010);
    wr_le16(req + 11, (uint16_t)yaml_ulong(step, "cmd", SLMP_CMD_RANDOM_READ));
    wr_le16(req + 13, 0);
    req[18] = SLMP_DEV_D;
    wr_le16(req + 19, 1);
    uint8_t resp[64];
    size_t resp_len = 0;
    int rc = slmp_stack_handle_request(priv->stack, req, 21, resp, sizeof(resp),
                                     &resp_len);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *result = expect ? yaml_cstr(expect, "result", "ok") : "ok";
    if (strcmp(result, "reject") == 0) {
        return ctt_check(run, idx, "inject", rc != 0,
                          "expected reject rc=%d", rc);
    }
    if (ctt_check(run, idx, "inject", rc == 0, "handle rc=%d", rc) != 0) {
        return -1;
    }
    return check_end_and_values(run, idx, "inject", expect, resp, resp_len);
}

static int step_soak(ctt_run_t *run, slmp_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    slmp_range_t range;
    if (fill_range(step, &range) != 0) {
        range.addr.device_code = SLMP_DEV_D;
        range.addr.head = 0;
        range.addr.unit = SLMP_ACCESS_WORD;
        range.quantity = 1;
    }
    int iterations = (int)yaml_long(step, "iterations", 32);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    int min_ok = expect && yaml_has(expect, "min_ok")
                     ? (int)yaml_long(expect, "min_ok", iterations)
                     : iterations;
    unsigned ok = 0;
    unsigned unexpected = 0;
    uint64_t last_ns = 0;
    for (int i = 0; i < iterations; i++) {
        uint8_t req[64];
        size_t req_len = 0;
        if (slmp_encode_batch_read(&priv->cfg, &range, req, sizeof(req),
                                  &req_len) != 0) {
            unexpected++;
            continue;
        }
        uint8_t resp[SLMP_FRAME_MAX];
        size_t resp_len = 0;
        uint16_t end = 0xFFFF;
        const uint8_t *data = NULL;
        size_t dlen = 0;
        if (slmp_stack_handle_request(priv->stack, req, req_len, resp,
                                     sizeof(resp), &resp_len) != 0 ||
            slmp_decode_response(resp, resp_len, &end, &data, &dlen) != 0 ||
            end != SLMP_END_OK) {
            unexpected++;
            continue;
        }
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now = (uint64_t)ts.tv_sec * 1000000000ull +
                       (uint64_t)ts.tv_nsec;
        if (last_ns) {
            ctt_metrics_note_period(&run->metrics, now - last_ns);
        }
        last_ns = now;
        ok++;
        run->metrics.rtc1_frames++;
    }
    run->metrics.unexpected_frames += unexpected;
    return ctt_check(run, idx, "soak", (int)ok >= min_ok,
                     "ok=%u min_ok=%d unexpected=%u", ok, min_ok, unexpected);
}

static int slmp_setup(ctt_run_t *run)
{
    slmp_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv) {
        return -1;
    }
    const yaml_node_t *dev = yaml_map_get(run->root, "device");
    memset(&priv->cfg, 0, sizeof(priv->cfg));
    priv->cfg.role = SLMP_ROLE_SERVER;
    priv->cfg.frame = frame_from_str(
        dev ? yaml_cstr(dev, "frame", "3e_binary") : "3e_binary");
    priv->cfg.network_no =
        (uint8_t)(dev ? yaml_ulong(dev, "network_no", 0) : 0);
    priv->cfg.pc_no = (uint8_t)(dev ? yaml_ulong(dev, "pc_no", 0xFF) : 0xFF);
    priv->cfg.dest_module_io =
        (uint16_t)(dev ? yaml_ulong(dev, "dest_module_io", 0x03FF) : 0x03FF);
    priv->cfg.dest_multidrop =
        (uint8_t)(dev ? yaml_ulong(dev, "dest_multidrop", 0) : 0);
    priv->cfg.monitoring_timer =
        (uint16_t)(dev ? yaml_ulong(dev, "monitoring_timer", 0x0010) : 0x0010);
    priv->cfg.port = (int)(dev ? yaml_long(dev, "port", 5000) : 5000);
    if (priv->cfg.frame != SLMP_FRAME_3E_BINARY) {
        LOG_ERROR("ctt", "slmp DUT frame must be 3e_binary (got %d)",
                  (int)priv->cfg.frame);
        free(priv);
        return -1;
    }
    priv->stack = slmp_stack_create(&priv->cfg);
    if (!priv->stack) {
        LOG_ERROR("ctt", "slmp_stack_create failed");
        free(priv);
        return -1;
    }
    run->priv = priv;
    LOG_INFO("ctt", "slmp DUT Binary 3E server pc_no=0x%02X io=0x%04X",
             priv->cfg.pc_no, priv->cfg.dest_module_io);
    return 0;
}

static void slmp_teardown(ctt_run_t *run)
{
    slmp_priv_t *priv = run->priv;
    if (priv) {
        slmp_stack_destroy(priv->stack);
        free(priv);
        run->priv = NULL;
    }
}

static int slmp_step(ctt_run_t *run, const yaml_node_t *step, int index)
{
    slmp_priv_t *priv = run->priv;
    const char *action = yaml_cstr(step, "action", "");
    if (strcmp(action, "device_lookup") == 0) {
        return step_device_lookup(run, step, index);
    }
    if (strcmp(action, "create_stack") == 0) {
        return step_create_stack(run, priv, step, index);
    }
    if (strcmp(action, "encode_batch_read") == 0) {
        return step_encode_read(run, priv, step, index);
    }
    if (strcmp(action, "encode_batch_write") == 0) {
        return step_encode_write(run, priv, step, index);
    }
    if (strcmp(action, "seed_words") == 0) {
        return step_seed_words(run, priv, step, index);
    }
    if (strcmp(action, "seed_bits") == 0) {
        return step_seed_bits(run, priv, step, index);
    }
    if (strcmp(action, "batch_read") == 0) {
        return step_batch_read(run, priv, step, index);
    }
    if (strcmp(action, "batch_write") == 0) {
        return step_batch_write(run, priv, step, index);
    }
    if (strcmp(action, "map_check_words") == 0) {
        return step_map_check_words(run, priv, step, index);
    }
    if (strcmp(action, "map_check_bits") == 0) {
        return step_map_check_bits(run, priv, step, index);
    }
    if (strcmp(action, "inject") == 0) {
        return step_inject(run, priv, step, index);
    }
    if (strcmp(action, "soak") == 0) {
        return step_soak(run, priv, step, index);
    }
    ctt_failf(run, index, action,
              "unknown action (slmp Binary 3E: device_lookup, create_stack, "
              "encode_batch_read, encode_batch_write, seed_words, seed_bits, "
              "batch_read, batch_write, map_check_words, map_check_bits, "
              "inject, soak; 4E/ASCII not in scope)");
    return -1;
}

const ctt_plugin_t ctt_plugin_slmp = {
    .name = "slmp",
    .setup = slmp_setup,
    .step = slmp_step,
    .teardown = slmp_teardown,
};
