#include "ctt.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logger.h"
#include "mb_stack.h"

typedef struct {
    mb_stack_t *stack;
    uint8_t unit_id;
    uint16_t next_tid;
} mb_priv_t;

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int fc_from_name(const char *s)
{
    if (!s || !s[0]) {
        return -1;
    }
    if (isdigit((unsigned char)s[0]) || (s[0] == '0' && s[1] == 'x')) {
        char *end = NULL;
        unsigned long v = strtoul(s, &end, 0);
        if (end && *end == '\0' && v <= 0xFF) {
            return (int)v;
        }
        return -1;
    }
    if (strcmp(s, "read_coils") == 0) {
        return MB_FC_READ_COILS;
    }
    if (strcmp(s, "read_discrete") == 0) {
        return MB_FC_READ_DISCRETE;
    }
    if (strcmp(s, "read_holding") == 0) {
        return MB_FC_READ_HOLDING;
    }
    if (strcmp(s, "read_input") == 0) {
        return MB_FC_READ_INPUT;
    }
    if (strcmp(s, "write_single_coil") == 0) {
        return MB_FC_WRITE_SINGLE_COIL;
    }
    if (strcmp(s, "write_single_reg") == 0) {
        return MB_FC_WRITE_SINGLE_REG;
    }
    if (strcmp(s, "write_multi_coils") == 0) {
        return MB_FC_WRITE_MULTI_COILS;
    }
    if (strcmp(s, "write_multi_regs") == 0) {
        return MB_FC_WRITE_MULTI_REGS;
    }
    if (strcmp(s, "mask_write") == 0) {
        return MB_FC_MASK_WRITE_REG;
    }
    if (strcmp(s, "read_write_regs") == 0) {
        return MB_FC_READ_WRITE_REGS;
    }
    return -1;
}

static int yaml_fc(const yaml_node_t *map, const char *key, int def)
{
    const char *s = yaml_cstr(map, key, NULL);
    if (!s) {
        return def;
    }
    int fc = fc_from_name(s);
    return fc >= 0 ? fc : def;
}

static mb_reg_type_t type_from_str(const char *s)
{
    if (!s) {
        return MB_REG_HOLDING;
    }
    if (strcmp(s, "input") == 0) {
        return MB_REG_INPUT;
    }
    if (strcmp(s, "coil") == 0 || strcmp(s, "coils") == 0) {
        return MB_REG_COIL;
    }
    if (strcmp(s, "discrete") == 0) {
        return MB_REG_DISCRETE;
    }
    return MB_REG_HOLDING;
}

static int is_bit_type(mb_reg_type_t t)
{
    return t == MB_REG_COIL || t == MB_REG_DISCRETE;
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

static int seed_map(ctt_run_t *run, mb_priv_t *priv, const yaml_node_t *step,
                    int idx)
{
    const char *tname = yaml_cstr(step, "type", "holding");
    mb_reg_type_t t = type_from_str(tname);
    uint16_t addr = (uint16_t)yaml_ulong(step, "address", 0);
    const char *ascii = yaml_cstr(step, "ascii", NULL);
    if (ascii && ascii[0]) {
        int rc = mb_stack_write_bytes(priv->stack, t, addr,
                                      (const uint8_t *)ascii, strlen(ascii));
        return ctt_check(run, idx, "seed", rc == 0,
                          "seed ascii type=%s addr=%u rc=%d", tname, addr,
                          rc);
    }
    if (is_bit_type(t)) {
        uint8_t bits[256];
        int n = load_u8s(step, "bits", bits, 256);
        if (n <= 0) {
            ctt_failf(run, idx, "seed", "bits: list required for coil/discrete");
            return -1;
        }
        int rc = mb_stack_write_bits(priv->stack, t, addr, bits, (uint16_t)n);
        return ctt_check(run, idx, "seed", rc == 0,
                          "seed bits type=%s addr=%u n=%d rc=%d", tname, addr,
                          n, rc);
    }
    uint16_t vals[128];
    int n = load_u16s(step, "values", vals, 128);
    if (n <= 0) {
        ctt_failf(run, idx, "seed", "values: list required");
        return -1;
    }
    int rc = mb_stack_write_regs(priv->stack, t, addr, vals, (uint16_t)n);
    return ctt_check(run, idx, "seed", rc == 0,
                      "seed regs type=%s addr=%u n=%d rc=%d", tname, addr, n,
                      rc);
}

static int map_check(ctt_run_t *run, mb_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    const char *tname = yaml_cstr(step, "type", "holding");
    mb_reg_type_t t = type_from_str(tname);
    uint16_t addr = (uint16_t)yaml_ulong(step, "address", 0);
    const char *ascii = yaml_cstr(step, "ascii", NULL);
    if (ascii && ascii[0]) {
        size_t n = strlen(ascii);
        uint8_t buf[128];
        if (n > sizeof(buf)) {
            ctt_failf(run, idx, "map_check", "ascii too long");
            return -1;
        }
        int rc = mb_stack_read_bytes(priv->stack, t, addr, buf, n);
        if (ctt_check(run, idx, "map_check", rc == 0, "read_bytes rc=%d",
                      rc) != 0) {
            return -1;
        }
        return ctt_check(run, idx, "map_check", memcmp(buf, ascii, n) == 0,
                          "ascii mismatch");
    }
    if (is_bit_type(t)) {
        uint8_t want[256];
        int n = load_u8s(step, "bits", want, 256);
        if (n <= 0) {
            ctt_failf(run, idx, "map_check", "bits: list required");
            return -1;
        }
        uint8_t got[256];
        int rc = mb_stack_read_bits(priv->stack, t, addr, got, (uint16_t)n);
        if (ctt_check(run, idx, "map_check", rc == 0, "read_bits rc=%d",
                      rc) != 0) {
            return -1;
        }
        for (int i = 0; i < n; i++) {
            if (ctt_check(run, idx, "map_check", got[i] == want[i],
                          "bit[%d] want=%u got=%u", i, want[i], got[i]) != 0) {
                return -1;
            }
        }
        return 0;
    }
    uint16_t want[128];
    int n = load_u16s(step, "values", want, 128);
    if (n <= 0) {
        ctt_failf(run, idx, "map_check", "values: list required");
        return -1;
    }
    uint16_t got[128];
    int rc = mb_stack_read_regs(priv->stack, t, addr, got, (uint16_t)n);
    if (ctt_check(run, idx, "map_check", rc == 0, "read_regs rc=%d", rc) != 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (ctt_check(run, idx, "map_check", got[i] == want[i],
                      "reg[%u] want=0x%04X got=0x%04X", addr + i, want[i],
                      got[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int build_request(mb_priv_t *priv, const yaml_node_t *step, uint8_t *req,
                         size_t cap, size_t *out_len)
{
    int fc = yaml_fc(step, "fc", -1);
    if (fc < 0) {
        return -EINVAL;
    }
    uint16_t tid = (uint16_t)yaml_ulong(step, "tid", priv->next_tid);
    priv->next_tid = (uint16_t)(tid + 1);
    uint8_t unit = (uint8_t)yaml_ulong(step, "unit_id", priv->unit_id);
    uint16_t addr = (uint16_t)yaml_ulong(step, "address", 0);
    uint16_t qty = (uint16_t)yaml_ulong(step, "quantity", 1);
    uint8_t pdu[MB_PDU_MAX];
    size_t pdu_len = 0;

    switch (fc) {
    case MB_FC_READ_COILS:
    case MB_FC_READ_DISCRETE:
    case MB_FC_READ_HOLDING:
    case MB_FC_READ_INPUT:
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, qty);
        pdu_len = 5;
        break;
    case MB_FC_WRITE_SINGLE_COIL:
    case MB_FC_WRITE_SINGLE_REG:
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, (uint16_t)yaml_ulong(step, "value", 0));
        pdu_len = 5;
        break;
    case MB_FC_WRITE_MULTI_COILS: {
        uint8_t bits[256];
        int n = load_u8s(step, "bits", bits, 256);
        if (n <= 0) {
            return -EINVAL;
        }
        qty = (uint16_t)n;
        uint8_t nbytes = (uint8_t)((qty + 7) / 8);
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, qty);
        pdu[5] = nbytes;
        memset(pdu + 6, 0, nbytes);
        for (uint16_t i = 0; i < qty; i++) {
            if (bits[i]) {
                pdu[6 + i / 8] |= (uint8_t)(1u << (i % 8));
            }
        }
        pdu_len = 6u + nbytes;
        break;
    }
    case MB_FC_WRITE_MULTI_REGS: {
        uint16_t vals[123];
        int n = load_u16s(step, "values", vals, 123);
        if (n <= 0) {
            return -EINVAL;
        }
        qty = (uint16_t)n;
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, qty);
        pdu[5] = (uint8_t)(qty * 2);
        for (int i = 0; i < n; i++) {
            wr_be16(pdu + 6 + i * 2, vals[i]);
        }
        pdu_len = 6u + (size_t)qty * 2u;
        break;
    }
    case MB_FC_MASK_WRITE_REG:
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, (uint16_t)yaml_ulong(step, "and_mask", 0));
        wr_be16(pdu + 5, (uint16_t)yaml_ulong(step, "or_mask", 0));
        pdu_len = 7;
        break;
    case MB_FC_READ_WRITE_REGS: {
        uint16_t raddr = (uint16_t)yaml_ulong(step, "read_address", addr);
        uint16_t rqty = (uint16_t)yaml_ulong(step, "read_quantity", qty);
        uint16_t waddr = (uint16_t)yaml_ulong(step, "write_address", 0);
        uint16_t vals[121];
        int n = load_u16s(step, "values", vals, 121);
        if (n <= 0) {
            return -EINVAL;
        }
        uint16_t wqty = (uint16_t)n;
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, raddr);
        wr_be16(pdu + 3, rqty);
        wr_be16(pdu + 5, waddr);
        wr_be16(pdu + 7, wqty);
        pdu[9] = (uint8_t)(wqty * 2);
        for (int i = 0; i < n; i++) {
            wr_be16(pdu + 10 + i * 2, vals[i]);
        }
        pdu_len = 10u + (size_t)wqty * 2u;
        break;
    }
    default:
        /* Illegal / unknown FC: still emit a 5-byte style PDU so DUT can
         * return exception illegal function. */
        pdu[0] = (uint8_t)fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, qty);
        pdu_len = 5;
        break;
    }

    size_t total = MB_MBAP_LEN + pdu_len;
    if (total > cap) {
        return -ENOSPC;
    }
    wr_be16(req, tid);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, (uint16_t)(1 + pdu_len));
    req[6] = unit;
    memcpy(req + 7, pdu, pdu_len);
    *out_len = total;
    return 0;
}

static int check_response(ctt_run_t *run, int idx, const char *action,
                           const yaml_node_t *expect, const uint8_t *resp,
                           size_t resp_len)
{
    if (!expect) {
        return 0;
    }
    int want_none = yaml_bool(expect, "no_response", 0);
    if (want_none) {
        return ctt_check(run, idx, action, resp_len == 0,
                          "expected no ADU, got len=%zu", resp_len);
    }
    if (ctt_check(run, idx, action, resp_len >= 9,
                  "short ADU len=%zu", resp_len) != 0) {
        return -1;
    }
    uint8_t fc = resp[7];
    int exception = yaml_bool(expect, "exception", 0) || (fc & 0x80);
    if (yaml_has(expect, "exception")) {
        int want_ex = yaml_bool(expect, "exception", 0);
        if (ctt_check(run, idx, action, ((fc & 0x80) != 0) == want_ex,
                      "exception flag want=%d fc=0x%02X", want_ex, fc) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "fc")) {
        int want_fc = yaml_fc(expect, "fc", -1);
        if (ctt_check(run, idx, action, want_fc >= 0 && fc == (uint8_t)want_fc,
                      "fc want=0x%02X got=0x%02X", want_fc, fc) != 0) {
            return -1;
        }
    }
    if (exception && yaml_has(expect, "exception_code")) {
        uint8_t code = resp[8];
        unsigned long want = yaml_ulong(expect, "exception_code", 0);
        return ctt_check(run, idx, action, code == (uint8_t)want,
                          "exception_code want=0x%02lX got=0x%02X", want, code);
    }
    if (yaml_has(expect, "byte_count") && resp_len > 8) {
        unsigned long want = yaml_ulong(expect, "byte_count", 0);
        if (ctt_check(run, idx, action, resp[8] == (uint8_t)want,
                      "byte_count want=%lu got=%u", want, resp[8]) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "length")) {
        unsigned long want = yaml_ulong(expect, "length", 0);
        if (ctt_check(run, idx, action, resp_len == want,
                      "len want=%lu got=%zu", want, resp_len) != 0) {
            return -1;
        }
    }
    if (yaml_has(expect, "values") && resp_len > 9 && !(fc & 0x80)) {
        uint16_t want[128];
        int n = load_u16s(expect, "values", want, 128);
        if (n < 0) {
            ctt_failf(run, idx, action, "bad expect.values");
            return -1;
        }
        uint8_t bc = resp[8];
        if (ctt_check(run, idx, action, (size_t)bc >= (size_t)n * 2u &&
                                           resp_len >= 9u + (size_t)n * 2u,
                      "payload short bc=%u n=%d", bc, n) != 0) {
            return -1;
        }
        for (int i = 0; i < n; i++) {
            uint16_t got = rd_be16(resp + 9 + i * 2);
            if (ctt_check(run, idx, action, got == want[i],
                          "value[%d] want=0x%04X got=0x%04X", i, want[i],
                          got) != 0) {
                return -1;
            }
        }
    }
    if (yaml_has(expect, "bits") && resp_len > 9 && !(fc & 0x80)) {
        uint8_t want[256];
        int n = load_u8s(expect, "bits", want, 256);
        if (n < 0) {
            ctt_failf(run, idx, action, "bad expect.bits");
            return -1;
        }
        for (int i = 0; i < n; i++) {
            int bit = (resp[9 + i / 8] >> (i % 8)) & 1;
            if (ctt_check(run, idx, action, bit == want[i],
                          "bit[%d] want=%u got=%d", i, want[i], bit) != 0) {
                return -1;
            }
        }
    }
    if (yaml_has(expect, "ascii") && resp_len > 9 && !(fc & 0x80)) {
        const char *ascii = yaml_cstr(expect, "ascii", "");
        size_t n = strlen(ascii);
        if (ctt_check(run, idx, action, resp[8] >= n && resp_len >= 9 + n,
                      "ascii payload short") != 0) {
            return -1;
        }
        return ctt_check(run, idx, action, memcmp(resp + 9, ascii, n) == 0,
                          "ascii mismatch");
    }
    return 0;
}

static int do_request(ctt_run_t *run, mb_priv_t *priv, const yaml_node_t *step,
                      int idx, const char *action)
{
    uint8_t req[MB_ADU_MAX];
    size_t req_len = 0;
    if (build_request(priv, step, req, sizeof(req), &req_len) != 0) {
        ctt_failf(run, idx, action, "failed to assemble ADU (fc/values)");
        return -1;
    }
    uint8_t resp[MB_ADU_MAX];
    size_t resp_len = 0;
    int rc = mb_stack_handle_adu(priv->stack, req, req_len, resp, sizeof(resp),
                                  &resp_len);
    if (ctt_check(run, idx, action, rc == 0, "handle_adu rc=%d", rc) != 0) {
        return -1;
    }
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    return check_response(run, idx, action, expect, resp, resp_len);
}

static int step_soak(ctt_run_t *run, mb_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    int iterations = (int)yaml_long(step, "iterations", 32);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    int min_ok = expect && yaml_has(expect, "min_ok")
                     ? (int)yaml_long(expect, "min_ok", iterations)
                     : iterations;
    unsigned unexpected = 0;
    unsigned ok = 0;
    uint64_t last_ns = 0;
    for (int i = 0; i < iterations; i++) {
        uint8_t req[MB_ADU_MAX];
        size_t req_len = 0;
        if (build_request(priv, step, req, sizeof(req), &req_len) != 0) {
            unexpected++;
            continue;
        }
        uint8_t resp[MB_ADU_MAX];
        size_t resp_len = 0;
        int rc = mb_stack_handle_adu(priv->stack, req, req_len, resp,
                                      sizeof(resp), &resp_len);
        if (rc != 0 || resp_len < 9 || (resp[7] & 0x80)) {
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
        run->metrics.rtc1_frames++; /* reuse counter: successful PDUs */
    }
    run->metrics.unexpected_frames += unexpected;
    if (ctt_check(run, idx, "soak", (int)ok >= min_ok,
                  "ok=%u min_ok=%d unexpected=%u", ok, min_ok,
                  unexpected) != 0) {
        return -1;
    }
    if (expect && yaml_has(expect, "unexpected_frames")) {
        unsigned want = (unsigned)yaml_ulong(expect, "unexpected_frames", 0);
        return ctt_check(run, idx, "soak", unexpected == want,
                          "unexpected want=%u got=%u", want, unexpected);
    }
    return 0;
}

static int mb_setup(ctt_run_t *run)
{
    mb_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv) {
        return -1;
    }
    const yaml_node_t *dev = yaml_map_get(run->root, "device");
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = (int)(dev ? yaml_long(dev, "unit_id", 1) : 1);
    cfg.unit_id_any = dev ? yaml_bool(dev, "unit_id_any", 0) : 0;
    cfg.n_holding = (uint16_t)(dev ? yaml_ulong(dev, "n_holding", 64) : 64);
    cfg.n_input = (uint16_t)(dev ? yaml_ulong(dev, "n_input", 64) : 64);
    cfg.n_coil = (uint16_t)(dev ? yaml_ulong(dev, "n_coil", 64) : 64);
    cfg.n_discrete =
        (uint16_t)(dev ? yaml_ulong(dev, "n_discrete", 64) : 64);
    if (dev && yaml_has(dev, "port")) {
        cfg.port = (int)yaml_long(dev, "port", 1502);
    } else {
        cfg.port = 1502;
    }
    priv->stack = mb_stack_create(&cfg);
    if (!priv->stack) {
        LOG_ERROR("ctt", "mb_stack_create failed");
        free(priv);
        return -1;
    }
    priv->unit_id = (uint8_t)cfg.unit_id;
    priv->next_tid = 1;
    run->priv = priv;
    LOG_INFO("ctt", "modbus_tcp DUT server unit_id=%d maps H=%u I=%u C=%u D=%u",
             cfg.unit_id, cfg.n_holding, cfg.n_input, cfg.n_coil,
             cfg.n_discrete);
    return 0;
}

static void mb_teardown(ctt_run_t *run)
{
    mb_priv_t *priv = run->priv;
    if (priv) {
        mb_stack_destroy(priv->stack);
        free(priv);
        run->priv = NULL;
    }
}

static int mb_step(ctt_run_t *run, const yaml_node_t *step, int index)
{
    mb_priv_t *priv = run->priv;
    const char *action = yaml_cstr(step, "action", "");
    if (strcmp(action, "seed") == 0) {
        return seed_map(run, priv, step, index);
    }
    if (strcmp(action, "map_check") == 0) {
        return map_check(run, priv, step, index);
    }
    if (strcmp(action, "request") == 0) {
        return do_request(run, priv, step, index, action);
    }
    if (strcmp(action, "soak") == 0) {
        return step_soak(run, priv, step, index);
    }
    ctt_failf(run, index, action,
              "unknown action (modbus_tcp: seed, request, map_check, soak)");
    return -1;
}

const ctt_plugin_t ctt_plugin_modbus_tcp = {
    .name = "modbus_tcp",
    .setup = mb_setup,
    .step = mb_step,
    .teardown = mb_teardown,
};
