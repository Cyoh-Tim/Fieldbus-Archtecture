/* T4 + T12-15: after Connect, RTC1 uses the input IOCR period
 * (SendClockFactor × ReductionRatio × 31.25 µs), not cfg.cycle_us,
 * and CycleCounter advances by that same SCF×RR. The output CR clock
 * stays the data-hold clock and must not replace the input clock. */
#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;

static uint8_t g_tx[4][PN_FRAME_MAX];
static size_t g_txlen[4];
static int g_ntx;

static int cap_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (g_ntx < 4 && len <= sizeof(g_tx[0])) {
        memcpy(g_tx[g_ntx], frame, len);
        g_txlen[g_ntx] = len;
        g_ntx++;
    }
    return (int)len;
}

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void fill_aruuid(uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = (uint8_t)(0xA0 + i);
    }
}

static size_t wr_block(uint8_t *p, uint16_t type, const uint8_t *body,
                       uint16_t body_len)
{
    uint16_t blen = (uint16_t)(2 + body_len);
    pn_wr_be16(p, type);
    pn_wr_be16(p + 2, blen);
    p[4] = 1;
    p[5] = 0;
    memcpy(p + 6, body, body_len);
    size_t n = 4u + blen;
    if (n & 1u) {
        p[n++] = 0;
    }
    return n;
}

static size_t ndr_wrap(uint8_t *out, const uint8_t *blocks, size_t n)
{
    pn_wr_le32(out, (uint32_t)n);
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

static size_t wrap_rpc(uint8_t *out, const uint8_t *stub, size_t slen)
{
    memset(out, 0, 80);
    out[0] = 1;
    out[1] = 0;
    pn_wr_le16(out + 68, 0);
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t4-test");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.cycle_us = 8000;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    return s;
}

/* IOCRBlockReq body (after BlockVersion). SCF at +14, RR at +16.
 * DataLength 0 and no IODataObject list: the stack keeps cfg.input_len. */
static void fill_iocr(uint8_t body[18], uint16_t iocr_type, uint16_t frame_id,
                      uint16_t scf, uint16_t rr)
{
    memset(body, 0, 18);
    pn_wr_be16(body, iocr_type);
    pn_wr_be16(body + 2, iocr_type == PN_IOCR_INPUT ? 1 : 2);
    pn_wr_be16(body + 12, frame_id);
    pn_wr_be16(body + 14, scf);
    pn_wr_be16(body + 16, rr);
}

/* in_scf/in_rr 0 omits the input IOCR. out_scf/out_rr 0 omits the output. */
static size_t build_connect(uint8_t *pdu, uint16_t in_scf, uint16_t in_rr,
                            uint16_t out_scf, uint16_t out_rr)
{
    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[26];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));

    uint8_t iocr[18];
    if (in_scf != 0 && in_rr != 0) {
        fill_iocr(iocr, PN_IOCR_INPUT, 0x8001, in_scf, in_rr);
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr, sizeof(iocr));
    }
    if (out_scf != 0 && out_rr != 0) {
        fill_iocr(iocr, PN_IOCR_OUTPUT, 0x8002, out_scf, out_rr);
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr, sizeof(iocr));
    }
    uint8_t stub[384];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, stub, sn);
}

static int connect_ok(pn_stack_t *s, uint16_t in_scf, uint16_t in_rr,
                      uint16_t out_scf, uint16_t out_rr)
{
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu, in_scf, in_rr, out_scf, out_rr);
    g_ntx = 0;
    if (pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) !=
        0) {
        return 0;
    }
    return pn_stack_ar_up(s) == 1;
}

/* Legacy RTC1: eth(14) FrameID(2) data(input_len) IOPS(1) CycleCounter(2). */
static int frame_cc(const uint8_t *frame, size_t len, uint16_t *cc)
{
    size_t off = 14u + 2u + 32u + 1u;
    if (len < off + 2u) {
        return 0;
    }
    if (pn_rd_be16(frame + 12) != PN_ETHTYPE_PN) {
        return 0;
    }
    if (pn_rd_be16(frame + 14) != 0x8001) {
        return 0;
    }
    *cc = pn_rd_be16(frame + off);
    return 1;
}

/* next due is now+period. `before` is taken just before the send. */
static int due_is(const pn_stack_t *s, uint64_t before, uint64_t period_ns)
{
    if (s->last_rt_ns < before + period_ns) {
        return 0;
    }
    /* The send reads the clock once; allow 2 ms of scheduling slack. */
    return s->last_rt_ns <= before + period_ns + 2000000ull;
}

static void test_input_16ms_overrides_cfg_8ms(void)
{
    /* SCF 32 × RR 16 × 31.25 µs = 16 ms. cfg.cycle_us is 8 ms.
     * Output CR is a different clock (32 × 32 = 32 ms) and must stay
     * the watchdog clock. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "16ms create");
    expect(connect_ok(s, 32, 16, 32, 32), "16ms connect");
    expect(s->ar.in_send_clock_factor == 32 && s->ar.in_reduction_ratio == 16,
           "16ms input clock stored");
    expect(s->ar.send_clock_factor == 32 && s->ar.reduction_ratio == 32,
           "16ms output clock not replaced by input");

    uint64_t before = pn_now_ns();
    pn_rt_send_if_due(s);
    expect(g_ntx == 1, "16ms first RTC1");
    if (!due_is(s, before, 16000000ull)) {
        fprintf(stderr,
                "FAIL: 16ms next due delta %llu ns (want ~16000000, cfg is "
                "8000000)\n",
                (unsigned long long)(s->last_rt_ns > before ? s->last_rt_ns - before
                                                           : 0));
        g_fail = 1;
    }
    pn_rt_send_if_due(s);
    expect(g_ntx == 1, "16ms second poll is not due yet");

    uint16_t cc0 = 0;
    expect(g_ntx >= 1 && frame_cc(g_tx[0], g_txlen[0], &cc0), "16ms cc0");
    s->last_rt_ns = 0;
    pn_rt_send_if_due(s);
    uint16_t cc1 = 0;
    expect(g_ntx >= 2 && frame_cc(g_tx[1], g_txlen[1], &cc1), "16ms cc1");
    if (g_fail == 0 || (g_ntx >= 2)) {
        uint16_t step = (uint16_t)(cc1 - cc0);
        if (step != (uint16_t)(32u * 16u)) {
            fprintf(stderr,
                    "FAIL: 16ms CycleCounter step %u (want %u = SCF×RR)\n",
                    step, 32u * 16u);
            g_fail = 1;
        }
    }
    pn_stack_destroy(s);
}

static void test_cycle_counter_step_when_period_equals_cfg(void)
{
    /* 32 × 8 × 31.25 µs = 8 ms, same as cfg.cycle_us. The interval
     * matches either clock; the counter must still advance by SCF×RR. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "eq create");
    expect(connect_ok(s, 32, 8, 32, 8), "eq connect");
    pn_rt_send_if_due(s);
    uint16_t cc0 = 0;
    expect(g_ntx >= 1 && frame_cc(g_tx[0], g_txlen[0], &cc0), "eq cc0");
    s->last_rt_ns = 0;
    pn_rt_send_if_due(s);
    uint16_t cc1 = 0;
    expect(g_ntx >= 2 && frame_cc(g_tx[1], g_txlen[1], &cc1), "eq cc1");
    uint16_t step = (uint16_t)(cc1 - cc0);
    if (step != (uint16_t)(32u * 8u)) {
        fprintf(stderr, "FAIL: 8ms CycleCounter step %u (want %u = SCF×RR)\n",
                step, 32u * 8u);
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

static void test_output_clock_does_not_set_tx_period(void)
{
    /* No input IOCR. Output SCF×RR is 16 ms. TX stays on cfg.cycle_us
     * and CycleCounter stays +1 per frame. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "out-only create");
    expect(connect_ok(s, 0, 0, 32, 16), "out-only connect");
    expect(s->ar.send_clock_factor == 32 && s->ar.reduction_ratio == 16,
           "out-only output clock stored");

    uint64_t before = pn_now_ns();
    pn_rt_send_if_due(s);
    if (!due_is(s, before, 8000000ull)) {
        fprintf(stderr,
                "FAIL: out-only next due delta %llu ns (want ~8000000 from "
                "cfg.cycle_us)\n",
                (unsigned long long)(s->last_rt_ns > before ? s->last_rt_ns - before
                                                           : 0));
        g_fail = 1;
    }
    uint16_t cc0 = 0;
    expect(g_ntx >= 1 && frame_cc(g_tx[0], g_txlen[0], &cc0), "out-only cc0");
    s->last_rt_ns = 0;
    pn_rt_send_if_due(s);
    uint16_t cc1 = 0;
    expect(g_ntx >= 2 && frame_cc(g_tx[1], g_txlen[1], &cc1), "out-only cc1");
    uint16_t step = (uint16_t)(cc1 - cc0);
    if (step != 1) {
        fprintf(stderr, "FAIL: out-only CycleCounter step %u (want 1)\n", step);
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

int main(void)
{
    test_input_16ms_overrides_cfg_8ms();
    test_cycle_counter_step_when_period_equals_cfg();
    test_output_clock_does_not_set_tx_period();
    if (g_fail) {
        fprintf(stderr, "test_pn_t4: FAILED\n");
        return 1;
    }
    printf("test_pn_t4: ok\n");
    return 0;
}
