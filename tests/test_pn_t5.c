/* T5 (PN): Connect rejects an input IOCR faster than cfg.cycle_us.
 *
 * cfg.cycle_us is the fastest update this device can produce. The input
 * IOCR period is SendClockFactor × ReductionRatio × 31.25 µs.
 *
 * RT Class 1 checks follow p-net pf_cmdev_check_iocr_param and
 * pf_cmdev_check_iocr_param_full, and apply to the input IOCR only:
 * - SCF not in {1,2,4,8,16,32,64,128} → PNIOStatus DB 81 02 0A
 *   (ErrorCode2 10, GatingCycle / SendClockFactor).
 * - RR outside 1..512, or RR >= 256 with SCF > 64, or RR == 512 with
 *   SCF > 32 → DB 81 02 0B (ErrorCode2 11, ReductionRatio).
 * - Otherwise, if SCF×RR×31.25 µs < cycle_us → DB 81 02 0B.
 * ReductionRatio need not be a power of two. A SendClock that is in the
 * set above is legal even when GSDML advertises only 32. Output IOCR
 * timing is not a reject. No input IOCR is not a short-cycle request.
 *
 * PNIOStatus is the little-endian NDR integer
 * ErrorCode<<24 | ErrorDecode<<16 | ErrorCode1<<8 | ErrorCode2.
 * Logical DB 81 02 0B is therefore the bytes 0B 02 81 DB.
 */
#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;

static uint8_t g_tx[PN_FRAME_MAX];
static size_t g_txlen;
static int g_ntx;

static int capture_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (len <= PN_FRAME_MAX) {
        memcpy(g_tx, frame, len);
        g_txlen = len;
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

static void expect_u32(uint32_t got, uint32_t want, const char *msg)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s (got 0x%08x want 0x%08x)\n", msg, got, want);
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
    out[4] = 0x10; /* drep: little-endian integers */
    pn_wr_le16(out + 68, 0);
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

/* in_present/out_present: include that IOCR. sc/rr are SendClockFactor
 * and ReductionRatio. */
static size_t build_connect(uint8_t *pdu, int in_present, uint16_t in_sc,
                            uint16_t in_rr, int out_present, uint16_t out_sc,
                            uint16_t out_rr)
{
    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[26];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));

    if (out_present) {
        uint8_t outb[18];
        memset(outb, 0, sizeof(outb));
        pn_wr_be16(outb, PN_IOCR_OUTPUT);
        pn_wr_be16(outb + 12, 0x8002);
        pn_wr_be16(outb + 14, out_sc);
        pn_wr_be16(outb + 16, out_rr);
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, outb, sizeof(outb));
    }
    if (in_present) {
        uint8_t inb[18];
        memset(inb, 0, sizeof(inb));
        pn_wr_be16(inb, PN_IOCR_INPUT);
        pn_wr_be16(inb + 12, 0x8001);
        pn_wr_be16(inb + 14, in_sc);
        pn_wr_be16(inb + 16, in_rr);
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, inb, sizeof(inb));
    }
    uint8_t stub[384];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, stub, sn);
}

static pn_stack_t *make_stack(uint32_t cycle_us)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t5");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.cycle_us = cycle_us;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    return s;
}

static void expect_reject(pn_stack_t *s, const uint8_t *resp, size_t rlen,
                          uint32_t want, const char *msg)
{
    expect(rlen == 100, "reject rsp is 80-byte RPC + 20-byte NDR");
    const uint8_t *stub = resp + 80;
    expect_u32(pn_rd_le32(stub), want, msg);
    expect_u32(pn_rd_le32(stub + 4), 0, "reject ArgsLength");
    expect_u32(pn_rd_le32(stub + 8), 0, "reject MaxCount");
    expect_u32(pn_rd_le32(stub + 12), 0, "reject Offset");
    expect_u32(pn_rd_le32(stub + 16), 0, "reject ActualCount");
    expect(pn_stack_ar_up(s) == 0, "rejected Connect did not establish an AR");
    g_ntx = 0;
    pn_rt_send_if_due(s);
    expect(g_ntx == 0, "rejected Connect sent RTC1");
}

static int connect_rpc(pn_stack_t *s, int in_present, uint16_t in_sc,
                       uint16_t in_rr, int out_present, uint16_t out_sc,
                       uint16_t out_rr, uint8_t *resp, size_t *rlen)
{
    uint8_t pdu[512];
    size_t plen =
        build_connect(pdu, in_present, in_sc, in_rr, out_present, out_sc, out_rr);
    return pn_rpc_handle(s, pdu, plen, resp, 1024, rlen, 0x0a000001);
}

/* 8 ms device, input SCF=32 RR=4 → 4 ms. Oracle case. */
static void test_reject_4ms_on_8ms_device(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "4ms create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 4, 1, 32, 4, resp, &rlen) == 0, "4ms connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Bu, "4ms PNIOStatus DB 81 02 0B");
    pn_stack_destroy(s);
}

/* Equal to the minimum is allowed: SCF=32 RR=8 → 8 ms. */
static void test_accept_period_equal_to_minimum(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "eq create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 8, 1, 32, 16, resp, &rlen) == 0,
           "eq connect rpc");
    expect(pn_stack_ar_up(s) == 1, "8ms input accepted");
    expect_u32(pn_rd_le32(resp + 80), 0, "eq PNIOStatus OK");
    expect(s->ar.send_clock_factor == 32 && s->ar.reduction_ratio == 16,
           "output clock still stored for data-hold");
    pn_stack_destroy(s);
}

/* A 4 ms device may accept SCF=32 RR=4. cycle_us is the floor. */
static void test_accept_4ms_when_cycle_us_is_4ms(void)
{
    pn_stack_t *s = make_stack(4000);
    expect(s != NULL, "fast create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 4, 1, 32, 4, resp, &rlen) == 0,
           "fast connect rpc");
    expect(pn_stack_ar_up(s) == 1, "4ms accepted when cycle_us is 4000");
    pn_stack_destroy(s);
}

/* SCF outside {1,2,4,...,128} is ErrorCode2 10, even when the period
 * is at least cycle_us. 48 × 8 × 31.25 µs = 12 ms. */
static void test_reject_scf_not_in_rt_class_1_set(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "scf create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 48, 8, 1, 32, 16, resp, &rlen) == 0,
           "scf connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Au, "bad SCF PNIOStatus DB 81 02 0A");
    pn_stack_destroy(s);
}

/* 256 is a power of two but past 128. 256 × 1 × 31.25 µs = 8 ms, so
 * only the SendClockFactor rule applies. */
static void test_reject_scf_above_128(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "scf128 create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 256, 1, 1, 32, 16, resp, &rlen) == 0,
           "scf128 connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Au, "SCF 256 PNIOStatus DB 81 02 0A");
    pn_stack_destroy(s);
}

/* SCF=64 is in the RT Class 1 set. GSDML advertises SendClock 32, but
 * that advertisement is not an extra reject. 64 × 4 × 31.25 µs = 8 ms. */
static void test_accept_scf_64_at_minimum(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "scf64 create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 64, 4, 1, 32, 16, resp, &rlen) == 0,
           "scf64 connect rpc");
    expect(pn_stack_ar_up(s) == 1, "SCF 64 at cycle_us accepted");
    expect_u32(pn_rd_le32(resp + 80), 0, "scf64 PNIOStatus OK");
    pn_stack_destroy(s);
}

/* RR need not be a power of two. 32 × 24 × 31.25 µs = 24 ms. */
static void test_accept_non_power_of_two_rr(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "rr create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 24, 1, 32, 16, resp, &rlen) == 0,
           "rr connect rpc");
    expect(pn_stack_ar_up(s) == 1, "non-pow2 RR 24 accepted");
    expect_u32(pn_rd_le32(resp + 80), 0, "non-pow2 PNIOStatus OK");
    pn_stack_destroy(s);
}

/* RR above 512 is ReductionRatio even when the period is long.
 * 32 × 1024 × 31.25 µs = 1024 ms. */
static void test_reject_rr_above_512(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "rr512 create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 1024, 1, 32, 16, resp, &rlen) == 0,
           "rr512 connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Bu, "RR 1024 PNIOStatus DB 81 02 0B");
    pn_stack_destroy(s);
}

/* RR == 0 is outside 1..512. */
static void test_reject_rr_zero(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "rr0 create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 0, 1, 32, 16, resp, &rlen) == 0,
           "rr0 connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Bu, "RR 0 PNIOStatus DB 81 02 0B");
    pn_stack_destroy(s);
}

/* p-net: RR >= 256 requires SCF <= 64. 128 × 256 × 31.25 µs = 1024 ms. */
static void test_reject_rr_256_scf_above_64(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "rr256 create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 128, 256, 1, 32, 16, resp, &rlen) == 0,
           "rr256 connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Bu,
                  "RR 256 SCF 128 PNIOStatus DB 81 02 0B");
    pn_stack_destroy(s);
}

/* p-net: RR == 512 requires SCF <= 32. 64 × 512 × 31.25 µs = 1024 ms. */
static void test_reject_rr_512_scf_above_32(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "rr512scf create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 64, 512, 1, 32, 16, resp, &rlen) == 0,
           "rr512scf connect rpc");
    expect_reject(s, resp, rlen, 0xDB81020Bu,
                  "RR 512 SCF 64 PNIOStatus DB 81 02 0B");
    pn_stack_destroy(s);
}

/* The legal corner: RR=512 and SCF=32. 32 × 512 × 31.25 µs = 512 ms. */
static void test_accept_rr_512_scf_32(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "rrmax create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 512, 1, 32, 16, resp, &rlen) == 0,
           "rrmax connect rpc");
    expect(pn_stack_ar_up(s) == 1, "RR 512 SCF 32 accepted");
    pn_stack_destroy(s);
}

/* Only the input IOCR is limited by cycle_us. A short output CR with a
 * legal input CR is still accepted; data-hold keeps the output clock. */
static void test_short_output_cr_does_not_reject(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "out create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 16, 1, 32, 4, resp, &rlen) == 0,
           "out connect rpc");
    expect(pn_stack_ar_up(s) == 1, "short output CR accepted");
    expect(s->ar.send_clock_factor == 32 && s->ar.reduction_ratio == 4,
           "output clock stored");
    pn_stack_destroy(s);
}

/* No input IOCR (CTT Connect is AR-only) is not a short-cycle request. */
static void test_no_input_iocr_still_connects(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "none create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 0, 0, 0, 0, 0, 0, resp, &rlen) == 0,
           "none connect rpc");
    expect(pn_stack_ar_up(s) == 1, "AR-only Connect accepted");
    pn_stack_destroy(s);
}

/* A rejected short cycle must not replace an AR that is already up. */
static void test_reject_keeps_established_ar(void)
{
    pn_stack_t *s = make_stack(8000);
    expect(s != NULL, "keep create");
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(connect_rpc(s, 1, 32, 16, 1, 32, 16, resp, &rlen) == 0,
           "keep first rpc");
    expect(pn_stack_ar_up(s) == 1, "keep ar up");
    uint16_t rr = s->ar.reduction_ratio;

    rlen = 0;
    expect(connect_rpc(s, 1, 32, 4, 1, 32, 4, resp, &rlen) == 0,
           "keep short rpc");
    expect_u32(pn_rd_le32(resp + 80), 0xDB81020Bu, "keep short status");
    expect(pn_stack_ar_up(s) == 1, "keep ar still up");
    expect(s->ar.reduction_ratio == rr, "keep output clock unchanged");
    expect(s->ar.owner_ip == 0x0a000001, "keep owner");
    pn_stack_destroy(s);
}

int main(void)
{
    test_reject_4ms_on_8ms_device();
    test_accept_period_equal_to_minimum();
    test_accept_4ms_when_cycle_us_is_4ms();
    test_reject_scf_not_in_rt_class_1_set();
    test_reject_scf_above_128();
    test_accept_scf_64_at_minimum();
    test_accept_non_power_of_two_rr();
    test_reject_rr_above_512();
    test_reject_rr_zero();
    test_reject_rr_256_scf_above_64();
    test_reject_rr_512_scf_above_32();
    test_accept_rr_512_scf_32();
    test_short_output_cr_does_not_reject();
    test_no_input_iocr_still_connects();
    test_reject_keeps_established_ar();
    if (g_fail) {
        fprintf(stderr, "test_pn_t5: FAILED\n");
        return 1;
    }
    printf("test_pn_t5: OK\n");
    return 0;
}
