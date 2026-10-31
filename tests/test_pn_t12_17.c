/*
 * T12-17: a standard Release (opnum 1, ReleaseBlockReq 0x0114) must be
 * answered with ReleaseBlockRes 0x8114, ControlCommand Done (0x0008),
 * and the AR must drop so RTC1 stops. The pre-fix stack only accepts a
 * 0x0101 AR block and answers a real 0x0114 with -EPERM, leaving the AR
 * and RTC1 up until the activity timeout.
 *
 * Block layout matches scapy IODControlReq/IODControlRes (padding,
 * ARUUID, SessionKey, AlarmSequenceNumber, ControlCommand,
 * ControlBlockProperties). Oracle: test_release_standard_block.
 */
#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int g_fail;

static uint8_t g_tx[8][PN_FRAME_MAX];
static size_t g_txlen[8];
static int g_ntx;

static int capture_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (g_ntx < 8 && len <= PN_FRAME_MAX) {
        memcpy(g_tx[g_ntx], frame, len);
        g_txlen[g_ntx] = len;
    }
    g_ntx++;
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

static size_t wrap_rpc(uint8_t *out, uint16_t op, const uint8_t *stub,
                       size_t slen)
{
    memset(out, 0, 80);
    out[0] = 1;
    out[1] = 0;
    pn_wr_le16(out + 68, op);
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t12-17");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.cycle_us = 8000;
    return pn_stack_create(&cfg);
}

static size_t build_connect(uint8_t *pdu)
{
    uint8_t ar[2 + 16 + 2 + 6];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1); /* SessionKey */
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 0, stub, sn);
}

/* ReleaseBlockReq 0x0114. Same body as IODControlReq: pad, ARUUID,
 * SessionKey, AlarmSequenceNumber, ControlCommand=Release 0x0004. */
static size_t build_release(uint8_t *pdu, const uint8_t uuid[16])
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    memcpy(body + 2, uuid, 16);
    pn_wr_be16(body + 18, 1);
    pn_wr_be16(body + 22, 0x0004);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, 0x0114, body, sizeof(body));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 1, stub, sn);
}

static int frame_is_rtc1(const uint8_t *f, size_t n)
{
    size_t off = 12;
    if (n < 18) {
        return 0;
    }
    if (pn_rd_be16(f + 12) == 0x8100) {
        off = 16;
    }
    if (n < off + 4) {
        return 0;
    }
    if (pn_rd_be16(f + off) != PN_ETHTYPE_PN) {
        return 0;
    }
    uint16_t fid = pn_rd_be16(f + off + 2);
    return fid >= 0x8000 && fid <= 0xBFFF;
}

static int count_rtc1(void)
{
    int n = 0;
    int lim = g_ntx < 8 ? g_ntx : 8;
    for (int i = 0; i < lim; i++) {
        if (frame_is_rtc1(g_tx[i], g_txlen[i])) {
            n++;
        }
    }
    return n;
}

static void poll_rtc1(pn_stack_t *s)
{
    g_ntx = 0;
    s->last_rt_ns = 0;
    pn_stack_poll(s);
}

/* ReleaseBlockRes 0x8114: ARUUID, SessionKey, ControlCommand Done. */
static int release_res_ok(const uint8_t *resp, size_t rlen,
                          const uint8_t uuid[16])
{
    if (rlen < 80u + 20u + 32u) {
        fprintf(stderr, "FAIL: Release response short rlen=%zu\n", rlen);
        return 0;
    }
    const uint8_t *blk = resp + 100;
    uint16_t btype = pn_rd_be16(blk);
    uint16_t blen = pn_rd_be16(blk + 2);
    uint16_t session = pn_rd_be16(blk + 24);
    uint16_t cmd = pn_rd_be16(blk + 28);
    if (btype != 0x8114 || blen != 28 || memcmp(blk + 8, uuid, 16) != 0 ||
        session != 1 || cmd != PN_CONTROL_DONE) {
        fprintf(stderr,
                "FAIL: ReleaseBlockRes type=0x%04x len=%u session=%u "
                "cmd=0x%04x (want 0x8114 / 28 / 1 / Done 0x0008)\n",
                btype, blen, session, cmd);
        return 0;
    }
    return 1;
}

static void test_release_standard_block(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "create");
    if (!s) {
        return;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    expect(pn_stack_start(s) == 0, "start");

    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    uint8_t uuid[16];
    fill_aruuid(uuid);
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "connect");
    expect(pn_stack_ar_up(s) == 1, "ar up after connect");

    poll_rtc1(s);
    expect(count_rtc1() >= 1, "RTC1 while AR is up");

    uint8_t bad[16];
    fill_aruuid(bad);
    bad[0] ^= 0xff;
    plen = build_release(pdu, bad);
    rlen = 0;
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    if (rc != -EPERM) {
        fprintf(stderr, "FAIL: wrong-uuid Release rc=%d want -EPERM\n", rc);
        g_fail = 1;
    }
    expect(pn_stack_ar_up(s) == 1, "AR kept after wrong-uuid Release");

    plen = build_release(pdu, uuid);
    rlen = 0;
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099);
    if (rc != -EPERM) {
        fprintf(stderr, "FAIL: wrong-IP Release rc=%d want -EPERM\n", rc);
        g_fail = 1;
    }
    expect(pn_stack_ar_up(s) == 1, "AR kept after wrong-IP Release");

    rlen = 0;
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    if (rc != 0) {
        fprintf(stderr,
                "FAIL: standard Release(0x0114) rc=%d (want 0). "
                "AR still %s\n",
                rc, pn_stack_ar_up(s) ? "up" : "down");
        g_fail = 1;
    }
    if (!release_res_ok(resp, rlen, uuid)) {
        g_fail = 1;
    }
    expect(pn_stack_ar_up(s) == 0, "AR down after Release");

    poll_rtc1(s);
    int rtc = count_rtc1();
    if (rtc != 0) {
        fprintf(stderr, "FAIL: RTC1 still sent after Release (frames=%d)\n",
                rtc);
        g_fail = 1;
    }

    pn_stack_destroy(s);
}

int main(void)
{
    test_release_standard_block();
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_17: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_17: OK\n");
    return 0;
}
