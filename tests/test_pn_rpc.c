#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int g_fail;

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
    snprintf(cfg.station_name, sizeof(cfg.station_name), "rpc-test");
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
    pn_wr_be16(ar + 18, 1);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 0, stub, sn);
}

static void test_write_short_block(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "pn create");

    uint8_t pdu[512];
    size_t plen = build_connect(pdu);
    uint8_t resp[1024];
    size_t rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "connect");
    expect(pn_stack_ar_up(s) == 1, "ar up");

    uint8_t rec_before[64];
    size_t rec_before_n = 0;
    pn_record_read(s, 0, 1, PN_INDEX_IM1, rec_before, sizeof(rec_before),
                   &rec_before_n);

    /* IODWriteReq body_len=30: old code read body+30..33 (OOB). */
    uint8_t short_body[30];
    memset(short_body, 0, sizeof(short_body));
    pn_wr_be16(short_body, 1);
    fill_aruuid(short_body + 2);
    pn_wr_be16(short_body + 22, 0);
    pn_wr_be16(short_body + 24, 1);
    pn_wr_be16(short_body + 28, PN_INDEX_IM1);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_IOD_WRITE_REQ, short_body, 30);
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 3, stub, sn);
    rlen = 0;
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc != 0, "short write rejected");
    uint8_t rec[64];
    size_t rec_n = 0;
    pn_record_read(s, 0, 1, PN_INDEX_IM1, rec, sizeof(rec), &rec_n);
    expect(rec_n == rec_before_n && memcmp(rec, rec_before, rec_n) == 0,
           "short write did not store payload");
    pn_stack_destroy(s);
}

static void test_ar_ownership(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "pn create2");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "first connect");
    expect(pn_stack_ar_up(s) == 1, "ar up first");

    /* Second Connect while AR is up: reject, keep first AR. */
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000002) ==
               0,
           "second connect rpc");
    expect(pn_stack_ar_up(s) == 1, "ar still up after second connect");

    /* Control from wrong IP */
    uint8_t cbody[26];
    memset(cbody, 0, sizeof(cbody));
    fill_aruuid(cbody + 2);
    pn_wr_be16(cbody + 22, PN_CONTROL_PRM_END);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, cbody, sizeof(cbody));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 4, stub, sn);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099) ==
               -EPERM,
           "control wrong IP");
    expect(pn_stack_app_ready(s) == 0, "no app ready after wrong IP");

    /* Control with wrong UUID from owner IP */
    memset(cbody, 0, sizeof(cbody));
    cbody[2] = 0xFF;
    pn_wr_be16(cbody + 22, PN_CONTROL_PRM_END);
    bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, cbody, sizeof(cbody));
    sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 4, stub, sn);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               -EPERM,
           "control wrong uuid");

    /* Matching Control */
    memset(cbody, 0, sizeof(cbody));
    fill_aruuid(cbody + 2);
    pn_wr_be16(cbody + 22, PN_CONTROL_PRM_END);
    bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, cbody, sizeof(cbody));
    sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 4, stub, sn);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "control ok");
    expect(pn_stack_app_ready(s) == 1, "app ready");

    /* Write with matching UUID */
    uint8_t wbody[34 + 8];
    memset(wbody, 0, sizeof(wbody));
    pn_wr_be16(wbody, 1);
    fill_aruuid(wbody + 2);
    pn_wr_be16(wbody + 22, 0);
    pn_wr_be16(wbody + 24, 1);
    pn_wr_be16(wbody + 28, PN_INDEX_IM1);
    pn_wr_be32(wbody + 30, 6);
    memcpy(wbody + 34, "line-A", 6);
    bn = wr_block(blocks, PN_BLOCK_IOD_WRITE_REQ, wbody, 40);
    /* blocks[64] may be tight: wr_block of 40 body = 46. OK. */
    sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 3, stub, sn);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "write ok");

    /* Release from wrong IP must keep AR */
    uint8_t rel[18];
    memset(rel, 0, sizeof(rel));
    fill_aruuid(rel + 2);
    bn = wr_block(blocks, PN_BLOCK_AR_REQ, rel, sizeof(rel));
    sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 1, stub, sn);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099) ==
               -EPERM,
           "release wrong IP");
    expect(pn_stack_ar_up(s) == 1, "ar still up");

    /* Matching Release */
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "release ok");
    expect(pn_stack_ar_up(s) == 0, "ar down");
    pn_stack_destroy(s);
}

static void test_ndr_huge_args_len(void)
{
    /* Fuzz: NDR argsLen/actual = UINT32_MAX used to wrap 20+n and OOB-read. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "ndr create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "ndr connect");
    expect(pn_stack_ar_up(s) == 1, "ndr ar up");

    memset(pdu, 0, sizeof(pdu));
    pdu[0] = 1;
    pdu[1] = 0;
    pn_wr_le16(pdu + 68, 1); /* Release */
    pn_wr_le16(pdu + 74, 24);
    memset(pdu + 80, 0xff, 24); /* argsMax/Len/max/offset/actual = UINT32_MAX */
    rlen = 0;
    int rc = pn_rpc_handle(s, pdu, 80 + 24, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc == -EPERM || rc == 0, "huge NDR release handled");
    expect(pn_stack_ar_up(s) == 1, "AR kept when UUID not parsed");
    pn_stack_destroy(s);
}

static void test_ar_timeout_and_replace(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "to create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "to first connect");
    expect(pn_stack_ar_up(s) == 1, "to ar up");

    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000002) ==
               0,
           "to other-ip connect rpc");
    expect(pn_stack_ar_up(s) == 1, "to ar kept vs other IP");
    expect(s->ar.owner_ip == 0x0a000001, "to owner unchanged");

    s->ar.last_cmi_ns = pn_now_ns() - (PN_CMI_ACTIVITY_TIMEOUT_NS + 1000000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "to ar down after CMI timeout");

    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "to connect after timeout");
    expect(pn_stack_ar_up(s) == 1, "to ar up after timeout connect");
    expect(s->ar.owner_ip == 0x0a000001, "to new owner");

    s->ar.saw_rt = 1;
    s->ar.last_rt_rx_ns =
        pn_now_ns() - ((uint64_t)s->cfg.cycle_us * 1000ull * 3ull + 1000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "to ar down after data-hold");
    pn_stack_destroy(s);
}

int main(void)
{
    test_write_short_block();
    test_ar_ownership();
    test_ndr_huge_args_len();
    test_ar_timeout_and_replace();
    if (g_fail) {
        fprintf(stderr, "test_pn_rpc: FAILED\n");
        return 1;
    }
    printf("test_pn_rpc: OK\n");
    return 0;
}
