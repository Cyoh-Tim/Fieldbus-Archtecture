#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;

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

    /* Write with matching UUID. Record bytes follow the 64-byte header. */
    uint8_t wbody[58];
    memset(wbody, 0, sizeof(wbody));
    pn_wr_be16(wbody, 1);
    fill_aruuid(wbody + 2);
    pn_wr_be16(wbody + 22, 0);
    pn_wr_be16(wbody + 24, 1);
    pn_wr_be16(wbody + 28, PN_INDEX_IM1);
    pn_wr_be32(wbody + 30, 6);
    uint8_t wblocks[80];
    bn = wr_block(wblocks, PN_BLOCK_IOD_WRITE_REQ, wbody, sizeof(wbody));
    memcpy(wblocks + bn, "line-A", 6);
    bn += 6;
    sn = ndr_wrap(stub, wblocks, bn);
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

    /* No IOCR in this Connect: arm the negotiated clock explicitly.
     * 32 × 8 × 31.25 µs = 8 ms, times DataHoldFactor 3. */
    s->ar.send_clock_factor = 32;
    s->ar.reduction_ratio = 8;
    s->ar.data_hold_factor = 3;
    s->ar.saw_rt = 1;
    s->ar.last_rt_rx_ns =
        pn_now_ns() -
        (32ull * 8ull * PN_SEND_CLOCK_BASE_NS * 3ull + 1000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "to ar down after data-hold");
    pn_stack_destroy(s);
}

static void fill_init_uuid(uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = (uint8_t)(0x40 + i);
    }
}

/* session, optional CMInitiatorObjectUUID, optional input FrameID,
 * optional garbage Security Class 1 block. */
static size_t build_connect_ex(uint8_t *pdu, uint16_t session, int with_init,
                               uint16_t in_fid, int bad_sec)
{
    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[42];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, session);
    ar[20] = 0x02;
    if (with_init) {
        fill_init_uuid(ar + 26);
    }
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, with_init ? 42 : 26);

    if (in_fid != 0) {
        uint8_t iocr[18];
        memset(iocr, 0, sizeof(iocr));
        pn_wr_be16(iocr, PN_IOCR_INPUT);
        pn_wr_be16(iocr + 12, in_fid);
        pn_wr_be16(iocr + 14, 1);
        pn_wr_be16(iocr + 16, 1);
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr, sizeof(iocr));
    }
    if (bad_sec) {
        uint8_t sec[2 + PN_HMAC_LEN];
        memset(sec, 0x5A, sizeof(sec));
        pn_wr_be16(sec, 0x0001);
        bn += wr_block(blocks + bn, PN_BLOCK_SEC_INT, sec, sizeof(sec));
    }
    uint8_t stub[384];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 0, stub, sn);
}

static void test_connect_reject_keeps_ar(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "keep create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect_ex(pdu, 7, 1, 0, 0);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "keep first connect");
    expect(pn_stack_ar_up(s) == 1, "keep ar up");
    expect(s->ar.session_key == 7, "keep session");
    expect(s->ar.have_initiator_uuid == 1, "keep initiator uuid");
    s->ar.prm_end = 1;
    uint16_t fid = s->ar.in_frame_id;

    s->cfg.security_class = PN_SECURITY_CLASS_1;
    plen = build_connect_ex(pdu, 99, 1, 0x80AA, 0);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "unsigned same-ip connect rpc");
    expect(pn_stack_ar_up(s) == 1, "ar kept after unsigned connect");
    expect(s->ar.session_key == 7, "session kept after unsigned");
    expect(s->ar.prm_end == 1, "prm_end kept after unsigned");
    expect(s->ar.owner_ip == 0x0a000001, "owner kept after unsigned");
    expect(s->ar.in_frame_id == fid, "frame id kept after unsigned");

    memset(s->cfg.psk, 0x11, PN_PSK_LEN);
    s->cfg.psk_set = 1;
    plen = build_connect_ex(pdu, 99, 1, 0x80AA, 1);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099) ==
               0,
           "bad hmac other-ip connect rpc");
    expect(pn_stack_ar_up(s) == 1, "ar kept after bad hmac");
    expect(s->ar.session_key == 7 && s->ar.prm_end == 1, "state kept after hmac");
    expect(s->ar.owner_ip == 0x0a000001, "owner kept after uuid-match hmac fail");
    expect(s->ar.in_frame_id == fid, "frame id kept after hmac");

    s->cfg.security_class = 0;
    plen = build_connect_ex(pdu, 99, 1, 0x80AA, 0);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099) ==
               0,
           "valid same-uuid replace rpc");
    expect(pn_stack_ar_up(s) == 1, "ar up after replace");
    expect(s->ar.owner_ip == 0x0a000099, "replaced owner");
    expect(s->ar.session_key == 99, "replaced session");
    expect(s->ar.in_frame_id == 0x80AA, "replaced frame id");
    expect(s->ar.prm_end == 0, "replace cleared old prm_end");
    pn_stack_destroy(s);
}

static size_t build_connect_iocr(uint8_t *pdu, uint16_t scf, uint16_t rr,
                                 uint16_t dhold)
{
    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[26];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));

    uint8_t outb[30];
    memset(outb, 0, sizeof(outb));
    pn_wr_be16(outb, PN_IOCR_OUTPUT);
    pn_wr_be16(outb + 10, 9);
    pn_wr_be16(outb + 12, 0x8002);
    pn_wr_be16(outb + 14, scf);
    pn_wr_be16(outb + 16, rr);
    pn_wr_be16(outb + 26, 9);
    pn_wr_be16(outb + 28, dhold);
    bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, outb, sizeof(outb));

    /* Later input CR with a 31.25 µs clock must not replace the O→T clock. */
    uint8_t inb[18];
    memset(inb, 0, sizeof(inb));
    pn_wr_be16(inb, PN_IOCR_INPUT);
    pn_wr_be16(inb + 12, 0x8001);
    pn_wr_be16(inb + 14, 1);
    pn_wr_be16(inb + 16, 1);
    bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, inb, sizeof(inb));

    uint8_t stub[384];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 0, stub, sn);
}

static void test_data_hold_iocr_cycle(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "iocr create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    const uint16_t scf = 32;
    const uint16_t rr = 32;
    const uint16_t dhold = 3;
    size_t plen = build_connect_iocr(pdu, scf, rr, dhold);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "iocr connect");
    expect(s->ar.send_clock_factor == scf, "scf from output cr");
    expect(s->ar.reduction_ratio == rr, "rr from output cr");
    expect(s->ar.data_hold_factor == dhold, "data hold not watchdog");
    uint64_t hold =
        (uint64_t)scf * (uint64_t)rr * PN_SEND_CLOCK_BASE_NS * (uint64_t)dhold;
    uint64_t cfg_hold = (uint64_t)s->cfg.cycle_us * 1000ull * 3ull;
    expect(hold > cfg_hold, "negotiated hold longer than cfg cycle");

    s->ar.saw_rt = 1;
    s->ar.last_rt_rx_ns = pn_now_ns() - (cfg_hold + 1000000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 1, "cfg-cycle silence does not abort");

    s->ar.last_rt_rx_ns = pn_now_ns() - (hold + 1000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "negotiated data-hold aborts");
    pn_stack_destroy(s);
}

static void test_ar_block_mac_bounds(void)
{
    /* Exact-sized Connect whose AR body is 24 bytes. The old guard
     * (blen >= 24) memcpy'd a 6-byte MAC at body+20, two bytes past
     * the block and, here, past the allocation. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "mac bounds create");
    const uint16_t body_len = 24;
    const uint16_t block_len = (uint16_t)(2 + body_len);
    size_t blocks_n = 4u + block_len;
    size_t stub_n = 20 + blocks_n;
    size_t pdu_n = 80 + stub_n;
    uint8_t *pdu = calloc(1, pdu_n);
    expect(pdu != NULL, "mac bounds alloc");
    pdu[0] = 1;
    pn_wr_le16(pdu + 68, 0);
    pn_wr_le16(pdu + 74, (uint16_t)stub_n);
    pn_wr_le32(pdu + 80, (uint32_t)blocks_n);
    pn_wr_le32(pdu + 84, (uint32_t)blocks_n);
    pn_wr_le32(pdu + 88, (uint32_t)blocks_n);
    pn_wr_le32(pdu + 96, (uint32_t)blocks_n);
    uint8_t *blk = pdu + 100;
    pn_wr_be16(blk, PN_BLOCK_AR_REQ);
    pn_wr_be16(blk + 2, block_len);
    blk[4] = 1;
    memset(blk + 6, 0xAB, body_len);
    uint8_t resp[256];
    size_t rlen = 0;
    expect(pn_rpc_handle(s, pdu, pdu_n, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "short ar mac rpc");
    expect(pn_stack_ar_up(s) == 1, "short ar still connects");
    int mac_set = 0;
    for (int i = 0; i < 6; i++) {
        if (s->ar.initiator_mac[i] != 0) {
            mac_set = 1;
        }
    }
    expect(!mac_set, "short ar did not copy mac");
    expect(s->ar.uuid[0] == 0, "short ar did not parse uuid");
    free(pdu);
    pn_stack_destroy(s);
}

static void test_no_iocr_clock_still_reclaims(void)
{
    /* Connect with no output IOCR still gets default frame IDs. After
     * PrmEnd / O→T the AR must not live forever: the 2 s CMI window
     * stays armed, and a received O→T refreshes it. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "noclk create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "noclk connect");
    expect(s->ar.send_clock_factor == 0 && s->ar.reduction_ratio == 0,
           "noclk no negotiated clock");
    expect(s->ar.out_frame_id == 0x8002, "noclk default out frame");
    s->ar.prm_end = 1;
    s->ar.app_ready = 1;
    s->ar.saw_rt = 1;
    s->ar.last_rt_rx_ns = pn_now_ns() - 1000000ull;
    s->ar.last_cmi_ns = pn_now_ns() - (PN_CMI_ACTIVITY_TIMEOUT_NS + 1000000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 1, "noclk recent O->T keeps AR");

    s->ar.last_rt_rx_ns = pn_now_ns() - (PN_CMI_ACTIVITY_TIMEOUT_NS + 1000000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "noclk CMI abort after silence");

    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099) ==
               0,
           "noclk other-ip connect");
    expect(pn_stack_ar_up(s) == 1 && s->ar.owner_ip == 0x0a000099,
           "noclk new owner");
    pn_stack_destroy(s);
}

static void test_cmi_ignores_own_tx(void)
{
    /* Our RTC1 TX must not suppress CMI. No O→T / PrmEnd => abort, then
     * a different controller may Connect. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "tx create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "tx connect");
    expect(pn_stack_ar_up(s) == 1, "tx ar up");
    pn_rt_send_if_due(s);
    expect(pn_stack_ar_up(s) == 1, "tx ar still up after our RTC1");
    expect(s->ar.saw_rt == 0 && s->ar.prm_end == 0, "tx no controller liveness");

    s->ar.last_cmi_ns = pn_now_ns() - (PN_CMI_ACTIVITY_TIMEOUT_NS + 1000000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "tx CMI abort after own TX");

    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000099) ==
               0,
           "tx other-ip connect after abort");
    expect(pn_stack_ar_up(s) == 1, "tx new ar up");
    expect(s->ar.owner_ip == 0x0a000099, "tx new owner");
    pn_stack_destroy(s);
}

/* T12-1: response NDR is PNIOStatus, ArgsLength, MaxCount, Offset,
 * ActualCount, then blocks. A successful Connect.rsp starts with status 0,
 * not the block length. T12-4 appends ARServerBlock for station name
 * "rpc-test" (16 bytes), so the blocks are 0x48 + 0x10 = 0x58. */
static void test_connect_response_ndr_pniostatus(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "ndr-res create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "ndr-res connect");
    expect(rlen >= 80 + 20, "ndr-res rsp short");
    const uint8_t *stub = resp + 80;
    uint32_t status = pn_rd_le32(stub);
    uint32_t args_len = pn_rd_le32(stub + 4);
    uint32_t max_count = pn_rd_le32(stub + 8);
    uint32_t offset = pn_rd_le32(stub + 12);
    uint32_t actual = pn_rd_le32(stub + 16);
    expect_u32(status, 0, "Connect.rsp PNIOStatus");
    expect_u32(args_len, 0x58, "Connect.rsp ArgsLength");
    expect_u32(max_count, 0x58, "Connect.rsp MaxCount");
    expect_u32(offset, 0, "Connect.rsp Offset");
    expect_u32(actual, 0x58, "Connect.rsp ActualCount");
    expect(rlen == 80 + 20 + 0x58, "Connect.rsp length is header + NDR + blocks");
    expect(pn_rd_be16(stub + 20) == PN_BLOCK_AR_RES, "blocks follow the NDR header");
    pn_stack_destroy(s);
}

/* T12-1: a rejected Connect still answers, but the first NDR word is the
 * PNIOStatus (the existing 81 00 00 00 indicator) and there are no blocks. */
static void test_connect_error_ndr_pniostatus(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "ndr-err create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "ndr-err first connect");
    expect(pn_stack_ar_up(s) == 1, "ndr-err ar up");

    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000002) ==
               0,
           "ndr-err other-ip connect");
    expect(pn_stack_ar_up(s) == 1, "ndr-err ar kept");
    expect(s->ar.owner_ip == 0x0a000001, "ndr-err owner kept");
    expect(rlen == 100, "error rsp is 80-byte RPC + 20-byte NDR");
    const uint8_t *stub = resp + 80;
    expect_u32(pn_rd_be32(stub), 0x81u << 24, "error PNIOStatus bytes 81 00 00 00");
    expect_u32(pn_rd_le32(stub + 4), 0, "error ArgsLength");
    expect_u32(pn_rd_le32(stub + 8), 0, "error MaxCount");
    expect_u32(pn_rd_le32(stub + 12), 0, "error Offset");
    expect_u32(pn_rd_le32(stub + 16), 0, "error ActualCount");
    pn_stack_destroy(s);
}

/* T12-3: spec IODWriteReq is a 64-byte header (block_length 60) and the
 * record bytes follow that header. The response is IODWriteResHeader
 * (0x8008, 64 bytes). A later Read is IODReadResHeader (0x8009, 64 bytes)
 * plus an I&M block that starts with its own BlockHeader (0x0020..0x0024). */
static void test_t12_3_rw_res_headers_and_write_data(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-3 create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-3 connect");
    expect(pn_stack_ar_up(s) == 1, "t12-3 ar up");

    uint8_t im1[60];
    memset(im1, ' ', sizeof(im1));
    pn_wr_be16(im1, 0x0021);
    pn_wr_be16(im1 + 2, 56);
    im1[4] = 1;
    im1[5] = 0;
    memcpy(im1 + 6, "ORACLE-FUNCTION", 15);
    memcpy(im1 + 38, "ORACLE-LOCATION", 15);

    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 7); /* seqNum */
    fill_aruuid(body + 2);
    pn_wr_be32(body + 18, 0); /* API */
    pn_wr_be16(body + 22, 0);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, PN_INDEX_IM1);
    pn_wr_be32(body + 30, (uint32_t)sizeof(im1));

    uint8_t blocks[160];
    size_t bn = wr_block(blocks, PN_BLOCK_IOD_WRITE_REQ, body, sizeof(body));
    expect(bn == 64, "IODWriteReqHeader is 64 bytes");
    memcpy(blocks + bn, im1, sizeof(im1));
    bn += sizeof(im1);
    uint8_t stub[256];
    size_t sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 3, stub, sn);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-3 write");
    expect(rlen >= 80 + 20, "t12-3 write rsp short");
    const uint8_t *rstub = resp + 80;
    expect_u32(pn_rd_le32(rstub), 0, "write PNIOStatus");
    uint32_t wlen = pn_rd_le32(rstub + 4);
    expect(wlen >= 64, "write res carries a 64-byte IODWriteResHeader");
    if (wlen >= 64 && rlen >= 100 + 64) {
        const uint8_t *wb = rstub + 20;
        expect(pn_rd_be16(wb) == 0x8008, "IODWriteResHeader block type 0x8008");
        expect(pn_rd_be16(wb + 2) == 60, "IODWriteResHeader block_length 60");
        expect(pn_rd_be16(wb + 6) == 7, "write res echoes seqNum");
        expect(memcmp(wb + 8, body + 2, 16) == 0, "write res echoes ARUUID");
        expect(pn_rd_be16(wb + 34) == PN_INDEX_IM1, "write res echoes index");
        expect_u32(pn_rd_be32(wb + 36), (uint32_t)sizeof(im1),
                   "write res recordDataLength");
        expect_u32(pn_rd_be32(wb + 44), 0, "write res PNIOStatus in header");
    }

    uint8_t stored[80];
    size_t stored_n = 0;
    expect(pn_record_read(s, 0, 1, PN_INDEX_IM1, stored, sizeof(stored),
                          &stored_n) == 0,
           "t12-3 direct I&M1 read");
    int saw_func = 0;
    if (stored_n >= 15) {
        for (size_t i = 0; i + 15 <= stored_n; i++) {
            if (memcmp(stored + i, "ORACLE-FUNCTION", 15) == 0) {
                saw_func = 1;
                break;
            }
        }
    }
    expect(saw_func, "I&M1 kept ORACLE-FUNCTION (data is after the 64-byte header)");

    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 9);
    fill_aruuid(body + 2);
    pn_wr_be16(body + 22, 0);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, PN_INDEX_IM1);
    pn_wr_be32(body + 30, 4096);
    bn = wr_block(blocks, PN_BLOCK_IOD_READ_REQ, body, sizeof(body));
    sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 2, stub, sn);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-3 read im1");
    expect(rlen >= 100, "t12-3 read rsp short");
    rstub = resp + 80;
    expect_u32(pn_rd_le32(rstub), 0, "read PNIOStatus");
    uint32_t rblen = pn_rd_le32(rstub + 4);
    expect(rblen >= 64, "read res carries a 64-byte IODReadResHeader");
    if (rblen >= 64 && rlen >= 100 + 64) {
        const uint8_t *rb = rstub + 20;
        expect(pn_rd_be16(rb) == 0x8009, "IODReadResHeader block type 0x8009");
        expect(pn_rd_be16(rb + 2) == 60, "IODReadResHeader block_length 60");
        expect(pn_rd_be16(rb + 6) == 9, "read res echoes seqNum");
        uint32_t rdlen = pn_rd_be32(rb + 36);
        expect(rdlen == 60, "I&M1 recordDataLength includes BlockHeader");
        expect(rblen >= 64 + rdlen, "record bytes follow the read header");
        if (rblen >= 64 + 60) {
            const uint8_t *rec = rb + 64;
            expect(pn_rd_be16(rec) == 0x0021, "I&M1 BlockHeader 0x0021");
            expect(pn_rd_be16(rec + 2) == 56, "I&M1 block_length 56");
            expect(rec[4] == 1 && rec[5] == 0, "I&M1 block version 1.0");
            expect(memcmp(rec + 6, "ORACLE-FUNCTION", 15) == 0,
                   "read record TagFunction");
            expect(memcmp(rec + 38, "ORACLE-LOCATION", 15) == 0,
                   "read record TagLocation");
        }
    }

    pn_wr_be16(body + 28, PN_INDEX_IM0);
    bn = wr_block(blocks, PN_BLOCK_IOD_READ_REQ, body, sizeof(body));
    sn = ndr_wrap(stub, blocks, bn);
    plen = wrap_rpc(pdu, 2, stub, sn);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-3 read im0");
    rstub = resp + 80;
    rblen = (rlen >= 100) ? pn_rd_le32(rstub + 4) : 0;
    expect(rblen >= 64 + 60, "I&M0 read res is header plus record");
    if (rblen >= 64 + 60 && rlen >= 100 + 64 + 8) {
        const uint8_t *rb = rstub + 20;
        expect(pn_rd_be16(rb) == 0x8009, "I&M0 response starts with 0x8009");
        const uint8_t *rec = rb + 64;
        expect(pn_rd_be16(rec) == 0x0020, "I&M0 BlockHeader 0x0020");
        expect(pn_rd_be16(rec + 2) == 56, "I&M0 block_length 56");
        expect(pn_rd_be16(rec + 6) == 0xABCD, "I&M0 VendorID 0xABCD");
        expect(memcmp(rec + 8, "FB-ARCH-PN-DEV", 14) == 0, "I&M0 OrderID");
    }
    pn_stack_destroy(s);
}

/* T12-4 repro. Connect carries the oracle IOCR layout (scapy pnio_rpc):
 * input C_SDU DataLength 40, (1,1) input data at FrameOffset 3, IOPS at 35,
 * output-submodule IOCS at 36. Output (1,1) data is at FrameOffset 4 so a
 * fixed copy from C_SDU byte 0 is visibly wrong. ExpectedSubmodule slot 1
 * ModuleIdent 0xDEADBEEF must produce ModuleDiffBlock 0x8104, and every
 * Connect.rsp must carry ARServerBlock 0x8106 with the station name. */
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

/* IOCRBlockReq input, oracle layout. DataLength 40, FrameID 0x8001.
 * IODataObjects: (0,1)@0 (0,0x8000)@1 (0,0x8001)@2 (1,1)@3. IOCS (1,1)@36. */
static const uint8_t k_iocr_in[] = {
    0x01, 0x02, 0x00, 0x50, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x88, 0x92,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x80, 0x01, 0x00, 0x20, 0x00, 0x10,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x03, 0x00, 0x03,
    0xc0, 0x00, 0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x24};

/* IOCRBlockReq output. Same as the oracle except (1,1) FrameOffset is 4
 * (oracle uses 0, which the fixed layout copies by accident). FrameID 0x8000. */
static const uint8_t k_iocr_out_off4[] = {
    0x01, 0x02, 0x00, 0x50, 0x01, 0x00, 0x00, 0x02, 0x00, 0x02, 0x88, 0x92,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x80, 0x00, 0x00, 0x20, 0x00, 0x10,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x03, 0x00, 0x03,
    0xc0, 0x00, 0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x21, 0x00, 0x00, 0x80, 0x00, 0x00, 0x22,
    0x00, 0x00, 0x80, 0x01, 0x00, 0x23, 0x00, 0x01, 0x00, 0x01, 0x00, 0x24};

/* ExpectedSubmoduleBlockReq, slot 1 ModuleIdent 0x00000010 (GSDML MOD_IO). */
static const uint8_t k_exp_mod10[] = {
    0x01, 0x04, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x03, 0x00, 0x01, 0x00, 0x20,
    0x01, 0x01, 0x00, 0x02, 0x00, 0x20, 0x01, 0x01};

/* Same block with slot 1 ModuleIdent 0xDEADBEEF. */
static const uint8_t k_exp_dead[] = {
    0x01, 0x04, 0x00, 0x4c, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x03, 0x00, 0x01, 0x00, 0x20,
    0x01, 0x01, 0x00, 0x02, 0x00, 0x20, 0x01, 0x01};

/* Only the plugged GSDML submodules: (0, 0x8000, ident 2) and (1, 1, ident 0x11). */
static const uint8_t k_exp_match[] = {
    0x01, 0x04, 0x00, 0x3c, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x11, 0x00, 0x03, 0x00, 0x01, 0x00, 0x20, 0x01, 0x01, 0x00, 0x02,
    0x00, 0x20, 0x01, 0x01};

static size_t build_iocr_connect(uint8_t *pdu, const uint8_t *exp, size_t explen)
{
    uint8_t blocks[512];
    size_t bn = 0;
    uint8_t ar[2 + 16 + 2 + 6];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    ar[20] = 0x00;
    ar[21] = 0x11;
    ar[22] = 0x22;
    ar[23] = 0x33;
    ar[24] = 0x44;
    ar[25] = 0x55;
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    memcpy(blocks + bn, k_iocr_in, sizeof(k_iocr_in));
    bn += sizeof(k_iocr_in);
    memcpy(blocks + bn, k_iocr_out_off4, sizeof(k_iocr_out_off4));
    bn += sizeof(k_iocr_out_off4);
    memcpy(blocks + bn, exp, explen);
    bn += explen;
    uint8_t stub[640];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 0, stub, sn);
}

static const uint8_t *find_rsp_block(const uint8_t *resp, size_t rlen,
                                    uint16_t type, size_t *blen)
{
    if (rlen < 100) {
        return NULL;
    }
    const uint8_t *stub = resp + 80;
    uint32_t n = pn_rd_le32(stub + 4);
    if (20u + (size_t)n > rlen - 80) {
        return NULL;
    }
    const uint8_t *p = stub + 20;
    size_t off = 0;
    while (off + 4 <= n) {
        uint16_t t = pn_rd_be16(p + off);
        uint16_t bl = pn_rd_be16(p + off + 2);
        if (bl < 2 || off + 4u + (size_t)bl > n) {
            break;
        }
        if (t == type) {
            *blen = 4u + (size_t)bl;
            return p + off;
        }
        off += 4u + (size_t)bl;
        if (off & 1u) {
            off++;
        }
    }
    return NULL;
}

/* ModuleDiffBlock body: NumberOfAPIs, then API / NumberOfModules /
 * (Slot, ModuleIdent, ModuleState, NumberOfSubmodules, subs...). */
static int diff_slot(const uint8_t *blk, size_t n, uint16_t slot,
                     uint16_t *state, uint32_t *ident)
{
    if (n < 8) {
        return 0;
    }
    size_t off = 6;
    uint16_t napis = pn_rd_be16(blk + off);
    off += 2;
    for (uint16_t a = 0; a < napis; a++) {
        if (off + 6 > n) {
            return 0;
        }
        off += 4;
        uint16_t nmod = pn_rd_be16(blk + off);
        off += 2;
        for (uint16_t m = 0; m < nmod; m++) {
            if (off + 10 > n) {
                return 0;
            }
            uint16_t sl = pn_rd_be16(blk + off);
            uint32_t id = pn_rd_be32(blk + off + 2);
            uint16_t st = pn_rd_be16(blk + off + 6);
            off += 8;
            uint16_t nsub = pn_rd_be16(blk + off);
            off += 2;
            if (off + (size_t)nsub * 8u > n) {
                return 0;
            }
            off += (size_t)nsub * 8u;
            if (sl == slot) {
                *state = st;
                *ident = id;
                return 1;
            }
        }
    }
    return 0;
}

static void test_t12_4_iocr_offsets_and_blocks(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-4 create");
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    expect(pn_stack_start(s) == 0, "t12-4 start");
    g_ntx = 0;

    uint8_t pdu[768];
    uint8_t resp[2048];
    size_t rlen = 0;
    size_t plen = build_iocr_connect(pdu, k_exp_mod10, sizeof(k_exp_mod10));
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-4 connect");
    expect(pn_stack_ar_up(s) == 1, "t12-4 ar up");
    expect(rlen >= 100, "t12-4 connect rsp");
    expect_u32(pn_rd_le32(resp + 80), 0, "t12-4 PNIOStatus");

    size_t blen = 0;
    const uint8_t *srv = find_rsp_block(resp, rlen, 0x8106, &blen);
    expect(srv != NULL, "t12-4 ARServerBlock 0x8106 missing");
    if (srv && blen >= 8) {
        uint16_t nlen = pn_rd_be16(srv + 6);
        expect(nlen == 8 && blen >= 8u + 8u &&
                   memcmp(srv + 8, "rpc-test", 8) == 0,
               "t12-4 ARServer station name");
    }

    uint8_t pat[32];
    for (int i = 0; i < 32; i++) {
        pat[i] = (uint8_t)(0x10 + i);
    }
    expect(pn_stack_write_input(s, 0, pat, sizeof(pat)) == 0, "t12-4 write input");
    g_ntx = 0;
    pn_rt_send_if_due(s);

    const uint8_t *pay = NULL;
    size_t paylen = 0;
    int saw = 0;
    for (int i = 0; i < g_ntx; i++) {
        if (g_txlen[i] >= 16 && pn_rd_be16(g_tx[i] + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(g_tx[i] + 14) == 0x8001) {
            pay = g_tx[i] + 14;
            paylen = g_txlen[i] - 14;
            saw = 1;
            break;
        }
    }
    expect(saw, "t12-4 RTC1 input frame");
    if (saw && paylen >= 2 + 4) {
        const uint8_t *sdu = pay + 2;
        size_t sdu_len = paylen - 2 - 4;
        if (sdu_len != 40 || memcmp(sdu + 3, pat, 32) != 0 || sdu[35] != 0x80 ||
            sdu[36] != 0x80) {
            fprintf(stderr,
                    "FAIL: t12-4 C_SDU len=%zu (want 40) data@3 %s IOPS@35=%02x "
                    "IOCS@36=%02x\n",
                    sdu_len,
                    (sdu_len >= 35 && memcmp(sdu + 3, pat, 32) == 0) ? "ok"
                                                                    : "mismatch",
                    sdu_len > 35 ? sdu[35] : 0, sdu_len > 36 ? sdu[36] : 0);
            g_fail = 1;
        }
    }

    uint8_t ot[14 + 2 + 40 + 4];
    memset(ot, 0, sizeof(ot));
    memcpy(ot, s->cfg.mac, 6);
    ot[6] = 0x00;
    ot[7] = 0x11;
    ot[8] = 0x22;
    ot[9] = 0x33;
    ot[10] = 0x44;
    ot[11] = 0x55;
    pn_wr_be16(ot + 12, PN_ETHTYPE_PN);
    pn_wr_be16(ot + 14, 0x8000);
    ot[16] = 0x11; /* C_SDU[0], not the output object */
    ot[20] = 0xA5; /* C_SDU[4] = FrameOffset of (1,1) output */
    memset(ot + 21, 0xA5, 7);
    expect(pn_stack_handle_eth(s, ot, sizeof(ot)) == 0, "t12-4 inject output");
    uint8_t got[8];
    memset(got, 0, sizeof(got));
    expect(pn_stack_read_output(s, 0, got, sizeof(got)) == 0, "t12-4 read output");
    int out_ok = 1;
    for (int i = 0; i < 8; i++) {
        if (got[i] != 0xA5) {
            out_ok = 0;
        }
    }
    if (!out_ok) {
        fprintf(stderr, "FAIL: t12-4 output image");
        for (int i = 0; i < 8; i++) {
            fprintf(stderr, " %02x", got[i]);
        }
        fprintf(stderr, " (want 8x A5 from FrameOffset 4, not C_SDU[0]=11)\n");
        g_fail = 1;
    }

    pn_stack_destroy(s);

    s = make_stack();
    expect(s != NULL, "t12-4 diff create");
    plen = build_iocr_connect(pdu, k_exp_dead, sizeof(k_exp_dead));
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-4 wrong-module connect");
    expect_u32(pn_rd_le32(resp + 80), 0, "t12-4 wrong-module PNIOStatus still OK");
    blen = 0;
    const uint8_t *diff = find_rsp_block(resp, rlen, 0x8104, &blen);
    expect(diff != NULL, "t12-4 ModuleDiffBlock 0x8104 missing");
    if (diff) {
        uint16_t st = 0xFFFF;
        uint32_t id = 0;
        int hit = diff_slot(diff, blen, 1, &st, &id);
        /* PROPER_MODULE is 2. A mismatched plugged module is SUBSTITUTE (3),
         * and the ident reported is the real module (GSDML 0x00000010). */
        if (!hit || st == 2 || id != 0x00000010u) {
            fprintf(stderr,
                    "FAIL: t12-4 slot1 diff hit=%d state=0x%04x ident=0x%08x\n",
                    hit, st, id);
            g_fail = 1;
        }
    }
    pn_stack_destroy(s);

    s = make_stack();
    expect(s != NULL, "t12-4 match create");
    plen = build_iocr_connect(pdu, k_exp_match, sizeof(k_exp_match));
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-4 matching connect");
    blen = 0;
    diff = find_rsp_block(resp, rlen, 0x8104, &blen);
    expect(diff == NULL, "t12-4 ModuleDiffBlock on a matching configuration");
    pn_stack_destroy(s);
}

int main(void)
{
    test_t12_4_iocr_offsets_and_blocks();
    test_t12_3_rw_res_headers_and_write_data();
    test_connect_response_ndr_pniostatus();
    test_connect_error_ndr_pniostatus();
    test_write_short_block();
    test_ar_ownership();
    test_ndr_huge_args_len();
    test_ar_timeout_and_replace();
    test_cmi_ignores_own_tx();
    test_connect_reject_keeps_ar();
    test_data_hold_iocr_cycle();
    test_no_iocr_clock_still_reclaims();
    test_ar_block_mac_bounds();
    if (g_fail) {
        fprintf(stderr, "test_pn_rpc: FAILED\n");
        return 1;
    }
    printf("test_pn_rpc: OK\n");
    return 0;
}
