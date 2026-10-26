#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* CMInitiatorObjectUUID wire bytes (mixed-endian UUID in the AR block). */
static void fill_initiator_uuid(uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = (uint8_t)(0xC0 + i);
    }
}

/* PNIO Controller interface UUID on the wire (DEA00002-6C97-11D1-8271-00A02442DF7D). */
static const uint8_t k_pnio_controller_if[16] = {
    0x02, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11,
    0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D};

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

/* CL RPC v4, LE integers, this device's object and the PNIO interface. */
static void stamp_cl_req(uint8_t *out)
{
    static const uint8_t obj[16] = {
        0x00, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xab, 0xcd};
    static const uint8_t iface[16] = {
        0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d};
    out[0] = 4;
    out[4] = 0x10;
    memcpy(out + 8, obj, 16);
    memcpy(out + 24, iface, 16);
}

static size_t wrap_rpc(uint8_t *out, uint16_t op, const uint8_t *stub,
                       size_t slen)
{
    memset(out, 0, 80);
    out[1] = 0;
    stamp_cl_req(out);
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

/* Connect with CMInitiatorObjectUUID and CMInitiatorUDPRTPort so
 * ApplicationReady can copy those fields (T12-5). */
static size_t build_connect_initiator_port(uint8_t *pdu, uint16_t udp_rt_port)
{
    uint8_t ar[50];
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
    fill_initiator_uuid(ar + 26);
    pn_wr_be32(ar + 42, 0x00000001); /* ARProperties */
    pn_wr_be16(ar + 46, 600);
    pn_wr_be16(ar + 48, udp_rt_port); /* CMInitiatorUDPRTPort */
    uint8_t blocks[80];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    uint8_t stub[160];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 0, stub, sn);
}

static size_t build_connect_initiator(uint8_t *pdu)
{
    return build_connect_initiator_port(pdu, 0x8892); /* L2 RT marker */
}

static size_t build_prm_end(uint8_t *pdu)
{
    uint8_t cbody[26];
    memset(cbody, 0, sizeof(cbody));
    fill_aruuid(cbody + 2);
    pn_wr_be16(cbody + 18, 1);
    pn_wr_be16(cbody + 22, PN_CONTROL_PRM_END);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, cbody, sizeof(cbody));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 4, stub, sn);
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
    pdu[1] = 0;
    stamp_cl_req(pdu);
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
 * optional garbage vendor integrity extension block. */
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
        /* 16 ms (SCF 32 × RR 16). A 31.25 µs clock is below cycle_us and
         * is rejected (T5); this path only needs a legal input period. */
        pn_wr_be16(iocr + 14, 32);
        pn_wr_be16(iocr + 16, 16);
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

    s->cfg.security_class = PN_VENDOR_INTEGRITY;
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

    /* Later input CR (16 ms) must not replace the O→T clock (32 ms).
     * A sub-minimum input period is rejected (T5). */
    uint8_t inb[18];
    memset(inb, 0, sizeof(inb));
    pn_wr_be16(inb, PN_IOCR_INPUT);
    pn_wr_be16(inb + 12, 0x8001);
    pn_wr_be16(inb + 14, 32);
    pn_wr_be16(inb + 16, 16);
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
    stamp_cl_req(pdu);
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
 * not the block length. This Connect has no ARProperties, so StartupMode
 * is Legacy and ARServerBlock is not appended.
 * Blocks: ARBlockRes 34 + IOCRBlockRes 12 + IOCRBlockRes 12
 * + AlarmCRBlockRes 12 (T12-12 body is 6, BlockLength 8) = 0x46. */
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
    expect_u32(args_len, 0x46, "Connect.rsp ArgsLength");
    expect_u32(max_count, 0x46, "Connect.rsp MaxCount");
    expect_u32(offset, 0, "Connect.rsp Offset");
    expect_u32(actual, 0x46, "Connect.rsp ActualCount");
    expect(rlen == 80 + 20 + 0x46, "Connect.rsp length is header + NDR + blocks");
    expect(pn_rd_be16(stub + 20) == PN_BLOCK_AR_RES, "blocks follow the NDR header");
    pn_stack_destroy(s);
}

/* T12-1: a rejected Connect still answers. The first NDR word is the
 * PNIOStatus and there are no blocks. Other-controller rejection is still
 * the legacy value 0x81000000 (queue 59 owns DB 81 40 04). The integer is
 * little-endian on the wire, so the bytes are 00 00 00 81. */
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
    expect_u32(pn_rd_le32(stub), 0x81u << 24, "error PNIOStatus LE 0x81000000");
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

/* T12-5: PrmEnd.rsp is IODControlRes 0x8110 with ControlCommand Done
 * (0x0008), not 0x0111 echoing PrmEnd. After PrmEnd the device queues an
 * ApplicationReady RPC request: rpc_vers=4, object=CMInitiatorObjectUUID,
 * interface=PNIO Controller, block 0x0112. A later 0x8112 clears the
 * pending request so it is not taken again. */
static void test_t12_5_prm_end_and_app_ready(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-5 create");
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect_initiator(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-5 connect");
    expect(pn_stack_ar_up(s) == 1, "t12-5 ar up");

    plen = build_prm_end(pdu);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-5 prm-end");
    expect(rlen >= 80 + 20 + 32, "t12-5 prm-end rsp short");
    const uint8_t *rstub = resp + 80;
    expect_u32(pn_rd_le32(rstub), 0, "prm-end PNIOStatus");
    uint32_t blen = pn_rd_le32(rstub + 4);
    expect(blen >= 32, "prm-end ArgsLength covers IODControlRes");
    const uint8_t *blk = rstub + 20;
    expect(pn_rd_be16(blk) == 0x8110, "PrmEnd res block type 0x8110");
    expect(pn_rd_be16(blk + 2) == 28, "PrmEnd res block_length 28");
    uint8_t want_uuid[16];
    fill_aruuid(want_uuid);
    expect(memcmp(blk + 8, want_uuid, 16) == 0, "PrmEnd res ARUUID");
    expect(pn_rd_be16(blk + 24) == 1, "PrmEnd res SessionKey");
    expect(pn_rd_be16(blk + 28) == 0x0008, "PrmEnd res ControlCommand Done");
    expect(pn_stack_app_ready(s) == 1, "t12-5 app_ready after PrmEnd");

    expect(s->pending_rpc_tx_len >= 80 + 20 + 32, "t12-5 AppReady queued");
    const uint8_t *tx = s->pending_rpc_tx;
    expect(tx[0] == 4, "AppReady rpc_vers=4");
    expect(tx[1] == 0, "AppReady ptype=request");
    expect(pn_rd_le16(tx + 68) == 4, "AppReady opnum=Control");
    uint8_t init_uuid[16];
    fill_initiator_uuid(init_uuid);
    uint8_t obj_dce[16];
    obj_dce[0] = init_uuid[3];
    obj_dce[1] = init_uuid[2];
    obj_dce[2] = init_uuid[1];
    obj_dce[3] = init_uuid[0];
    obj_dce[4] = init_uuid[5];
    obj_dce[5] = init_uuid[4];
    obj_dce[6] = init_uuid[7];
    obj_dce[7] = init_uuid[6];
    memcpy(obj_dce + 8, init_uuid + 8, 8);
    expect(memcmp(tx + 8, obj_dce, 16) == 0,
           "AppReady object=CMInitiatorObjectUUID (DCE mixed-endian)");
    expect(memcmp(tx + 24, k_pnio_controller_if, 16) == 0,
           "AppReady interface=PNIO Controller");
    uint32_t args_len = pn_rd_le32(tx + 80 + 4);
    expect(args_len >= 32, "AppReady ArgsLength");
    const uint8_t *areq = tx + 100;
    expect(pn_rd_be16(areq) == 0x0112, "AppReady block type 0x0112");
    expect(memcmp(areq + 8, want_uuid, 16) == 0, "AppReady ARUUID");
    expect(pn_rd_be16(areq + 24) == 1, "AppReady SessionKey");
    expect(pn_rd_be16(areq + 28) == PN_CONTROL_APP_READY,
           "AppReady ControlCommand ApplicationReady");

    /* 0x8112 from the controller clears the pending indication. */
    uint8_t cres[26];
    memset(cres, 0, sizeof(cres));
    fill_aruuid(cres + 2);
    pn_wr_be16(cres + 18, 1);
    pn_wr_be16(cres + 22, 0x0008);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, 0x8112, cres, sizeof(cres));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t ack[256];
    memset(ack, 0, 80);
    ack[0] = 4;
    ack[1] = 2; /* RPC response */
    ack[4] = 0x10; /* LE drep: opnum and NDR follow the request byte order */
    pn_wr_le16(ack + 68, 4);
    pn_wr_le16(ack + 74, (uint16_t)sn);
    memcpy(ack + 80, stub, sn);
    rlen = 0;
    expect(pn_rpc_handle(s, ack, 80 + sn, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-5 0x8112 ack");
    expect(s->pending_rpc_tx_len == 0, "t12-5 pending cleared by 0x8112");
    uint8_t takebuf[512];
    size_t tn2 = 0;
    expect(pn_stack_take_rpc_tx(s, takebuf, sizeof(takebuf), &tn2) == -EAGAIN,
           "t12-5 no AppReady after 0x8112");
    pn_stack_destroy(s);
}

static int udp_bind_loopback(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int udp_recv_ms(int fd, uint8_t *buf, size_t cap, int timeout_ms)
{
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        return 0;
    }
    ssize_t n = recv(fd, buf, cap, 0);
    return n > 0 ? (int)n : 0;
}

/* T12-5: ApplicationReady is DCE/RPC to the Connect sender's UDP 34964.
 * CMInitiatorUDPRTPort is an RT marker (often 0x8892, sometimes 0xC000)
 * and is not the RPC destination. */
static void test_t12_5_app_ready_dest_rpc_port(void)
{
    const uint16_t advertised = 0xC000;
    const uint32_t ctrl_ip = 0x7f000001; /* 127.0.0.1, host order */
    int listen_rpc = udp_bind_loopback(PN_RPC_PORT);
    int listen_adv = udp_bind_loopback(advertised);
    expect(listen_rpc >= 0, "bind controller UDP 34964");
    expect(listen_adv >= 0, "bind controller UDP 0xC000");

    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-5 dest create");
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    expect(tx >= 0, "t12-5 dest tx socket");
    if (s && tx >= 0 && listen_rpc >= 0 && listen_adv >= 0) {
        s->fd_rpc = tx;
        tx = -1; /* pn_stack_destroy closes fd_rpc */

        uint8_t pdu[512];
        uint8_t resp[1024];
        size_t rlen = 0;
        size_t plen = build_connect_initiator_port(pdu, advertised);
        expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, ctrl_ip) ==
                   0,
               "t12-5 dest connect");
        expect(s->ar.initiator_udp_rt_port == advertised,
               "t12-5 stored CMInitiatorUDPRTPort 0xC000");
        expect(s->ar.owner_ip == ctrl_ip, "t12-5 dest owner is Connect sender");

        plen = build_prm_end(pdu);
        rlen = 0;
        expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, ctrl_ip) ==
                   0,
               "t12-5 dest prm-end");
        expect(s->pending_rpc_tx_len >= 80, "t12-5 dest AppReady queued");

        pn_rpc_poll(s);

        uint8_t got_rpc[PN_FRAME_MAX];
        uint8_t got_adv[PN_FRAME_MAX];
        int n_rpc = udp_recv_ms(listen_rpc, got_rpc, sizeof(got_rpc), 200);
        int n_adv = udp_recv_ms(listen_adv, got_adv, sizeof(got_adv), 50);
        uint16_t got_port = 0;
        if (n_rpc > 0) {
            got_port = PN_RPC_PORT;
        } else if (n_adv > 0) {
            got_port = advertised;
        }
        if (got_port != PN_RPC_PORT) {
            fprintf(stderr,
                    "FAIL: ApplicationReady dest port (got %u want %u)\n",
                    got_port, (unsigned)PN_RPC_PORT);
            g_fail = 1;
        }
        expect(n_adv == 0,
               "ApplicationReady ignores CMInitiatorUDPRTPort 0xC000");
        if (n_rpc > 0 && s->pending_rpc_tx_len > 0) {
            expect(n_rpc == (int)s->pending_rpc_tx_len &&
                       memcmp(got_rpc, s->pending_rpc_tx, (size_t)n_rpc) == 0,
                   "ApplicationReady payload on UDP 34964");
        }
    }
    if (s) {
        pn_stack_destroy(s);
    }
    if (tx >= 0) {
        close(tx);
    }
    if (listen_rpc >= 0) {
        close(listen_rpc);
    }
    if (listen_adv >= 0) {
        close(listen_adv);
    }
}

/* T12-6: RTC1 APDUStatus DataStatus must be 0x35
 * (Primary 0x01 | DataValid 0x04 | ProviderState Run 0x10 |
 * StationProblemIndicator no-problem 0x20). PN_DATASTATUS_RUN 0x20 was
 * the no-problem bit; that yields 0x25 = ProviderState Stop. */
static void test_t12_6_rtc1_datastatus_run(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-6 create");
    if (!s) {
        return;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);

    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-6 connect");
    expect(pn_stack_ar_up(s) == 1, "t12-6 ar up");

    g_ntx = 0;
    g_txlen = 0;
    pn_rt_send_if_due(s);
    expect(g_ntx >= 1 && g_txlen >= 22, "t12-6 RTC1 frame sent");
    if (g_txlen >= 22) {
        /* RTC1 is 802.1Q-tagged: EtherType and FrameID follow the TCI. */
        size_t fid_off = (pn_rd_be16(g_tx + 12) == PN_ETHTYPE_VLAN) ? 18u : 14u;
        uint16_t et = pn_rd_be16(g_tx + fid_off - 2);
        uint16_t fid = pn_rd_be16(g_tx + fid_off);
        uint8_t ds = g_tx[g_txlen - 2];
        uint8_t ts = g_tx[g_txlen - 1];
        expect(et == PN_ETHTYPE_PN, "t12-6 ethertype 0x8892");
        expect(fid == 0x8001, "t12-6 input FrameID 0x8001");
        expect(ts == 0, "t12-6 TransferStatus 0");
        if (ds != 0x35) {
            fprintf(stderr,
                    "FAIL: RTC1 DataStatus got 0x%02x want 0x35 "
                    "(Primary|Valid|Run 0x10|NoProblem; 0x25 is Stop)\n",
                    ds);
            g_fail = 1;
        }
        expect((ds & 0x10) != 0, "t12-6 ProviderState Run bit 0x10");
        expect(PN_DATASTATUS_RUN == 0x10u,
               "PN_DATASTATUS_RUN is ProviderState 0x10, not 0x20");
    }
    pn_stack_destroy(s);
}

/* T12-14. Headers below are what a controller sends. The stack before
 * the fix ignores drep (always LE), rpc_vers, interface UUID, and object
 * UUID, answers the first fragment, has no EPM, and times CMI out at 2 s. */
static const uint8_t k_t1214_obj_le[16] = {
    0x00, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11,
    0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xAB, 0xCD};
static const uint8_t k_t1214_obj_swapped_le[16] = {
    0x00, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11,
    0x82, 0x71, 0x00, 0x01, 0xAB, 0xCD, 0x00, 0x01};
static const uint8_t k_t1214_if_le[16] = {
    0x01, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11,
    0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D};
static const uint8_t k_t1214_obj_be[16] = {
    0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1,
    0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xAB, 0xCD};
static const uint8_t k_t1214_if_be[16] = {
    0xDE, 0xA0, 0x00, 0x01, 0x6C, 0x97, 0x11, 0xD1,
    0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D};
static const uint8_t k_t1214_epm_le[16] = {
    0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11,
    0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA};

static void t1214_w32(uint8_t *p, uint32_t v, int be)
{
    if (be) {
        pn_wr_be32(p, v);
    } else {
        pn_wr_le32(p, v);
    }
}

static void t1214_w16(uint8_t *p, uint16_t v, int be)
{
    if (be) {
        pn_wr_be16(p, v);
    } else {
        pn_wr_le16(p, v);
    }
}

static uint32_t t1214_r32(const uint8_t *p, int be)
{
    return be ? pn_rd_be32(p) : pn_rd_le32(p);
}

static uint16_t t1214_r16(const uint8_t *p, int be)
{
    return be ? pn_rd_be16(p) : pn_rd_le16(p);
}

static size_t t1214_connect_stub(uint8_t *stub, int be, uint16_t factor)
{
    uint8_t ar[50];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    uint16_t body = 26;
    if (factor != 0) {
        pn_wr_be16(ar + 46, factor);
        pn_wr_be16(ar + 48, 0x8892);
        body = 50;
    }
    uint8_t blocks[96];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, body);
    t1214_w32(stub, (uint32_t)bn, be);
    t1214_w32(stub + 4, (uint32_t)bn, be);
    t1214_w32(stub + 8, (uint32_t)bn, be);
    t1214_w32(stub + 12, 0, be);
    t1214_w32(stub + 16, (uint32_t)bn, be);
    memcpy(stub + 20, blocks, bn);
    return 20u + bn;
}

static size_t t1214_req(uint8_t *out, int vers, int be, uint16_t op,
                        const uint8_t *obj, const uint8_t *iface,
                        const uint8_t *stub, size_t slen, uint8_t flags1,
                        uint16_t fragnum, uint32_t seq)
{
    memset(out, 0, 80);
    out[0] = (uint8_t)vers;
    out[2] = flags1;
    out[4] = be ? 0x00 : 0x10;
    if (obj) {
        memcpy(out + 8, obj, 16);
    }
    if (iface) {
        memcpy(out + 24, iface, 16);
    }
    out[40] = 0xA1;
    out[55] = 0x5A;
    t1214_w32(out + 64, seq, be);
    t1214_w16(out + 68, op, be);
    t1214_w16(out + 74, (uint16_t)slen, be);
    t1214_w16(out + 76, fragnum, be);
    memcpy(out + 80, stub, slen);
    return 80u + slen;
}

static void test_t12_14_be_drep(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-14 be create");
    uint8_t stub[160];
    size_t sn = t1214_connect_stub(stub, 1, 0);
    uint8_t pdu[320];
    size_t plen = t1214_req(pdu, 4, 1, 0, k_t1214_obj_be, k_t1214_if_be, stub,
                            sn, 0x20, 0, 1);
    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc == 0 && rlen >= 100 && pn_stack_ar_up(s) == 1, "t12-14 BE Connect");
    if (rlen >= 100) {
        int be = (resp[4] >> 4) != 1;
        uint16_t frag = t1214_r16(resp + 74, be);
        expect(resp[1] == 2, "t12-14 BE ptype response");
        expect(frag == (uint16_t)(rlen - 80), "t12-14 BE fragment length matches drep");
        uint32_t args = t1214_r32(resp + 84, be);
        uint32_t off = t1214_r32(resp + 92, be);
        uint32_t actual = t1214_r32(resp + 96, be);
        expect(off == 0 && args == actual && 100u + args <= rlen,
               "t12-14 BE NDR lengths match drep");
        if (100u + args <= rlen) {
            expect(pn_rd_be16(resp + 100) == 0x8101, "t12-14 BE ARBlockRes");
        }
    }
    pn_stack_destroy(s);
}

static void test_t12_14_rpc_vers_and_uuids(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-14 vers create");
    uint8_t stub[160];
    size_t sn = t1214_connect_stub(stub, 0, 0);
    uint8_t pdu[320];
    uint8_t resp[1024];
    size_t rlen = 0;

    size_t plen = t1214_req(pdu, 1, 0, 0, k_t1214_obj_le, k_t1214_if_le, stub,
                            sn, 0x20, 0, 1);
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc != 0 && rlen == 0 && pn_stack_ar_up(s) == 0,
           "t12-14 rpc_vers 1 rejected");

    uint8_t bad_if[16];
    memset(bad_if, 0x5A, sizeof(bad_if));
    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_le, bad_if, stub, sn, 0x20, 0, 2);
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect((rc != 0 || rlen == 0 || (rlen > 1 && (resp[1] == 3 || resp[1] == 6))) &&
               pn_stack_ar_up(s) == 0,
           "t12-14 unknown interface not served");

    uint8_t bad_obj[16];
    memset(bad_obj, 0x11, sizeof(bad_obj));
    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 0, bad_obj, k_t1214_if_le, stub, sn, 0x20, 0, 3);
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc != 0 && rlen == 0 && pn_stack_ar_up(s) == 0,
           "t12-14 wrong object UUID rejected");

    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_le, k_t1214_if_le, stub, sn, 0x20,
                     0, 4);
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc == 0 && rlen > 80 && pn_stack_ar_up(s) == 1,
           "t12-14 device object UUID (instance, device, vendor) accepted");
    pn_stack_destroy(s);

    s = make_stack();
    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_swapped_le, k_t1214_if_le, stub,
                     sn, 0x20, 0, 5);
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc == 0 && pn_stack_ar_up(s) == 1,
           "t12-14 oracle object tail (instance, vendor, device) accepted");
    pn_stack_destroy(s);
}

static void test_t12_14_fragment_and_epm(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-14 frag create");
    uint8_t stub[160];
    size_t sn = t1214_connect_stub(stub, 0, 0);
    size_t cut = (sn / 2u) & ~7u;
    if (cut == 0 || cut >= sn) {
        cut = 8;
    }
    uint8_t pdu[320];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_le, k_t1214_if_le, stub,
                            cut, 0x2C, 0, 7);
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect((rc != 0 || rlen == 0 || (rlen > 1 && resp[1] == 9)) &&
               pn_stack_ar_up(s) == 0,
           "t12-14 first fragment does not Connect");
    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_le, k_t1214_if_le, stub + cut,
                     sn - cut, 0x2E, 1, 7);
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc == 0 && rlen >= 100 && resp[1] == 2 && pn_stack_ar_up(s) == 1,
           "t12-14 last fragment completes Connect");
    pn_stack_destroy(s);

    s = make_stack();
    uint8_t estub[8];
    memset(estub, 0, sizeof(estub));
    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 2, NULL, k_t1214_epm_le, estub, sizeof(estub),
                     0x20, 0, 1);
    rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    expect(rc == 0 && rlen >= 80 + 28 && resp[1] == 2, "t12-14 EPM lookup response");
    if (rlen >= 80 + 28) {
        const uint8_t *body = resp + 80;
        size_t blen = rlen - 80;
        int be = (resp[4] >> 4) != 1;
        uint32_t nent = t1214_r32(body + 20, be);
        expect(nent >= 1, "t12-14 EPM num_ents");
        int found = 0;
        for (size_t i = 0; i + 16 <= blen; i++) {
            if (memcmp(body + i, k_t1214_if_le, 16) == 0) {
                found = 1;
                break;
            }
        }
        expect(found, "t12-14 EPM tower has PNIO Device interface");
        expect(t1214_r32(body + blen - 4, be) == 0, "t12-14 EPM status 0");
    }
    pn_stack_destroy(s);
}

static void test_t12_14_activity_timeout(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-14 cmi create");
    uint8_t stub[160];
    size_t sn = t1214_connect_stub(stub, 0, 600);
    uint8_t pdu[320];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_le, k_t1214_if_le, stub,
                            sn, 0x20, 0, 1);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-14 factor 600 connect");
    expect(s->ar.cmi_activity_factor == 600, "t12-14 stored ActivityTimeoutFactor 600");
    s->ar.last_cmi_ns = pn_now_ns() - (3ull * 1000000000ull);
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 1, "t12-14 60 s window survives 3 s of silence");
    pn_stack_destroy(s);

    s = make_stack();
    sn = t1214_connect_stub(stub, 0, 1);
    rlen = 0;
    plen = t1214_req(pdu, 4, 0, 0, k_t1214_obj_le, k_t1214_if_le, stub, sn, 0x20,
                     0, 1);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-14 factor 1 connect");
    expect(s->ar.cmi_activity_factor == 1, "t12-14 stored ActivityTimeoutFactor 1");
    s->ar.last_cmi_ns = pn_now_ns() - 50000000ull; /* 50 ms */
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 1, "t12-14 100 ms window keeps 50 ms silence");
    s->ar.last_cmi_ns = pn_now_ns() - 150000000ull; /* 150 ms */
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "t12-14 100 ms window aborts after 150 ms");
    pn_stack_destroy(s);
}

int main(void)
{
    test_t12_14_be_drep();
    test_t12_14_rpc_vers_and_uuids();
    test_t12_14_fragment_and_epm();
    test_t12_14_activity_timeout();
    test_t12_5_prm_end_and_app_ready();
    test_t12_5_app_ready_dest_rpc_port();
    test_t12_6_rtc1_datastatus_run();
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
