/*
 * PROFINET Ethernet (DCP / RTC1 / alarm) fuzzer — CC-B RT Class 1 only.
 *
 * The original harness injected raw frames with security_class=0 and no AR.
 * RTC1 only runs when dest MAC is ours and FrameID == AR.out_frame_id
 * (pn_rt.c ~3%). DCP Set HMAC (pn_sec.c) needs security_class=1 + PSK.
 *
 * Byte 0 selects a mode. Connect (via handle_rpc) establishes the AR, then
 * ETH frames use the station MAC / DCP multicast and the live O→T FrameID.
 *
 * Each input restores NameOfStation "fuzz" and a zero IP on g_open. Mode 2
 * (and a stitched DCP Set) otherwise latches the name, and the next
 * Identify-by-name matches nothing.
 */
#include "pn_crypto.h"
#include "pn_endian.h"
#include "pn_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUZZ_IN  32
#define FUZZ_OUT 8
#define OP_CONNECT 0
#define OP_CONTROL 4

static const uint8_t k_mac_dev[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
static const uint8_t k_mac_ctl[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x02};
static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
static const uint8_t k_psk[PN_PSK_LEN] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

static pn_stack_t *g_open;
static pn_stack_t *g_sec;
static pn_stack_t *g_enf;

static uint8_t u8_at(const uint8_t *p, size_t n, size_t i, uint8_t d)
{
    return i < n ? p[i] : d;
}

static void fill_uuid(uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = (uint8_t)(0xA0 + i);
    }
}

static int dummy_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    (void)frame;
    return (int)len;
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

static size_t wrap_rpc(uint8_t *out, size_t cap, uint16_t op, const uint8_t *stub,
                       size_t slen)
{
    if (cap < 80 + slen) {
        return 0;
    }
    memset(out, 0, 80);
    out[0] = 4;
    out[4] = 0x10;
    static const uint8_t obj[16] = {
        0x00, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xab, 0xcd};
    static const uint8_t iface[16] = {
        0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d};
    memcpy(out + 8, obj, 16);
    memcpy(out + 24, iface, 16);
    pn_wr_le16(out + 68, op);
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

static void feed_rpc(pn_stack_t *s, const uint8_t *pdu, size_t n)
{
    uint8_t resp[1024];
    size_t rlen = 0;
    (void)pn_stack_handle_rpc(s, pdu, n, resp, sizeof(resp), &rlen);
}

static void do_connect(pn_stack_t *s, int hmac)
{
    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[26];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_uuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, k_mac_ctl, 6);
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));

    uint8_t iocr_out[32];
    memset(iocr_out, 0, sizeof(iocr_out));
    pn_wr_be16(iocr_out, PN_IOCR_OUTPUT);
    pn_wr_be16(iocr_out + 10, (uint16_t)(FUZZ_OUT + 1));
    pn_wr_be16(iocr_out + 12, 0x8002);
    pn_wr_be16(iocr_out + 14, 32);
    pn_wr_be16(iocr_out + 16, 8);
    pn_wr_be16(iocr_out + 26, 3);
    pn_wr_be16(iocr_out + 28, 3);
    bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr_out, sizeof(iocr_out));

    uint8_t iocr_in[18];
    memset(iocr_in, 0, sizeof(iocr_in));
    pn_wr_be16(iocr_in, PN_IOCR_INPUT);
    pn_wr_be16(iocr_in + 10, (uint16_t)(FUZZ_IN + 1));
    pn_wr_be16(iocr_in + 12, 0x8001);
    bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr_in, sizeof(iocr_in));

    if (hmac) {
        uint8_t mac[PN_HMAC_LEN];
        pn_hmac_sha256(k_psk, PN_PSK_LEN, blocks, bn, mac);
        uint8_t sec[2 + PN_HMAC_LEN];
        pn_wr_be16(sec, 0x0001);
        memcpy(sec + 2, mac, PN_HMAC_LEN);
        bn += wr_block(blocks + bn, PN_BLOCK_SEC_INT, sec, sizeof(sec));
    }

    uint8_t stub[320];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t pdu[400];
    size_t n = wrap_rpc(pdu, sizeof(pdu), OP_CONNECT, stub, sn);
    if (n) {
        feed_rpc(s, pdu, n);
    }
}

static void do_prmend(pn_stack_t *s)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    fill_uuid(body + 2);
    pn_wr_be16(body + 22, PN_CONTROL_PRM_END);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, body, sizeof(body));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t pdu[256];
    size_t n = wrap_rpc(pdu, sizeof(pdu), OP_CONTROL, stub, sn);
    if (n) {
        feed_rpc(s, pdu, n);
    }
    uint8_t tx[256];
    size_t tn = 0;
    (void)pn_stack_take_rpc_tx(s, tx, sizeof(tx), &tn);
}

static void ensure_ar(pn_stack_t *s, int hmac)
{
    if (!pn_stack_ar_up(s)) {
        do_connect(s, hmac);
    }
}

static size_t wrap_eth(uint8_t *out, size_t cap, const uint8_t dst[6],
                       const uint8_t src[6], const uint8_t *pay, size_t plen)
{
    return pn_eth_build(out, cap, dst, src, PN_ETHTYPE_PN, pay, plen);
}

static void inject_rtc1(pn_stack_t *s, const uint8_t *data, size_t dlen)
{
    uint8_t pay[2 + FUZZ_OUT + 8];
    pn_wr_be16(pay, 0x8002);
    memset(pay + 2, 0x5A, FUZZ_OUT);
    if (dlen) {
        memcpy(pay + 2, data, dlen < FUZZ_OUT ? dlen : FUZZ_OUT);
    }
    size_t n = 2u + FUZZ_OUT;
    pay[n++] = PN_IOPS_GOOD;
    pn_wr_be16(pay + n, 1);
    n += 2;
    pay[n++] = (uint8_t)(PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                         PN_DATASTATUS_RUN);
    pay[n++] = 0;
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = wrap_eth(frame, sizeof(frame), k_mac_dev, k_mac_ctl, pay, n);
    if (flen) {
        (void)pn_stack_handle_eth(s, frame, flen);
    }
}

static size_t dcp_hdr(uint8_t *pay, uint16_t fid, uint8_t svc, uint32_t xid,
                      const uint8_t *blocks, size_t bn)
{
    pn_wr_be16(pay, fid);
    pay[2] = svc;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    if (bn) {
        memcpy(pay + 12, blocks, bn);
    }
    return 12 + bn;
}

static size_t dcp_block(uint8_t *p, uint8_t opt, uint8_t sub, const uint8_t *d,
                        uint16_t dlen)
{
    p[0] = opt;
    p[1] = sub;
    pn_wr_be16(p + 2, dlen);
    if (dlen) {
        memcpy(p + 4, d, dlen);
    }
    size_t n = 4u + dlen;
    if (dlen & 1u) {
        p[n++] = 0;
    }
    return n;
}

static void inject_dcp(pn_stack_t *s, const uint8_t dst[6], uint16_t fid,
                       uint8_t svc, const uint8_t *blocks, size_t bn)
{
    uint8_t pay[256];
    size_t plen = dcp_hdr(pay, fid, svc, 0xAABBCCDD, blocks, bn);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = wrap_eth(frame, sizeof(frame), dst, k_mac_ctl, pay, plen);
    if (flen) {
        (void)pn_stack_handle_eth(s, frame, flen);
    }
}

static void inject_dcp_set_signed(pn_stack_t *s, int bad)
{
    uint8_t nameblk[2 + 8];
    pn_wr_be16(nameblk, 1);
    memcpy(nameblk + 2, "fuzz-ok", 7);
    uint8_t blocks[128];
    size_t bn = dcp_block(blocks, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, nameblk,
                          9);
    uint8_t pay[256];
    size_t plen = dcp_hdr(pay, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, 0xAABBCCDD,
                          blocks, bn);
    uint8_t mac[PN_HMAC_LEN];
    pn_hmac_sha256(k_psk, PN_PSK_LEN, pay, plen, mac);
    if (bad) {
        mac[0] ^= 0xFF;
    }
    bn += dcp_block(blocks + bn, PN_DCP_OPT_SEC, PN_DCP_SUB_SEC_HMAC, mac,
                    PN_HMAC_LEN);
    plen = dcp_hdr(pay, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, 0xAABBCCDD, blocks,
                   bn);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = wrap_eth(frame, sizeof(frame), k_mac_dev, k_mac_ctl, pay, plen);
    if (flen) {
        (void)pn_stack_handle_eth(s, frame, flen);
    }
}

static void stitch_eth(pn_stack_t *s, const uint8_t *data, size_t n, int rtc)
{
    uint8_t buf[PN_FRAME_MAX];
    if (n > sizeof(buf)) {
        n = sizeof(buf);
    }
    if (n < 14) {
        (void)pn_stack_handle_eth(s, data, n);
        return;
    }
    memcpy(buf, data, n);
    uint16_t et = pn_rd_be16(buf + 12);
    if (et == PN_ETHTYPE_PN && n >= 16) {
        uint16_t fid = pn_rd_be16(buf + 14);
        if (fid == PN_FRAMEID_DCP_ID_REQ || fid == PN_FRAMEID_DCP_HELLO) {
            memcpy(buf, k_dcp_mc, 6);
        } else {
            memcpy(buf, k_mac_dev, 6);
        }
        memcpy(buf + 6, k_mac_ctl, 6);
        if (rtc && fid != PN_FRAMEID_DCP_ID_REQ && fid != PN_FRAMEID_DCP_GETSET &&
            fid != PN_FRAMEID_DCP_HELLO) {
            pn_wr_be16(buf + 14, 0x8002);
        }
    }
    (void)pn_stack_handle_eth(s, buf, n);
}

static pn_stack_t *make_stack(int sec, int enforce)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "fuzz");
    memcpy(cfg.mac, k_mac_dev, 6);
    cfg.mac_set = 1;
    cfg.input_len = FUZZ_IN;
    cfg.output_len = FUZZ_OUT;
    cfg.cycle_us = 8000;
    if (sec) {
        cfg.security_class = PN_VENDOR_INTEGRITY;
        memcpy(cfg.psk, k_psk, PN_PSK_LEN);
        cfg.psk_set = 1;
    }
    cfg.enforce_security_class = enforce ? 1 : 0;
    if (enforce && !sec) {
        cfg.security_class = PN_VENDOR_INTEGRITY;
        memcpy(cfg.psk, k_psk, PN_PSK_LEN);
        cfg.psk_set = 1;
    }
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    pn_eth_ops_t ops = {.send = dummy_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    (void)pn_stack_start(s);
    return s;
}

static void restore_open_cfg(void)
{
    const pn_cfg_t *c;
    if (!g_open) {
        return;
    }
    c = pn_stack_cfg(g_open);
    if (!c) {
        return;
    }
    if (strcmp(c->station_name, "fuzz") != 0) {
        uint8_t sblk[2 + 8];
        uint8_t blocks[24];
        size_t bn;
        memset(sblk, 0, sizeof(sblk));
        pn_wr_be16(sblk, 1);
        memcpy(sblk + 2, "fuzz", 4);
        bn = dcp_block(blocks, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, sblk, 6);
        inject_dcp(g_open, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, blocks,
                   bn);
    }
    if (c->ip || c->netmask || c->gateway) {
        uint8_t ipblk[14];
        uint8_t blocks[24];
        size_t bn;
        memset(ipblk, 0, sizeof(ipblk));
        pn_wr_be16(ipblk, 1);
        bn = dcp_block(blocks, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipblk, 14);
        inject_dcp(g_open, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, blocks,
                   bn);
    }
}

static int fuzz_init(void)
{
    g_open = make_stack(0, 0);
    g_sec = make_stack(1, 0);
    g_enf = make_stack(1, 1);
    return (g_open && g_sec && g_enf) ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_open && fuzz_init() != 0) {
        return 0;
    }
    restore_open_cfg();
    if (size == 0) {
        ensure_ar(g_open, 0);
        return 0;
    }

    uint8_t mode = (uint8_t)(data[0] & 7u);
    const uint8_t *p = data + 1;
    size_t plen = size - 1;

    switch (mode) {
    case 0: /* raw / dest-MAC stitch (legacy corpus) */
        stitch_eth(g_open, p, plen, 0);
        break;
    case 1: { /* DCP Identify All on multicast */
        uint8_t blk[4] = {0xFF, 0xFF, 0x00, 0x00};
        inject_dcp(g_open, k_dcp_mc, PN_FRAMEID_DCP_ID_REQ, PN_DCP_IDENTIFY, blk,
                   4);
        break;
    }
    case 2: { /* DCP Identify name + Get + unsigned Set / IP / Signal (class 0) */
        uint8_t nblk[8];
        memcpy(nblk, "fuzz", 4);
        uint8_t blocks[48];
        size_t bn = dcp_block(blocks, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, nblk,
                              4);
        inject_dcp(g_open, k_dcp_mc, PN_FRAMEID_DCP_ID_REQ, PN_DCP_IDENTIFY,
                   blocks, bn);
        uint8_t gblk[4] = {PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, 0, 0};
        inject_dcp(g_open, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_GET, gblk, 4);
        uint8_t sblk[2 + 8];
        pn_wr_be16(sblk, 1);
        memcpy(sblk + 2, "fuzz2", 5);
        bn = dcp_block(blocks, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, sblk, 7);
        inject_dcp(g_open, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, blocks,
                   bn);
        uint8_t ipblk[2 + 12];
        memset(ipblk, 0, sizeof(ipblk));
        pn_wr_be16(ipblk, 1);
        ipblk[2] = 10;
        ipblk[5] = 20;
        ipblk[6] = 255;
        ipblk[7] = 255;
        ipblk[8] = 255;
        ipblk[9] = 0;
        bn = dcp_block(blocks, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipblk, 14);
        inject_dcp(g_open, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, blocks,
                   bn);
        uint8_t sig[2 + 2];
        pn_wr_be16(sig, 1);
        pn_wr_be16(sig + 2, 0x0100);
        bn = dcp_block(blocks, PN_DCP_OPT_CTRL, PN_DCP_SUB_CTRL_SIGNAL, sig, 4);
        inject_dcp(g_open, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, blocks,
                   bn);
        inject_dcp(g_open, k_dcp_mc, PN_FRAMEID_DCP_HELLO, PN_DCP_HELLO, NULL,
                   0);
        break;
    }
    case 3: { /* DCP Set HMAC on class=1 / enforce_security_class */
        pn_stack_t *st = (u8_at(p, plen, 1, 0) & 1u) ? g_enf : g_sec;
        switch (u8_at(p, plen, 0, 0) & 3u) {
        case 0: {
            uint8_t sblk[2 + 8];
            pn_wr_be16(sblk, 1);
            memcpy(sblk + 2, "nohmac", 6);
            uint8_t blocks[16];
            size_t bn =
                dcp_block(blocks, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, sblk, 8);
            inject_dcp(st, k_mac_dev, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, blocks,
                       bn);
            break;
        }
        case 1:
            inject_dcp_set_signed(st, 1);
            break;
        default:
            inject_dcp_set_signed(st, 0);
            break;
        }
        break;
    }
    case 4: /* AR + RTC1 (pn_rt consume) */
        ensure_ar(g_open, 0);
        inject_rtc1(g_open, p, plen);
        pn_stack_poll(g_open);
        break;
    case 5: /* PrmEnd + RTC1 + poll (data-hold / produce) */
        ensure_ar(g_open, 0);
        do_prmend(g_open);
        inject_rtc1(g_open, p, plen);
        pn_stack_poll(g_open);
        break;
    case 6: { /* alarm TX + inject Alarm High/Low looking frames */
        ensure_ar(g_open, 0);
        (void)pn_stack_send_alarm(g_open);
        (void)pn_stack_send_alarm_ex(g_open, PN_FRAMEID_ALARM_LOW);
        uint8_t pay[32];
        memset(pay, 0, sizeof(pay));
        pn_wr_be16(pay, (u8_at(p, plen, 0, 0) & 1) ? PN_FRAMEID_ALARM_LOW
                                                   : PN_FRAMEID_ALARM_HIGH);
        uint8_t frame[PN_FRAME_MAX];
        size_t flen = wrap_eth(frame, sizeof(frame), k_mac_dev, k_mac_ctl, pay,
                               sizeof(pay));
        if (flen) {
            (void)pn_stack_handle_eth(g_open, frame, flen);
        }
        break;
    }
    default: /* stitch fuzzed ETH onto AR + RTC1 FrameID */
        ensure_ar(g_open, 0);
        stitch_eth(g_open, p, plen, 1);
        inject_rtc1(g_open, p, plen);
        ensure_ar(g_sec, 1);
        inject_dcp_set_signed(g_sec, 0);
        ensure_ar(g_enf, 1);
        inject_dcp_set_signed(g_enf, 0);
        break;
    }
    return 0;
}
