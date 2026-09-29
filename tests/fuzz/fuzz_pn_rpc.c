/*
 * PROFINET CM (DCE/RPC) fuzzer — CC-B RT Class 1 only.
 *
 * The original harness dumped raw UDP payloads into pn_stack_handle_rpc()
 * with no AR. Connect rarely parsed, so Write/PrmEnd/AppReady/Release and
 * Security Class 1 HMAC never ran. pn_rt.c stayed dark (no IOCR / no ETH).
 *
 * Byte 0 selects a mode. A live AR is kept via a valid Connect (AR + IOCR
 * input/output + AlarmCR + ExpectedSubmodule). A second stack runs
 * security_class=1 + PSK so pn_sec.c is exercised.
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
#define OP_RELEASE 1
#define OP_READ    2
#define OP_WRITE   3
#define OP_CONTROL 4

static const uint8_t k_mac_dev[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
static const uint8_t k_mac_ctl[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x02};
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
    out[0] = 1;
    out[1] = 0;
    pn_wr_le16(out + 68, op);
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

static void feed_rpc(pn_stack_t *s, const uint8_t *pdu, size_t n)
{
    uint8_t resp[2048];
    size_t rlen = 0;
    (void)pn_stack_handle_rpc(s, pdu, n, resp, sizeof(resp), &rlen);
}

static size_t build_connect_blocks(uint8_t *blocks, size_t cap, int with_hmac,
                                   int hmac_bad, const uint8_t *mut, size_t mlen)
{
    size_t bn = 0;
    uint16_t out_fid = 0x8002;
    uint16_t in_fid = 0x8001;
    uint16_t sc = 32;
    uint16_t rr = 8;
    uint16_t dhold = 3;
    uint16_t out_dl = (uint16_t)(FUZZ_OUT + 1);
    uint16_t in_dl = (uint16_t)(FUZZ_IN + 1);
    if (mlen >= 2) {
        uint16_t v = (uint16_t)(((uint16_t)mut[0] << 8) | mut[1]);
        if (v != 0) {
            out_fid = v;
        }
    }
    if (mlen >= 4) {
        uint16_t v = (uint16_t)(((uint16_t)mut[2] << 8) | mut[3]);
        if (v != 0) {
            in_fid = v;
        }
    }
    if (mlen >= 5 && mut[4] != 0) {
        sc = mut[4];
    }
    if (mlen >= 6 && mut[5] != 0) {
        rr = mut[5];
    }
    if (mlen >= 7 && mut[6] != 0) {
        dhold = mut[6];
    }
    if (mlen >= 8 && mut[7] != 0) {
        out_dl = (uint16_t)((mut[7] % (FUZZ_OUT + 1u)) + 1u);
    }

    uint8_t ar[42];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_uuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, k_mac_ctl, 6);
    for (int i = 0; i < 16; i++) {
        ar[26 + i] = (uint8_t)(0x40 + i);
    }
    bn += wr_block(blocks + bn, PN_BLOCK_AR_REQ, ar, 42);

    uint8_t iocr_in[18];
    memset(iocr_in, 0, sizeof(iocr_in));
    pn_wr_be16(iocr_in, PN_IOCR_INPUT);
    pn_wr_be16(iocr_in + 2, 1);
    pn_wr_be16(iocr_in + 10, in_dl);
    pn_wr_be16(iocr_in + 12, in_fid);
    pn_wr_be16(iocr_in + 14, 32);
    pn_wr_be16(iocr_in + 16, 8);
    bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr_in, sizeof(iocr_in));

    uint8_t iocr_out[32];
    memset(iocr_out, 0, sizeof(iocr_out));
    pn_wr_be16(iocr_out, PN_IOCR_OUTPUT);
    pn_wr_be16(iocr_out + 2, 2);
    pn_wr_be16(iocr_out + 10, out_dl);
    pn_wr_be16(iocr_out + 12, out_fid);
    pn_wr_be16(iocr_out + 14, sc);
    pn_wr_be16(iocr_out + 16, rr);
    pn_wr_be16(iocr_out + 26, 3);
    pn_wr_be16(iocr_out + 28, dhold);
    bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, iocr_out, sizeof(iocr_out));

    uint8_t alarm[8];
    memset(alarm, 0, sizeof(alarm));
    pn_wr_be16(alarm, 0x0001);
    pn_wr_be16(alarm + 2, 1);
    pn_wr_be16(alarm + 4, 200);
    pn_wr_be16(alarm + 6, 0x00A0);
    bn += wr_block(blocks + bn, PN_BLOCK_ALARMCR_REQ, alarm, sizeof(alarm));

    uint8_t exp[16];
    memset(exp, 0, sizeof(exp));
    pn_wr_be16(exp, 0);
    pn_wr_be16(exp + 2, 1);
    pn_wr_be32(exp + 4, 0);
    pn_wr_be16(exp + 8, 0x0001);
    pn_wr_be16(exp + 10, FUZZ_IN);
    bn += wr_block(blocks + bn, PN_BLOCK_EXPSUB_REQ, exp, sizeof(exp));

    if (with_hmac) {
        uint8_t mac[PN_HMAC_LEN];
        pn_hmac_sha256(k_psk, PN_PSK_LEN, blocks, bn, mac);
        if (hmac_bad) {
            mac[0] ^= 0xFF;
        }
        uint8_t sec[2 + PN_HMAC_LEN];
        pn_wr_be16(sec, 0x0001);
        memcpy(sec + 2, mac, PN_HMAC_LEN);
        bn += wr_block(blocks + bn, PN_BLOCK_SEC_INT, sec, sizeof(sec));
    }
    if (bn > cap) {
        return 0;
    }
    return bn;
}

static size_t build_connect_pdu(uint8_t *pdu, size_t cap, int with_hmac,
                                int hmac_bad, const uint8_t *mut, size_t mlen)
{
    uint8_t blocks[512];
    size_t bn = build_connect_blocks(blocks, sizeof(blocks), with_hmac, hmac_bad,
                                     mut, mlen);
    if (!bn) {
        return 0;
    }
    uint8_t stub[600];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, cap, OP_CONNECT, stub, sn);
}

static void do_connect(pn_stack_t *s, int hmac, int hmac_bad, const uint8_t *mut,
                       size_t mlen)
{
    uint8_t pdu[800];
    size_t n = build_connect_pdu(pdu, sizeof(pdu), hmac, hmac_bad, mut, mlen);
    if (n) {
        feed_rpc(s, pdu, n);
    }
}

static void ensure_ar(pn_stack_t *s, int hmac)
{
    if (!pn_stack_ar_up(s)) {
        do_connect(s, hmac, 0, NULL, 0);
    }
}

static void do_write(pn_stack_t *s, uint16_t index, const uint8_t *data,
                     size_t dlen)
{
    if (dlen > 64) {
        dlen = 64;
    }
    uint8_t body[34 + 64];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1);
    fill_uuid(body + 2);
    pn_wr_be16(body + 22, 0);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, index);
    pn_wr_be32(body + 30, (uint32_t)dlen);
    if (dlen) {
        memcpy(body + 34, data, dlen);
    }
    uint8_t blocks[160];
    size_t bn = wr_block(blocks, PN_BLOCK_IOD_WRITE_REQ, body,
                         (uint16_t)(34 + dlen));
    uint8_t stub[200];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t pdu[320];
    size_t n = wrap_rpc(pdu, sizeof(pdu), OP_WRITE, stub, sn);
    if (n) {
        feed_rpc(s, pdu, n);
    }
}

static void do_read(pn_stack_t *s, uint16_t index)
{
    uint8_t body[30];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1);
    fill_uuid(body + 2);
    pn_wr_be16(body + 22, 0);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, index);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_IOD_READ_REQ, body, sizeof(body));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t pdu[256];
    size_t n = wrap_rpc(pdu, sizeof(pdu), OP_READ, stub, sn);
    if (n) {
        feed_rpc(s, pdu, n);
    }
}

static void do_control(pn_stack_t *s, uint16_t cmd)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    fill_uuid(body + 2);
    pn_wr_be16(body + 18, 1);
    pn_wr_be16(body + 22, cmd);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, body, sizeof(body));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t pdu[256];
    size_t n = wrap_rpc(pdu, sizeof(pdu), OP_CONTROL, stub, sn);
    if (n) {
        feed_rpc(s, pdu, n);
    }
    uint8_t tx[512];
    size_t tn = 0;
    (void)pn_stack_take_rpc_tx(s, tx, sizeof(tx), &tn);
}

static void do_release(pn_stack_t *s)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    fill_uuid(body + 2);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, body, 18);
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    uint8_t pdu[256];
    size_t n = wrap_rpc(pdu, sizeof(pdu), OP_RELEASE, stub, sn);
    if (n) {
        feed_rpc(s, pdu, n);
    }
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
        cfg.security_class = PN_SECURITY_CLASS_1;
        memcpy(cfg.psk, k_psk, PN_PSK_LEN);
        cfg.psk_set = 1;
    }
    cfg.enforce_security_class = enforce ? 1 : 0;
    if (enforce && !sec) {
        /* create() refuses class 0 + enforce; class 1 + PSK is the valid pair. */
        cfg.security_class = PN_SECURITY_CLASS_1;
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

static int fuzz_init(void)
{
    g_open = make_stack(0, 0);
    g_sec = make_stack(1, 0);
    g_enf = make_stack(1, 1);
    return (g_open && g_sec && g_enf) ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint16_t k_idx[] = {PN_INDEX_IM0, PN_INDEX_IM1, PN_INDEX_IM2,
                                     PN_INDEX_IM3, PN_INDEX_IM4, 0x8000};

    if (!g_open && fuzz_init() != 0) {
        return 0;
    }
    if (size == 0) {
        ensure_ar(g_open, 0);
        return 0;
    }

    uint8_t mode = (uint8_t)(data[0] & 7u);
    const uint8_t *p = data + 1;
    size_t plen = size - 1;
    uint8_t pdu[2048];

    switch (mode) {
    case 0: /* raw (legacy corpus) */
        feed_rpc(g_open, p, plen);
        break;
    case 1: /* valid Connect (mutated IOCR) then remaining bytes as the next RPC */
        ensure_ar(g_open, 0);
        do_connect(g_open, 0, 0, p, plen);
        if (plen >= 80) {
            size_t n = plen > sizeof(pdu) ? sizeof(pdu) : plen;
            memcpy(pdu, p, n);
            pdu[0] = 1;
            pdu[1] = 0;
            feed_rpc(g_open, pdu, n);
        } else if (plen) {
            feed_rpc(g_open, p, plen);
        }
        break;
    case 2: /* Write parameter record */
        ensure_ar(g_open, 0);
        do_write(g_open, k_idx[u8_at(p, plen, 0, 1) % 6u], p, plen);
        break;
    case 3: /* Read I&M */
        ensure_ar(g_open, 0);
        do_read(g_open, k_idx[u8_at(p, plen, 0, 0) % 6u]);
        break;
    case 4: /* PrmEnd → ApplicationReady indication */
        ensure_ar(g_open, 0);
        do_write(g_open, PN_INDEX_IM1, p, plen > 8 ? 8 : plen);
        do_control(g_open, PN_CONTROL_PRM_END);
        break;
    case 5: /* AppReady control + raw follow-up */
        ensure_ar(g_open, 0);
        do_control(g_open, PN_CONTROL_PRM_END);
        do_control(g_open, PN_CONTROL_APP_READY);
        if (plen >= 2) {
            feed_rpc(g_open, p, plen);
        }
        break;
    case 6: /* Release then re-Connect */
        ensure_ar(g_open, 0);
        do_release(g_open);
        do_connect(g_open, 0, 0, p, plen);
        break;
    default: { /* security_class=1 / enforce_security_class HMAC Connect */
        pn_stack_t *st = (u8_at(p, plen, 1, 0) & 1u) ? g_enf : g_sec;
        switch (u8_at(p, plen, 0, 0) & 3u) {
        case 0:
            do_connect(st, 0, 0, NULL, 0); /* missing HMAC → reject */
            break;
        case 1:
            do_connect(st, 1, 1, p, plen); /* bad HMAC */
            break;
        default:
            do_connect(st, 1, 0, p, plen);
            do_write(st, PN_INDEX_IM1, p, plen > 4 ? 4 : plen);
            do_control(st, PN_CONTROL_PRM_END);
            break;
        }
        break;
    }
    }
    return 0;
}
