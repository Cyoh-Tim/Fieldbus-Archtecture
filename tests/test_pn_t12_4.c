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

/* T12-4 repro. Connect carries the oracle IOCR layout (scapy pnio_rpc):
 * input C_SDU DataLength 40, (1,1) input data at FrameOffset 3, IOPS at 35,
 * output-submodule IOCS at 36. Output (1,1) data is at FrameOffset 4 so a
 * fixed copy from C_SDU byte 0 is visibly wrong. ExpectedSubmodule slot 1
 * ModuleIdent 0xDEADBEEF must produce ModuleDiffBlock 0x8104. This AR
 * has no ARProperties, so StartupMode is Legacy and ARServerBlock
 * 0x8106 must be absent. NO_IO submodules carry one Input
 * DataDescription (0001 0000 01 01). */
static uint8_t g_t124_tx[4][PN_FRAME_MAX];
static size_t g_t124_txlen[4];
static int g_t124_ntx;

static int t124_cap_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (g_t124_ntx < 4 && len <= sizeof(g_t124_tx[0])) {
        memcpy(g_t124_tx[g_t124_ntx], frame, len);
        g_t124_txlen[g_t124_ntx] = len;
        g_t124_ntx++;
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

/* ExpectedSubmoduleBlockReq, slot 1 ModuleIdent 0x00000010 (GSDML MOD_IO).
 * Each NO_IO submodule (type 0) is followed by one Input DataDescription
 * 0001 0000 01 01. INPUT_OUTPUT (type 3) has two. */
static const uint8_t k_exp_mod10[] = {
    0x01, 0x04, 0x00, 0x5e, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11,
    0x00, 0x03, 0x00, 0x01, 0x00, 0x20, 0x01, 0x01, 0x00, 0x02, 0x00, 0x20,
    0x01, 0x01};

/* Same block with slot 1 ModuleIdent 0xDEADBEEF. */
static const uint8_t k_exp_dead[] = {
    0x01, 0x04, 0x00, 0x5e, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad,
    0xbe, 0xef, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11,
    0x00, 0x03, 0x00, 0x01, 0x00, 0x20, 0x01, 0x01, 0x00, 0x02, 0x00, 0x20,
    0x01, 0x01};

/* Only the plugged GSDML submodules: (0, 0x8000, ident 2) and (1, 1, ident 0x11). */
static const uint8_t k_exp_match[] = {
    0x01, 0x04, 0x00, 0x42, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x20, 0x01, 0x01, 0x00, 0x02, 0x00, 0x20, 0x01, 0x01};

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

/* Same Connect with a full ARBlockReq. ARProperties is at body offset 42.
 * Bit 30 is StartupMode (1 = Advanced). */
static size_t build_iocr_connect_props(uint8_t *pdu, const uint8_t *exp,
                                       size_t explen, uint32_t ar_props)
{
    uint8_t blocks[512];
    size_t bn = 0;
    uint8_t ar[46];
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
    pn_wr_be32(ar + 42, ar_props);
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
    pn_eth_ops_t ops = {.send = t124_cap_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    expect(pn_stack_start(s) == 0, "t12-4 start");
    g_t124_ntx = 0;

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
    expect(srv == NULL,
           "t12-4 Legacy Connect must not include ARServerBlock 0x8106");

    uint8_t pat[32];
    for (int i = 0; i < 32; i++) {
        pat[i] = (uint8_t)(0x10 + i);
    }
    expect(pn_stack_write_input(s, 0, pat, sizeof(pat)) == 0, "t12-4 write input");
    g_t124_ntx = 0;
    pn_rt_send_if_due(s);

    const uint8_t *pay = NULL;
    size_t paylen = 0;
    int saw = 0;
    for (int i = 0; i < g_t124_ntx; i++) {
        /* RTC1 is 802.1Q-tagged: TPID at 12, EtherType at 16, FrameID at 18. */
        size_t fid_off = 14;
        if (g_t124_txlen[i] >= 18 &&
            pn_rd_be16(g_t124_tx[i] + 12) == PN_ETHTYPE_VLAN) {
            fid_off = 18;
        }
        if (g_t124_txlen[i] >= fid_off + 2 &&
            pn_rd_be16(g_t124_tx[i] + fid_off - 2) == PN_ETHTYPE_PN &&
            pn_rd_be16(g_t124_tx[i] + fid_off) == 0x8001) {
            pay = g_t124_tx[i] + fid_off;
            paylen = g_t124_txlen[i] - fid_off;
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

/* ARServerBlock(0x8106) only when ARProperties.StartupMode=Advanced (bit 30).
 * Legacy (0x00000011) must omit it; Advanced (0x40000011) must include the
 * station name. */
static void test_t12_4_arserver_only_advanced(void)
{
    uint8_t pdu[768];
    uint8_t resp[2048];
    size_t rlen = 0;
    size_t blen = 0;

    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-4 legacy-props create");
    size_t plen = build_iocr_connect_props(pdu, k_exp_match, sizeof(k_exp_match),
                                           0x00000011u);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-4 legacy-props connect");
    const uint8_t *srv = find_rsp_block(resp, rlen, 0x8106, &blen);
    expect(srv == NULL,
           "t12-4 Legacy ARProperties must not include ARServerBlock 0x8106");
    pn_stack_destroy(s);

    s = make_stack();
    expect(s != NULL, "t12-4 advanced create");
    rlen = 0;
    plen = build_iocr_connect_props(pdu, k_exp_match, sizeof(k_exp_match),
                                    0x40000011u);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-4 advanced connect");
    blen = 0;
    srv = find_rsp_block(resp, rlen, 0x8106, &blen);
    expect(srv != NULL, "t12-4 Advanced Connect missing ARServerBlock 0x8106");
    if (srv && blen >= 8) {
        uint16_t nlen = pn_rd_be16(srv + 6);
        expect(nlen == 8 && blen >= 16 && memcmp(srv + 8, "rpc-test", 8) == 0,
               "t12-4 Advanced ARServer station name");
    }
    pn_stack_destroy(s);
}

int main(void)
{
    test_t12_4_iocr_offsets_and_blocks();
    test_t12_4_arserver_only_advanced();
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_4: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_4: OK\n");
    return 0;
}
