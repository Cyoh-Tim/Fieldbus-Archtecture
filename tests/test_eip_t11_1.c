/*
 * T11-1: O→T 32-bit Run/Idle header.
 *
 * Standard Exclusive Owner O→T size is application data + 2 (CIP sequence)
 * + 4 (Run/Idle). A 2-byte output assembly is NCP size 8 (0x4808). The
 * stack must accept that Forward Open, copy only the assembly bytes into
 * the output image, and clear outputs when Run/Idle bit 0 is 0 (PROGRAM).
 *
 * Before the fix the same request is rejected:
 *   D4 00 20 01 09 01
 *   (Forward Open reply, general 0x20, extended 0x0109).
 */
#include "eip_endian.h"
#include "eip_stack.h"

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

static void expect_cip(const uint8_t *cip, size_t n, uint8_t status,
                       const char *msg)
{
    if (n >= 3 && cip[2] == status) {
        return;
    }
    fprintf(stderr, "FAIL: %s (cip", msg);
    for (size_t i = 0; i < n && i < 24; i++) {
        fprintf(stderr, " %02X", cip[i]);
    }
    fprintf(stderr, ")\n");
    g_fail = 1;
}

static uint32_t test_register(eip_stack_t *s)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t n = 0;
    if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp), &n) !=
        0) {
        return 0;
    }
    if (n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static eip_stack_t *make_stack(uint16_t in_sz, uint16_t out_sz)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = in_sz;
    cfg.output_size = out_sz;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.rpi_us = 20000;
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        eip_stack_destroy(s);
        return NULL;
    }
    return s;
}

/* Forward Open body. ncp_bytes is 2 (0x54) or 4 (Large 0x5B). */
static size_t build_fo(uint8_t *fo, int large, uint16_t serial,
                       uint32_t o2t_ncp, uint32_t t2o_ncp)
{
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, 0x1337);
    off += 2;
    eip_wr_le32(fo + off, 0xCAFEBABE);
    off += 4;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, o2t_ncp);
        off += 4;
    } else {
        eip_wr_le16(fo + off, (uint16_t)o2t_ncp);
        off += 2;
    }
    eip_wr_le32(fo + off, 20000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, t2o_ncp);
        off += 4;
    } else {
        eip_wr_le16(fo + off, (uint16_t)t2o_ncp);
        off += 2;
    }
    fo[off++] = 0x01;
    fo[off++] = 4;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = 100;
    fo[off++] = 0x2C;
    fo[off++] = 101;
    fo[off++] = 0x2C;
    fo[off++] = 150;
    return off;
}

/* Returns CIP reply length, or 0. *o2t is the success reply's O→T id. */
static size_t forward_open(eip_stack_t *s, uint32_t sess, int large,
                           uint16_t serial, uint32_t o2t_ncp, uint32_t t2o_ncp,
                           uint8_t *cip_out, size_t cip_cap, uint32_t *o2t)
{
    uint8_t fo[80];
    size_t fo_len = build_fo(fo, large, serial, o2t_ncp, t2o_ncp);
    uint8_t cip[96];
    cip[0] = large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, fo_len);
    size_t cip_len = 6 + fo_len;

    uint8_t body[160];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 160];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);

    uint8_t resp[512];
    size_t resp_len = 0;
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return 0;
    }
    if (resp_len < EIP_ENCAP_HDR_SIZE + 8) {
        return 0;
    }
    const uint8_t *b = resp + EIP_ENCAP_HDR_SIZE;
    size_t bl = resp_len - EIP_ENCAP_HDR_SIZE;
    size_t off = 6;
    uint16_t items = eip_rd_le16(b + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > bl) {
            return 0;
        }
        uint16_t type = eip_rd_le16(b + off);
        uint16_t length = eip_rd_le16(b + off + 2);
        off += 4;
        if (off + length > bl) {
            return 0;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA && length >= 4 &&
            length <= cip_cap) {
            memcpy(cip_out, b + off, length);
            if (o2t && length >= 8 && cip_out[2] == 0) {
                *o2t = eip_rd_le32(cip_out + 4);
            }
            return length;
        }
        off += length;
    }
    return 0;
}

/* Class 1 O→T. run_idle < 0 means no 32-bit header. */
static size_t build_o2t(uint8_t *io, uint32_t o2t, uint32_t seq,
                        int run_idle, const uint8_t *data, uint16_t dlen)
{
    size_t ioff = 0;
    uint16_t extra = run_idle >= 0 ? 4u : 0u;
    eip_wr_le16(io + ioff, 2);
    ioff += 2;
    eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
    ioff += 2;
    eip_wr_le16(io + ioff, 8);
    ioff += 2;
    eip_wr_le32(io + ioff, o2t);
    ioff += 4;
    eip_wr_le32(io + ioff, seq);
    ioff += 4;
    eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
    ioff += 2;
    eip_wr_le16(io + ioff, (uint16_t)(2u + extra + dlen));
    ioff += 2;
    eip_wr_le16(io + ioff, (uint16_t)(seq & 0xffff));
    ioff += 2;
    if (run_idle >= 0) {
        eip_wr_le32(io + ioff, run_idle ? 0x00000001u : 0x00000000u);
        ioff += 4;
    }
    memcpy(io + ioff, data, dlen);
    ioff += dlen;
    return ioff;
}

static void expect_output(eip_stack_t *s, uint8_t a, uint8_t b, const char *msg)
{
    uint8_t out[2];
    int n = eip_stack_read_output(s, 0, out, 2);
    if (n != 2 || out[0] != a || out[1] != b) {
        fprintf(stderr, "FAIL: %s (got %d bytes %02X %02X, want %02X %02X)\n",
                msg, n, n > 0 ? out[0] : 0, n > 1 ? out[1] : 0, a, b);
        g_fail = 1;
    }
}

/* 2-byte output, 4-byte input. O→T = 8 (data+seq+Run/Idle), T→O = 6. */
static void test_logix_o2t_run_idle(int large, uint32_t o2t_ncp,
                                    uint32_t t2o_ncp, const char *label)
{
    eip_stack_t *s = make_stack(4, 2);
    expect(s != NULL, "stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, "session");

    uint8_t cip[64];
    uint32_t o2t = 0;
    size_t n = forward_open(s, sess, large, 0x1001, o2t_ncp, t2o_ncp, cip,
                            sizeof(cip), &o2t);
    expect(n >= 4, label);
    expect_cip(cip, n, CIP_STATUS_SUCCESS, label);
    expect(o2t != 0, "o2t id");
    if (cip[2] != CIP_STATUS_SUCCESS || o2t == 0) {
        eip_stack_destroy(s);
        return;
    }

    uint8_t io[64];
    uint8_t run_data[2] = {0xAA, 0x55};
    size_t iolen = build_o2t(io, o2t, 1, 1, run_data, 2);
    expect(eip_stack_handle_io(s, io, iolen) == 0, "run io");
    expect_output(s, 0xAA, 0x55, "run strips header (not 01 00)");

    /* PROGRAM / Idle must not keep the previous outputs. */
    uint8_t idle_data[2] = {0xFF, 0xEE};
    iolen = build_o2t(io, o2t, 2, 0, idle_data, 2);
    expect(eip_stack_handle_io(s, io, iolen) == 0, "idle io");
    expect_output(s, 0x00, 0x00, "idle clears outputs");

    /* Bit 0 is Run even when other header bits are set. */
    uint8_t again[2] = {0x7E, 0x3C};
    iolen = build_o2t(io, o2t, 3, 1, again, 2);
    /* Header sits at offset 20: CPF 18 bytes + CIP sequence 2. */
    eip_wr_le32(io + 20, 0x80000001u);
    expect(eip_stack_handle_io(s, io, iolen) == 0, "run with high bits");
    expect_output(s, 0x7E, 0x3C, "run bit0 applies data");

    uint8_t junk[2] = {0x11, 0x22};
    iolen = build_o2t(io, o2t, 4, 0, junk, 2);
    eip_wr_le32(io + 20, 0x00000002u); /* bit 0 clear */
    expect(eip_stack_handle_io(s, io, iolen) == 0, "idle with other bits");
    expect_output(s, 0x00, 0x00, "idle ignores payload and previous run");

    eip_stack_destroy(s);
}

static void test_modeless_unchanged(void)
{
    eip_stack_t *s = make_stack(4, 2);
    expect(s != NULL, "modeless stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    uint32_t o2t = 0;
    /* O→T = data+seq = 4 (0x4804), T→O = 6. No Run/Idle header. */
    size_t n = forward_open(s, sess, 0, 0x1002, 0x4804, 0x4806, cip,
                            sizeof(cip), &o2t);
    expect_cip(cip, n, CIP_STATUS_SUCCESS, "modeless FO");
    uint8_t data[2] = {0xAA, 0x55};
    uint8_t io[64];
    size_t iolen = build_o2t(io, o2t, 1, -1, data, 2);
    expect(eip_stack_handle_io(s, io, iolen) == 0, "modeless io");
    expect_output(s, 0xAA, 0x55, "modeless copies data");
    eip_stack_destroy(s);
}

static void test_t2o_run_idle_size_still_rejected(void)
{
    eip_stack_t *s = make_stack(4, 2);
    expect(s != NULL, "t2o stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    uint32_t o2t = 0;
    /* T→O size 10 = input+6. O→T stays modeless. T→O has no Run/Idle. */
    size_t n = forward_open(s, sess, 0, 0x1003, 0x4804, 0x480A, cip,
                            sizeof(cip), &o2t);
    expect_cip(cip, n, CIP_STATUS_CONN_FAILURE, "t2o +6 rejected");
    expect(n >= 6 && eip_rd_le16(cip + 4) == CIP_EXT_CONN_SIZE,
           "t2o extended 0x0109");
    expect(eip_stack_class1_up(s) == 0, "t2o reject leaves class1 down");
    eip_stack_destroy(s);
}

int main(void)
{
    /* Scanner-style 16-bit NCP: P2P, scheduled, fixed, size 8 and 6. */
    test_logix_o2t_run_idle(0, 0x4808, 0x4806,
                            "standard FO O->T data+6 (NCP 0x4808)");
    /* Size field alone, the way a harness that omits NCP flag bits encodes it. */
    test_logix_o2t_run_idle(0, 8, 6, "standard FO O->T size word 8");
    /* Large Forward Open: size in the low 16 bits of the 32-bit NCP. */
    test_logix_o2t_run_idle(1, 0x48000008u, 0x48000006u,
                            "large FO O->T data+6");
    test_modeless_unchanged();
    test_t2o_run_idle_size_still_rejected();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_1: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_1: ok\n");
    return 0;
}
