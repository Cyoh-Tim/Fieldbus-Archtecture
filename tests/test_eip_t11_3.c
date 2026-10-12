/*
 * T11-3: Forward Open / Forward Close failure response format.
 *
 * Connection Manager errors are General Status 0x01 plus an extended status
 * word, not general 0x20 / 0x05 / 0x04 / 0x02. An unsuccessful Forward Open
 * then carries Connection Serial, Originator Vendor, Originator Serial,
 * Remaining Path Size, and Reserved (10 bytes). Forward Close of a triad
 * that is not open is 0x01 / 0x0107, not success.
 *
 * Wire values below are the CIP Vol 1 Connection Manager codes named in
 * docs/protocols/ethernetip.md (5.6.7, 5.7, 6.3, C.2). This file does not
 * include the stack's private headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <stdio.h>
#include <string.h>

#define EXT_CONN_IN_USE 0x0100
#define EXT_CONN_SIZE 0x0109
#define EXT_CONN_NOT_FOUND 0x0107
#define EXT_OUT_OF_CONNS 0x0113
#define EXT_INVALID_APP_PATH 0x0117
#define EXT_PARAM_ERROR 0x0205
#define EXT_INVALID_SEGMENT 0x0315

#define VENDOR 0x1337
#define ORIG_SERIAL 0xCAFEBABEu

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void dump_cip(const char *msg, const uint8_t *cip, size_t n)
{
    fprintf(stderr, "FAIL: %s (len=%zu cip", msg, n);
    for (size_t i = 0; i < n && i < 32; i++) {
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

static eip_stack_t *make_stack(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 4;
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

/* Exclusive-owner path: Assembly class, config 100, O→T 101, T→O 150. */
static size_t append_path(uint8_t *fo, size_t off, uint8_t in_inst)
{
    fo[off++] = 4; /* words */
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = 100;
    fo[off++] = 0x2C;
    fo[off++] = 101;
    fo[off++] = 0x2C;
    fo[off++] = in_inst;
    return off;
}

static size_t build_fo(uint8_t *fo, int large, uint16_t serial, uint32_t o2t_ncp,
                       uint32_t t2o_ncp, uint8_t in_inst)
{
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0x44332211u);
    off += 4;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, VENDOR);
    off += 2;
    eip_wr_le32(fo + off, ORIG_SERIAL);
    off += 4;
    fo[off++] = 0; /* timeout multiplier */
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
    fo[off++] = 0x01; /* class 1 cyclic */
    return append_path(fo, off, in_inst);
}

static size_t send_cip(eip_stack_t *s, uint32_t sess, const uint8_t *cip,
                       size_t cip_len, uint8_t *cip_out, size_t cip_cap)
{
    uint8_t body[256];
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

    uint8_t req[EIP_ENCAP_HDR_SIZE + 256];
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
        if (type == EIP_ITEM_UNCONNECTED_DATA && length <= cip_cap) {
            memcpy(cip_out, b + off, length);
            return length;
        }
        off += length;
    }
    return 0;
}

static size_t forward_open(eip_stack_t *s, uint32_t sess, int large,
                           uint16_t serial, uint32_t o2t_ncp, uint32_t t2o_ncp,
                           uint8_t in_inst, uint8_t *cip_out, size_t cip_cap)
{
    uint8_t fo[96];
    size_t fo_len = build_fo(fo, large, serial, o2t_ncp, t2o_ncp, in_inst);
    uint8_t cip[128];
    cip[0] = large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, fo_len);
    return send_cip(s, sess, cip, 6 + fo_len, cip_out, cip_cap);
}

static size_t forward_close(eip_stack_t *s, uint32_t sess, uint16_t serial,
                            uint16_t vendor, uint32_t orig, uint8_t *cip_out,
                            size_t cip_cap)
{
    uint8_t fc[12];
    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, serial);
    eip_wr_le16(fc + 4, vendor);
    eip_wr_le32(fc + 6, orig);
    fc[10] = 0;
    fc[11] = 0;
    uint8_t cip[32];
    cip[0] = CIP_SVC_FORWARD_CLOSE;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fc, sizeof(fc));
    return send_cip(s, sess, cip, 6 + sizeof(fc), cip_out, cip_cap);
}

/* Unsuccessful FO/FC: 0x01 + one extended word + triad + size byte + reserved. */
static void expect_cm_fail(const uint8_t *cip, size_t n, uint8_t reply,
                           uint16_t ext, uint16_t serial, const char *msg)
{
    if (n == 16 && cip[0] == reply && cip[1] == 0 && cip[2] == 0x01 &&
        cip[3] == 1 && eip_rd_le16(cip + 4) == ext &&
        eip_rd_le16(cip + 6) == serial && eip_rd_le16(cip + 8) == VENDOR &&
        eip_rd_le32(cip + 10) == ORIG_SERIAL && cip[14] == 0 && cip[15] == 0) {
        return;
    }
    dump_cip(msg, cip, n);
}

static void test_bad_size(int large)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "bad size stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, "bad size session");
    uint8_t cip[64];
    /* O→T = output+seq = 6, T→O = 99 (not input or input+2). */
    uint32_t o2t = large ? 0x00000006u : 6u;
    uint32_t t2o = large ? 99u : 99u;
    size_t n = forward_open(s, sess, large, 0x1234, o2t, t2o, 150, cip,
                            sizeof(cip));
    expect_cm_fail(cip, n, (uint8_t)((large ? 0x5B : 0x54) | 0x80),
                   EXT_CONN_SIZE, 0x1234,
                   large ? "large FO bad T->O size" : "FO bad T->O size");
    expect(eip_stack_class1_up(s) == 0, "bad size leaves class1 down");
    eip_stack_destroy(s);
}

static void test_bad_path_and_segment(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "path stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    /* Path parses, but T→O instance is not the configured input assembly. */
    size_t n =
        forward_open(s, sess, 0, 0x2201, 6, 10, 99, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_INVALID_APP_PATH, 0x2201,
                   "FO unknown assembly is 0x01/0x0117");
    expect(eip_stack_class1_up(s) == 0, "bad path leaves class1 down");

    /* Simple Data Segment 0x80 is not a valid connection-path segment here. */
    uint8_t fo[96];
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    memset(fo + off, 0, 8);
    off += 8;
    eip_wr_le16(fo + off, 0x2202);
    off += 2;
    eip_wr_le16(fo + off, VENDOR);
    off += 2;
    eip_wr_le32(fo + off, ORIG_SERIAL);
    off += 4;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, 6);
    off += 2;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, 10);
    off += 2;
    fo[off++] = 0x01;
    /* 6 words: normal 4-word path plus 0x80, size 1, two data bytes. */
    fo[off++] = 6;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = 100;
    fo[off++] = 0x2C;
    fo[off++] = 101;
    fo[off++] = 0x2C;
    fo[off++] = 150;
    fo[off++] = 0x80;
    fo[off++] = 0x01;
    fo[off++] = 0xAA;
    fo[off++] = 0xBB;
    uint8_t reqcip[128];
    reqcip[0] = CIP_SVC_FORWARD_OPEN;
    reqcip[1] = 2;
    reqcip[2] = 0x20;
    reqcip[3] = CIP_CLASS_CONN_MANAGER;
    reqcip[4] = 0x24;
    reqcip[5] = 1;
    memcpy(reqcip + 6, fo, off);
    n = send_cip(s, sess, reqcip, 6 + off, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_INVALID_SEGMENT, 0x2202,
                   "FO invalid segment is 0x01/0x0315");
    eip_stack_destroy(s);
}

static void test_truncated_and_short(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "trunc stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t fo[96];
    size_t fo_len = build_fo(fo, 0, 0x3301, 6, 10, 150);
    /* Claim a path longer than the bytes that follow. */
    fo[fo_len - 9] = 20;
    uint8_t reqcip[128];
    reqcip[0] = CIP_SVC_FORWARD_OPEN;
    reqcip[1] = 2;
    reqcip[2] = 0x20;
    reqcip[3] = CIP_CLASS_CONN_MANAGER;
    reqcip[4] = 0x24;
    reqcip[5] = 1;
    memcpy(reqcip + 6, fo, fo_len);
    uint8_t cip[64];
    size_t n = send_cip(s, sess, reqcip, 6 + fo_len, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_PARAM_ERROR, 0x3301,
                   "FO path size past end is 0x01/0x0205");

    /* Body long enough for the triad (18 bytes) but shorter than a FO. */
    uint8_t short_body[20];
    memset(short_body, 0, sizeof(short_body));
    short_body[0] = 0x0A;
    short_body[1] = 0x05;
    eip_wr_le16(short_body + 10, 0x3302);
    eip_wr_le16(short_body + 12, VENDOR);
    eip_wr_le32(short_body + 14, ORIG_SERIAL);
    reqcip[0] = CIP_SVC_FORWARD_OPEN;
    memcpy(reqcip + 6, short_body, sizeof(short_body));
    n = send_cip(s, sess, reqcip, 6 + sizeof(short_body), cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_PARAM_ERROR, 0x3302,
                   "short FO is 0x01/0x0205 with triad");
    expect(eip_stack_class1_up(s) == 0, "malformed FO leaves class1 down");
    eip_stack_destroy(s);
}

static void test_duplicate_has_tail(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "dup stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0, 0x4401, 6, 10, 150, cip, sizeof(cip));
    expect(n >= 4 && cip[0] == 0xD4 && cip[2] == 0x00, "first FO succeeds");
    expect(eip_stack_class1_up(s) == 1, "class1 up after FO");
    n = forward_open(s, sess, 0, 0x4401, 6, 10, 150, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_CONN_IN_USE, 0x4401,
                   "duplicate FO is 0x01/0x0100 plus triad");
    expect(eip_stack_class1_up(s) == 1, "duplicate does not drop the connection");
    eip_stack_destroy(s);
}

static void test_forward_close_missing_and_present(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "fc stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    size_t n = forward_close(s, sess, 0x5501, VENDOR, ORIG_SERIAL, cip,
                             sizeof(cip));
    expect_cm_fail(cip, n, 0xCE, EXT_CONN_NOT_FOUND, 0x5501,
                   "FC of missing connection is 0x01/0x0107");
    expect(eip_stack_class1_up(s) == 0, "missing FC leaves class1 down");

    n = forward_open(s, sess, 0, 0x5502, 6, 10, 150, cip, sizeof(cip));
    expect(n >= 4 && cip[2] == 0x00, "FO before close");
    expect(eip_stack_class1_up(s) == 1, "class1 up before close");
    n = forward_close(s, sess, 0x5502, VENDOR, ORIG_SERIAL, cip, sizeof(cip));
    if (!(n == 14 && cip[0] == 0xCE && cip[2] == 0x00 && cip[3] == 0 &&
          eip_rd_le16(cip + 4) == 0x5502 && eip_rd_le16(cip + 6) == VENDOR &&
          eip_rd_le32(cip + 8) == ORIG_SERIAL && cip[12] == 0 &&
          cip[13] == 0)) {
        dump_cip("successful FC echoes triad", cip, n);
    }
    expect(eip_stack_class1_up(s) == 0, "FC clears the connection");

    n = forward_close(s, sess, 0x5502, VENDOR, ORIG_SERIAL, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xCE, EXT_CONN_NOT_FOUND, 0x5502,
                   "second FC of the same triad is 0x01/0x0107");
    eip_stack_destroy(s);
}

static void test_out_of_connections(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "slots stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    for (uint16_t i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        size_t n = forward_open(s, sess, 0, (uint16_t)(0x6000 + i), 6, 10, 150,
                                cip, sizeof(cip));
        if (!(n >= 4 && cip[2] == 0x00)) {
            dump_cip("filling class1 slots", cip, n);
            eip_stack_destroy(s);
            return;
        }
    }
    expect(eip_stack_class1_up(s) == 1, "slots full still reports class1");
    size_t n = forward_open(s, sess, 0, 0x60FF, 6, 10, 150, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_OUT_OF_CONNS, 0x60FF,
                   "no free slot is 0x01/0x0113");
    expect(eip_stack_class1_up(s) == 1, "rejected FO keeps existing connections");
    eip_stack_destroy(s);
}

int main(void)
{
    test_bad_size(0);
    test_bad_size(1);
    test_bad_path_and_segment();
    test_truncated_and_short();
    test_duplicate_has_tail();
    test_forward_close_missing_and_present();
    test_out_of_connections();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_3: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_3: ok\n");
    return 0;
}
