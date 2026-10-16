/*
 * T11-7: Transport class/trigger is checked on Forward Open.
 *
 * Class 3 (and any combination other than Class 1 cyclic) must be rejected
 * with General Status 0x01 and extended status 0x0103. The unsuccessful
 * reply uses the T11-3 Connection Manager shape. The request must not
 * occupy a Class 1 slot: the same triad can then open as Class 1 cyclic.
 *
 * Bits (docs/protocols/ethernetip.md 5.6.5): 0-3 class, 4-6 trigger
 * (0 cyclic, 1 change-of-state, 2 application), bit 7 direction. Direction
 * is not part of the 0x0103 combination (M5). SendUnitData (0x70) stays
 * unimplemented; this test does not ask the stack to speak Class 3.
 *
 * Wire values are the CIP Vol 1 Connection Manager codes named in
 * docs/protocols/ethernetip.md (5.6.5, 6.3, C.2). This file does not include
 * the stack's private headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <stdio.h>
#include <string.h>

#define EXT_TRANSPORT_TRIGGER 0x0103

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
    for (size_t i = 0; i < n && i < 40; i++) {
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
static size_t append_path(uint8_t *fo, size_t off)
{
    fo[off++] = 4; /* words */
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

static size_t build_fo(uint8_t *fo, int large, uint16_t serial, uint8_t transport)
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
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, 6); /* output 4 + sequence */
        off += 4;
    } else {
        eip_wr_le16(fo + off, 6);
        off += 2;
    }
    eip_wr_le32(fo + off, 20000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, 10); /* input 8 + sequence */
        off += 4;
    } else {
        eip_wr_le16(fo + off, 10);
        off += 2;
    }
    fo[off++] = transport;
    return append_path(fo, off);
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
                           uint16_t serial, uint8_t transport, uint8_t *cip_out,
                           size_t cip_cap)
{
    uint8_t fo[96];
    size_t fo_len = build_fo(fo, large, serial, transport);
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
                            uint8_t *cip_out, size_t cip_cap)
{
    uint8_t fc[12];
    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, serial);
    eip_wr_le16(fc + 4, VENDOR);
    eip_wr_le32(fc + 6, ORIG_SERIAL);
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

/* Unsuccessful FO: 0x01 + one extended word + triad + size byte + reserved. */
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

/* Class 3 application/server (0xA3) must not be installed as Class 1. */
static void test_class3_does_not_take_slot(int large)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, large ? "class3 large stack" : "class3 stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, large ? "class3 large session" : "class3 session");
    uint8_t reply = (uint8_t)((large ? CIP_SVC_LARGE_FORWARD_OPEN
                                     : CIP_SVC_FORWARD_OPEN) |
                              0x80);
    const char *kind = large ? "large" : "standard";
    uint8_t cip[64];
    const uint16_t serial = 0x1707;
    size_t n = forward_open(s, sess, large, serial, 0xA3, cip, sizeof(cip));
    char msg[96];
    snprintf(msg, sizeof(msg),
             "%s Class 3 (0xA3) Forward Open is 0x01/0x0103", kind);
    expect_cm_fail(cip, n, reply, EXT_TRANSPORT_TRIGGER, serial, msg);
    expect(eip_stack_class1_up(s) == 0, large ? "class3 large leaves class1 down"
                                              : "class3 leaves class1 down");

    /* Same triad, Class 1 cyclic: the rejected open must not still own it. */
    n = forward_open(s, sess, large, serial, 0x01, cip, sizeof(cip));
    snprintf(msg, sizeof(msg),
             "%s Class 1 cyclic opens after Class 3 was rejected", kind);
    if (!(n >= 4 && cip[0] == reply && cip[2] == 0x00)) {
        dump_cip(msg, cip, n);
    }
    expect(eip_stack_class1_up(s) == 1,
           large ? "class1 up after cyclic open (large)"
                 : "class1 up after cyclic open");
    eip_stack_destroy(s);
}

static void test_unsupported_combinations(int large)
{
    struct {
        uint8_t tt;
        const char *what;
    } cases[] = {
        {0x00, "Class 0 cyclic"},
        {0x02, "Class 2 cyclic"},
        {0x03, "Class 3 cyclic"},
        {0x11, "Class 1 change-of-state"},
        {0x21, "Class 1 application trigger"},
        {0xA3, "Class 3 application/server"},
        {0x71, "Class 1 reserved trigger"},
    };
    eip_stack_t *s = make_stack();
    expect(s != NULL, large ? "combo large stack" : "combo stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t reply = (uint8_t)((large ? CIP_SVC_LARGE_FORWARD_OPEN
                                     : CIP_SVC_FORWARD_OPEN) |
                              0x80);
    const char *kind = large ? "large" : "standard";
    uint8_t cip[64];
    uint16_t serial = large ? 0x1800 : 0x1700;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        serial++;
        char msg[96];
        snprintf(msg, sizeof(msg), "%s %s is 0x01/0x0103", kind, cases[i].what);
        size_t n = forward_open(s, sess, large, serial, cases[i].tt, cip,
                                sizeof(cip));
        expect_cm_fail(cip, n, reply, EXT_TRANSPORT_TRIGGER, serial, msg);
        expect(eip_stack_class1_up(s) == 0, "rejected transport leaves class1 down");
    }
    eip_stack_destroy(s);
}

/* Class 1 cyclic is accepted. Direction (bit 7) is not the 0x0103 check. */
static void test_class1_cyclic_accepted(int large)
{
    uint8_t accepted[] = {0x01, 0x81};
    eip_stack_t *s = make_stack();
    expect(s != NULL, large ? "cyclic large stack" : "cyclic stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t reply = (uint8_t)((large ? CIP_SVC_LARGE_FORWARD_OPEN
                                     : CIP_SVC_FORWARD_OPEN) |
                              0x80);
    uint8_t cip[64];
    uint16_t serial = large ? 0x1900 : 0x1710;
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        serial++;
        size_t n = forward_open(s, sess, large, serial, accepted[i], cip,
                                sizeof(cip));
        char msg[80];
        snprintf(msg, sizeof(msg), "transport 0x%02X Class 1 cyclic is accepted",
                 accepted[i]);
        if (!(n >= 4 && cip[0] == reply && cip[2] == 0x00)) {
            dump_cip(msg, cip, n);
        }
        expect(eip_stack_class1_up(s) == 1, "accepted cyclic brings class1 up");
        n = forward_close(s, sess, serial, cip, sizeof(cip));
        expect(n >= 4 && cip[2] == 0x00, "close after accepted cyclic");
        expect(eip_stack_class1_up(s) == 0, "class1 down after close");
    }
    eip_stack_destroy(s);
}

int main(void)
{
    test_class3_does_not_take_slot(0);
    test_class3_does_not_take_slot(1);
    test_unsupported_combinations(0);
    test_unsupported_combinations(1);
    test_class1_cyclic_accepted(0);
    test_class1_cyclic_accepted(1);
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_7: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_7: ok\n");
    return 0;
}
