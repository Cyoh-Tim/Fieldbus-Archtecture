/*
 * T11-5: Exclusive Owner ownership, and NCP connection type.
 *
 * A second Exclusive Owner Forward Open for the same output assembly, from
 * a different connection triad, must be rejected with General Status 0x01
 * and extended status 0x0106 (ownership conflict). The unsuccessful reply
 * uses the T11-3 Connection Manager shape: extended status, triad, Remaining
 * Path Size. The first owner stays up and keeps the output image. The same
 * triad is still 0x0100 (duplicate), not 0x0106. After Forward Close of the
 * owner, a new triad may open.
 *
 * Network connection type 1 (Multicast) and 3 (Reserved) are rejected:
 * T->O with 0x0124, O->T with 0x0123, same reply shape. Type 0 (Null) and
 * 2 (Point-to-point) are accepted. 16-bit NCP uses bits 13-14. Large
 * Forward Open uses 32-bit NCP bits 29-30. The EDS Connection1 dword
 * advertises T->O point-to-point only.
 *
 * Wire values are the CIP Vol 1 Connection Manager codes named in
 * docs/protocols/ethernetip.md (6.3, 6.6, C.2). This file does not include
 * the stack's private headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <stdio.h>
#include <string.h>

#define EXT_CONN_IN_USE 0x0100
#define EXT_OWNERSHIP_CONFLICT 0x0106
#define EXT_CONN_NOT_FOUND 0x0107
#define EXT_INVALID_O2T_TYPE 0x0123
#define EXT_INVALID_T2O_TYPE 0x0124

#ifndef T11_5_EDS_PATH
#define T11_5_EDS_PATH "stacks/ethernetip/eds/FieldbusSensor.eds"
#endif

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

static size_t build_fo(uint8_t *fo, int large, uint16_t serial, uint32_t orig,
                       uint32_t o2t_ncp, uint32_t t2o_ncp)
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
    eip_wr_le32(fo + off, orig);
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
    fo[off++] = 0x01; /* class 1 cyclic */
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
                           uint16_t serial, uint32_t orig, uint32_t o2t_ncp,
                           uint32_t t2o_ncp, uint8_t *cip_out, size_t cip_cap)
{
    uint8_t fo[96];
    size_t fo_len = build_fo(fo, large, serial, orig, o2t_ncp, t2o_ncp);
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
                            uint32_t orig, uint8_t *cip_out, size_t cip_cap)
{
    uint8_t fc[12];
    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, serial);
    eip_wr_le16(fc + 4, VENDOR);
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

/* 16-bit NCP: type P2P (10), priority scheduled (10), size in the low 9 bits.
 * Same layout as the oracle encoder (tests/oracle/test_eip_oracle.py ncp()).
 */
static uint16_t ncp_p2p(uint16_t size)
{
    return (uint16_t)((0x2u << 13) | (0x2u << 10) | (size & 0x1ffu));
}

static void expect_cm_fail(const uint8_t *cip, size_t n, uint8_t reply,
                           uint16_t ext, uint16_t serial, uint32_t orig,
                           const char *msg)
{
    if (n == 16 && cip[0] == reply && cip[1] == 0 && cip[2] == 0x01 &&
        cip[3] == 1 && eip_rd_le16(cip + 4) == ext &&
        eip_rd_le16(cip + 6) == serial && eip_rd_le16(cip + 8) == VENDOR &&
        eip_rd_le32(cip + 10) == orig && cip[14] == 0 && cip[15] == 0) {
        return;
    }
    dump_cip(msg, cip, n);
}

static int write_output(eip_stack_t *s, uint32_t o2t, uint8_t byte)
{
    uint8_t io[64];
    size_t ioff = 0;
    eip_wr_le16(io + ioff, 2);
    ioff += 2;
    eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
    ioff += 2;
    eip_wr_le16(io + ioff, 8);
    ioff += 2;
    eip_wr_le32(io + ioff, o2t);
    ioff += 4;
    eip_wr_le32(io + ioff, 1);
    ioff += 4;
    eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
    ioff += 2;
    eip_wr_le16(io + ioff, 2 + 4);
    ioff += 2;
    eip_wr_le16(io + ioff, 1);
    ioff += 2;
    memset(io + ioff, byte, 4);
    ioff += 4;
    return eip_stack_handle_io(s, io, ioff);
}

static void test_second_owner_rejected(int large)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "owner stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, "owner session");
    /* O→T = output + seq = 6, T→O = input + seq = 10. P2P, as the oracle. */
    uint32_t o2t_ncp = large ? (uint32_t)ncp_p2p(6) : ncp_p2p(6);
    uint32_t t2o_ncp = large ? (uint32_t)ncp_p2p(10) : ncp_p2p(10);
    /* Large Forward Open connection type is bits 29-30. This pattern
     * leaves those bits 0 (Null), which is still accepted.
     */
    if (large) {
        o2t_ncp = (0x2u << 20) | (0x2u << 17) | 6u;
        t2o_ncp = (0x2u << 20) | (0x2u << 17) | 10u;
    }
    uint8_t cip[64];
    size_t n = forward_open(s, sess, large, 0x1001, ORIG_SERIAL, o2t_ncp,
                            t2o_ncp, cip, sizeof(cip));
    expect(n >= 12 && cip[0] == (uint8_t)((large ? 0x5B : 0x54) | 0x80) &&
               cip[2] == 0x00,
           large ? "large first EO succeeds" : "first EO succeeds");
    uint32_t o2t = (n >= 8) ? eip_rd_le32(cip + 4) : 0;
    expect(o2t != 0, "first EO returns an O->T id");
    expect(eip_stack_class1_up(s) == 1, "class1 up after first EO");
    expect(write_output(s, o2t, 0xA5) == 0, "owner O->T applied");
    uint8_t outb[4];
    expect(eip_stack_read_output(s, 0, outb, 4) == 4, "read output");
    expect(outb[0] == 0xA5 && outb[3] == 0xA5, "output image is owner's");

    n = forward_open(s, sess, large, 0x1002, ORIG_SERIAL, o2t_ncp, t2o_ncp,
                     cip, sizeof(cip));
    expect_cm_fail(cip, n, (uint8_t)((large ? 0x5B : 0x54) | 0x80),
                   EXT_OWNERSHIP_CONFLICT, 0x1002, ORIG_SERIAL,
                   large ? "large second EO is 0x01/0x0106"
                         : "second EO is 0x01/0x0106");
    expect(eip_stack_class1_up(s) == 1, "rejected EO leaves the owner up");
    expect(eip_stack_read_output(s, 0, outb, 4) == 4, "output still readable");
    expect(outb[0] == 0xA5 && outb[3] == 0xA5,
           "rejected EO did not change the output image");

    /* The rejected triad was not installed. */
    n = forward_close(s, sess, 0x1002, ORIG_SERIAL, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xCE, EXT_CONN_NOT_FOUND, 0x1002, ORIG_SERIAL,
                   "close of rejected triad is 0x01/0x0107");
    expect(eip_stack_class1_up(s) == 1, "missing close leaves the owner up");

    /* Same triad as the owner is duplicate (0x0100), checked before ownership. */
    n = forward_open(s, sess, large, 0x1001, ORIG_SERIAL, o2t_ncp, t2o_ncp,
                     cip, sizeof(cip));
    expect_cm_fail(cip, n, (uint8_t)((large ? 0x5B : 0x54) | 0x80),
                   EXT_CONN_IN_USE, 0x1001, ORIG_SERIAL,
                   "duplicate triad is 0x01/0x0100");

    /* Different originator serial is still a second owner. */
    n = forward_open(s, sess, large, 0x1001, 0x11111111u, o2t_ncp, t2o_ncp,
                     cip, sizeof(cip));
    expect_cm_fail(cip, n, (uint8_t)((large ? 0x5B : 0x54) | 0x80),
                   EXT_OWNERSHIP_CONFLICT, 0x1001, 0x11111111u,
                   "different originator serial is 0x01/0x0106");

    n = forward_close(s, sess, 0x1001, ORIG_SERIAL, cip, sizeof(cip));
    expect(n >= 4 && cip[2] == 0x00, "close of the owner succeeds");
    expect(eip_stack_class1_up(s) == 0, "class1 down after the owner closes");

    n = forward_open(s, sess, large, 0x1003, ORIG_SERIAL, o2t_ncp, t2o_ncp,
                     cip, sizeof(cip));
    expect(n >= 4 && cip[2] == 0x00, "new EO succeeds after the owner closes");
    expect(eip_stack_class1_up(s) == 1, "class1 up for the new owner");
    eip_stack_destroy(s);
}

/* CTT writes the connection size with type bits left 0. That is still an
 * Exclusive Owner when the path consumes the output assembly.
 */
static void test_size_only_ncp_second_owner(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "size-only stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0, 0x2001, ORIG_SERIAL, 6, 10, cip,
                            sizeof(cip));
    expect(n >= 4 && cip[2] == 0x00, "size-only first EO succeeds");
    n = forward_open(s, sess, 0, 0x2002, ORIG_SERIAL, 6, 10, cip, sizeof(cip));
    expect_cm_fail(cip, n, 0xD4, EXT_OWNERSHIP_CONFLICT, 0x2002, ORIG_SERIAL,
                   "size-only second EO is 0x01/0x0106");
    expect(eip_stack_class1_up(s) == 1, "size-only reject leaves class1 up");
    eip_stack_destroy(s);
}

/* type: 0 Null, 1 Multicast, 2 P2P, 3 Reserved. Size stays in the low bits. */
static uint32_t ncp_type(int large, unsigned type, uint16_t size)
{
    if (large) {
        return ((uint32_t)(type & 3u) << 29) | (uint32_t)size;
    }
    return ((uint32_t)(type & 3u) << 13) | (uint32_t)(size & 0x1ffu);
}

static void test_connection_type(int large)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, large ? "type stack large" : "type stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, large ? "type session large" : "type session");
    uint8_t reply = (uint8_t)((large ? CIP_SVC_LARGE_FORWARD_OPEN
                                     : CIP_SVC_FORWARD_OPEN) |
                              0x80);
    const char *kind = large ? "large" : "standard";
    struct {
        unsigned o2t;
        unsigned t2o;
        uint16_t ext;
        const char *what;
    } cases[] = {
        {2, 1, EXT_INVALID_T2O_TYPE, "T->O multicast is 0x01/0x0124"},
        {2, 3, EXT_INVALID_T2O_TYPE, "T->O reserved is 0x01/0x0124"},
        {1, 2, EXT_INVALID_O2T_TYPE, "O->T multicast is 0x01/0x0123"},
        {3, 2, EXT_INVALID_O2T_TYPE, "O->T reserved is 0x01/0x0123"},
        {0, 0, 0, "Null connection type is accepted"},
        {2, 2, 0, "P2P connection type is accepted"},
    };
    uint8_t cip[64];
    uint16_t serial = 0x3100;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        serial++;
        char msg[96];
        snprintf(msg, sizeof(msg), "%s %s", kind, cases[i].what);
        size_t n = forward_open(s, sess, large, serial, ORIG_SERIAL,
                                ncp_type(large, cases[i].o2t, 6),
                                ncp_type(large, cases[i].t2o, 10), cip,
                                sizeof(cip));
        if (cases[i].ext == 0) {
            expect(n >= 4 && cip[2] == 0x00, msg);
            expect(eip_stack_class1_up(s) == 1, "accepted type brings class1 up");
            n = forward_close(s, sess, serial, ORIG_SERIAL, cip, sizeof(cip));
            expect(n >= 4 && cip[2] == 0x00, "close after accepted type");
            expect(eip_stack_class1_up(s) == 0, "class1 down after accepted close");
        } else {
            expect_cm_fail(cip, n, reply, cases[i].ext, serial, ORIG_SERIAL, msg);
            expect(eip_stack_class1_up(s) == 0,
                   "rejected type leaves class1 down");
        }
    }
    eip_stack_destroy(s);
}

/* Connection1 advertises T->O point-to-point only (bit 21 clear). */
static void test_eds_t2o_p2p_only(void)
{
    FILE *f = fopen(T11_5_EDS_PATH, "rb");
    expect(f != NULL, "open FieldbusSensor.eds");
    if (!f) {
        return;
    }
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    int extra = fgetc(f);
    fclose(f);
    buf[n] = '\0';
    expect(extra == EOF, "EDS fits in the test buffer");
    expect(strstr(buf, "Connection1") != NULL, "EDS has Connection1");
    expect(strstr(buf, "Connection2") == NULL, "EDS keeps only Connection1");
    expect(strstr(buf, "0x44440405") != NULL, "Connection1 dword is 0x44440405");
    expect(strstr(buf, "0x44640405") == NULL, "T->O multicast bit stays clear");
    expect(strstr(buf, "T->O P2P only") != NULL, "EDS comment is T->O P2P only");
}

int main(void)
{
    test_second_owner_rejected(0);
    test_second_owner_rejected(1);
    test_size_only_ncp_second_owner();
    test_connection_type(0);
    test_connection_type(1);
    test_eds_t2o_p2p_only();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_5: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_5: ok\n");
    return 0;
}
