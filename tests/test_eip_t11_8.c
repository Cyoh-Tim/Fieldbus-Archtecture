/*
 * T11-8: Class 1 consume rules and Forward Open parameter checks.
 *
 * An older encapsulation sequence must not overwrite outputs (UDP reorder).
 * Timeout multiplier 8..255 is reserved (0x01/0x0133), not clamped to 7.
 * An Electronic Key is checked (0x0114 vendor/product, 0x0115 device type,
 * 0x0116 revision). A Simple Data Segment (0x80) is configuration data and
 * is accepted when its word count matches the config assembly (0x0126 when
 * it does not).
 *
 * Wire values are the CIP Vol 1 codes named in docs/protocols/ethernetip.md
 * (5.6.6, 5.8.1, 6.4, C.2, M5, M6). This file does not include the stack's
 * private headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <stdio.h>
#include <string.h>

#define EXT_EKEY_VENDOR 0x0114
#define EXT_EKEY_TYPE 0x0115
#define EXT_EKEY_REV 0x0116
#define EXT_CONFIG_WORDS 0x0126
#define EXT_TIMEOUT_MULT 0x0133
#define EXT_INVALID_SEGMENT 0x0315

#define ORIG_VENDOR 0x1337
#define ORIG_SERIAL 0xCAFEBABEu

#define DEV_VENDOR 0xABCD
#define DEV_TYPE 12
#define DEV_PRODUCT 1
#define DEV_MAJOR 1
#define DEV_MINOR 1

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
    cfg.vendor_id = DEV_VENDOR;
    cfg.device_type = DEV_TYPE;
    cfg.product_code = DEV_PRODUCT;
    cfg.major_rev = DEV_MAJOR;
    cfg.minor_rev = DEV_MINOR;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.config_size = 2;
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

static size_t assembly_path(uint8_t *p)
{
    p[0] = 0x20;
    p[1] = CIP_CLASS_ASSEMBLY;
    p[2] = 0x24;
    p[3] = 100;
    p[4] = 0x2C;
    p[5] = 101;
    p[6] = 0x2C;
    p[7] = 150;
    return 8;
}

/* Format 4 key: 34 04 vendor type product major minor. major bit7 = compat. */
static size_t ekey(uint8_t *p, uint16_t vendor, uint16_t dtype, uint16_t product,
                   uint8_t major, uint8_t minor)
{
    p[0] = 0x34;
    p[1] = 0x04;
    eip_wr_le16(p + 2, vendor);
    eip_wr_le16(p + 4, dtype);
    eip_wr_le16(p + 6, product);
    p[8] = major;
    p[9] = minor;
    return 10;
}

static size_t send_cip(eip_stack_t *s, uint32_t sess, const uint8_t *cip,
                       size_t cip_len, uint8_t *cip_out, size_t cip_cap)
{
    uint8_t body[320];
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
    if (boff + cip_len > sizeof(body)) {
        return 0;
    }
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 320];
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

static size_t forward_open(eip_stack_t *s, uint32_t sess, uint16_t serial,
                           uint8_t mult, const uint8_t *path, size_t path_len,
                           uint8_t *cip_out, size_t cip_cap)
{
    uint8_t fo[160];
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0x44332211u);
    off += 4;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, ORIG_VENDOR);
    off += 2;
    eip_wr_le32(fo + off, ORIG_SERIAL);
    off += 4;
    fo[off++] = mult;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, 6); /* output 4 + sequence */
    off += 2;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, 10); /* input 8 + sequence */
    off += 2;
    fo[off++] = 0x01; /* client, cyclic, class 1 */
    fo[off++] = (uint8_t)(path_len / 2u);
    memcpy(fo + off, path, path_len);
    off += path_len;

    uint8_t cip[192];
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);
    return send_cip(s, sess, cip, 6 + off, cip_out, cip_cap);
}

static void expect_cm_fail(const uint8_t *cip, size_t n, uint16_t ext,
                           uint16_t serial, const char *msg)
{
    if (n == 16 && cip[0] == 0xD4 && cip[1] == 0 && cip[2] == 0x01 &&
        cip[3] == 1 && eip_rd_le16(cip + 4) == ext &&
        eip_rd_le16(cip + 6) == serial && eip_rd_le16(cip + 8) == ORIG_VENDOR &&
        eip_rd_le32(cip + 10) == ORIG_SERIAL && cip[14] == 0 && cip[15] == 0) {
        return;
    }
    dump_cip(msg, cip, n);
}

static int fo_succeeded(const uint8_t *cip, size_t n, uint32_t *o2t)
{
    if (n >= 12 && cip[0] == 0xD4 && cip[2] == 0x00) {
        if (o2t) {
            *o2t = eip_rd_le32(cip + 4);
        }
        return 1;
    }
    return 0;
}

/* Modeless O→T: sequenced address (encap seq) + connected data (CIP seq + data). */
static size_t build_o2t(uint8_t *io, uint32_t o2t, uint32_t encap, uint16_t cip,
                        const uint8_t *data, uint16_t dlen)
{
    size_t ioff = 0;
    eip_wr_le16(io + ioff, 2);
    ioff += 2;
    eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
    ioff += 2;
    eip_wr_le16(io + ioff, 8);
    ioff += 2;
    eip_wr_le32(io + ioff, o2t);
    ioff += 4;
    eip_wr_le32(io + ioff, encap);
    ioff += 4;
    eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
    ioff += 2;
    eip_wr_le16(io + ioff, (uint16_t)(2u + dlen));
    ioff += 2;
    eip_wr_le16(io + ioff, cip);
    ioff += 2;
    memcpy(io + ioff, data, dlen);
    ioff += dlen;
    return ioff;
}

static void expect_output(eip_stack_t *s, uint8_t byte, const char *msg)
{
    uint8_t out[4];
    int n = eip_stack_read_output(s, 0, out, 4);
    if (n != 4 || out[0] != byte || out[1] != byte || out[2] != byte ||
        out[3] != byte) {
        fprintf(stderr,
                "FAIL: %s (got %d bytes %02X %02X %02X %02X, want %02X)\n",
                msg, n, n > 0 ? out[0] : 0, n > 1 ? out[1] : 0,
                n > 2 ? out[2] : 0, n > 3 ? out[3] : 0, byte);
        g_fail = 1;
    }
}

static int open_owner(eip_stack_t *s, uint16_t serial, uint32_t *o2t,
                      const char *msg)
{
    uint32_t sess = test_register(s);
    expect(sess != 0, "session");
    uint8_t path[8];
    size_t plen = assembly_path(path);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, serial, 0, path, plen, cip, sizeof(cip));
    if (!fo_succeeded(cip, n, o2t) || *o2t == 0) {
        dump_cip(msg, cip, n);
        return 0;
    }
    return 1;
}

static void test_older_sequence_discarded(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "seq stack");
    if (!s) {
        return;
    }
    uint32_t o2t = 0;
    if (!open_owner(s, 0x1801, &o2t, "seq forward open")) {
        eip_stack_destroy(s);
        return;
    }
    uint8_t io[64];
    uint8_t newer[4];
    uint8_t older[4];
    memset(newer, 0x10, sizeof(newer));
    memset(older, 0x09, sizeof(older));
    size_t n = build_o2t(io, o2t, 10, 10, newer, 4);
    expect(eip_stack_handle_io(s, io, n) == 0, "seq 10 consumed");
    expect_output(s, 0x10, "seq 10 applied");
    n = build_o2t(io, o2t, 9, 9, older, 4);
    expect(eip_stack_handle_io(s, io, n) == 0, "seq 9 handled");
    expect_output(s, 0x10, "older encap seq 9 discarded (not applied)");

    /* Same encap sequence is not newer either. */
    uint8_t dup[4];
    memset(dup, 0x22, sizeof(dup));
    n = build_o2t(io, o2t, 10, 11, dup, 4);
    expect(eip_stack_handle_io(s, io, n) == 0, "duplicate encap handled");
    expect_output(s, 0x10, "duplicate encap seq 10 discarded");

    /* A strictly newer encapsulation sequence is consumed. */
    uint8_t next[4];
    memset(next, 0x11, sizeof(next));
    n = build_o2t(io, o2t, 11, 11, next, 4);
    expect(eip_stack_handle_io(s, io, n) == 0, "seq 11 consumed");
    expect_output(s, 0x11, "newer encap seq 11 applied");
    eip_stack_destroy(s);
}

static void test_duplicate_cip_sequence_not_applied(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "cip seq stack");
    if (!s) {
        return;
    }
    uint32_t o2t = 0;
    if (!open_owner(s, 0x1802, &o2t, "cip seq forward open")) {
        eip_stack_destroy(s);
        return;
    }
    uint8_t io[64];
    uint8_t first[4];
    uint8_t again[4];
    memset(first, 0xA1, sizeof(first));
    memset(again, 0xB2, sizeof(again));
    size_t n = build_o2t(io, o2t, 10, 10, first, 4);
    expect(eip_stack_handle_io(s, io, n) == 0, "first cip seq");
    expect_output(s, 0xA1, "first cip seq applied");
    /* Newer encapsulation sequence, same CIP sequence: not new data. */
    n = build_o2t(io, o2t, 11, 10, again, 4);
    expect(eip_stack_handle_io(s, io, n) == 0, "duplicate cip seq handled");
    expect_output(s, 0xA1, "duplicate CIP sequence did not overwrite outputs");
    eip_stack_destroy(s);
}

static void test_timeout_multiplier(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "mult stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t path[8];
    size_t plen = assembly_path(path);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0x1810, 8, path, plen, cip, sizeof(cip));
    expect_cm_fail(cip, n, EXT_TIMEOUT_MULT, 0x1810,
                   "timeout multiplier 8 is 0x01/0x0133");
    expect(eip_stack_class1_up(s) == 0, "multiplier 8 leaves class1 down");

    n = forward_open(s, sess, 0x1811, 255, path, plen, cip, sizeof(cip));
    expect_cm_fail(cip, n, EXT_TIMEOUT_MULT, 0x1811,
                   "timeout multiplier 255 is 0x01/0x0133");
    expect(eip_stack_class1_up(s) == 0, "multiplier 255 leaves class1 down");

    n = forward_open(s, sess, 0x1812, 7, path, plen, cip, sizeof(cip));
    expect(fo_succeeded(cip, n, NULL), "timeout multiplier 7 is accepted");
    if (!fo_succeeded(cip, n, NULL)) {
        dump_cip("multiplier 7", cip, n);
    }
    expect(eip_stack_class1_up(s) == 1, "multiplier 7 brings class1 up");
    eip_stack_destroy(s);
}

static void expect_key(eip_stack_t *s, uint32_t sess, uint16_t serial,
                       const uint8_t *path, size_t plen, int accept, uint16_t ext,
                       const char *msg)
{
    uint8_t cip[64];
    size_t n = forward_open(s, sess, serial, 0, path, plen, cip, sizeof(cip));
    if (accept) {
        if (!fo_succeeded(cip, n, NULL)) {
            dump_cip(msg, cip, n);
        }
        expect(eip_stack_class1_up(s) == 1, msg);
    } else {
        expect_cm_fail(cip, n, ext, serial, msg);
        expect(eip_stack_class1_up(s) == 0, msg);
    }
}

static void test_electronic_key(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "ekey stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t path[32];
    uint8_t apath[8];
    size_t alen = assembly_path(apath);
    size_t klen;
    size_t plen;

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT, DEV_MAJOR, DEV_MINOR);
    memcpy(path + klen, apath, alen);
    plen = klen + alen;
    expect_key(s, sess, 0x1820, path, plen, 1, 0, "exact electronic key accepted");

    /* Close so the next key can open. Forward Close is triad-only. */
    {
        uint8_t fc[12];
        fc[0] = 0x0A;
        fc[1] = 0x05;
        eip_wr_le16(fc + 2, 0x1820);
        eip_wr_le16(fc + 4, ORIG_VENDOR);
        eip_wr_le32(fc + 6, ORIG_SERIAL);
        fc[10] = 0;
        fc[11] = 0;
        uint8_t req[32];
        req[0] = CIP_SVC_FORWARD_CLOSE;
        req[1] = 2;
        req[2] = 0x20;
        req[3] = CIP_CLASS_CONN_MANAGER;
        req[4] = 0x24;
        req[5] = 1;
        memcpy(req + 6, fc, sizeof(fc));
        uint8_t cip[64];
        size_t n = send_cip(s, sess, req, 6 + sizeof(fc), cip, sizeof(cip));
        expect(n >= 4 && cip[2] == 0x00, "close after exact key");
    }

    klen = ekey(path, 0x1234, DEV_TYPE, DEV_PRODUCT, DEV_MAJOR, DEV_MINOR);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1821, path, klen + alen, 0, EXT_EKEY_VENDOR,
               "vendor mismatch is 0x01/0x0114");

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, 0x0099, DEV_MAJOR, DEV_MINOR);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1822, path, klen + alen, 0, EXT_EKEY_VENDOR,
               "product code mismatch is 0x01/0x0114");

    klen = ekey(path, DEV_VENDOR, 0x0099, DEV_PRODUCT, DEV_MAJOR, DEV_MINOR);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1823, path, klen + alen, 0, EXT_EKEY_TYPE,
               "device type mismatch is 0x01/0x0115");

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT, 9, DEV_MINOR);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1824, path, klen + alen, 0, EXT_EKEY_REV,
               "major revision mismatch is 0x01/0x0116");

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT, DEV_MAJOR, 9);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1825, path, klen + alen, 0, EXT_EKEY_REV,
               "minor revision mismatch is 0x01/0x0116");

    /* 0 in vendor, type, or product skips that field. Major 0 skips revision.
     * Minor 0 with a matching major skips the minor (compat bit clear). */
    klen = ekey(path, 0, 0, 0, 0, 9);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1826, path, klen + alen, 1, 0,
               "zero vendor/type/product and major 0 accepted");
    {
        uint8_t fc[12];
        fc[0] = 0x0A;
        fc[1] = 0x05;
        eip_wr_le16(fc + 2, 0x1826);
        eip_wr_le16(fc + 4, ORIG_VENDOR);
        eip_wr_le32(fc + 6, ORIG_SERIAL);
        fc[10] = 0;
        fc[11] = 0;
        uint8_t req[32];
        req[0] = CIP_SVC_FORWARD_CLOSE;
        req[1] = 2;
        req[2] = 0x20;
        req[3] = CIP_CLASS_CONN_MANAGER;
        req[4] = 0x24;
        req[5] = 1;
        memcpy(req + 6, fc, sizeof(fc));
        uint8_t cip[64];
        send_cip(s, sess, req, 6 + sizeof(fc), cip, sizeof(cip));
    }

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT, DEV_MAJOR, 0);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1827, path, klen + alen, 1, 0,
               "minor 0 with matching major accepted");
    {
        uint8_t fc[12];
        fc[0] = 0x0A;
        fc[1] = 0x05;
        eip_wr_le16(fc + 2, 0x1827);
        eip_wr_le16(fc + 4, ORIG_VENDOR);
        eip_wr_le32(fc + 6, ORIG_SERIAL);
        fc[10] = 0;
        fc[11] = 0;
        uint8_t req[32];
        req[0] = CIP_SVC_FORWARD_CLOSE;
        req[1] = 2;
        req[2] = 0x20;
        req[3] = CIP_CLASS_CONN_MANAGER;
        req[4] = 0x24;
        req[5] = 1;
        memcpy(req + 6, fc, sizeof(fc));
        uint8_t cip[64];
        send_cip(s, sess, req, 6 + sizeof(fc), cip, sizeof(cip));
    }

    /* Compatibility bit set: same major, minor in 1..device minor. */
    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT,
                (uint8_t)(0x80 | DEV_MAJOR), DEV_MINOR);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1828, path, klen + alen, 1, 0,
               "compat bit with equal revision accepted");
    {
        uint8_t fc[12];
        fc[0] = 0x0A;
        fc[1] = 0x05;
        eip_wr_le16(fc + 2, 0x1828);
        eip_wr_le16(fc + 4, ORIG_VENDOR);
        eip_wr_le32(fc + 6, ORIG_SERIAL);
        fc[10] = 0;
        fc[11] = 0;
        uint8_t req[32];
        req[0] = CIP_SVC_FORWARD_CLOSE;
        req[1] = 2;
        req[2] = 0x20;
        req[3] = CIP_CLASS_CONN_MANAGER;
        req[4] = 0x24;
        req[5] = 1;
        memcpy(req + 6, fc, sizeof(fc));
        uint8_t cip[64];
        send_cip(s, sess, req, 6 + sizeof(fc), cip, sizeof(cip));
    }

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT,
                (uint8_t)(0x80 | DEV_MAJOR), 0);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x1829, path, klen + alen, 0, EXT_EKEY_REV,
               "compat bit with minor 0 is 0x01/0x0116");

    klen = ekey(path, DEV_VENDOR, DEV_TYPE, DEV_PRODUCT,
                (uint8_t)(0x80 | DEV_MAJOR), 2);
    memcpy(path + klen, apath, alen);
    expect_key(s, sess, 0x182A, path, klen + alen, 0, EXT_EKEY_REV,
               "compat bit with newer minor is 0x01/0x0116");

    /* Key format other than 4 is an invalid segment, not a skipped key. */
    path[0] = 0x34;
    path[1] = 0x03;
    memset(path + 2, 0, 8);
    memcpy(path + 10, apath, alen);
    expect_key(s, sess, 0x182B, path, 10 + alen, 0, EXT_INVALID_SEGMENT,
               "electronic key format 3 is 0x01/0x0315");

    eip_stack_destroy(s);
}

static int read_config(eip_stack_t *s, uint32_t sess, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    uint8_t req[8] = {0x0E, 3, 0x20, CIP_CLASS_ASSEMBLY, 0x24, 100, 0x30, 0x03};
    uint8_t cip[32];
    size_t n = send_cip(s, sess, req, sizeof(req), cip, sizeof(cip));
    if (n < 4 || cip[2] != 0x00) {
        return 0;
    }
    size_t dlen = n - 4;
    if (dlen > cap) {
        dlen = cap;
    }
    memcpy(out, cip + 4, dlen);
    *out_len = dlen;
    return 1;
}

static void test_config_data_segment(void)
{
    eip_stack_t *s = make_stack();
    expect(s != NULL, "data seg stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t path[16];
    size_t plen = assembly_path(path);
    /* Oracle shape: assembly path, then 0x80, one word, AA BB. */
    path[plen++] = 0x80;
    path[plen++] = 0x01;
    path[plen++] = 0xAA;
    path[plen++] = 0xBB;
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0x1830, 0, path, plen, cip, sizeof(cip));
    if (!fo_succeeded(cip, n, NULL)) {
        dump_cip("data segment at end of path accepted", cip, n);
    } else {
        expect(eip_stack_class1_up(s) == 1, "data segment brings class1 up");
        uint8_t cfg[4];
        size_t clen = 0;
        expect(read_config(s, sess, cfg, sizeof(cfg), &clen) && clen == 2 &&
                   cfg[0] == 0xAA && cfg[1] == 0xBB,
               "config assembly received AA BB");
    }

    /* Wrong word count for a 2-byte config assembly. */
    eip_stack_destroy(s);
    s = make_stack();
    expect(s != NULL, "data seg mismatch stack");
    if (!s) {
        return;
    }
    sess = test_register(s);
    plen = assembly_path(path);
    path[plen++] = 0x80;
    path[plen++] = 0x02; /* 4 bytes, config assembly is 2 */
    path[plen++] = 0x01;
    path[plen++] = 0x02;
    path[plen++] = 0x03;
    path[plen++] = 0x04;
    n = forward_open(s, sess, 0x1831, 0, path, plen, cip, sizeof(cip));
    expect_cm_fail(cip, n, EXT_CONFIG_WORDS, 0x1831,
                   "config data word count mismatch is 0x01/0x0126");
    expect(eip_stack_class1_up(s) == 0, "bad config size leaves class1 down");

    /* Data segment between the config instance and the connection points. */
    eip_stack_destroy(s);
    s = make_stack();
    expect(s != NULL, "data seg middle stack");
    if (!s) {
        return;
    }
    sess = test_register(s);
    path[0] = 0x20;
    path[1] = CIP_CLASS_ASSEMBLY;
    path[2] = 0x24;
    path[3] = 100;
    path[4] = 0x80;
    path[5] = 0x01;
    path[6] = 0xCC;
    path[7] = 0xDD;
    path[8] = 0x2C;
    path[9] = 101;
    path[10] = 0x2C;
    path[11] = 150;
    n = forward_open(s, sess, 0x1832, 0, path, 12, cip, sizeof(cip));
    if (!fo_succeeded(cip, n, NULL)) {
        dump_cip("data segment in the middle of the path accepted", cip, n);
    } else {
        uint8_t cfg[4];
        size_t clen = 0;
        expect(read_config(s, sess, cfg, sizeof(cfg), &clen) && clen == 2 &&
                   cfg[0] == 0xCC && cfg[1] == 0xDD,
               "middle data segment written to config assembly");
    }
    eip_stack_destroy(s);
}

int main(void)
{
    test_older_sequence_discarded();
    test_duplicate_cip_sequence_not_applied();
    test_timeout_multiplier();
    test_electronic_key();
    test_config_data_segment();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_8: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_8: ok\n");
    return 0;
}
