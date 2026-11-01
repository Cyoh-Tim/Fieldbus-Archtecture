/* T12-18: an unsupported record index is a PNIORW invalid-index error.
 *
 * Read  PNIOStatus DE 80 B0 00 (NDR integer 0xDE80B000).
 * Write PNIOStatus DF 80 B0 00 (NDR integer 0xDF80B000).
 * Little-endian drep stores that integer as bytes 00 B0 80 DE / 00 B0 80 DF.
 * The IODReadRes/IODWriteRes header carries the same status big-endian
 * (bytes DE 80 B0 00 / DF 80 B0 00) and no record payload.
 *
 * Supported and left successful: I&M0–4 reads, I&M1–4 writes, and the
 * empty GSDML parameter record (index 1, Length 0).
 */
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define UNSUPPORTED_INDEX 0x7777u /* oracle */
#define CTT_UNKNOWN_INDEX 0x1234u /* PN-B-NEG-005 */
#define PARAM_INDEX       1u      /* GSDML ParameterRecordDataItem */

#define PNIO_READ_BAD_INDEX  0xDE80B000u
#define PNIO_WRITE_BAD_INDEX 0xDF80B000u

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
    out[0] = 4;
    out[1] = 0;
    out[4] = 0x10; /* drep: little-endian integers */
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

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t12-18");
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

static size_t build_read(uint8_t *pdu, uint16_t index)
{
    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1);
    fill_aruuid(body + 2);
    pn_wr_be16(body + 22, 1);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, index);
    pn_wr_be32(body + 30, 4096);
    uint8_t blocks[80];
    size_t bn = wr_block(blocks, PN_BLOCK_IOD_READ_REQ, body, sizeof(body));
    uint8_t stub[160];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 2, stub, sn);
}

static size_t build_write(uint8_t *pdu, uint16_t index, const uint8_t *data,
                          size_t dlen)
{
    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1);
    fill_aruuid(body + 2);
    pn_wr_be16(body + 22, 1);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, index);
    pn_wr_be32(body + 30, (uint32_t)dlen);
    uint8_t blocks[160];
    size_t bn = wr_block(blocks, PN_BLOCK_IOD_WRITE_REQ, body, sizeof(body));
    if (dlen > 0 && data) {
        memcpy(blocks + bn, data, dlen);
        bn += dlen;
    }
    uint8_t stub[256];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, 3, stub, sn);
}

/* Header PNIOStatus sits after AdditionalValue1/2: block offset 44. */
static void expect_rw_error(const uint8_t *resp, size_t rlen, uint16_t res_type,
                            uint32_t want, const char *what)
{
    expect(rlen >= 100 + 64, what);
    if (rlen < 100 + 64) {
        return;
    }
    const uint8_t *stub = resp + 80;
    char msg[96];
    snprintf(msg, sizeof(msg), "%s NDR PNIOStatus", what);
    expect_u32(pn_rd_le32(stub), want, msg);
    uint32_t args = pn_rd_le32(stub + 4);
    snprintf(msg, sizeof(msg), "%s ArgsLength is the 64-byte header only", what);
    expect_u32(args, 64, msg);
    const uint8_t *blk = stub + 20;
    snprintf(msg, sizeof(msg), "%s response block type", what);
    expect(pn_rd_be16(blk) == res_type, msg);
    snprintf(msg, sizeof(msg), "%s recordDataLength", what);
    expect_u32(pn_rd_be32(blk + 36), 0, msg);
    uint8_t raw[4];
    pn_wr_be32(raw, want);
    snprintf(msg, sizeof(msg), "%s header PNIOStatus", what);
    expect(memcmp(blk + 44, raw, 4) == 0, msg);
}

static void test_direct_unsupported(pn_stack_t *s)
{
    uint8_t rec[16];
    size_t n = 99;
    memset(rec, 0x5A, sizeof(rec));
    int rc = pn_record_read(s, 1, 1, UNSUPPORTED_INDEX, rec, sizeof(rec), &n);
    expect(rc == -ENOENT, "direct read of 0x7777 returns -ENOENT");
    expect(n == 0, "direct read of 0x7777 writes no payload");

    const uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    rc = pn_record_write(s, 1, 1, UNSUPPORTED_INDEX, data, sizeof(data));
    expect(rc == -ENOENT, "direct write of 0x7777 returns -ENOENT");

    rc = pn_record_read(s, 0, 1, CTT_UNKNOWN_INDEX, rec, sizeof(rec), &n);
    expect(rc == -ENOENT, "direct read of 0x1234 returns -ENOENT");
    rc = pn_record_write(s, 0, 1, CTT_UNKNOWN_INDEX, data, sizeof(data));
    expect(rc == -ENOENT, "direct write of 0x1234 returns -ENOENT");
}

static void test_rpc_unsupported(pn_stack_t *s)
{
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "connect");
    expect(pn_stack_ar_up(s) == 1, "ar up");

    plen = build_read(pdu, UNSUPPORTED_INDEX);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "read 0x7777 answered");
    expect_rw_error(resp, rlen, PN_BLOCK_IOD_READ_RES, PNIO_READ_BAD_INDEX,
                    "read 0x7777");

    plen = build_read(pdu, CTT_UNKNOWN_INDEX);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "read 0x1234 answered");
    expect_rw_error(resp, rlen, PN_BLOCK_IOD_READ_RES, PNIO_READ_BAD_INDEX,
                    "read 0x1234");

    const uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    plen = build_write(pdu, UNSUPPORTED_INDEX, data, sizeof(data));
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "write 0x7777 answered");
    expect_rw_error(resp, rlen, PN_BLOCK_IOD_WRITE_RES, PNIO_WRITE_BAD_INDEX,
                    "write 0x7777");

    plen = build_write(pdu, CTT_UNKNOWN_INDEX, data, sizeof(data));
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "write 0x1234 answered");
    expect_rw_error(resp, rlen, PN_BLOCK_IOD_WRITE_RES, PNIO_WRITE_BAD_INDEX,
                    "write 0x1234");
}

static void test_supported_still_ok(pn_stack_t *s)
{
    uint8_t rec[128];
    size_t n = 0;
    expect(pn_record_read(s, 0, 1, PN_INDEX_IM0, rec, sizeof(rec), &n) == 0,
           "I&M0 read still succeeds");
    /* BlockHeader 6 + VendorID 2, then OrderID. */
    expect(n >= 22 && memcmp(rec + 8, "FB-ARCH-PN-DEV", 14) == 0,
           "I&M0 OrderID unchanged");

    n = 99;
    memset(rec, 0x5A, sizeof(rec));
    expect(pn_record_read(s, 1, 1, PARAM_INDEX, rec, sizeof(rec), &n) == 0,
           "GSDML index 1 read still succeeds");
    expect(n == 0, "GSDML index 1 read is empty (Length 0), not 4 zero bytes");

    expect(pn_record_write(s, 1, 1, PARAM_INDEX, NULL, 0) == 0,
           "GSDML index 1 write still succeeds");

    uint8_t im[8];
    memset(im, 'A', sizeof(im));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM1, im, sizeof(im)) == 0,
           "I&M1 write still succeeds");

    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_read(pdu, PN_INDEX_IM0);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "rpc I&M0 read");
    expect(rlen >= 100, "rpc I&M0 response");
    if (rlen >= 100) {
        expect_u32(pn_rd_le32(resp + 80), 0, "I&M0 NDR PNIOStatus OK");
    }
    plen = build_write(pdu, PARAM_INDEX, NULL, 0);
    rlen = 0;
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "rpc index 1 write");
    if (rlen >= 100) {
        expect_u32(pn_rd_le32(resp + 80), 0, "index 1 write NDR PNIOStatus OK");
    }
}

int main(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "create");
    if (s) {
        test_direct_unsupported(s);
        test_rpc_unsupported(s);
        test_supported_still_ok(s);
        pn_stack_destroy(s);
    }
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_18: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_18: OK\n");
    return 0;
}
