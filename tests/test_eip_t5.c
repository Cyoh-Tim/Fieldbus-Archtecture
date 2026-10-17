/*
 * T5 (EIP): reject a Forward Open whose RPI is shorter than the device
 * minimum, and return the actual production interval when a longer RPI
 * is not a multiple of that minimum.
 *
 * Minimum RPI is eip_cfg_t.rpi_us (µs). The oracle DUT sets it to 8000,
 * which is cycle_ms 8 × 1000. CIP Vol 1 Connection Manager:
 *   General Status 0x01, Extended 0x0112 "RPI value(s) not acceptable",
 *   Additional Status Size 6 words: 0x0112, O→T type, T→O type,
 *   O→T RPI (UDINT), T→O RPI (UDINT). Type 2 is the minimum acceptable
 *   RPI. The unsuccessful Forward Open tail is the T11-3 triad plus
 *   Remaining Path Size and a reserved byte.
 * A request at or above the minimum that is not a multiple is accepted,
 * and both APIs are the requested value rounded up to the next multiple.
 *
 * This file does not include the stack's private headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <stdio.h>
#include <string.h>

#define EXT_RPI_NOT_ACCEPTABLE 0x0112
#define RPI_TYPE_MINIMUM 2

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

static eip_stack_t *make_stack(uint32_t min_rpi_us)
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
    cfg.rpi_us = min_rpi_us;
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        eip_stack_destroy(s);
        return NULL;
    }
    return s;
}

static size_t append_path(uint8_t *fo, size_t off)
{
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

static size_t build_fo(uint8_t *fo, int large, uint16_t serial, uint32_t o2t_rpi,
                       uint32_t t2o_rpi)
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
    eip_wr_le16(fo + off, VENDOR);
    off += 2;
    eip_wr_le32(fo + off, ORIG_SERIAL);
    off += 4;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, o2t_rpi);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, 6); /* output 4 + sequence */
        off += 4;
    } else {
        eip_wr_le16(fo + off, 6);
        off += 2;
    }
    eip_wr_le32(fo + off, t2o_rpi);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, 10); /* input 8 + sequence */
        off += 4;
    } else {
        eip_wr_le16(fo + off, 10);
        off += 2;
    }
    fo[off++] = 0x01;
    return append_path(fo, off);
}

static size_t forward_open(eip_stack_t *s, uint32_t sess, int large,
                           uint16_t serial, uint32_t o2t_rpi, uint32_t t2o_rpi,
                           uint8_t *cip_out, size_t cip_cap)
{
    uint8_t fo[96];
    size_t fo_len = build_fo(fo, large, serial, o2t_rpi, t2o_rpi);
    uint8_t cip[128];
    cip[0] = large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, fo_len);
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
    eip_wr_le16(body + boff, (uint16_t)(6 + fo_len));
    boff += 2;
    memcpy(body + boff, cip, 6 + fo_len);
    boff += 6 + fo_len;

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

/* 0x01 / 0x0112, additional status 6 words, then the 10-byte FO tail. */
static void expect_rpi_reject(const uint8_t *cip, size_t n, uint8_t reply,
                              uint16_t serial, uint32_t min_us, const char *msg)
{
    if (n == 26 && cip[0] == reply && cip[1] == 0 && cip[2] == 0x01 &&
        cip[3] == 6 && eip_rd_le16(cip + 4) == EXT_RPI_NOT_ACCEPTABLE &&
        cip[6] == RPI_TYPE_MINIMUM && cip[7] == RPI_TYPE_MINIMUM &&
        eip_rd_le32(cip + 8) == min_us && eip_rd_le32(cip + 12) == min_us &&
        eip_rd_le16(cip + 16) == serial && eip_rd_le16(cip + 18) == VENDOR &&
        eip_rd_le32(cip + 20) == ORIG_SERIAL && cip[24] == 0 && cip[25] == 0) {
        return;
    }
    dump_cip(msg, cip, n);
}

static void expect_api(const uint8_t *cip, size_t n, uint8_t reply,
                       uint32_t o2t_api, uint32_t t2o_api, const char *msg)
{
    if (n >= 28 && cip[0] == reply && cip[2] == 0x00 &&
        eip_rd_le32(cip + 20) == o2t_api && eip_rd_le32(cip + 24) == t2o_api) {
        return;
    }
    dump_cip(msg, cip, n);
}

static void test_below_minimum_rejected(int large)
{
    eip_stack_t *s = make_stack(8000);
    expect(s != NULL, "short RPI stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, "short RPI session");
    uint8_t cip[64];
    uint8_t reply = (uint8_t)((large ? CIP_SVC_LARGE_FORWARD_OPEN
                                     : CIP_SVC_FORWARD_OPEN) |
                              CIP_SVC_REPLY);
    size_t n = forward_open(s, sess, large, 0x0500, 500, 500, cip, sizeof(cip));
    expect_rpi_reject(cip, n, reply, 0x0500, 8000,
                      large ? "large FO 500us accepted or wrong 0x0112"
                            : "FO 500us accepted or wrong 0x0112");
    expect(eip_stack_class1_up(s) == 0, "short RPI leaves class1 down");
    eip_stack_destroy(s);
}

static void test_one_direction_below_minimum(void)
{
    eip_stack_t *s = make_stack(8000);
    expect(s != NULL, "one-sided stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    /* T→O is legal; O→T is under the minimum. The whole open is refused. */
    size_t n = forward_open(s, sess, 0, 0x0501, 500, 8000, cip, sizeof(cip));
    expect_rpi_reject(cip, n, 0xD4, 0x0501, 8000,
                      "O->T 500us with legal T->O still accepted");
    expect(eip_stack_class1_up(s) == 0, "one-sided short RPI leaves class1 down");
    eip_stack_destroy(s);
}

static void test_custom_minimum(void)
{
    eip_stack_t *s = make_stack(4000);
    expect(s != NULL, "custom min stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0, 0x0502, 3000, 3000, cip, sizeof(cip));
    expect_rpi_reject(cip, n, 0xD4, 0x0502, 4000,
                      "3000us against min 4000us accepted or wrong minimum");
    expect(eip_stack_class1_up(s) == 0, "custom min reject leaves class1 down");
    eip_stack_destroy(s);
}

static void test_accepted_api_is_rounded_multiple(void)
{
    eip_stack_t *s = make_stack(8000);
    expect(s != NULL, "round stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0, 0x1001, 10000, 10000, cip, sizeof(cip));
    expect_api(cip, n, 0xD4, 16000, 16000,
               "RPI 10000us API is not 16000 (next 8000us multiple)");
    expect(eip_stack_class1_up(s) == 1, "rounded RPI opens class1");
    eip_stack_destroy(s);
}

static void test_exact_and_multiple_echo_requested(void)
{
    eip_stack_t *s = make_stack(8000);
    expect(s != NULL, "echo stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    size_t n = forward_open(s, sess, 0, 0x1002, 8000, 8000, cip, sizeof(cip));
    expect_api(cip, n, 0xD4, 8000, 8000, "minimum RPI 8000us API is not 8000");
    eip_stack_destroy(s);

    /* A second Exclusive Owner needs its own stack (0x0106 otherwise). */
    s = make_stack(8000);
    expect(s != NULL, "multiple stack");
    if (!s) {
        return;
    }
    sess = test_register(s);
    n = forward_open(s, sess, 0, 0x1003, 16000, 24000, cip, sizeof(cip));
    expect_api(cip, n, 0xD4, 16000, 24000,
               "exact multiples 16000/24000 were rewritten");
    eip_stack_destroy(s);
}

static void test_round_uses_configured_minimum(void)
{
    eip_stack_t *s = make_stack(4000);
    expect(s != NULL, "round-4ms stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    uint8_t cip[64];
    /* 5000 is above 4000 and not a multiple → 8000. */
    size_t n = forward_open(s, sess, 0, 0x1004, 5000, 4000, cip, sizeof(cip));
    expect_api(cip, n, 0xD4, 8000, 4000,
               "min 4000us: O->T 5000 API is not 8000");
    eip_stack_destroy(s);
}

int main(void)
{
    test_below_minimum_rejected(0);
    test_below_minimum_rejected(1);
    test_one_direction_below_minimum();
    test_custom_minimum();
    test_accepted_api_is_rounded_multiple();
    test_exact_and_multiple_echo_requested();
    test_round_uses_configured_minimum();
    if (g_fail) {
        fprintf(stderr, "test_eip_t5: FAILED\n");
        return 1;
    }
    printf("test_eip_t5: ok\n");
    return 0;
}
