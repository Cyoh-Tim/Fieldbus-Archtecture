/*
 * T10-5: SLMP server simulator end codes and error information.
 *
 * Spec (docs/protocols/slmp.md 5.9, appendix D-2/D-3/D-8):
 *   - unsupported command/subcommand is C059h (C050h is an ASCII conversion error)
 *   - an abnormal response carries 9 bytes of error information after the end code
 *   - a batch write whose data length does not match the point count is an
 *     error response (C061h), not a silent drop
 *
 * Error information layout (5.9 example, appendix B-7s): the request route
 * (network, PC, request-destination I/O, multidrop) followed by the request
 * command and subcommand.
 */
#include "slmp_stack.h"

#include <stdint.h>
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

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static void wr_le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
}

static slmp_stack_t *make_server(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    cfg.port = 5000;
    cfg.network_no = 0;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.monitoring_timer = 0x10;
    return slmp_stack_create(&cfg);
}

/* Binary 3E request. plen is the on-wire write-data byte count (0 for a read).
 * The length field is 12 + plen, which is the slice the TCP server passes in. */
static size_t build_req(uint8_t *out, uint8_t net, uint8_t pc, uint16_t io,
                        uint8_t multi, uint16_t cmd, uint16_t sub, uint8_t code,
                        uint32_t head, uint16_t qty, const uint8_t *payload,
                        size_t plen)
{
    wr_le16(out, SLMP_SUBHEADER_REQ_3E);
    out[2] = net;
    out[3] = pc;
    wr_le16(out + 4, io);
    out[6] = multi;
    wr_le16(out + 7, (uint16_t)(12u + plen));
    wr_le16(out + 9, 0x0010);
    wr_le16(out + 11, cmd);
    wr_le16(out + 13, sub);
    wr_le24(out + 15, head);
    out[18] = code;
    wr_le16(out + 19, qty);
    if (plen && payload) {
        memcpy(out + 21, payload, plen);
    }
    return 21u + plen;
}

static int handle(slmp_stack_t *s, const uint8_t *req, size_t n, uint8_t *resp,
                  size_t *resp_len, const char *what)
{
    int rc = slmp_stack_handle_request(s, req, n, resp, SLMP_FRAME_MAX, resp_len);
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s: handle rc=%d (no response)\n", what, rc);
        g_fail = 1;
        *resp_len = 0;
        return rc;
    }
    return 0;
}

/* Abnormal reply: end code, length 11, and the 9-byte 5.9 error information. */
static void expect_error(const uint8_t *resp, size_t resp_len, const uint8_t *req,
                         uint16_t end_code, const char *what)
{
    char msg[256];
    uint16_t end = 0xFFFF;
    const uint8_t *data = NULL;
    size_t dlen = 0;
    int rc = slmp_decode_response(resp, resp_len, &end, &data, &dlen);
    snprintf(msg, sizeof(msg), "%s: decode rc=%d resp_len=%zu", what, rc, resp_len);
    expect(rc == 0, msg);
    if (rc != 0) {
        return;
    }
    snprintf(msg, sizeof(msg), "%s: end want=0x%04X got=0x%04X", what, end_code, end);
    expect(end == end_code, msg);
    snprintf(msg, sizeof(msg), "%s: response data length want=11 got=%u", what,
             resp_len >= 9 ? rd_le16(resp + 7) : 0);
    expect(resp_len >= 20 && rd_le16(resp + 7) == 11, msg);
    snprintf(msg, sizeof(msg), "%s: error info len want=9 got=%zu", what, dlen);
    expect(dlen == 9 && data != NULL, msg);
    if (dlen != 9 || !data) {
        return;
    }
    uint8_t want[9];
    memcpy(want, req + 2, 5);
    memcpy(want + 5, req + 11, 4);
    snprintf(msg, sizeof(msg),
             "%s: error info got "
             "%02X %02X %02X %02X %02X %02X %02X %02X %02X want "
             "%02X %02X %02X %02X %02X %02X %02X %02X %02X",
             what, data[0], data[1], data[2], data[3], data[4], data[5], data[6],
             data[7], data[8], want[0], want[1], want[2], want[3], want[4], want[5],
             want[6], want[7], want[8]);
    expect(memcmp(data, want, 9) == 0, msg);
}

static void test_unsupported_command(slmp_stack_t *s)
{
    uint8_t req[64];
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    /* Random read is defined but not implemented. CTT reject_non_3e injects 0x0403. */
    size_t n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_RANDOM_READ,
                         SLMP_SUB_WORD, SLMP_DEV_D, 0, 1, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "random read 0403") == 0) {
        expect_error(resp, resp_len, req, 0xC059, "random read 0403");
    }

    /* Oracle raw command 0x0619, same end code. */
    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, 0x0619, SLMP_SUB_WORD, SLMP_DEV_D,
                  0, 1, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "command 0619") == 0) {
        expect_error(resp, resp_len, req, 0xC059, "command 0619");
    }

    /* Unsupported subcommand of a supported command. */
    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_READ, 0x0002,
                  SLMP_DEV_D, 0, 1, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "subcommand 0002") == 0) {
        expect_error(resp, resp_len, req, 0xC059, "subcommand 0002");
    }

    /* Route other than the own-station example is echoed into the error info. */
    n = build_req(req, 0x02, 0x05, 0x0012, 0x07, SLMP_CMD_BATCH_READ, 0x0003,
                  SLMP_DEV_D, 0, 1, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "routed subcommand") == 0) {
        expect_error(resp, resp_len, req, 0xC059, "routed subcommand");
    }
}

static void test_other_abnormal_carry_error_info(slmp_stack_t *s)
{
    uint8_t req[64];
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;

    size_t n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_READ,
                         SLMP_SUB_WORD, SLMP_DEV_D, 0, 0, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "qty 0") == 0) {
        expect_error(resp, resp_len, req, 0xC051, "qty 0");
    }

    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_READ, SLMP_SUB_WORD,
                  0xEE, 0, 1, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "unknown device") == 0) {
        expect_error(resp, resp_len, req, 0xC056, "unknown device");
    }

    /* Past the word map: same shape as appendix B-7s (C056 + 9-byte info). */
    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_READ, SLMP_SUB_WORD,
                  SLMP_DEV_D, 4096, 1, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "D4096 range") == 0) {
        expect_error(resp, resp_len, req, 0xC056, "D4096 range");
    }
}

static void test_write_length_mismatch(slmp_stack_t *s)
{
    uint16_t seed = 0x1111;
    expect(slmp_stack_write_words(s, SLMP_DEV_D, 0, &seed, 1) == 0, "seed D0");

    uint8_t req[64];
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    uint8_t short_pay[1] = {0x34};
    /* 2 words need 4 bytes; the frame declares 1. */
    size_t n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_WRITE,
                         SLMP_SUB_WORD, SLMP_DEV_D, 0, 2, short_pay, 1);
    if (handle(s, req, n, resp, &resp_len, "short word write") == 0) {
        expect_error(resp, resp_len, req, 0xC061, "short word write");
    }
    uint16_t got = 0;
    expect(slmp_stack_read_words(s, SLMP_DEV_D, 0, &got, 1) == 0, "read D0 short");
    expect(got == 0x1111, "short write must not change D0");

    uint8_t long_pay[4] = {0x78, 0x56, 0x34, 0x12};
    /* 1 word needs 2 bytes; the frame declares 4. */
    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD,
                  SLMP_DEV_D, 0, 1, long_pay, 4);
    if (handle(s, req, n, resp, &resp_len, "long word write") == 0) {
        expect_error(resp, resp_len, req, 0xC061, "long word write");
    }
    got = 0;
    expect(slmp_stack_read_words(s, SLMP_DEV_D, 0, &got, 1) == 0, "read D0 long");
    expect(got == 0x1111, "long write must not change D0");

    uint8_t bits[1] = {1};
    expect(slmp_stack_write_bits(s, SLMP_DEV_M, 0, bits, 1) == 0, "seed M0");
    /* 3 bit points pack into 2 bytes; the frame declares 0. */
    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_WRITE, SLMP_SUB_BIT,
                  SLMP_DEV_M, 0, 3, NULL, 0);
    if (handle(s, req, n, resp, &resp_len, "short bit write") == 0) {
        expect_error(resp, resp_len, req, 0xC061, "short bit write");
    }
    uint8_t bit = 0xFF;
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 0, &bit, 1) == 0, "read M0");
    expect(bit == 1, "short bit write must not change M0");
}

static void test_matching_write_and_read_stay_normal(slmp_stack_t *s)
{
    uint8_t pay[2] = {0x34, 0x12};
    uint8_t req[64];
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    size_t n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_WRITE,
                         SLMP_SUB_WORD, SLMP_DEV_D, 10, 1, pay, 2);
    expect(handle(s, req, n, resp, &resp_len, "exact write") == 0, "exact write");
    uint16_t end = 0xFFFF;
    const uint8_t *data = NULL;
    size_t dlen = 99;
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "exact write decode");
    expect(end == 0x0000 && dlen == 0, "exact write has no error info");
    uint16_t got = 0;
    expect(slmp_stack_read_words(s, SLMP_DEV_D, 10, &got, 1) == 0, "read D10");
    expect(got == 0x1234, "D10 written");

    n = build_req(req, 0x00, 0xFF, 0x03FF, 0x00, SLMP_CMD_BATCH_READ, SLMP_SUB_WORD,
                  SLMP_DEV_D, 10, 1, NULL, 0);
    expect(handle(s, req, n, resp, &resp_len, "exact read") == 0, "exact read");
    end = 0xFFFF;
    data = NULL;
    dlen = 0;
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "exact read decode");
    expect(end == 0x0000 && dlen == 2 && data && data[0] == 0x34 && data[1] == 0x12,
           "exact read returns the word, not error info");
}

int main(void)
{
    slmp_stack_t *s = make_server();
    expect(s != NULL, "server create");
    if (s) {
        test_unsupported_command(s);
        test_other_abnormal_carry_error_info(s);
        test_write_length_mismatch(s);
        test_matching_write_and_read_stay_normal(s);
        slmp_stack_destroy(s);
    }
    if (g_fail) {
        fprintf(stderr, "test_slmp_t10_5: FAILED\n");
        return 1;
    }
    printf("test_slmp_t10_5: OK\n");
    return 0;
}
