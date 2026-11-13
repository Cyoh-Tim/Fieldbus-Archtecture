/*
 * T10-6: server simulator word-unit access of a bit device.
 *
 * The head device number is a bit number (docs/protocols/slmp.md 4.5, 8.6,
 * appendix D-5). M16 in word units is M16..M31, and bit0 of that word is M16.
 * It is not word index 16 (M256..M271). One word at head H covers bits
 * H .. H+15 (bit0 of the word is device H), including a head that is not a
 * multiple of 16.
 */
#include "slmp_stack.h"

#include <errno.h>
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

static size_t build_req(uint8_t *out, uint16_t cmd, uint16_t sub, uint8_t code,
                        uint32_t head, uint16_t qty, const uint8_t *payload,
                        size_t plen)
{
    wr_le16(out, SLMP_SUBHEADER_REQ_3E);
    out[2] = 0x00;
    out[3] = 0xFF;
    wr_le16(out + 4, 0x03FF);
    out[6] = 0x00;
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

/* Oracle case: word write M16 = 0x0001 sets M16, visible as bit0 of the
 * second word when M0 is read for 2 words. M256 stays OFF. */
static void test_m16_word_is_bit_number(slmp_stack_t *s)
{
    uint16_t one = 0x0001;
    char msg[128];
    int rc = slmp_stack_write_words(s, SLMP_DEV_M, 16, &one, 1);
    snprintf(msg, sizeof(msg), "write M16 word rc=%d", rc);
    expect(rc == 0, msg);

    uint8_t bit = 0xFF;
    rc = slmp_stack_read_bits(s, SLMP_DEV_M, 16, &bit, 1);
    snprintf(msg, sizeof(msg), "read M16 bit rc=%d value=%u", rc, bit);
    expect(rc == 0 && bit == 1, msg);

    bit = 0xFF;
    rc = slmp_stack_read_bits(s, SLMP_DEV_M, 256, &bit, 1);
    snprintf(msg, sizeof(msg), "M256 (old word-index 16) rc=%d value=%u", rc, bit);
    expect(rc == 0 && bit == 0, msg);

    uint16_t words[2] = {0xFFFF, 0xFFFF};
    rc = slmp_stack_read_words(s, SLMP_DEV_M, 0, words, 2);
    snprintf(msg, sizeof(msg), "read M0 x2 rc=%d words=%04X %04X", rc, words[0],
             words[1]);
    expect(rc == 0 && words[0] == 0 && (words[1] & 0x0001) == 1, msg);
}

/* D-5's other wrong mapping: head 1 used to select word index 1 (M16..M31).
 * bit0 of the word is the head device, so head 1 is M1..M16. */
static void test_unaligned_head_is_bit_number(slmp_stack_t *s)
{
    uint8_t on = 1;
    expect(slmp_stack_write_bits(s, SLMP_DEV_M, 0, &on, 1) == 0, "seed M0");

    uint16_t one = 0x0001;
    char msg[128];
    int rc = slmp_stack_write_words(s, SLMP_DEV_M, 1, &one, 1);
    snprintf(msg, sizeof(msg), "write M1 word rc=%d", rc);
    expect(rc == 0, msg);

    uint8_t m0 = 0xFF, m1 = 0xFF, m16 = 0xFF;
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 0, &m0, 1) == 0, "read M0");
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 1, &m1, 1) == 0, "read M1");
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 16, &m16, 1) == 0, "read M16");
    snprintf(msg, sizeof(msg), "head 1 bit0 is M1 (M0=%u M1=%u M16=%u)", m0, m1,
             m16);
    expect(m0 == 1 && m1 == 1 && m16 == 0, msg);

    uint16_t back = 0;
    rc = slmp_stack_read_words(s, SLMP_DEV_M, 1, &back, 1);
    snprintf(msg, sizeof(msg), "read back M1 word rc=%d value=%04X", rc, back);
    expect(rc == 0 && back == 0x0001, msg);
}

/* Head 0 stays the first 16 bits, so M0 = 0x0002 still turns M1 on. */
static void test_m0_word_still_packs_lsb(slmp_stack_t *s)
{
    uint16_t w = 0x0002;
    expect(slmp_stack_write_words(s, SLMP_DEV_M, 0, &w, 1) == 0, "write M0");
    uint8_t m0 = 1, m1 = 0;
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 0, &m0, 1) == 0 && m0 == 0, "M0 off");
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 1, &m1, 1) == 0 && m1 == 1, "M1 on");
}

/* A word device head is still a word index. */
static void test_word_device_head_unchanged(slmp_stack_t *s)
{
    uint16_t w = 0xABCD;
    uint16_t got = 0, neighbor = 0xFFFF;
    expect(slmp_stack_write_words(s, SLMP_DEV_D, 16, &w, 1) == 0, "write D16");
    expect(slmp_stack_read_words(s, SLMP_DEV_D, 16, &got, 1) == 0 && got == 0xABCD,
           "read D16");
    expect(slmp_stack_read_words(s, SLMP_DEV_D, 1, &neighbor, 1) == 0 && neighbor == 0,
           "D1 not aliased");
}

/* 8192-bit map: the last full word starts at bit 8176. Bit 8192 does not fit. */
static void test_bit_span_range(slmp_stack_t *s)
{
    uint16_t w = 0x0001;
    char msg[96];
    int rc = slmp_stack_write_words(s, SLMP_DEV_M, 8176, &w, 1);
    snprintf(msg, sizeof(msg), "write M8176 rc=%d", rc);
    expect(rc == 0, msg);
    uint8_t bit = 0;
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 8176, &bit, 1) == 0 && bit == 1,
           "M8176 on");
    rc = slmp_stack_write_words(s, SLMP_DEV_M, 8177, &w, 1);
    snprintf(msg, sizeof(msg), "write M8177 (past 8192) rc=%d", rc);
    expect(rc == -ERANGE, msg);
}

static void test_wire_m16(slmp_stack_t *s)
{
    uint8_t req[64];
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    uint8_t pay[2] = {0x01, 0x00}; /* 0x0001 LE */
    size_t n = build_req(req, SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD, SLMP_DEV_M, 16,
                         1, pay, 2);
    int rc = slmp_stack_handle_request(s, req, n, resp, sizeof(resp), &resp_len);
    uint16_t end = 0xFFFF;
    const uint8_t *data = NULL;
    size_t dlen = 0;
    expect(rc == 0, "wire write M16 handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0 && end == 0,
           "wire write M16 end");

    n = build_req(req, SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, SLMP_DEV_M, 0, 2, NULL, 0);
    rc = slmp_stack_handle_request(s, req, n, resp, sizeof(resp), &resp_len);
    end = 0xFFFF;
    data = NULL;
    dlen = 0;
    expect(rc == 0 && slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "wire read M0 x2");
    expect(end == 0 && dlen == 4 && data != NULL, "wire read payload");
    if (end == 0 && dlen == 4 && data) {
        uint16_t w0 = rd_le16(data);
        uint16_t w1 = rd_le16(data + 2);
        char msg[96];
        snprintf(msg, sizeof(msg), "wire M0 x2 = %04X %04X", w0, w1);
        expect(w0 == 0 && (w1 & 0x0001) == 1, msg);
    }

    uint8_t bit = 0;
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 256, &bit, 1) == 0 && bit == 0,
           "wire write did not land on M256");
}

int main(void)
{
    slmp_stack_t *s = make_server();
    expect(s != NULL, "server create");
    if (s) {
        test_m16_word_is_bit_number(s);
        slmp_stack_destroy(s);
    }

    s = make_server();
    if (s) {
        test_unaligned_head_is_bit_number(s);
        slmp_stack_destroy(s);
    }

    s = make_server();
    if (s) {
        test_m0_word_still_packs_lsb(s);
        test_word_device_head_unchanged(s);
        test_bit_span_range(s);
        slmp_stack_destroy(s);
    }

    s = make_server();
    if (s) {
        test_wire_m16(s);
        slmp_stack_destroy(s);
    }

    if (g_fail) {
        fprintf(stderr, "test_slmp_t10_6: FAILED\n");
        return 1;
    }
    printf("test_slmp_t10_6: OK\n");
    return 0;
}
