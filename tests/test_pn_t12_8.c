/*
 * T12-8: RTC1 and RTA alarm frames are always sent with an 802.1Q tag.
 * TCI is a fixed value, not a copy of the Connect header:
 *   RTC1 and Alarm High  0xC000 (PCP 6, VID 0)
 *   Alarm Low            0xA000 (PCP 5, VID 0)
 * A missing block or TCI 0 still carries that tag. A Connect value
 * such as 0xE005 is not put on the wire (Connect rejection of a bad
 * tag header is outside this test).
 * T12-7 pads a tagged 32-byte input (C_SDU 33) to C_SDU 36, so the
 * RTC1 frame without FCS is 60 octets. Alarm FrameIDs are outside
 * the RTC1 range and stay unpadded.
 */
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static uint8_t g_tx[PN_FRAME_MAX];
static size_t g_txlen;
static int g_ntx;

static int capture_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (len <= PN_FRAME_MAX) {
        memcpy(g_tx, frame, len);
        g_txlen = len;
        g_ntx++;
    }
    return 0;
}

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
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

static size_t wrap_rpc(uint8_t *out, const uint8_t *stub, size_t slen)
{
    memset(out, 0, 80);
    out[0] = 1;
    out[1] = 0;
    pn_wr_le16(out + 68, 0); /* Connect */
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

static void fill_iocr(uint8_t *b, uint16_t iocr_type, uint16_t frame_id,
                      uint16_t tag)
{
    memset(b, 0, 32);
    pn_wr_be16(b + 0, iocr_type);
    pn_wr_be16(b + 2, iocr_type == PN_IOCR_INPUT ? 1 : 2);
    pn_wr_be16(b + 4, PN_ETHTYPE_PN);
    pn_wr_be32(b + 6, 0x00000001u);
    pn_wr_be16(b + 10, 33); /* DataLength; stack keeps data_len-1 */
    pn_wr_be16(b + 12, frame_id);
    pn_wr_be16(b + 14, 32);
    pn_wr_be16(b + 16, 32);
    pn_wr_be16(b + 26, 3); /* WatchdogFactor */
    pn_wr_be16(b + 28, 3); /* DataHoldFactor */
    pn_wr_be16(b + 30, tag); /* IOCRTagHeader */
}

/* with_iocr: input CR tag `in_tag`, output CR tag `out_tag`.
 * with_alarm: AlarmCRTagHeaderHigh/Low. */
static size_t build_connect(uint8_t *pdu, int with_iocr, uint16_t in_tag,
                            uint16_t out_tag, int with_alarm,
                            uint16_t alarm_high, uint16_t alarm_low)
{
    static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t ar[26];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, mac, 6);

    uint8_t blocks[256];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    if (with_iocr) {
        uint8_t in_cr[32];
        uint8_t out_cr[32];
        fill_iocr(in_cr, PN_IOCR_INPUT, 0x8001, in_tag);
        fill_iocr(out_cr, PN_IOCR_OUTPUT, 0x8002, out_tag);
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, in_cr, sizeof(in_cr));
        bn += wr_block(blocks + bn, PN_BLOCK_IOCR_REQ, out_cr, sizeof(out_cr));
    }
    if (with_alarm) {
        uint8_t al[20];
        memset(al, 0, sizeof(al));
        pn_wr_be16(al + 0, 1); /* AlarmCRType */
        pn_wr_be16(al + 2, PN_ETHTYPE_PN);
        pn_wr_be16(al + 16, alarm_high);
        pn_wr_be16(al + 18, alarm_low);
        bn += wr_block(blocks + bn, PN_BLOCK_ALARMCR_REQ, al, sizeof(al));
    }
    uint8_t stub[320];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, stub, sn);
}

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t12-8");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.cycle_us = 8000;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    return s;
}

static int connect_ok(pn_stack_t *s, const uint8_t *pdu, size_t plen,
                      const char *what)
{
    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    if (rc != 0 || pn_stack_ar_up(s) != 1) {
        fprintf(stderr, "FAIL: %s connect rc=%d ar=%d\n", what, rc,
                pn_stack_ar_up(s));
        g_fail = 1;
        return 0;
    }
    return 1;
}

static void tx_reset(void)
{
    g_ntx = 0;
    g_txlen = 0;
}

/* RTC1 for input_len 32: C_SDU 33 padded to 36.
 * Tagged Ethernet is 18+2+36+4 = 60. */
static const size_t k_rtc1_tagged = 60;
/* Alarm dummy payload is 32 bytes. Tagged Ethernet is 18+32 = 50.
 * Not RTC1, so the C_SDU 36 pad does not apply. */
static const size_t k_alarm_tagged = 50;

static void expect_tagged(const char *what, uint16_t want_tci, uint16_t want_fid,
                          size_t want_len)
{
    if (g_ntx < 1 || g_txlen < 20) {
        fprintf(stderr, "FAIL: %s no frame (ntx=%d len=%zu)\n", what, g_ntx,
                g_txlen);
        g_fail = 1;
        return;
    }
    uint16_t tpid = pn_rd_be16(g_tx + 12);
    if (tpid != PN_ETHTYPE_VLAN) {
        fprintf(stderr,
                "FAIL: %s no 802.1Q tag (offset 12 ethertype=0x%04x len=%zu; "
                "want TPID=0x8100 TCI=0x%04x inner=0x8892 fid=0x%04x len=%zu)\n",
                what, tpid, g_txlen, want_tci, want_fid, want_len);
        g_fail = 1;
        return;
    }
    uint16_t tci = pn_rd_be16(g_tx + 14);
    uint16_t et = pn_rd_be16(g_tx + 16);
    uint16_t fid = pn_rd_be16(g_tx + 18);
    unsigned pcp = (unsigned)((tci >> 13) & 7u);
    unsigned vid = (unsigned)(tci & 0x0fffu);
    unsigned want_pcp = (unsigned)((want_tci >> 13) & 7u);
    unsigned want_vid = (unsigned)(want_tci & 0x0fffu);
    static const uint8_t dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t src[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    if (tpid != PN_ETHTYPE_VLAN || tci != want_tci || et != PN_ETHTYPE_PN ||
        fid != want_fid || g_txlen != want_len || memcmp(g_tx, dst, 6) != 0 ||
        memcmp(g_tx + 6, src, 6) != 0) {
        fprintf(stderr,
                "FAIL: %s VLAN tag got TPID=0x%04x TCI=0x%04x (PCP %u VID %u) "
                "et=0x%04x fid=0x%04x len=%zu; want TPID=0x8100 TCI=0x%04x "
                "(PCP %u VID %u) et=0x8892 fid=0x%04x len=%zu\n",
                what, tpid, tci, pcp, vid, et, fid, g_txlen, want_tci, want_pcp,
                want_vid, want_fid, want_len);
        g_fail = 1;
    }
}

static void test_rtc1_input_tag_pcp6(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "rtc1 pcp6 create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    /* Output CR header is PCP 5. RTC1 still uses the fixed PCP 6 / VID 0
     * tag; the output CR header is not copied. */
    size_t plen = build_connect(pdu, 1, 0xC000, 0xA000, 0, 0, 0);
    if (!connect_ok(s, pdu, plen, "rtc1 pcp6")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    pn_rt_send_if_due(s);
    expect_tagged("RTC1 IOCRTagHeader 0xC000", 0xC000, 0x8001, k_rtc1_tagged);
    pn_stack_destroy(s);
}

static void test_rtc1_ignores_connect_tci(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "rtc1 fixed create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    /* PCP 7, VID 5 in Connect. TX TCI stays the fixed 0xC000. */
    size_t plen = build_connect(pdu, 1, 0xE005, 0xC000, 0, 0, 0);
    if (!connect_ok(s, pdu, plen, "rtc1 fixed")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    pn_rt_send_if_due(s);
    expect_tagged("RTC1 ignores Connect TCI 0xE005", 0xC000, 0x8001,
                  k_rtc1_tagged);
    pn_stack_destroy(s);
}

static void test_rtc1_without_iocr_still_tagged(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "rtc1 notag create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    size_t plen = build_connect(pdu, 0, 0, 0, 0, 0, 0);
    if (!connect_ok(s, pdu, plen, "rtc1 notag")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    pn_rt_send_if_due(s);
    expect_tagged("RTC1 no IOCRTagHeader", 0xC000, 0x8001, k_rtc1_tagged);
    pn_stack_destroy(s);
}

static void test_rtc1_zero_tag_still_tagged(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "rtc1 zero create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    size_t plen = build_connect(pdu, 1, 0x0000, 0x0000, 0, 0, 0);
    if (!connect_ok(s, pdu, plen, "rtc1 zero")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    pn_rt_send_if_due(s);
    expect_tagged("RTC1 IOCRTagHeader 0", 0xC000, 0x8001, k_rtc1_tagged);
    pn_stack_destroy(s);
}

static void test_alarm_low_pcp5_high_from_header(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "alarm tag create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    size_t plen = build_connect(pdu, 1, 0xC000, 0xC000, 1, 0xC000, 0xA000);
    if (!connect_ok(s, pdu, plen, "alarm tag")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    int rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW);
    expect(rc == 0, "alarm low send");
    expect_tagged("Alarm Low TagHeaderLow 0xA000", 0xA000, PN_FRAMEID_ALARM_LOW,
                  k_alarm_tagged);

    tx_reset();
    rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_HIGH);
    expect(rc == 0, "alarm high send");
    expect_tagged("Alarm High TagHeaderHigh 0xC000", 0xC000,
                  PN_FRAMEID_ALARM_HIGH, k_alarm_tagged);
    pn_stack_destroy(s);
}

static void test_alarm_without_header_still_tagged(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "alarm notag create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    size_t plen = build_connect(pdu, 0, 0, 0, 0, 0, 0);
    if (!connect_ok(s, pdu, plen, "alarm notag")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    int rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW);
    expect(rc == 0, "alarm low send without header");
    expect_tagged("Alarm Low no AlarmCRTagHeader", 0xA000, PN_FRAMEID_ALARM_LOW,
                  k_alarm_tagged);
    tx_reset();
    rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_HIGH);
    expect(rc == 0, "alarm high send without header");
    expect_tagged("Alarm High no AlarmCRTagHeader", 0xC000,
                  PN_FRAMEID_ALARM_HIGH, k_alarm_tagged);
    pn_stack_destroy(s);
}

static void test_alarm_ignores_connect_tci(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "alarm fixed create");
    if (!s) {
        return;
    }
    uint8_t pdu[512];
    /* Non-zero headers that are not the fixed PCP 6 / PCP 5 values. */
    size_t plen = build_connect(pdu, 1, 0xC000, 0xC000, 1, 0xE005, 0x0000);
    if (!connect_ok(s, pdu, plen, "alarm fixed")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    int rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW);
    expect(rc == 0, "alarm low send ignores Connect TCI");
    expect_tagged("Alarm Low ignores Connect TCI 0", 0xA000,
                  PN_FRAMEID_ALARM_LOW, k_alarm_tagged);
    tx_reset();
    rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_HIGH);
    expect(rc == 0, "alarm high send ignores Connect TCI");
    expect_tagged("Alarm High ignores Connect TCI 0xE005", 0xC000,
                  PN_FRAMEID_ALARM_HIGH, k_alarm_tagged);
    pn_stack_destroy(s);
}

int main(void)
{
    test_rtc1_input_tag_pcp6();
    test_rtc1_ignores_connect_tci();
    test_rtc1_without_iocr_still_tagged();
    test_rtc1_zero_tag_still_tagged();
    test_alarm_low_pcp5_high_from_header();
    test_alarm_without_header_still_tagged();
    test_alarm_ignores_connect_tci();
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_8: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_8: OK\n");
    return 0;
}
