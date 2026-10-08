#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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
    return (int)len;
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

static size_t wrap_rpc(uint8_t *out, uint16_t op, const uint8_t *stub,
                       size_t slen)
{
    memset(out, 0, 80);
    out[0] = 1;
    out[1] = 0;
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
    snprintf(cfg.station_name, sizeof(cfg.station_name), "rpc-test");
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

/* T12-7 after T12-8: RTC1 is always 802.1Q-tagged, so C_SDU is at least
 * 36 octets (18 + FrameID(2) + 36 + APDU(4) = 60). Padding is zero bytes
 * between IO data/IOPS and APDUStatus. The untagged 40-octet rule is not
 * used on the send path. */
static void t12_7_arm(pn_stack_t *s)
{
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "t12-7 connect");
    expect(pn_stack_ar_up(s) == 1, "t12-7 ar up");
}

static void t12_7_send(pn_stack_t *s)
{
    s->last_rt_ns = 0;
    g_ntx = 0;
    g_txlen = 0;
    pn_rt_send_if_due(s);
}

static void expect_tag(const char *what)
{
    if (g_txlen < 18) {
        return;
    }
    expect(pn_rd_be16(g_tx + 12) == PN_ETHTYPE_VLAN, what);
    expect(pn_rd_be16(g_tx + 14) == PN_VLAN_TCI_RTC1, "t12-7 TCI PCP 6 VID 0");
    expect(pn_rd_be16(g_tx + 16) == PN_ETHTYPE_PN, "t12-7 ethertype after tag");
    expect(pn_rd_be16(g_tx + 18) == 0x8001, "t12-7 FrameID 0x8001");
}

static void test_t12_7_short_input_pads_before_apdu(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-7 short create");
    if (!s) {
        return;
    }
    for (int i = 0; i < 32; i++) {
        s->input_image[i] = (uint8_t)(0x10 + i);
    }
    t12_7_arm(s);
    /* IOCR DataLength is not what this rule follows. A stored length above
     * the image is clamped, then the emitted C_SDU is still padded to 36. */
    s->ar.in_data_len = 200;
    t12_7_send(s);
    expect(g_ntx == 1, "t12-7 short sent");
    if (g_txlen != 60) {
        fprintf(stderr,
                "FAIL: RTC1 frame length got %zu want 60 "
                "(32B IO + IOPS, tagged C_SDU padded to 36; got a short frame)\n",
                g_txlen);
        g_fail = 1;
    }
    expect_tag("t12-7 tag at offset 12");
    if (g_txlen >= 60) {
        int data_ok = 1;
        for (int i = 0; i < 32; i++) {
            if (g_tx[20 + i] != (uint8_t)(0x10 + i)) {
                data_ok = 0;
            }
        }
        expect(data_ok, "t12-7 IO data unchanged at C_SDU start");
        expect(g_tx[52] == PN_IOPS_GOOD, "t12-7 IOPS immediately after IO data");
        int pad_ok = 1;
        for (size_t i = 53; i < 56; i++) {
            if (g_tx[i] != 0) {
                pad_ok = 0;
            }
        }
        expect(pad_ok, "t12-7 zeros between IOPS and APDUStatus");
        expect(pn_rd_be16(g_tx + 56) == 0, "t12-7 CycleCounter is the first APDU byte");
        expect(g_tx[58] == 0x35, "t12-7 DataStatus 0x35 at end-1, not NIC trailer");
        expect(g_tx[59] == 0, "t12-7 TransferStatus is the last byte");
        expect(g_txlen - 18 - 2 - 4 == 36, "t12-7 C_SDU is 36");
    }

    t12_7_send(s);
    if (g_txlen >= 60) {
        expect(pn_rd_be16(g_tx + 56) == 1, "t12-7 next CycleCounter is +1 at the APDU");
        int pad_ok = 1;
        for (size_t i = 53; i < 56; i++) {
            if (g_tx[i] != 0) {
                pad_ok = 0;
            }
        }
        expect(pad_ok, "t12-7 pad stays zero when the counter increments");
    }
    pn_stack_destroy(s);
}

static void test_t12_7_one_byte_short_of_minimum(void)
{
    /* 34B data + IOPS = 35. One pad octet makes C_SDU 36 and the frame 60. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-7 boundary create");
    if (!s) {
        return;
    }
    s->cfg.input_len = 34;
    for (int i = 0; i < 34; i++) {
        s->input_image[i] = (uint8_t)i;
    }
    t12_7_arm(s);
    t12_7_send(s);
    if (g_txlen != 60) {
        fprintf(stderr,
                "FAIL: RTC1 34B input frame length got %zu want 60 "
                "(C_SDU 35 needs 1 pad octet)\n",
                g_txlen);
        g_fail = 1;
    }
    if (g_txlen >= 60) {
        expect(pn_rd_be16(g_tx + 12) == PN_ETHTYPE_VLAN, "t12-7 boundary tag");
        expect(g_tx[20 + 34] == PN_IOPS_GOOD, "t12-7 boundary IOPS");
        expect(g_tx[20 + 35] == 0, "t12-7 single pad octet before APDU");
        expect(g_tx[58] == 0x35, "t12-7 boundary DataStatus at end");
        expect(g_txlen - 18 - 2 - 4 == 36, "t12-7 boundary C_SDU 36");
    }
    pn_stack_destroy(s);
}

static void test_t12_7_long_csdu_is_not_padded(void)
{
    /* 48B + IOPS = 49 >= 36. APDUStatus follows IOPS with no gap.
     * 38B + IOPS = 39 is above 36, so the old untagged minimum of 40
     * must not add another octet. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-7 long create");
    if (!s) {
        return;
    }
    s->cfg.input_len = 48;
    for (int i = 0; i < 48; i++) {
        s->input_image[i] = (uint8_t)(0xA0 + i);
    }
    t12_7_arm(s);
    s->ar.in_data_len = 48;
    t12_7_send(s);
    expect(g_txlen == 73, "t12-7 long frame is 18+2+49+4");
    if (g_txlen >= 73) {
        expect(pn_rd_be16(g_tx + 12) == PN_ETHTYPE_VLAN, "t12-7 long tag");
        expect(g_tx[20 + 48] == PN_IOPS_GOOD, "t12-7 long IOPS");
        expect(pn_rd_be16(g_tx + 20 + 49) == 0, "t12-7 long CycleCounter follows IOPS");
        expect(g_tx[g_txlen - 2] == 0x35, "t12-7 long DataStatus");
        expect(g_txlen - 18 - 2 - 4 == 49, "t12-7 long C_SDU stays 49");
    }

    s->cfg.input_len = 38;
    s->ar.in_data_len = 38;
    for (int i = 0; i < 38; i++) {
        s->input_image[i] = (uint8_t)i;
    }
    t12_7_send(s);
    expect(g_txlen == 63, "t12-7 39-octet C_SDU is not padded to 40");
    if (g_txlen >= 63) {
        expect(g_tx[20 + 38] == PN_IOPS_GOOD, "t12-7 38B IOPS");
        expect(pn_rd_be16(g_tx + 20 + 39) == 1, "t12-7 38B CycleCounter follows IOPS");
        expect(g_tx[g_txlen - 2] == 0x35, "t12-7 38B DataStatus");
        expect(g_txlen - 18 - 2 - 4 == 39, "t12-7 38B C_SDU stays 39");
    }
    pn_stack_destroy(s);
}

static void test_t12_7_short_image_ignores_larger_iocr_length(void)
{
    /* in_data_len 4 is the IO image the stack will copy. Padding reaches
     * the 36-octet minimum and does not grow to an IOCR DataLength. */
    pn_stack_t *s = make_stack();
    expect(s != NULL, "t12-7 image create");
    if (!s) {
        return;
    }
    s->input_image[0] = 0x11;
    s->input_image[1] = 0x22;
    s->input_image[2] = 0x33;
    s->input_image[3] = 0x44;
    t12_7_arm(s);
    s->ar.in_data_len = 4;
    t12_7_send(s);
    if (g_txlen != 60) {
        fprintf(stderr,
                "FAIL: RTC1 4B image frame length got %zu want 60 "
                "(pad C_SDU to 36, not to an IOCR length)\n",
                g_txlen);
        g_fail = 1;
    }
    if (g_txlen >= 60) {
        expect(pn_rd_be16(g_tx + 12) == PN_ETHTYPE_VLAN, "t12-7 4B image tag");
        expect(g_tx[20] == 0x11 && g_tx[21] == 0x22 && g_tx[22] == 0x33 &&
                   g_tx[23] == 0x44,
               "t12-7 4B image kept");
        expect(g_tx[24] == PN_IOPS_GOOD, "t12-7 IOPS after 4B image");
        int pad_ok = 1;
        for (size_t i = 25; i < 56; i++) {
            if (g_tx[i] != 0) {
                pad_ok = 0;
            }
        }
        expect(pad_ok, "t12-7 pad fills the rest of the 36-octet C_SDU");
        expect(g_tx[58] == 0x35, "t12-7 4B image DataStatus at end");
        expect(g_txlen - 18 - 2 - 4 == 36, "t12-7 4B image C_SDU is the minimum 36");
    }
    pn_stack_destroy(s);
}

static size_t t12_7_raw_rtc1(uint8_t *frame, size_t cap, uint16_t fid,
                             uint16_t data_len, int vlan)
{
    uint8_t pay[PN_IO_MAX + 16];
    if (2u + data_len + 1u + 4u > sizeof(pay)) {
        return 0;
    }
    pn_wr_be16(pay, fid);
    memset(pay + 2, 0x5A, data_len);
    size_t n = 2u + data_len;
    pay[n++] = PN_IOPS_GOOD;
    pn_wr_be16(pay + n, 0x0007);
    n += 2;
    pay[n++] = 0x35;
    pay[n++] = 0x00;
    uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    if (vlan) {
        return pn_eth_build_vlan(frame, cap, mac, mac, PN_VLAN_TCI_RTC1,
                                 PN_ETHTYPE_PN, pay, n);
    }
    return pn_eth_build(frame, cap, mac, mac, PN_ETHTYPE_PN, pay, n);
}

static void test_t12_7_vlan_minimum_is_36(void)
{
    uint8_t frame[PN_FRAME_MAX];
    /* 8B IO + IOPS = 9. The tag is already on the frame, so C_SDU
     * minimum is 36 and the frame is 60. */
    size_t n = t12_7_raw_rtc1(frame, sizeof(frame), 0x8001, 8, 1);
    expect(n == 18 + 2 + 9 + 4, "t12-7 vlan raw length before pad");
    expect(pn_rd_be16(frame + 12) == PN_ETHTYPE_VLAN, "t12-7 raw tag at offset 12");
    n = pn_rtc1_pad_min_csdu(frame, n, sizeof(frame));
    expect(n == 60, "t12-7 vlan padded frame is 60");
    if (n == 60) {
        expect(pn_rd_be16(frame + 12) == PN_ETHTYPE_VLAN, "t12-7 vlan tag kept");
        expect(pn_rd_be16(frame + 14) == PN_VLAN_TCI_RTC1, "t12-7 vlan TCI kept");
        expect(pn_rd_be16(frame + 16) == PN_ETHTYPE_PN, "t12-7 vlan ethertype");
        expect(pn_rd_be16(frame + 18) == 0x8001, "t12-7 vlan FrameID");
        expect(frame[20 + 8] == PN_IOPS_GOOD, "t12-7 vlan IOPS after IO data");
        int pad_ok = 1;
        for (size_t i = 29; i < 56; i++) {
            if (frame[i] != 0) {
                pad_ok = 0;
            }
        }
        expect(pad_ok, "t12-7 vlan pad is between IOPS and APDU");
        expect(pn_rd_be16(frame + 56) == 0x0007, "t12-7 vlan CycleCounter at end");
        expect(frame[58] == 0x35 && frame[59] == 0, "t12-7 vlan APDU status at end");
        expect(n - 18 - 2 - 4 == 36, "t12-7 vlan C_SDU minimum is 36");
    }

    /* Already 40 octets of C_SDU: the minimum does not shrink it to 36. */
    n = t12_7_raw_rtc1(frame, sizeof(frame), 0x8001, 39, 1);
    size_t raw = n;
    n = pn_rtc1_pad_min_csdu(frame, n, sizeof(frame));
    expect(n == raw && n == 18 + 2 + 40 + 4, "t12-7 vlan does not shrink a 40-octet C_SDU");

    /* Untagged short payload is not padded to 40. That rule is not used. */
    n = t12_7_raw_rtc1(frame, sizeof(frame), 0x8001, 8, 0);
    size_t untagged = n;
    n = pn_rtc1_pad_min_csdu(frame, n, sizeof(frame));
    expect(n == untagged && n == 14 + 2 + 9 + 4, "t12-7 untagged frame is not padded to 40");
    expect(pn_rd_be16(frame + 12) == PN_ETHTYPE_PN, "t12-7 untagged ethertype stays");

    /* DCP and a too-small buffer are not rewritten into a padded RTC1. */
    n = t12_7_raw_rtc1(frame, sizeof(frame), PN_FRAMEID_DCP_ID_REQ, 8, 1);
    size_t dcp = pn_rtc1_pad_min_csdu(frame, n, sizeof(frame));
    expect(dcp == n, "t12-7 DCP frame is not padded");
    n = t12_7_raw_rtc1(frame, sizeof(frame), 0x8001, 8, 1);
    expect(pn_rtc1_pad_min_csdu(frame, n, n) == 0, "t12-7 pad that does not fit returns 0");
}

int main(void)
{
    test_t12_7_short_input_pads_before_apdu();
    test_t12_7_one_byte_short_of_minimum();
    test_t12_7_long_csdu_is_not_padded();
    test_t12_7_short_image_ignores_larger_iocr_length();
    test_t12_7_vlan_minimum_is_36();
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_7: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_7: OK\n");
    return 0;
}
