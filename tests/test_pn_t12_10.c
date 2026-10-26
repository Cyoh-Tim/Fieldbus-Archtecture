/*
 * T12-10: alarm RTA-PDU is a version-1 DATA PDU with an AlarmNotification
 * block, and AlarmDstEndpoint is the controller LocalAlarmReference from
 * AlarmCRBlockReq. ACK stops retransmission. When the ACK timer is
 * exhausted, or the AR aborts (data-hold / CMI), the device sends one
 * ERR-RTA-PDU and the output image becomes the substitute (all zeros;
 * this stack has no configured substitute values).
 *
 * Wire choices (IEC 61158-6-10 as implemented by p-net and captured
 * devices; see the issue comment on SendSeqNum):
 *   PDUType high nibble = version 1, low nibble = type (DATA 1, ACK 3, ERR 4)
 *   AddFlags low nibble = WindowSize 1, bit 4 = TACK (set on DATA)
 *   first DATA SendSeqNum 0xFFFF, AckSeqNum 0xFFFE
 *   after that DATA is TACKed, the next DATA SendSeqNum is 0x0000
 *   a controller DATA-RTA with TACK=1 and SendSeqNum equal to the
 *   expected sequence is answered with one ACK-RTA (PDUType 0x13,
 *   AddFlags 0x01). Its AckSeqNum is the sequence just accepted, and
 *   the next device DATA uses that same value.
 *   ERR PNIOStatus CF 81 FD plus RTA protocol ErrorCode2
 *     data-hold 0x05, CMI 0x06, alarm send give-up 0x08
 */
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int g_fail;

#define TX_MAX 16
static uint8_t g_tx[TX_MAX][256];
static size_t g_txlen[TX_MAX];
static int g_ntx;

static int capture_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (g_ntx < TX_MAX && len <= sizeof(g_tx[0])) {
        memcpy(g_tx[g_ntx], frame, len);
        g_txlen[g_ntx] = len;
        g_ntx++;
    } else if (len > sizeof(g_tx[0])) {
        fprintf(stderr, "FAIL: TX longer than capture slot (%zu)\n", len);
        g_fail = 1;
    }
    return 0;
}

static void tx_reset(void)
{
    g_ntx = 0;
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
    out[0] = 4;
    out[1] = 0;
    out[4] = 0x10;
    static const uint8_t obj[16] = {
        0x00, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xab, 0xcd};
    static const uint8_t iface[16] = {
        0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d};
    memcpy(out + 8, obj, 16);
    memcpy(out + 24, iface, 16);
    pn_wr_le16(out + 68, 0);
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

/* AlarmCR body after BlockVersion. LocalAlarmReference at offset 12. */
static size_t build_connect(uint8_t *pdu, uint16_t alarm_ref,
                            uint16_t timeout_factor, uint16_t retries)
{
    static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t ar[26];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, mac, 6);

    uint8_t al[20];
    memset(al, 0, sizeof(al));
    pn_wr_be16(al + 0, 1);
    pn_wr_be16(al + 2, PN_ETHTYPE_PN);
    pn_wr_be16(al + 8, timeout_factor);
    pn_wr_be16(al + 10, retries);
    pn_wr_be16(al + 12, alarm_ref);
    pn_wr_be16(al + 14, 200);
    pn_wr_be16(al + 16, PN_VLAN_TCI_ALARM_HIGH);
    pn_wr_be16(al + 18, PN_VLAN_TCI_ALARM_LOW);

    uint8_t blocks[128];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    bn += wr_block(blocks + bn, PN_BLOCK_ALARMCR_REQ, al, sizeof(al));
    uint8_t stub[256];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, stub, sn);
}

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t12-10");
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

static int connect_ok(pn_stack_t *s, uint16_t alarm_ref, uint16_t tf,
                      uint16_t retries, const char *what)
{
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu, alarm_ref, tf, retries);
    int rc = pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001);
    if (rc != 0 || pn_stack_ar_up(s) != 1) {
        fprintf(stderr, "FAIL: %s connect rc=%d ar=%d\n", what, rc,
                pn_stack_ar_up(s));
        g_fail = 1;
        return 0;
    }
    return 1;
}

/* RTA starts after the VLAN tag and FrameID. Returns -1 if not an alarm. */
static int alarm_rta(const uint8_t *f, size_t n, uint16_t want_fid,
                     const uint8_t **rta, size_t *rta_len)
{
    if (n < 18 + 2 + 12) {
        return 0;
    }
    if (pn_rd_be16(f + 12) != PN_ETHTYPE_VLAN) {
        return 0;
    }
    if (pn_rd_be16(f + 16) != PN_ETHTYPE_PN) {
        return 0;
    }
    if (pn_rd_be16(f + 18) != want_fid) {
        return 0;
    }
    *rta = f + 20;
    *rta_len = n - 20;
    return 1;
}

static void expect_data_notification(const char *what, const uint8_t *f,
                                    size_t n, uint16_t want_fid,
                                    uint16_t want_dst, uint16_t want_block)
{
    static const uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t src_mac[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    const uint8_t *rta = NULL;
    size_t rta_len = 0;
    if (!alarm_rta(f, n, want_fid, &rta, &rta_len)) {
        fprintf(stderr, "FAIL: %s not a tagged alarm 0x%04x (len=%zu et12=0x%04x)\n",
                what, want_fid, n, n >= 14 ? pn_rd_be16(f + 12) : 0);
        g_fail = 1;
        return;
    }
    uint16_t tci = pn_rd_be16(f + 14);
    uint16_t want_tci = want_fid == PN_FRAMEID_ALARM_LOW ? PN_VLAN_TCI_ALARM_LOW
                                                        : PN_VLAN_TCI_ALARM_HIGH;
    uint16_t dst_ep = pn_rd_be16(rta);
    uint16_t src_ep = pn_rd_be16(rta + 2);
    uint16_t var_len = pn_rd_be16(rta + 10);
    if (memcmp(f, dst_mac, 6) != 0 || memcmp(f + 6, src_mac, 6) != 0 ||
        tci != want_tci || rta[4] != 0x11 || (rta[5] & 0x0F) != 1 ||
        (rta[5] & 0x10) == 0 || dst_ep != want_dst || src_ep != 1 ||
        12u + var_len > rta_len || var_len < 6) {
        fprintf(stderr,
                "FAIL: %s RTA dst_ep=0x%04x src_ep=0x%04x pdu=0x%02x flags=0x%02x "
                "var=%u tci=0x%04x len=%zu (want dst_ep=0x%04x src_ep=1 pdu=0x11 "
                "flags TACK|WindowSize tci=0x%04x)\n",
                what, dst_ep, src_ep, rta[4], rta[5], var_len, tci, n, want_dst,
                want_tci);
        g_fail = 1;
        return;
    }
    const uint8_t *blk = rta + 12;
    uint16_t btype = pn_rd_be16(blk);
    uint16_t blen = pn_rd_be16(blk + 2);
    if (btype != want_block || blen != (uint16_t)(var_len - 4) || blk[4] != 1 ||
        blk[5] != 0) {
        fprintf(stderr,
                "FAIL: %s block type=0x%04x length=%u ver=%u.%u var=%u "
                "(want type=0x%04x length=var-4 version 1.0)\n",
                what, btype, blen, blk[4], blk[5], var_len, want_block);
        g_fail = 1;
    }
}

static int count_fid(uint16_t fid)
{
    int n = 0;
    for (int i = 0; i < g_ntx; i++) {
        const uint8_t *rta;
        size_t rl;
        if (alarm_rta(g_tx[i], g_txlen[i], fid, &rta, &rl)) {
            n++;
        }
    }
    return n;
}

static void sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000u;
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
}

static void test_low_format_and_dst(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "format create");
    if (!s) {
        return;
    }
    if (!connect_ok(s, 0x0007, 1, 3, "format")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    int rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW);
    expect(rc == 0, "low alarm send");
    expect(g_ntx == 1, "one low alarm frame");
    if (g_ntx >= 1) {
        expect_data_notification("Alarm Low", g_tx[0], g_txlen[0],
                                 PN_FRAMEID_ALARM_LOW, 0x0007, 0x0002);
        const uint8_t *rta;
        size_t rl;
        if (alarm_rta(g_tx[0], g_txlen[0], PN_FRAMEID_ALARM_LOW, &rta, &rl)) {
            uint16_t seq = pn_rd_be16(rta + 6);
            uint16_t ack = pn_rd_be16(rta + 8);
            expect(seq == 0xFFFF && ack == 0xFFFE, "first DATA seq FFFF/FFFE");
            if (seq != 0xFFFF || ack != 0xFFFE) {
                fprintf(stderr, "  got SendSeq=0x%04x AckSeq=0x%04x\n", seq, ack);
            }
        }
    }
    tx_reset();
    rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_HIGH);
    expect(rc == 0, "high alarm send");
    if (g_ntx >= 1) {
        expect_data_notification("Alarm High", g_tx[0], g_txlen[0],
                                 PN_FRAMEID_ALARM_HIGH, 0x0007, 0x0001);
    }
    pn_stack_destroy(s);
}

static size_t build_ack(uint8_t *frame, uint16_t fid, uint16_t ack_seq)
{
    uint8_t pay[16];
    memset(pay, 0, sizeof(pay));
    pn_wr_be16(pay, fid);
    pn_wr_be16(pay + 2, 1);      /* AlarmDstEndpoint = device LocalAlarmReference */
    pn_wr_be16(pay + 4, 0x0007); /* controller reference */
    pay[6] = 0x13;               /* ACK, version 1 */
    pay[7] = 0x01;               /* WindowSize 1, TACK 0 */
    pn_wr_be16(pay + 8, 0xFFFE);
    pn_wr_be16(pay + 10, ack_seq);
    pn_wr_be16(pay + 12, 0);
    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint16_t tci = fid == PN_FRAMEID_ALARM_LOW ? PN_VLAN_TCI_ALARM_LOW
                                              : PN_VLAN_TCI_ALARM_HIGH;
    return pn_eth_build_vlan(frame, 128, dst, src, tci, PN_ETHTYPE_PN, pay,
                             14);
}

static void test_ack_advances_seq_and_stops_retry(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "ack create");
    if (!s) {
        return;
    }
    if (pn_stack_start(s) != 0) {
        expect(0, "ack start");
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    if (!connect_ok(s, 0x0007, 1, 3, "ack")) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    expect(pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW) == 0, "ack first send");
    const uint8_t *rta = NULL;
    size_t rl = 0;
    uint16_t seq = 0;
    if (g_ntx < 1 ||
        !alarm_rta(g_tx[0], g_txlen[0], PN_FRAMEID_ALARM_LOW, &rta, &rl)) {
        expect(0, "ack first frame");
        pn_stack_destroy(s);
        return;
    }
    seq = pn_rd_be16(rta + 6);
    uint16_t first_ack = pn_rd_be16(rta + 8);
    if (seq != 0xFFFF || first_ack != 0xFFFE) {
        fprintf(stderr,
                "FAIL: first DATA seq FFFF/FFFE got SendSeq=0x%04x AckSeq=0x%04x\n",
                seq, first_ack);
        g_fail = 1;
    }
    uint8_t ack[128];
    size_t alen = build_ack(ack, PN_FRAMEID_ALARM_LOW, seq);
    expect(alen > 0, "ack frame built");
    expect(pn_stack_handle_eth(s, ack, alen) == 0, "ack injected");
    tx_reset();
    sleep_ms(250);
    pn_stack_poll(s);
    expect(count_fid(PN_FRAMEID_ALARM_LOW) == 0, "ACK suppresses retransmit");
    expect(pn_stack_ar_up(s) == 1, "AR stays up after ACK");
    tx_reset();
    int rc = pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW);
    expect(rc == 0, "second low alarm after ACK");
    if (g_ntx >= 1 &&
        alarm_rta(g_tx[0], g_txlen[0], PN_FRAMEID_ALARM_LOW, &rta, &rl)) {
        uint16_t next = pn_rd_be16(rta + 6);
        uint16_t next_ack = pn_rd_be16(rta + 8);
        /* Option A: TACK of the first DATA (0xFFFF) advances with
         * (send_seq + 1) & 0x7FFF, which is 0x0000. No controller DATA
         * has been accepted, so AckSeqNum stays 0xFFFE. */
        if (next != 0x0000 || next_ack != 0xFFFE) {
            fprintf(stderr,
                    "FAIL: DATA after ACK SendSeq=0x%04x AckSeq=0x%04x "
                    "want 0x0000/0xFFFE (first SendSeq=0x%04x)\n",
                    next, next_ack, seq);
            g_fail = 1;
        }
    } else {
        expect(0, "second alarm frame");
    }
    pn_stack_destroy(s);
}

static int find_err(uint16_t fid, const uint8_t **rta, size_t *rl)
{
    for (int i = 0; i < g_ntx; i++) {
        if (!alarm_rta(g_tx[i], g_txlen[i], fid, rta, rl)) {
            continue;
        }
        if ((*rta)[4] == 0x14) {
            return 1;
        }
    }
    return 0;
}

static void expect_err(const char *what, uint16_t fid, uint16_t dst_ep,
                       uint8_t code2)
{
    const uint8_t *rta = NULL;
    size_t rl = 0;
    if (!find_err(fid, &rta, &rl)) {
        fprintf(stderr, "FAIL: %s no ERR-RTA-PDU (ntx=%d)\n", what, g_ntx);
        g_fail = 1;
        return;
    }
    uint16_t var_len = pn_rd_be16(rta + 10);
    uint16_t got_dst = pn_rd_be16(rta);
    if ((rta[5] & 0x0F) != 1 || (rta[5] & 0x10) != 0 || var_len != 4 ||
        rl < 16 || got_dst != dst_ep || rta[12] != 0xCF || rta[13] != 0x81 ||
        rta[14] != 0xFD || rta[15] != code2) {
        fprintf(stderr,
                "FAIL: %s ERR dst=0x%04x flags=0x%02x var=%u status=%02x %02x "
                "%02x %02x (want dst=0x%04x flags WindowSize var=4 CF 81 FD %02x)\n",
                what, got_dst, rta[5], var_len, rl >= 13 ? rta[12] : 0,
                rl >= 14 ? rta[13] : 0, rl >= 15 ? rta[14] : 0,
                rl >= 16 ? rta[15] : 0, dst_ep, code2);
        g_fail = 1;
    }
}

static void test_retransmit_then_err_and_safe_output(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "retry create");
    if (!s) {
        return;
    }
    if (pn_stack_start(s) != 0) {
        expect(0, "retry start");
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    /* One retransmission, then give up. 100 ms per RTATimeoutFactor. */
    if (!connect_ok(s, 0x0007, 1, 1, "retry")) {
        pn_stack_destroy(s);
        return;
    }
    memset(s->output_image, 0xA5, s->cfg.output_len);
    tx_reset();
    expect(pn_stack_send_alarm_ex(s, PN_FRAMEID_ALARM_LOW) == 0, "retry send");
    expect(count_fid(PN_FRAMEID_ALARM_LOW) == 1, "initial DATA");
    sleep_ms(250);
    pn_stack_poll(s);
    expect(count_fid(PN_FRAMEID_ALARM_LOW) == 2, "one retransmit");
    expect(pn_stack_ar_up(s) == 1, "AR up after one retry");
    sleep_ms(250);
    pn_stack_poll(s);
    expect(pn_stack_ar_up(s) == 0, "AR down after ACK retries");
    expect_err("alarm ACK timeout", PN_FRAMEID_ALARM_LOW, 0x0007, 0x08);
    int safe = 1;
    for (uint16_t i = 0; i < s->cfg.output_len; i++) {
        if (s->output_image[i] != 0) {
            safe = 0;
        }
    }
    expect(safe, "output substitute is zero after alarm abort");
    pn_stack_destroy(s);
}

static void test_data_hold_abort_notifies_and_clears(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "dht create");
    if (!s) {
        return;
    }
    if (!connect_ok(s, 0x0007, 1, 3, "dht")) {
        pn_stack_destroy(s);
        return;
    }
    memset(s->output_image, 0x5A, s->cfg.output_len);
    s->ar.send_clock_factor = 32;
    s->ar.reduction_ratio = 32;
    s->ar.data_hold_factor = 3;
    s->ar.saw_rt = 1;
    uint64_t hold = 32ull * 32ull * PN_SEND_CLOCK_BASE_NS * 3ull;
    s->ar.last_rt_rx_ns = pn_now_ns() - (hold + 1000ull);
    tx_reset();
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "data-hold aborts");
    expect_err("data-hold", PN_FRAMEID_ALARM_LOW, 0x0007, 0x05);
    int safe = 1;
    for (uint16_t i = 0; i < s->cfg.output_len; i++) {
        if (s->output_image[i] != 0) {
            safe = 0;
        }
    }
    expect(safe, "output substitute is zero after data-hold");
    pn_stack_destroy(s);
}

static int count_pdu(uint16_t fid, uint8_t pdu)
{
    int n = 0;
    for (int i = 0; i < g_ntx; i++) {
        const uint8_t *rta;
        size_t rl;
        if (alarm_rta(g_tx[i], g_txlen[i], fid, &rta, &rl) && rta[4] == pdu) {
            n++;
        }
    }
    return n;
}

/* Controller AlarmAck as DATA-RTA, TACK=1. BlockType 0x8002 (low) or
 * 0x8001 (high). SendSeqNum is the sequence the device is expected to
 * accept; AckSeqNum acknowledges a device DATA when it matches. */
static size_t build_alarm_ack_data(uint8_t *frame, uint16_t fid,
                                   uint16_t send_seq, uint16_t ack_seq)
{
    uint8_t body[24];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 0x0001); /* AlarmType diagnosis; PNIOStatus OK */
    uint16_t block = fid == PN_FRAMEID_ALARM_LOW ? 0x8002u : 0x8001u;
    uint8_t blk[40];
    size_t blen = wr_block(blk, block, body, sizeof(body));
    uint8_t pay[80];
    memset(pay, 0, sizeof(pay));
    pn_wr_be16(pay, fid);
    pn_wr_be16(pay + 2, 1);
    pn_wr_be16(pay + 4, 0x0007);
    pay[6] = 0x11; /* DATA, version 1 */
    pay[7] = 0x11; /* TACK, WindowSize 1 */
    pn_wr_be16(pay + 8, send_seq);
    pn_wr_be16(pay + 10, ack_seq);
    pn_wr_be16(pay + 12, (uint16_t)blen);
    memcpy(pay + 14, blk, blen);
    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint16_t tci = fid == PN_FRAMEID_ALARM_LOW ? PN_VLAN_TCI_ALARM_LOW
                                              : PN_VLAN_TCI_ALARM_HIGH;
    return pn_eth_build_vlan(frame, 160, dst, src, tci, PN_ETHTYPE_PN, pay,
                             14u + blen);
}

static void expect_one_ack_rta(const char *what, uint16_t fid,
                               uint16_t want_send, uint16_t want_ack)
{
    int nack = count_pdu(fid, 0x13);
    if (g_ntx != 1 || nack != 1) {
        fprintf(stderr, "FAIL: %s ACK-RTA frames %d (tx=%d, want 1)\n", what,
                nack, g_ntx);
        g_fail = 1;
        return;
    }
    const uint8_t *rta = NULL;
    size_t rl = 0;
    if (!alarm_rta(g_tx[0], g_txlen[0], fid, &rta, &rl) || rl < 12) {
        fprintf(stderr, "FAIL: %s ACK-RTA is not a tagged alarm\n", what);
        g_fail = 1;
        return;
    }
    uint16_t dst_ep = pn_rd_be16(rta);
    uint16_t src_ep = pn_rd_be16(rta + 2);
    uint16_t seq = pn_rd_be16(rta + 6);
    uint16_t ack = pn_rd_be16(rta + 8);
    uint16_t var_len = pn_rd_be16(rta + 10);
    if (rta[4] != 0x13 || rta[5] != 0x01 || dst_ep != 0x0007 || src_ep != 1 ||
        seq != want_send || ack != want_ack || var_len != 0) {
        fprintf(stderr,
                "FAIL: %s ACK-RTA dst=0x%04x src=0x%04x pdu=0x%02x flags=0x%02x "
                "SendSeq=0x%04x AckSeq=0x%04x var=%u "
                "(want dst=0x0007 src=1 pdu=0x13 flags=0x01 "
                "SendSeq=0x%04x AckSeq=0x%04x var=0)\n",
                what, dst_ep, src_ep, rta[4], rta[5], seq, ack, var_len,
                want_send, want_ack);
        g_fail = 1;
    }
}

/* H1: device Notification, controller ACK-RTA, controller AlarmAck DATA.
 * The device must answer that DATA with one ACK-RTA. The next device
 * DATA uses SendSeqNum 0x0000 and AckSeqNum equal to the controller
 * SendSeqNum that was accepted. */
static void test_alarm_ack_data_gets_ack_rta(uint16_t fid, const char *what)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, what);
    if (!s) {
        return;
    }
    if (!connect_ok(s, 0x0007, 1, 3, what)) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    expect(pn_stack_send_alarm_ex(s, fid) == 0, what);
    const uint8_t *rta = NULL;
    size_t rl = 0;
    if (g_ntx < 1 || !alarm_rta(g_tx[0], g_txlen[0], fid, &rta, &rl)) {
        expect(0, what);
        pn_stack_destroy(s);
        return;
    }
    uint16_t dev_seq = pn_rd_be16(rta + 6);
    uint16_t dev_ack = pn_rd_be16(rta + 8);
    if (dev_seq != 0xFFFF || dev_ack != 0xFFFE) {
        fprintf(stderr,
                "FAIL: %s first DATA SendSeq=0x%04x AckSeq=0x%04x want FFFF/FFFE\n",
                what, dev_seq, dev_ack);
        g_fail = 1;
    }
    uint8_t ack[128];
    size_t alen = build_ack(ack, fid, dev_seq);
    expect(pn_stack_handle_eth(s, ack, alen) == 0, what);
    tx_reset();
    const uint16_t ctrl_seq = 0xFFFF; /* first expected controller sequence */
    uint8_t data[160];
    size_t dlen = build_alarm_ack_data(data, fid, ctrl_seq, dev_seq);
    expect(dlen > 0, what);
    expect(pn_stack_handle_eth(s, data, dlen) == 0, what);
    /* ACK-RTA SendSeqNum is send_seq_count_o (the DATA the controller
     * just TACKed, 0xFFFF). AckSeqNum is the accepted controller seq. */
    expect_one_ack_rta(what, fid, 0xFFFF, ctrl_seq);
    tx_reset();
    expect(pn_stack_send_alarm_ex(s, fid) == 0, what);
    if (g_ntx >= 1 && alarm_rta(g_tx[0], g_txlen[0], fid, &rta, &rl)) {
        uint16_t next = pn_rd_be16(rta + 6);
        uint16_t next_ack = pn_rd_be16(rta + 8);
        if (next != 0x0000 || next_ack != ctrl_seq) {
            fprintf(stderr,
                    "FAIL: %s DATA after ACK-RTA SendSeq=0x%04x AckSeq=0x%04x "
                    "want 0x0000/0x%04x\n",
                    what, next, next_ack, ctrl_seq);
            g_fail = 1;
        }
    } else {
        expect(0, what);
    }
    pn_stack_destroy(s);
}

/* H2: the controller DATA carries the TACK (AckSeq = device SendSeq).
 * The device DATA is not retransmitted, and one ACK-RTA is sent. */
static void test_data_piggyback_tack(uint16_t fid, const char *what)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, what);
    if (!s) {
        return;
    }
    if (pn_stack_start(s) != 0) {
        expect(0, what);
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    if (!connect_ok(s, 0x0007, 1, 3, what)) {
        pn_stack_destroy(s);
        return;
    }
    tx_reset();
    expect(pn_stack_send_alarm_ex(s, fid) == 0, what);
    const uint8_t *rta = NULL;
    size_t rl = 0;
    if (g_ntx < 1 || !alarm_rta(g_tx[0], g_txlen[0], fid, &rta, &rl)) {
        expect(0, what);
        pn_stack_destroy(s);
        return;
    }
    uint16_t dev_seq = pn_rd_be16(rta + 6);
    expect(dev_seq == 0xFFFF, what);
    tx_reset();
    uint8_t data[160];
    size_t dlen = build_alarm_ack_data(data, fid, 0xFFFF, dev_seq);
    expect(dlen > 0, what);
    expect(pn_stack_handle_eth(s, data, dlen) == 0, what);
    expect_one_ack_rta(what, fid, dev_seq, 0xFFFF);
    int ack_frames = count_pdu(fid, 0x13);
    sleep_ms(250);
    pn_stack_poll(s);
    int data_frames = count_pdu(fid, 0x11);
    if (data_frames != 0 || count_pdu(fid, 0x13) != ack_frames) {
        fprintf(stderr,
                "FAIL: %s retransmit DATA=%d ACK-RTA=%d (want DATA 0, ACK-RTA 1)\n",
                what, data_frames, count_pdu(fid, 0x13));
        g_fail = 1;
    }
    expect(pn_stack_ar_up(s) == 1, what);
    pn_stack_destroy(s);
}

static void test_cmi_abort_notifies(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "cmi create");
    if (!s) {
        return;
    }
    if (!connect_ok(s, 0x0007, 1, 3, "cmi")) {
        pn_stack_destroy(s);
        return;
    }
    memset(s->output_image, 0x11, s->cfg.output_len);
    s->ar.last_cmi_ns = pn_now_ns() - (PN_CMI_ACTIVITY_TIMEOUT_NS + 1000000ull);
    tx_reset();
    pn_ar_watchdog(s);
    expect(pn_stack_ar_up(s) == 0, "CMI timeout aborts");
    expect_err("CMI timeout", PN_FRAMEID_ALARM_LOW, 0x0007, 0x06);
    int safe = 1;
    for (uint16_t i = 0; i < s->cfg.output_len; i++) {
        if (s->output_image[i] != 0) {
            safe = 0;
        }
    }
    expect(safe, "output substitute is zero after CMI abort");
    pn_stack_destroy(s);
}

int main(void)
{
    test_low_format_and_dst();
    test_ack_advances_seq_and_stops_retry();
    test_alarm_ack_data_gets_ack_rta(PN_FRAMEID_ALARM_LOW, "H1 low AlarmAck");
    test_alarm_ack_data_gets_ack_rta(PN_FRAMEID_ALARM_HIGH, "H1 high AlarmAck");
    test_data_piggyback_tack(PN_FRAMEID_ALARM_LOW, "H2 low piggyback");
    test_data_piggyback_tack(PN_FRAMEID_ALARM_HIGH, "H2 high piggyback");
    test_retransmit_then_err_and_safe_output();
    test_data_hold_abort_notifies_and_clears();
    test_cmi_abort_notifies();
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_10: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_10: ok\n");
    return 0;
}
