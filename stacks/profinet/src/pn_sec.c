#include "pn_internal.h"

#include <errno.h>
#include <string.h>

#include "logger.h"
#include "pn_crypto.h"
#include "pn_endian.h"

/* IEC 61158-6-10 RTA-PDU. High nibble of PDUType is the version.
 * AddFlags bit 4 is TACK; the low nibble is WindowSize. */
#define RTA_VERSION  1u
#define RTA_TYPE_DATA 1u
#define RTA_TYPE_ACK  3u
#define RTA_TYPE_ERR  4u
#define RTA_ADD_WINDOW 0x01u
#define RTA_ADD_TACK   0x10u
#define RTA_SEQ_INIT   0xFFFFu
#define RTA_ACK_NONE   0xFFFEu
#define RTA_TIMEOUT_UNIT_NS 100000000ull /* RTATimeoutFactor × 100 ms */

static int alarm_channel(uint16_t frame_id)
{
    return frame_id == PN_FRAMEID_ALARM_LOW ? 0 : 1;
}

static uint16_t alarm_dst(const pn_ar_t *ar)
{
    if (ar->have_alarm_cr) {
        return ar->alarm_dst_ref;
    }
    return ar->alarm_src_ref ? ar->alarm_src_ref : 1;
}

static uint16_t alarm_src(const pn_ar_t *ar)
{
    return ar->alarm_src_ref ? ar->alarm_src_ref : 1;
}

void pn_alarm_arm(pn_ar_t *ar)
{
    if (!ar) {
        return;
    }
    ar->alarm_src_ref = 1;
    if (!ar->have_alarm_cr) {
        ar->alarm_dst_ref = 1;
        ar->rta_timeout_factor = 1;
        ar->rta_retries = 3;
    }
    for (int i = 0; i < 2; i++) {
        ar->alarm_ch[i].send_seq = RTA_SEQ_INIT;
        ar->alarm_ch[i].send_seq_o = RTA_ACK_NONE;
        ar->alarm_ch[i].ack_seq = RTA_ACK_NONE;
        ar->alarm_ch[i].exp_seq = RTA_SEQ_INIT;
        ar->alarm_ch[i].retries_left = 0;
        ar->alarm_ch[i].wait_ack = 0;
        ar->alarm_ch[i].ack_due_ns = 0;
        ar->alarm_ch[i].frame_len = 0;
    }
}

/* 0/0/0/0 means Connect never armed the counters. A later 0 is a real
 * sequence (0xFFFF + 1 wraps to 0), so that case is left alone. */
static void alarm_seq_ensure(pn_alarm_ch_t *ch)
{
    if (ch->send_seq == 0 && ch->send_seq_o == 0 && ch->ack_seq == 0 &&
        ch->exp_seq == 0) {
        ch->send_seq = RTA_SEQ_INIT;
        ch->send_seq_o = RTA_ACK_NONE;
        ch->ack_seq = RTA_ACK_NONE;
        ch->exp_seq = RTA_SEQ_INIT;
    }
}

/* AlarmNotification fixed part (no USI). BlockLength counts from
 * BlockVersion through AlarmSpecifier, so it is VarPartLen - 4. */
static size_t put_notification(uint8_t *pay, size_t cap, uint16_t frame_id,
                               uint16_t dst_ep, uint16_t src_ep,
                               uint16_t send_seq, uint16_t ack_seq, int tack)
{
    const uint16_t body = 2u + 4u + 2u + 2u + 4u + 4u + 2u; /* 20 */
    const uint16_t block_total = 6u + body;                 /* 26 */
    const uint16_t var_len = block_total;
    if (cap < 2u + 12u + block_total) {
        return 0;
    }
    size_t n = 0;
    pn_wr_be16(pay + n, frame_id);
    n += 2;
    pn_wr_be16(pay + n, dst_ep);
    n += 2;
    pn_wr_be16(pay + n, src_ep);
    n += 2;
    pay[n++] = (uint8_t)((RTA_VERSION << 4) | RTA_TYPE_DATA);
    pay[n++] = (uint8_t)(RTA_ADD_WINDOW | (tack ? RTA_ADD_TACK : 0));
    pn_wr_be16(pay + n, send_seq);
    n += 2;
    pn_wr_be16(pay + n, ack_seq);
    n += 2;
    pn_wr_be16(pay + n, var_len);
    n += 2;
    pn_wr_be16(pay + n, frame_id == PN_FRAMEID_ALARM_LOW ? 0x0002u : 0x0001u);
    n += 2;
    pn_wr_be16(pay + n, (uint16_t)(var_len - 4u));
    n += 2;
    pay[n++] = 1;
    pay[n++] = 0;
    pn_wr_be16(pay + n, 0x0001); /* Diagnosis */
    n += 2;
    pn_wr_be32(pay + n, 0); /* API */
    n += 4;
    pn_wr_be16(pay + n, 0); /* slot */
    n += 2;
    pn_wr_be16(pay + n, 1); /* subslot */
    n += 2;
    pn_wr_be32(pay + n, 0); /* module ident */
    n += 4;
    pn_wr_be32(pay + n, 0); /* submodule ident */
    n += 4;
    pn_wr_be16(pay + n, 0); /* AlarmSpecifier */
    n += 2;
    return n;
}

static int send_tagged_alarm(pn_stack_t *s, uint16_t frame_id,
                             const uint8_t *pay, size_t plen, uint8_t *saved,
                             size_t saved_cap, size_t *saved_len)
{
    uint8_t frame[PN_FRAME_MAX];
    uint16_t tci = (frame_id == PN_FRAMEID_ALARM_LOW) ? PN_VLAN_TCI_ALARM_LOW
                                                      : PN_VLAN_TCI_ALARM_HIGH;
    size_t flen = pn_eth_build_vlan(frame, sizeof(frame), s->ar.initiator_mac,
                                    s->cfg.mac, tci, PN_ETHTYPE_PN, pay, plen);
    if (!flen) {
        return -EMSGSIZE;
    }
    if (saved && saved_len && flen <= saved_cap) {
        memcpy(saved, frame, flen);
        *saved_len = flen;
    }
    return pn_eth_send(s, frame, flen);
}

int pn_sec_hmac(const pn_stack_t *s, const uint8_t *data, size_t len,
                uint8_t mac[PN_HMAC_LEN])
{
    if (!s->cfg.psk_set) {
        return -1;
    }
    pn_hmac_sha256(s->cfg.psk, PN_PSK_LEN, data, len, mac);
    return 0;
}

int pn_sec_ok(const pn_stack_t *s, const uint8_t *data, size_t len,
              const uint8_t mac[PN_HMAC_LEN])
{
    uint8_t expect[PN_HMAC_LEN];
    if (pn_sec_hmac(s, data, len, expect) != 0) {
        return 0;
    }
    return pn_ct_eq(expect, mac, PN_HMAC_LEN);
}

int pn_alarm_send_dummy(pn_stack_t *s, uint16_t frame_id)
{
    if (!s || !s->ar.established) {
        return -ENOTCONN;
    }
    if (frame_id != PN_FRAMEID_ALARM_HIGH && frame_id != PN_FRAMEID_ALARM_LOW) {
        frame_id = PN_FRAMEID_ALARM_HIGH;
    }
    int chi = alarm_channel(frame_id);
    pn_alarm_ch_t *ch = &s->ar.alarm_ch[chi];
    if (ch->wait_ack) {
        LOG_WARN("pn_alarm", "RTA channel %d waiting for ACK", chi);
        return -EBUSY;
    }
    alarm_seq_ensure(ch);
    uint8_t pay[64];
    size_t plen = put_notification(pay, sizeof(pay), frame_id, alarm_dst(&s->ar),
                                   alarm_src(&s->ar), ch->send_seq, ch->ack_seq,
                                   1);
    if (!plen) {
        return -EMSGSIZE;
    }
    ch->frame_len = 0;
    int rc = send_tagged_alarm(s, frame_id, pay, plen, ch->frame,
                               sizeof(ch->frame), &ch->frame_len);
    if (rc != 0) {
        ch->frame_len = 0;
        return rc;
    }
    uint64_t tout = (uint64_t)s->ar.rta_timeout_factor * RTA_TIMEOUT_UNIT_NS;
    if (tout > 0 && ch->frame_len > 0) {
        ch->wait_ack = 1;
        ch->retries_left = s->ar.rta_retries;
        ch->ack_due_ns = pn_now_ns() + tout;
    }
    LOG_INFO("pn_alarm", "TX RTA DATA FrameID=0x%04x dst_ep=0x%04x seq=0x%04x",
             frame_id, alarm_dst(&s->ar), ch->send_seq);
    return 0;
}

void pn_alarm_send_err(pn_stack_t *s, uint8_t code2)
{
    if (!s || !s->ar.established) {
        return;
    }
    pn_alarm_ch_t *ch = &s->ar.alarm_ch[0];
    alarm_seq_ensure(ch);
    uint16_t send_seq = ch->send_seq;
    uint16_t ack_seq = ch->ack_seq;
    uint8_t pay[20];
    size_t n = 0;
    pn_wr_be16(pay + n, PN_FRAMEID_ALARM_LOW);
    n += 2;
    pn_wr_be16(pay + n, alarm_dst(&s->ar));
    n += 2;
    pn_wr_be16(pay + n, alarm_src(&s->ar));
    n += 2;
    pay[n++] = (uint8_t)((RTA_VERSION << 4) | RTA_TYPE_ERR);
    pay[n++] = RTA_ADD_WINDOW;
    pn_wr_be16(pay + n, send_seq);
    n += 2;
    pn_wr_be16(pay + n, ack_seq);
    n += 2;
    pn_wr_be16(pay + n, 4);
    n += 2;
    pay[n++] = 0xCF; /* RTA error */
    pay[n++] = 0x81; /* PNIO */
    pay[n++] = 0xFD; /* RTA_ERR_CLS_PROTOCOL */
    pay[n++] = code2;
    int rc = send_tagged_alarm(s, PN_FRAMEID_ALARM_LOW, pay, n, NULL, 0, NULL);
    if (rc != 0) {
        LOG_WARN("pn_alarm", "ERR-RTA-PDU send failed (%d)", rc);
    } else {
        LOG_WARN("pn_alarm", "TX ERR-RTA-PDU code2=0x%02x", code2);
    }
}

/* APMS: a TACK whose AckSeqNum matches the outstanding DATA frees it
 * and advances send_seq. send_seq_o keeps the sequence just TACKed;
 * an ACK-RTA we send uses that value. Mirrors pf_alarm_apms_a_data_ind. */
static void apms_on_tack(pn_alarm_ch_t *ch, uint16_t ack_seq, uint16_t frame_id)
{
    if (!ch->wait_ack || ack_seq != ch->send_seq) {
        return;
    }
    ch->wait_ack = 0;
    ch->frame_len = 0;
    ch->ack_due_ns = 0;
    ch->retries_left = 0;
    ch->send_seq_o = ch->send_seq;
    ch->send_seq = (uint16_t)((ch->send_seq + 1u) & 0x7FFFu);
    LOG_INFO("pn_alarm", "RTA ACK FrameID=0x%04x next_seq=0x%04x", frame_id,
             ch->send_seq);
}

/* APMR ACK. PDUType ACK v1, WindowSize 1, TACK 0. SendSeqNum is
 * send_seq_count_o and AckSeqNum is exp_seq_count_o. Not saved for
 * retransmission. Mirrors pf_alarm_apmr_send_ack. */
static void send_ack_rta(pn_stack_t *s, uint16_t frame_id, const pn_alarm_ch_t *ch)
{
    uint8_t pay[16];
    size_t n = 0;
    pn_wr_be16(pay + n, frame_id);
    n += 2;
    pn_wr_be16(pay + n, alarm_dst(&s->ar));
    n += 2;
    pn_wr_be16(pay + n, alarm_src(&s->ar));
    n += 2;
    pay[n++] = (uint8_t)((RTA_VERSION << 4) | RTA_TYPE_ACK);
    pay[n++] = RTA_ADD_WINDOW;
    pn_wr_be16(pay + n, ch->send_seq_o);
    n += 2;
    pn_wr_be16(pay + n, ch->ack_seq);
    n += 2;
    pn_wr_be16(pay + n, 0);
    n += 2;
    int rc = send_tagged_alarm(s, frame_id, pay, n, NULL, 0, NULL);
    if (rc != 0) {
        LOG_WARN("pn_alarm", "ACK-RTA send failed (%d)", rc);
    } else {
        LOG_INFO("pn_alarm",
                 "TX ACK-RTA FrameID=0x%04x SendSeq=0x%04x AckSeq=0x%04x",
                 frame_id, ch->send_seq_o, ch->ack_seq);
    }
}

void pn_alarm_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (!s || !s->ar.established || !payload || plen < 2u + 12u) {
        return;
    }
    uint16_t fid = pn_rd_be16(payload);
    if (fid != PN_FRAMEID_ALARM_HIGH && fid != PN_FRAMEID_ALARM_LOW) {
        return;
    }
    const uint8_t *rta = payload + 2;
    if (pn_rd_be16(rta) != alarm_src(&s->ar)) {
        return;
    }
    uint8_t pdu = rta[4];
    if ((pdu >> 4) != RTA_VERSION) {
        return;
    }
    uint8_t typ = (uint8_t)(pdu & 0x0Fu);
    if (typ != RTA_TYPE_ACK && typ != RTA_TYPE_DATA) {
        return;
    }
    pn_alarm_ch_t *ch = &s->ar.alarm_ch[alarm_channel(fid)];
    uint16_t recv_seq = pn_rd_be16(rta + 6);
    uint16_t recv_ack = pn_rd_be16(rta + 8);
    if (typ == RTA_TYPE_ACK) {
        apms_on_tack(ch, recv_ack, fid);
        return;
    }
    /* APMR OPEN: DATA with TACK and SendSeqNum == exp_seq_count.
     * The AckSeqNum is handed to APMS first, then the expected
     * sequence advances and one ACK-RTA goes out. A DATA whose
     * SendSeqNum is not the expected value is left for a later pass
     * (p-net resends the ACK for exp_seq_count_o and NACKs the rest). */
    if ((rta[5] & RTA_ADD_TACK) == 0 || recv_seq != ch->exp_seq) {
        return;
    }
    apms_on_tack(ch, recv_ack, fid);
    ch->ack_seq = ch->exp_seq;
    ch->exp_seq = (uint16_t)((ch->exp_seq + 1u) & 0x7FFFu);
    send_ack_rta(s, fid, ch);
}

void pn_alarm_poll(pn_stack_t *s)
{
    if (!s || !s->ar.established || s->ar.rta_timeout_factor == 0) {
        return;
    }
    uint64_t now = pn_now_ns();
    uint64_t tout = (uint64_t)s->ar.rta_timeout_factor * RTA_TIMEOUT_UNIT_NS;
    for (int i = 0; i < 2; i++) {
        pn_alarm_ch_t *ch = &s->ar.alarm_ch[i];
        if (!ch->wait_ack || ch->ack_due_ns == 0 || now < ch->ack_due_ns) {
            continue;
        }
        if (ch->retries_left > 0 && ch->frame_len > 0) {
            ch->retries_left--;
            int rc = pn_eth_send(s, ch->frame, ch->frame_len);
            ch->ack_due_ns = now + tout;
            if (rc != 0) {
                LOG_WARN("pn_alarm", "RTA retransmit failed (%d)", rc);
            } else {
                LOG_WARN("pn_alarm", "RTA retransmit ch=%d left=%u", i,
                         ch->retries_left);
            }
        } else {
            pn_ar_abort(s, "alarm ACK timeout");
            return;
        }
    }
}
