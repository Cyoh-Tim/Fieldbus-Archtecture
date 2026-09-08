#include "pn_internal.h"

#include "logger.h"
#include "pn_endian.h"

#include <string.h>

#define RTA_PDU_DATA 1
#define RTA_PDU_ACK  3
#define RTA_VERSION  1
#define RTA_ADDFLAGS 0x21
#define RTA_TIMEOUT_NS 200000000ull
#define RTA_MAX_RETRY  8
#define RTA_PHASE_NS   750000000ull

static void alarm_reset_tx(pn_stack_t *s)
{
    s->alarm_rta_sent = 0;
    s->alarm_rta_acked = 0;
    s->alarm_send_seq = 0;
    s->alarm_retries = 0;
    s->last_alarm_ns = 0;
    s->alarm_kind = 0;
}

void pn_alarm_on_connect(pn_stack_t *s, const uint8_t *body, uint16_t blen)
{
    if (!s || !body || blen < 14) {
        return;
    }
    /* AlarmCRType, LT, AlarmCRProperties (32), RTATimeout, RTARetries,
     * LocalAlarmReference (controller), MaxAlarmDataLength, TagHeader* */
    s->alarm_type = pn_rd_be16(body);
    uint16_t local_off = 12;
    if (blen >= 20) {
        s->alarm_max_len = pn_rd_be16(body + 14);
        s->alarm_tci = pn_rd_be16(body + 16);
    } else {
        /* UINT16 properties variant */
        local_off = 10;
        if (blen >= 16) {
            s->alarm_max_len = pn_rd_be16(body + 12);
        }
    }
    s->alarm_peer_ref = pn_rd_be16(body + local_off);
    if (!s->alarm_local_ref) {
        s->alarm_local_ref = 1;
    }
    if (!s->alarm_max_len) {
        s->alarm_max_len = 200;
    }
    if (!s->alarm_type) {
        s->alarm_type = 1;
    }
    s->alarm_cr_ok = 1;
    alarm_reset_tx(s);
}

static int diag_remaining_after_first(const pn_stack_t *s)
{
    int seen = 0;
    int remain = 0;
    for (int i = 0; i < s->n_diag; i++) {
        if (!s->diag[i].present) {
            continue;
        }
        if (!seen) {
            seen = 1;
        } else {
            remain++;
        }
    }
    return remain;
}

static size_t put_notify(uint8_t *p, int kind, int remaining)
{
    uint16_t altype =
        (kind == 2) ? PN_ALARM_TYPE_PROCESS : PN_ALARM_TYPE_DIAG;
    uint16_t spec = PN_CHAN_APPEARS;
    if (kind == 1) {
        spec = remaining ? PN_CHAN_DISAPPEARS_REM : PN_CHAN_DISAPPEARS;
    }
    /* AlarmNotification-High + optional USI ChannelDiagnosis. */
    pn_wr_be16(p, 0x0001);
    p[4] = 1;
    p[5] = 0;
    pn_wr_be16(p + 6, altype);
    pn_wr_be32(p + 8, 0);
    pn_wr_be16(p + 12, 0);
    pn_wr_be16(p + 14, 0x8001);
    pn_wr_be32(p + 16, 1);
    pn_wr_be32(p + 20, 3);
    pn_wr_be16(p + 24, spec);
    if (kind == 2) {
        pn_wr_be16(p + 2, 24);
        pn_wr_be16(p + 26, 0);
        return 28;
    }
    pn_wr_be16(p + 2, 30);
    pn_wr_be16(p + 26, PN_USI_CHANNEL_DIAG);
    pn_wr_be16(p + 28, 0x8000);
    pn_wr_be16(p + 30, spec);
    pn_wr_be16(p + 32, 0x0010);
    return 34;
}

static void send_rta_data(pn_stack_t *s)
{
    if (!s->ar.established || s->ar.cm_state != PN_CM_DATAEX) {
        return;
    }
    uint16_t dst_ref = s->alarm_peer_ref ? s->alarm_peer_ref : 1;
    uint16_t src_ref = s->alarm_local_ref ? s->alarm_local_ref : 1;
    uint8_t pay[96];
    size_t n = 0;
    pn_wr_be16(pay + n, PN_FRAMEID_ALARM_HIGH);
    n += 2;
    pn_wr_be16(pay + n, dst_ref);
    n += 2;
    pn_wr_be16(pay + n, src_ref);
    n += 2;
    pay[n++] = (uint8_t)((RTA_VERSION << 4) | RTA_PDU_DATA);
    pay[n++] = RTA_ADDFLAGS;
    pn_wr_be16(pay + n, s->alarm_send_seq);
    n += 2;
    pn_wr_be16(pay + n, 0xFFFF);
    n += 2;
    size_t vlen_at = n;
    n += 2;
    size_t vn = put_notify(pay + n, s->alarm_kind,
                           diag_remaining_after_first(s));
    n += vn;
    pn_wr_be16(pay + vlen_at, (uint16_t)vn);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), s->ar.initiator_mac,
                               s->cfg.mac, PN_ETHTYPE_PN, pay, n);
    if (flen) {
        pn_eth_send(s, frame, flen);
        s->alarm_rta_sent = 1;
        if (s->alarm_kind == 0) {
            s->diag_present = 1;
            pn_diag_arm_default(s);
        }
        s->last_alarm_ns = pn_now_ns();
        LOG_INFO("pn_alarm", "RTA Data seq=%u kind=%d dst_ref=%u src_ref=%u",
                 s->alarm_send_seq, s->alarm_kind, dst_ref, src_ref);
    }
}

static void start_next_phase(pn_stack_t *s, int kind)
{
    s->alarm_kind = kind;
    s->alarm_send_seq++;
    s->alarm_rta_sent = 0;
    s->alarm_rta_acked = 0;
    s->alarm_retries = 0;
    send_rta_data(s);
}

void pn_alarm_poll(pn_stack_t *s)
{
    if (!s->ar.established || s->ar.cm_state != PN_CM_DATAEX) {
        return;
    }
    if (!s->alarm_cr_ok && !s->alarm_peer_ref && !s->alarm_local_ref) {
        /* Connect.res always offers AlarmCR; send one notify even if the
         * controller omitted AlarmCR_REQ (lab default refs = 1). */
        s->alarm_local_ref = 1;
        s->alarm_peer_ref = 1;
        s->alarm_max_len = 200;
        s->alarm_cr_ok = 1;
    }
    uint64_t now = pn_now_ns();
    if (s->alarm_rta_acked) {
        if (s->last_alarm_ns == 0 || now - s->last_alarm_ns < RTA_PHASE_NS) {
            return;
        }
        if (s->alarm_kind == 0) {
            start_next_phase(s, 1);
        } else if (s->alarm_kind == 1) {
            start_next_phase(s, 2);
        }
        return;
    }
    if (!s->alarm_rta_sent) {
        send_rta_data(s);
        return;
    }
    if (now - s->last_alarm_ns < RTA_TIMEOUT_NS) {
        return;
    }
    if (s->alarm_retries >= RTA_MAX_RETRY) {
        LOG_WARN("pn_alarm", "RTA retries exhausted seq=%u kind=%d",
                 s->alarm_send_seq, s->alarm_kind);
        if (s->alarm_kind == 2) {
            pn_diag_disappear(s, 1);
        }
        /* Mark acked so poll does not WARN on every subsequent cycle. */
        s->alarm_rta_acked = 1;
        s->last_alarm_ns = now;
        return;
    }
    s->alarm_retries++;
    send_rta_data(s);
}

void pn_alarm_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (!payload || plen < 14) {
        return;
    }
    uint16_t fid = pn_rd_be16(payload);
    if (fid != PN_FRAMEID_ALARM_HIGH && fid != PN_FRAMEID_ALARM_LOW) {
        return;
    }
    uint16_t dst_ref = pn_rd_be16(payload + 2);
    uint8_t pdu_type = payload[6];
    uint16_t ack_seq = pn_rd_be16(payload + 10);
    uint8_t kind = (uint8_t)(pdu_type & 0x0Fu);
    uint16_t local = s->alarm_local_ref ? s->alarm_local_ref : 1;
    if (kind == RTA_PDU_ACK && dst_ref == local &&
        ack_seq == s->alarm_send_seq) {
        s->alarm_rta_acked = 1;
        s->last_alarm_ns = pn_now_ns();
        if (s->alarm_kind == 1) {
            pn_diag_disappear(s, 0);
        } else if (s->alarm_kind == 2) {
            /* Lab ASE demo must not leave a sticky diagnosis for the AR. */
            pn_diag_disappear(s, 1);
        }
        LOG_INFO("pn_alarm", "RTA ACK seq=%u kind=%d", ack_seq, s->alarm_kind);
    }
}
