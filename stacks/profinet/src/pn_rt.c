#include "pn_internal.h"

#include <string.h>

#include "logger.h"
#include "pn_endian.h"

/* ERR-RTA-PDU ErrorCode2 for RTA_ERR_CLS_PROTOCOL (0xFD).
 * p-net: CONSUMER_DHT_EXPIRED 0x05, CMI_TIMEOUT 0x06,
 * ALARM_SEND_CNF_NEG 0x08, ABORT_REQ 0x0d. */
static uint8_t abort_rta_code2(const char *why)
{
    if (!why) {
        return 0x0d;
    }
    if (strstr(why, "data-hold") != NULL) {
        return 0x05;
    }
    if (strstr(why, "CMI") != NULL) {
        return 0x06;
    }
    if (strstr(why, "alarm ACK") != NULL) {
        return 0x08;
    }
    /* p-net PNET_ERROR_CODE_2_ABORT_DCP_STATION_NAME_CHANGED / RESET_TO_FACTORY. */
    if (strstr(why, "DCP station name") != NULL) {
        return 0x1F;
    }
    if (strstr(why, "DCP reset to factory") != NULL) {
        return 0x20;
    }
    return 0x0d;
}

void pn_ar_abort(pn_stack_t *s, const char *why)
{
    if (!s || !s->ar.established) {
        if (s) {
            memset(&s->ar, 0, sizeof(s->ar));
            s->last_rt_ns = 0;
        }
        return;
    }
    /* Substitute value. No per-submodule substitute is configured, so
     * the output image the application reads becomes zero. Do this
     * before the AR is dropped. */
    pthread_mutex_lock(&s->io_lock);
    memset(s->output_image, 0, s->cfg.output_len);
    pthread_mutex_unlock(&s->io_lock);
    pn_alarm_send_err(s, abort_rta_code2(why));
    LOG_WARN("pn_rt", "AR aborted: %s", why ? why : "timeout");
    memset(&s->ar, 0, sizeof(s->ar));
    s->last_rt_ns = 0;
}

static int ar_controller_live(const pn_ar_t *ar)
{
    /* Liveness is the controller, not our RTC1 transmit. */
    return ar->saw_rt || ar->prm_end || ar->app_ready;
}

void pn_ar_watchdog(pn_stack_t *s)
{
    if (!s || !s->ar.established) {
        return;
    }
    uint64_t now = pn_now_ns();
    if (!ar_controller_live(&s->ar)) {
        if (s->ar.last_cmi_ns != 0 && now > s->ar.last_cmi_ns &&
            (now - s->ar.last_cmi_ns) > PN_CMI_ACTIVITY_TIMEOUT_NS) {
            pn_ar_abort(s, "CMI activity timeout");
        }
        return;
    }

    /* No output-CR clock: do not disarm the watchdog. Stay on the CMI
     * window, and let a received O→T refresh it, so a vanished
     * controller is still reclaimed. cfg.cycle_us is not this period. */
    if (s->ar.send_clock_factor == 0 || s->ar.reduction_ratio == 0) {
        uint64_t base = s->ar.last_cmi_ns;
        if (s->ar.saw_rt && s->ar.last_rt_rx_ns > base) {
            base = s->ar.last_rt_rx_ns;
        }
        if (base != 0 && now > base &&
            (now - base) > PN_CMI_ACTIVITY_TIMEOUT_NS) {
            pn_ar_abort(s, "CMI activity timeout");
        }
        return;
    }
    unsigned factor = s->ar.data_hold_factor ? s->ar.data_hold_factor
                                             : (unsigned)PN_AR_DATA_HOLD_CYCLES;
    uint64_t hold = (uint64_t)s->ar.send_clock_factor *
                    (uint64_t)s->ar.reduction_ratio * PN_SEND_CLOCK_BASE_NS *
                    (uint64_t)factor;
    /* After PrmEnd/ApplReady with no O→T yet, silence is measured from
     * the last controller RPC. After the first O→T, from that frame. */
    uint64_t base = s->ar.saw_rt ? s->ar.last_rt_rx_ns : s->ar.last_cmi_ns;
    if (base != 0 && now > base && (now - base) > hold) {
        pn_ar_abort(s, "RT data-hold timer expired");
    }
}

#define PN_CSDU_MAX 1440

static const pn_exp_sub_t *exp_of(const pn_ar_t *ar, uint32_t api, uint16_t slot,
                                  uint16_t subslot)
{
    for (uint8_t i = 0; i < ar->exp_sub_n; i++) {
        if (ar->exp_sub[i].api == api && ar->exp_sub[i].slot == slot &&
            ar->exp_sub[i].subslot == subslot) {
            return &ar->exp_sub[i];
        }
    }
    return NULL;
}

/* SubmoduleProperties DiscardIOXS is bit 5 (scapy bit order). */
static int discard_ioxs(uint16_t props)
{
    return (props & 0x0020u) != 0;
}

static int sub_matches(const pn_ar_t *ar, uint32_t api, uint16_t slot,
                       uint16_t subslot)
{
    uint32_t real_mod = 0;
    uint32_t real_sub = 0;
    int is_io = 0;
    if (!pn_real_mod_ident(slot, &real_mod)) {
        return 0;
    }
    if (!pn_real_sub_find(slot, subslot, &real_sub, &is_io)) {
        return 0;
    }
    const pn_exp_sub_t *e = exp_of(ar, api, slot, subslot);
    if (e && (e->mod_ident != real_mod || e->sub_ident != real_sub)) {
        return 0;
    }
    return 1;
}

static void pack_input_csdu(pn_stack_t *s, uint8_t *csdu, uint16_t csdu_len)
{
    memset(csdu, 0, csdu_len);
    pthread_mutex_lock(&s->io_lock);
    for (uint8_t i = 0; i < s->ar.in_io_n; i++) {
        const pn_iocr_ref_t *r = &s->ar.in_io[i];
        const pn_exp_sub_t *e = exp_of(&s->ar, r->api, r->slot, r->subslot);
        uint16_t dlen = 0;
        uint8_t iops_len = 1;
        if (e && e->has_in) {
            dlen = e->in_len;
            iops_len = e->in_iops;
        } else if (e && discard_ioxs(e->props)) {
            iops_len = 0;
        }
        int good = sub_matches(&s->ar, r->api, r->slot, r->subslot);
        uint32_t real_sub = 0;
        int is_io = 0;
        int have = pn_real_sub_find(r->slot, r->subslot, &real_sub, &is_io);
        if (have && is_io && good && dlen > 0 && r->frame_off < csdu_len) {
            uint16_t n = dlen;
            if ((uint32_t)r->frame_off + n > csdu_len) {
                n = (uint16_t)(csdu_len - r->frame_off);
            }
            uint16_t copy = n;
            if (copy > s->cfg.input_len) {
                copy = s->cfg.input_len;
            }
            memcpy(csdu + r->frame_off, s->input_image, copy);
        }
        if (iops_len > 0) {
            uint32_t at = (uint32_t)r->frame_off + dlen;
            if (at < csdu_len) {
                csdu[at] = good ? PN_IOPS_GOOD : 0x00;
            }
        }
    }
    for (uint8_t i = 0; i < s->ar.in_iocs_n; i++) {
        const pn_iocr_ref_t *r = &s->ar.in_iocs[i];
        if (r->frame_off >= csdu_len) {
            continue;
        }
        int good = sub_matches(&s->ar, r->api, r->slot, r->subslot);
        csdu[r->frame_off] = good ? PN_IOPS_GOOD : 0x00;
    }
    pthread_mutex_unlock(&s->io_lock);
}

static void consume_output_csdu(pn_stack_t *s, const uint8_t *csdu, size_t avail)
{
    pthread_mutex_lock(&s->io_lock);
    for (uint8_t i = 0; i < s->ar.out_io_n; i++) {
        const pn_iocr_ref_t *r = &s->ar.out_io[i];
        const pn_exp_sub_t *e = exp_of(&s->ar, r->api, r->slot, r->subslot);
        if (!e || !e->has_out || e->out_len == 0) {
            continue;
        }
        uint32_t real_sub = 0;
        int is_io = 0;
        if (!pn_real_sub_find(r->slot, r->subslot, &real_sub, &is_io) || !is_io) {
            continue;
        }
        if (!sub_matches(&s->ar, r->api, r->slot, r->subslot)) {
            continue;
        }
        if ((size_t)r->frame_off >= avail) {
            continue;
        }
        uint16_t n = e->out_len;
        if ((size_t)r->frame_off + n > avail) {
            n = (uint16_t)(avail - r->frame_off);
        }
        if (n > s->cfg.output_len) {
            n = s->cfg.output_len;
        }
        memcpy(s->output_image, csdu + r->frame_off, n);
    }
    pthread_mutex_unlock(&s->io_lock);
}

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (!s->ar.established || plen < 6) {
        return;
    }
    uint16_t fid = pn_rd_be16(payload);
    if (fid == PN_FRAMEID_ALARM_HIGH || fid == PN_FRAMEID_ALARM_LOW) {
        pn_alarm_on_frame(s, payload, plen);
        return;
    }
    if (fid != s->ar.out_frame_id) {
        return;
    }
    if (s->ar.have_out_layout && s->ar.out_csdu_len > 0) {
        const uint8_t *csdu = payload + 2;
        size_t avail = plen - 2;
        if (avail >= (size_t)s->ar.out_csdu_len + 4u) {
            avail = s->ar.out_csdu_len;
        }
        consume_output_csdu(s, csdu, avail);
        s->ar.saw_rt = 1;
        s->ar.last_rt_rx_ns = pn_now_ns();
        return;
    }
    /* No IODataObject list: [FrameID][data][IOPS][CycleCounter][DataStatus][TransferStatus]. */
    size_t data_len = s->ar.out_data_len;
    if (data_len > s->cfg.output_len) {
        data_len = s->cfg.output_len;
    }
    if (2 + data_len + 1 + 4 > plen) {
        return;
    }
    pthread_mutex_lock(&s->io_lock);
    memcpy(s->output_image, payload + 2, data_len);
    pthread_mutex_unlock(&s->io_lock);
    s->ar.saw_rt = 1;
    s->ar.last_rt_rx_ns = pn_now_ns();
}

/* Tagged RTC1: 18 + FrameID(2) + C_SDU + APDU(4) >= 60 => C_SDU >= 36.
 * TX always has the tag, so the untagged C_SDU 40 rule is not used. */
_Static_assert(60u - 18u - 2u - 4u == 36u, "tagged RTC1 C_SDU minimum");

size_t pn_rtc1_pad_min_csdu(uint8_t *frame, size_t len, size_t cap)
{
    if (!frame || len == 0 || cap < len) {
        return 0;
    }
    /* Offset 12 must be TPID 0x8100. An untagged RTC1 frame is left
     * as built: the 40-octet minimum is not applied on this path. */
    if (len < 18 || pn_rd_be16(frame + 12) != PN_ETHTYPE_VLAN) {
        return len;
    }
    if (pn_rd_be16(frame + 16) != PN_ETHTYPE_PN) {
        return len;
    }
    if (len < 18u + 2u + 4u) {
        return len;
    }
    uint16_t fid = pn_rd_be16(frame + 18);
    /* RTC1 unicast range. Alarm, DCP, and RT multicast stay as built. */
    if (fid < 0x8000u || fid > 0xBBFFu) {
        return len;
    }
    size_t csdu = len - 18u - 2u - 4u;
    const size_t min_csdu = 36u;
    if (csdu >= min_csdu) {
        return len;
    }
    size_t pad = min_csdu - csdu;
    if (len + pad > cap) {
        LOG_ERROR("pn_rt",
                  "RTC1 C_SDU pad does not fit (len=%zu pad=%zu cap=%zu)",
                  len, pad, cap);
        return 0;
    }
    memmove(frame + (len - 4u) + pad, frame + (len - 4u), 4);
    memset(frame + (len - 4u), 0, pad);
    return len + pad;
}

/* Input CR period, or 0 when that CR did not negotiate a clock. */
static uint64_t input_cr_period_ns(const pn_stack_t *s)
{
    if (s->ar.in_send_clock_factor == 0 || s->ar.in_reduction_ratio == 0) {
        return 0;
    }
    return (uint64_t)s->ar.in_send_clock_factor *
           (uint64_t)s->ar.in_reduction_ratio * PN_SEND_CLOCK_BASE_NS;
}

static uint64_t cfg_period_ns(const pn_stack_t *s)
{
    uint64_t cfg = (uint64_t)s->cfg.cycle_us * 1000ull;
    return cfg ? cfg : 8000000ull;
}

/* Negotiated input period when it is at least cfg.cycle_us. A shorter
 * input period stays on cfg.cycle_us (rate ceiling / T5 rejects it). */
static uint64_t rt_send_period_ns(const pn_stack_t *s)
{
    uint64_t cfg = cfg_period_ns(s);
    uint64_t neg = input_cr_period_ns(s);
    if (neg == 0 || neg < cfg) {
        return cfg;
    }
    return neg;
}

/* SCF×RR when the frame interval is the negotiated input period.
 * Otherwise one count per frame, as before this clock existed. */
static uint16_t rt_cycle_step(const pn_stack_t *s)
{
    uint64_t neg = input_cr_period_ns(s);
    if (neg == 0 || neg < cfg_period_ns(s)) {
        return 1;
    }
    uint32_t prod = (uint32_t)s->ar.in_send_clock_factor *
                    (uint32_t)s->ar.in_reduction_ratio;
    uint16_t step = (uint16_t)prod;
    return step ? step : 1;
}

void pn_rt_send_if_due(pn_stack_t *s)
{
    if (!s->ar.established) {
        return;
    }
    uint64_t now = pn_now_ns();
    uint64_t period = rt_send_period_ns(s);
    /* last_rt_ns = next due (0 = due immediately). Phase += period so
     * poll jitter does not accumulate (soft CC-B / RT1; not IRT). */
    if (s->last_rt_ns != 0 && now < s->last_rt_ns) {
        return;
    }

    uint8_t pay[PN_FRAME_MAX];
    size_t n = 0;
    pn_wr_be16(pay, s->ar.in_frame_id);
    n += 2;
    if (s->ar.have_in_layout && s->ar.in_csdu_len > 0) {
        uint16_t csdu_len = s->ar.in_csdu_len;
        if (csdu_len > PN_CSDU_MAX) {
            csdu_len = PN_CSDU_MAX;
        }
        if (n + csdu_len + 4 > sizeof(pay)) {
            return;
        }
        pack_input_csdu(s, pay + n, csdu_len);
        n += csdu_len;
    } else {
        uint16_t data_len = s->ar.in_data_len;
        if (data_len == 0) {
            data_len = s->cfg.input_len;
        }
        if (data_len > s->cfg.input_len) {
            data_len = s->cfg.input_len;
        }
        pthread_mutex_lock(&s->io_lock);
        memcpy(pay + n, s->input_image, data_len);
        pthread_mutex_unlock(&s->io_lock);
        n += data_len;
        pay[n++] = PN_IOPS_GOOD;
    }
    pn_wr_be16(pay + n, s->cycle_counter);
    s->cycle_counter = (uint16_t)(s->cycle_counter + rt_cycle_step(s));
    n += 2;
    pay[n++] = (uint8_t)(PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                         PN_DATASTATUS_RUN | PN_DATASTATUS_NO_PROBLEM);
    pay[n++] = 0; /* TransferStatus */

    uint8_t dst[6];
    memcpy(dst, s->ar.initiator_mac, 6);
    uint8_t frame[PN_FRAME_MAX];
    /* Always 802.1Q. TCI is PCP 6 / VID 0, not the Connect IOCRTagHeader.
     * A short C_SDU is padded to 36 so the tagged frame is 60 octets
     * without FCS. The pad is before APDUStatus: trailer zeros after
     * the status are what a controller would read as DataStatus. */
    size_t flen = pn_eth_build_vlan(frame, sizeof(frame), dst, s->cfg.mac,
                                    PN_VLAN_TCI_RTC1, PN_ETHTYPE_PN, pay, n);
    if (flen) {
        flen = pn_rtc1_pad_min_csdu(frame, flen, sizeof(frame));
    }
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
    if (s->last_rt_ns == 0) {
        s->last_rt_ns = now + period;
    } else {
        s->last_rt_ns += period;
        if (s->last_rt_ns <= now) {
            s->last_rt_ns = now + period; /* slipped: resync, no burst */
        }
    }
}
