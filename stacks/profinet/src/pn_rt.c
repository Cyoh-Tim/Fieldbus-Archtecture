#include "pn_internal.h"

#include <string.h>

#include "logger.h"
#include "pn_endian.h"

void pn_ar_abort(pn_stack_t *s, const char *why)
{
    if (!s || !s->ar.established) {
        if (s) {
            memset(&s->ar, 0, sizeof(s->ar));
            s->last_rt_ns = 0;
        }
        return;
    }
    LOG_WARN("pn_rt", "AR aborted: %s", why ? why : "timeout");
    memset(&s->ar, 0, sizeof(s->ar));
    s->last_rt_ns = 0;
}

void pn_ar_watchdog(pn_stack_t *s)
{
    if (!s || !s->ar.established) {
        return;
    }
    uint64_t now = pn_now_ns();
    uint64_t cycle_ns = (uint64_t)s->cfg.cycle_us * 1000ull;
    if (cycle_ns == 0) {
        cycle_ns = 8000000ull;
    }
    uint64_t hold = cycle_ns * (uint64_t)PN_AR_DATA_HOLD_CYCLES;

    if (s->ar.saw_rt && s->ar.last_rt_rx_ns != 0 && now > s->ar.last_rt_rx_ns &&
        (now - s->ar.last_rt_rx_ns) > hold) {
        pn_ar_abort(s, "RT data-hold timer expired");
        return;
    }
    if (!s->ar.saw_rt && s->ar.last_cmi_ns != 0 && now > s->ar.last_cmi_ns &&
        (now - s->ar.last_cmi_ns) > PN_CMI_ACTIVITY_TIMEOUT_NS) {
        pn_ar_abort(s, "CMI activity timeout");
    }
}

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (!s->ar.established || plen < 6) {
        return;
    }
    uint16_t fid = pn_rd_be16(payload);
    if (fid != s->ar.out_frame_id) {
        return;
    }
    /* [FrameID][data][IOCS][CycleCounter][DataStatus][TransferStatus] */
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

void pn_rt_send_if_due(pn_stack_t *s)
{
    if (!s->ar.established) {
        return;
    }
    uint64_t now = pn_now_ns();
    uint64_t period = (uint64_t)s->cfg.cycle_us * 1000ull;
    if (period == 0) {
        period = 8000000ull;
    }
    /* last_rt_ns = next due (0 = due immediately). Phase += period so
     * poll jitter does not accumulate (soft CC-B / RT1; not IRT). */
    if (s->last_rt_ns != 0 && now < s->last_rt_ns) {
        return;
    }

    uint16_t data_len = s->ar.in_data_len;
    if (data_len == 0) {
        data_len = s->cfg.input_len;
    }
    if (data_len > s->cfg.input_len) {
        data_len = s->cfg.input_len;
    }

    uint8_t pay[PN_FRAME_MAX];
    size_t n = 0;
    pn_wr_be16(pay, s->ar.in_frame_id);
    n += 2;
    pthread_mutex_lock(&s->io_lock);
    memcpy(pay + n, s->input_image, data_len);
    pthread_mutex_unlock(&s->io_lock);
    n += data_len;
    pay[n++] = PN_IOPS_GOOD;
    pn_wr_be16(pay + n, s->cycle_counter++);
    n += 2;
    pay[n++] = (uint8_t)(PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                         PN_DATASTATUS_RUN);
    pay[n++] = 0; /* TransferStatus */

    uint8_t dst[6];
    memcpy(dst, s->ar.initiator_mac, 6);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(frame, sizeof(frame), dst, s->cfg.mac, PN_ETHTYPE_PN, pay, n);
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
