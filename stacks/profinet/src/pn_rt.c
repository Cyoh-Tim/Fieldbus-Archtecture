#include "pn_internal.h"

#include <string.h>

#include "logger.h"
#include "pn_endian.h"

static void copy_from_csdu(pn_stack_t *s, const uint8_t *csdu, size_t clen)
{
    const pn_iocr_t *cr = &s->ar.iocr_out;
    pthread_mutex_lock(&s->io_lock);
    if (cr->n_data == 0) {
        size_t n = s->ar.out_data_len;
        if (n > s->cfg.output_len) {
            n = s->cfg.output_len;
        }
        if (n > clen) {
            n = clen;
        }
        memcpy(s->output_image, csdu, n);
    } else {
        for (int i = 0; i < cr->n_data; i++) {
            const pn_submod_t *sm =
                pn_find_sub(&s->ar, cr->data[i].slot, cr->data[i].subslot);
            uint16_t len = sm ? sm->out_len : s->ar.out_data_len;
            uint16_t pi = sm ? sm->out_pi : 0;
            uint16_t off = cr->data[i].frame_off;
            if ((size_t)off + len > clen) {
                continue;
            }
            if ((size_t)pi + len > s->cfg.output_len) {
                if (pi >= s->cfg.output_len) {
                    continue;
                }
                len = (uint16_t)(s->cfg.output_len - pi);
            }
            memcpy(s->output_image + pi, csdu + off, len);
        }
    }
    pthread_mutex_unlock(&s->io_lock);
}

static size_t build_input_csdu(pn_stack_t *s, uint8_t *csdu, size_t cap)
{
    const pn_iocr_t *cr = &s->ar.iocr_in;
    size_t clen = cr->data_len;
    if (clen < (size_t)s->ar.in_data_len + 1u) {
        clen = (size_t)s->ar.in_data_len + 1u;
    }
    if (clen > cap) {
        clen = cap;
    }
    memset(csdu, 0, clen);
    pthread_mutex_lock(&s->io_lock);
    if (cr->n_data == 0) {
        size_t n = s->ar.in_data_len;
        if (n > s->cfg.input_len) {
            n = s->cfg.input_len;
        }
        if (n > clen) {
            n = clen;
        }
        memcpy(csdu, s->input_image, n);
        if (n < clen) {
            csdu[n] = PN_IOPS_GOOD;
        }
    } else {
        for (int i = 0; i < cr->n_data; i++) {
            const pn_submod_t *sm =
                pn_find_sub(&s->ar, cr->data[i].slot, cr->data[i].subslot);
            uint16_t len = sm ? sm->in_len : s->ar.in_data_len;
            uint16_t pi = sm ? sm->in_pi : 0;
            uint16_t iops_len = sm && sm->iops_len ? sm->iops_len : 1;
            uint16_t off = cr->data[i].frame_off;
            if ((size_t)off + len > clen) {
                continue;
            }
            if ((size_t)pi + len > PN_IO_MAX) {
                continue;
            }
            memcpy(csdu + off, s->input_image + pi, len);
            if ((size_t)off + len + iops_len <= clen) {
                memset(csdu + off + len, PN_IOPS_GOOD, iops_len);
            }
        }
        for (int i = 0; i < cr->n_iocs; i++) {
            uint16_t off = cr->iocs[i].frame_off;
            if (off < clen) {
                csdu[off] = PN_IOPS_GOOD;
            }
        }
    }
    pthread_mutex_unlock(&s->io_lock);
    return clen;
}

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (s->ar.cm_state < PN_CM_CONNECTED || plen < 6) {
        return;
    }
    uint16_t fid = pn_rd_be16(payload);
    if (fid != s->ar.out_frame_id) {
        return;
    }
    size_t csdu_len = s->ar.iocr_out.data_len;
    if (csdu_len == 0) {
        csdu_len = (size_t)s->ar.out_data_len + 1u;
    }
    if (2 + csdu_len > plen) {
        /* APDU status may still fit with a shorter C_SDU; take what we have. */
        if (plen < 7) {
            return;
        }
        csdu_len = plen - 6; /* leave room for APDU status if present */
        if (2 + csdu_len > plen) {
            csdu_len = plen - 2;
        }
    }
    copy_from_csdu(s, payload + 2, csdu_len);
    s->last_cpm_ns = pn_now_ns();
}

void pn_rt_send_if_due(pn_stack_t *s)
{
    if (!s->ar.established || s->ar.cm_state != PN_CM_DATAEX) {
        return;
    }
    uint64_t now = pn_now_ns();
    uint64_t period = pn_ar_cycle_ns(&s->ar, s->cfg.cycle_us);
    if (s->last_rt_ns != 0 && now - s->last_rt_ns < period) {
        return;
    }
    s->last_rt_ns = now;

    uint8_t pay[PN_FRAME_MAX];
    size_t n = 0;
    pn_wr_be16(pay, s->ar.in_frame_id);
    n += 2;
    n += build_input_csdu(s, pay + n, sizeof(pay) - n - 4);
    pn_wr_be16(pay + n, s->cycle_counter++);
    n += 2;
    pay[n++] = (uint8_t)(PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                         PN_DATASTATUS_RUN);
    pay[n++] = 0;

    uint8_t dst[6];
    memcpy(dst, s->ar.initiator_mac, 6);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen;
    uint16_t vid = s->ar.iocr_in.vlan_id;
    if (vid != 0) {
        uint8_t pcp = s->ar.iocr_in.pcp ? s->ar.iocr_in.pcp : 6;
        uint16_t tci = (uint16_t)(((uint16_t)pcp << 13) | vid);
        flen = pn_eth_build_vlan(frame, sizeof(frame), dst, s->cfg.mac, tci,
                                 PN_ETHTYPE_PN, pay, n);
    } else {
        flen = pn_eth_build(frame, sizeof(frame), dst, s->cfg.mac, PN_ETHTYPE_PN,
                            pay, n);
    }
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
}

void pn_rt_watchdog(pn_stack_t *s)
{
    if (!s->ar.established || s->ar.cm_state != PN_CM_DATAEX) {
        return;
    }
    if (s->ar.out_data_len == 0 && s->ar.iocr_out.n_data == 0) {
        return;
    }
    uint64_t now = pn_now_ns();
    uint64_t wd = pn_ar_watchdog_ns(&s->ar, s->cfg.cycle_us);
    if (s->last_cpm_ns == 0) {
        return;
    }
    if (now - s->last_cpm_ns <= wd) {
        return;
    }
    LOG_WARN("pn_rt", "output CR watchdog expired — AR down");
    pn_ar_reset(s);
}
