#include "pn_internal.h"

#include <errno.h>
#include <string.h>

#include "logger.h"
#include "pn_crypto.h"
#include "pn_endian.h"

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

    /* Minimal RTA AlarmNotification. Not a full PI alarm state machine. */
    uint8_t pay[32];
    memset(pay, 0, sizeof(pay));
    pn_wr_be16(pay, frame_id);
    pn_wr_be16(pay + 2, 1); /* dst endpoint */
    pn_wr_be16(pay + 4, 1); /* src endpoint */
    pay[6] = 0x01;          /* Data-RTA */
    pn_wr_be16(pay + 8, 1); /* send seq */
    pn_wr_be16(pay + 12, 12);
    pn_wr_be16(pay + 14, 0x0001); /* diagnosis appeared */
    pn_wr_be16(pay + 16, 0);      /* slot */
    pn_wr_be16(pay + 18, 1);      /* subslot */
    pn_wr_be16(pay + 20, 0x8000); /* manufacturer-specific USI */

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), s->ar.initiator_mac,
                               s->cfg.mac, PN_ETHTYPE_PN, pay, sizeof(pay));
    if (!flen) {
        return -EMSGSIZE;
    }
    int rc = pn_eth_send(s, frame, flen);
    if (rc == 0) {
        LOG_INFO("pn_alarm", "TX dummy Alarm FrameID=0x%04x", frame_id);
    }
    return rc;
}
