#include "pn_internal.h"

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

int pn_alarm_send_dummy(pn_stack_t *s)
{
    (void)s;
    return 0;
}
