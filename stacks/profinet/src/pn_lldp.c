#include "pn_internal.h"

#include <string.h>

#include "pn_endian.h"

static void tlv(uint8_t *buf, size_t *n, size_t cap, uint8_t type,
                const uint8_t *val, size_t vlen)
{
    if (*n + 2 + vlen > cap) {
        return;
    }
    uint16_t hdr = (uint16_t)(((uint16_t)type << 9) | (vlen & 0x1FF));
    pn_wr_be16(buf + *n, hdr);
    *n += 2;
    if (vlen && val) {
        memcpy(buf + *n, val, vlen);
    }
    *n += vlen;
}

void pn_lldp_send(pn_stack_t *s)
{
    static const uint8_t lldp_mc[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    uint8_t pdu[512];
    size_t n = 0;

    uint8_t chassis[1 + PN_STATION_NAME_MAX];
    chassis[0] = 7; /* locally assigned */
    size_t namelen = strlen(s->cfg.station_name);
    memcpy(chassis + 1, s->cfg.station_name, namelen);
    tlv(pdu, &n, sizeof(pdu), 1, chassis, 1 + namelen);

    uint8_t port[7];
    port[0] = 3; /* MAC address */
    memcpy(port + 1, s->cfg.mac, 6);
    tlv(pdu, &n, sizeof(pdu), 2, port, 7);

    uint8_t ttl[2];
    pn_wr_be16(ttl, 20);
    tlv(pdu, &n, sizeof(pdu), 3, ttl, 2);

    tlv(pdu, &n, sizeof(pdu), 5, (const uint8_t *)s->cfg.station_name, namelen);

    /* IEEE 802.3 / PN org-specific: chassis MAC (00-0C-CF, subtype 5) */
    uint8_t org[10];
    org[0] = 0x00;
    org[1] = 0x0C;
    org[2] = 0xCF;
    org[3] = 5;
    memcpy(org + 4, s->cfg.mac, 6);
    tlv(pdu, &n, sizeof(pdu), 127, org, 10);

    /* End of LLDPDU */
    tlv(pdu, &n, sizeof(pdu), 0, NULL, 0);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), lldp_mc, s->cfg.mac,
                               PN_ETHTYPE_LLDP, pdu, n);
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
}
