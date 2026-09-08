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

    uint8_t chassis[7];
    chassis[0] = 4; /* MAC address */
    memcpy(chassis + 1, s->cfg.mac, 6);
    tlv(pdu, &n, sizeof(pdu), 1, chassis, 7);

    static const char port_id[] = "port-001";
    uint8_t port[1 + sizeof(port_id)];
    port[0] = 7; /* locally assigned — matches PDPort / LLDP-MIB */
    memcpy(port + 1, port_id, sizeof(port_id) - 1);
    tlv(pdu, &n, sizeof(pdu), 2, port, (size_t)(1 + sizeof(port_id) - 1));

    uint8_t ttl[2];
    pn_wr_be16(ttl, 20);
    tlv(pdu, &n, sizeof(pdu), 3, ttl, 2);

    size_t namelen = strlen(s->cfg.station_name);
    tlv(pdu, &n, sizeof(pdu), 5, (const uint8_t *)s->cfg.station_name, namelen);

    uint8_t mgmt[12];
    mgmt[0] = 5; /* subtype + IPv4 */
    mgmt[1] = 1; /* IANA IPv4 */
    pn_wr_be32(mgmt + 2, s->cfg.ip);
    mgmt[6] = 1; /* unknown if numbering */
    pn_wr_be32(mgmt + 7, 0);
    mgmt[11] = 0; /* OID length */
    tlv(pdu, &n, sizeof(pdu), 8, mgmt, 12);

    /* IEEE 802.3 MAC/PHY Configuration/Status */
    uint8_t phy[9];
    phy[0] = 0x00;
    phy[1] = 0x12;
    phy[2] = 0x0F;
    phy[3] = 1;
    phy[4] = 0x03; /* autoneg supported + enabled */
    pn_wr_be16(phy + 5, 0);
    pn_wr_be16(phy + 7, 0x0010); /* 100BASE-TX FD */
    tlv(pdu, &n, sizeof(pdu), 127, phy, 9);

    uint8_t chassis_mac[10];
    chassis_mac[0] = 0x00;
    chassis_mac[1] = 0x0C;
    chassis_mac[2] = 0xCF;
    chassis_mac[3] = 5;
    memcpy(chassis_mac + 4, s->cfg.mac, 6);
    tlv(pdu, &n, sizeof(pdu), 127, chassis_mac, 10);

    uint8_t pst[8];
    pst[0] = 0x00;
    pst[1] = 0x0C;
    pst[2] = 0xCF;
    pst[3] = 2;
    pn_wr_be16(pst + 4, 0);
    pn_wr_be16(pst + 6, 0);
    tlv(pdu, &n, sizeof(pdu), 127, pst, 8);

    tlv(pdu, &n, sizeof(pdu), 0, NULL, 0);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), lldp_mc, s->cfg.mac,
                               PN_ETHTYPE_LLDP, pdu, n);
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
}

void pn_lldp_on_frame(pn_stack_t *s, const uint8_t *src, const uint8_t *payload,
                      size_t plen)
{
    if (!s || !payload) {
        return;
    }
    int changed = 0;
    size_t off = 0;
    while (off + 2 <= plen) {
        uint16_t hdr = pn_rd_be16(payload + off);
        uint8_t type = (uint8_t)(hdr >> 9);
        uint16_t len = (uint16_t)(hdr & 0x1FFu);
        off += 2;
        if (type == 0) {
            break;
        }
        if (off + len > plen) {
            break;
        }
        const uint8_t *val = payload + off;
        if (type == 1 && len >= 2) {
            s->lldp_rem_chassis_subtype = val[0];
            size_t clen = (size_t)len - 1;
            if (clen > sizeof(s->lldp_rem_chassis)) {
                clen = sizeof(s->lldp_rem_chassis);
            }
            memcpy(s->lldp_rem_chassis, val + 1, clen);
            s->lldp_rem_chassis_len = (uint8_t)clen;
            if (val[0] == 4 && len >= 7) {
                memcpy(s->lldp_rem_mac, val + 1, 6);
            }
            changed = 1;
        } else if (type == 2 && len >= 2) {
            s->lldp_rem_port_subtype = val[0];
            size_t plen_id = (size_t)len - 1;
            if (val[0] == 7 || val[0] == 5) {
                size_t n = plen_id < sizeof(s->lldp_rem_port) - 1
                               ? plen_id
                               : sizeof(s->lldp_rem_port) - 1;
                memcpy(s->lldp_rem_port, val + 1, n);
                s->lldp_rem_port[n] = '\0';
            } else {
                s->lldp_rem_port[0] = '\0';
            }
            changed = 1;
        } else if (type == 5 && len > 0) {
            size_t n = len < PN_STATION_NAME_MAX ? len : PN_STATION_NAME_MAX;
            memcpy(s->lldp_rem_name, val, n);
            s->lldp_rem_name[n] = '\0';
            s->lldp_rem_set = 1;
            changed = 1;
        }
        off += len;
    }
    if (!s->lldp_rem_set && src) {
        memcpy(s->lldp_rem_mac, src, 6);
    }
    if (changed) {
        s->lldp_last_change_ns = pn_now_ns();
        if (s->lldp_rem_name[0] || s->lldp_rem_chassis_len) {
            s->lldp_rem_set = 1;
        }
    }
}
