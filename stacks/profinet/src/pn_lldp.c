#include "pn_internal.h"

#include <string.h>

#include "pn_endian.h"

/* IEEE 802.1AB subtype 7: locally assigned. */
#define LLDP_SUBTYPE_LOCAL 7

/* PROFIBUS & PROFINET International OUI. 00-0C-CF is not this OUI. */
static const uint8_t k_pno_oui[3] = {0x00, 0x0E, 0xCF};
/* IEEE 802.3 organizationally specific OUI (MAC/PHY TLV). */
static const uint8_t k_ieee8023_oui[3] = {0x00, 0x12, 0x0F};

/* Current PROFINET Port ID. The older form was "port-001.<station>". */
static const char k_port_id[] = "port-001";

/* IEEE 802.3 clause 79.3.2 auto-negotiation support/status. */
#define LLDP_AUTONEG_SUPPORTED 0x01u
#define LLDP_AUTONEG_ENABLED 0x02u
/* RFC 3636 ifMauAutoNegCapAdvertisedBits, bit 0 in the MSB:
 * b100baseTXFD(5). Same MAU as GSDML PortSubmoduleItem MAUTypes="16"
 * (dot3MauType100BaseTXFD). */
#define LLDP_ADV_100BASE_TXFD 0x0400u
#define LLDP_MAU_100BASE_TXFD 16u

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

/* IEEE 802.1AB Management Address: IPv4 of this device.
 * Interface numbering subtype 2 is ifIndex. A mock or not-yet-opened
 * port has no OS index; a one-port device uses 1. */
static void add_mgmt_addr(uint8_t *pdu, size_t *n, size_t cap, pn_stack_t *s)
{
    uint8_t v[12];
    uint32_t ifindex = s->ifindex > 0 ? (uint32_t)s->ifindex : 1u;

    v[0] = 5; /* string length: subtype + 4-byte address */
    v[1] = 1; /* IANA Address Family: IPv4 */
    pn_wr_be32(v + 2, s->cfg.ip);
    v[6] = 2; /* ifIndex */
    pn_wr_be32(v + 7, ifindex);
    v[11] = 0; /* OID length */
    tlv(pdu, n, cap, 8, v, sizeof(v));
}

/* PNO subtype 2 Port Status. RT Class 2 and 3 are not used
 * (this stack is RT Class 1 only). LLDP_PortStatus 0 = OFF. */
static void add_port_status(uint8_t *pdu, size_t *n, size_t cap)
{
    uint8_t v[8];

    memcpy(v, k_pno_oui, 3);
    v[3] = 2;
    pn_wr_be16(v + 4, 0);
    pn_wr_be16(v + 6, 0);
    tlv(pdu, n, cap, 127, v, sizeof(v));
}

/* PNO subtype 5 Chassis MAC. */
static void add_chassis_mac(uint8_t *pdu, size_t *n, size_t cap,
                            const uint8_t mac[6])
{
    uint8_t v[10];

    memcpy(v, k_pno_oui, 3);
    v[3] = 5;
    memcpy(v + 4, mac, 6);
    tlv(pdu, n, cap, 127, v, sizeof(v));
}

/* IEEE 802.3 subtype 1 MAC/PHY Configuration/Status. */
static void add_mac_phy(uint8_t *pdu, size_t *n, size_t cap)
{
    uint8_t v[9];

    memcpy(v, k_ieee8023_oui, 3);
    v[3] = 1;
    v[4] = (uint8_t)(LLDP_AUTONEG_SUPPORTED | LLDP_AUTONEG_ENABLED);
    pn_wr_be16(v + 5, LLDP_ADV_100BASE_TXFD);
    pn_wr_be16(v + 7, LLDP_MAU_100BASE_TXFD);
    tlv(pdu, n, cap, 127, v, sizeof(v));
}

void pn_lldp_send(pn_stack_t *s)
{
    static const uint8_t lldp_mc[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    uint8_t pdu[512];
    size_t n = 0;

    uint8_t chassis[1 + PN_STATION_NAME_MAX];
    chassis[0] = LLDP_SUBTYPE_LOCAL;
    size_t namelen = strlen(s->cfg.station_name);
    memcpy(chassis + 1, s->cfg.station_name, namelen);
    tlv(pdu, &n, sizeof(pdu), 1, chassis, 1 + namelen);

    uint8_t port[1 + sizeof(k_port_id) - 1];
    port[0] = LLDP_SUBTYPE_LOCAL;
    memcpy(port + 1, k_port_id, sizeof(k_port_id) - 1);
    tlv(pdu, &n, sizeof(pdu), 2, port, sizeof(port));

    uint8_t ttl[2];
    pn_wr_be16(ttl, 20);
    tlv(pdu, &n, sizeof(pdu), 3, ttl, 2);

    tlv(pdu, &n, sizeof(pdu), 5, (const uint8_t *)s->cfg.station_name, namelen);

    add_mgmt_addr(pdu, &n, sizeof(pdu), s);
    add_port_status(pdu, &n, sizeof(pdu));
    add_chassis_mac(pdu, &n, sizeof(pdu), s->cfg.mac);
    add_mac_phy(pdu, &n, sizeof(pdu));

    /* End of LLDPDU */
    tlv(pdu, &n, sizeof(pdu), 0, NULL, 0);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), lldp_mc, s->cfg.mac,
                               PN_ETHTYPE_LLDP, pdu, n);
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
}
