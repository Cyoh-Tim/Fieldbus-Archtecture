#include "eip_endian.h"
#include "eip_internal.h"

#include <string.h>

/*
 * Minimal LLDP TX frame builder (IEEE 802.1AB-ish + ODVA TX-required path).
 * Reception / Data Table population is optional per ODVA for non-bridge
 * single-port adapters — we advertise TX-only via LLDP Management Object.
 */

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static size_t tlv(uint8_t *out, size_t cap, size_t off, uint8_t type,
                  const uint8_t *val, size_t len)
{
    if (off + 2 + len > cap) {
        return off;
    }
    uint16_t hdr = (uint16_t)(((uint16_t)type << 9) | (len & 0x1ff));
    wr_be16(out + off, hdr);
    if (len && val) {
        memcpy(out + off + 2, val, len);
    }
    return off + 2 + len;
}

int eip_lldp_build(eip_stack_t *s)
{
    uint8_t *out = s->lldp_last_frame;
    size_t cap = sizeof(s->lldp_last_frame);
    size_t off = 0;

    /* Ethernet header: dst nearest-bridge mcast, src placeholder MAC */
    static const uint8_t dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
    uint8_t src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    if (off + 14 > cap) {
        return -1;
    }
    memcpy(out + off, dst, 6);
    off += 6;
    memcpy(out + off, src, 6);
    off += 6;
    wr_be16(out + off, 0x88cc); /* LLDP ethertype */
    off += 2;

    /* Chassis ID — locally assigned MAC */
    off = tlv(out, cap, off, 1, src, 6);
    /* Port ID — port name */
    const char *port = s->cfg.iface[0] ? s->cfg.iface : "eth0";
    off = tlv(out, cap, off, 2, (const uint8_t *)port, strlen(port));
    /* TTL */
    uint8_t ttl[2];
    uint16_t hold = (uint16_t)(s->lldp_tx_interval_sec * s->lldp_tx_hold);
    if (hold == 0) {
        hold = 120;
    }
    wr_be16(ttl, hold);
    off = tlv(out, cap, off, 3, ttl, 2);
    /* System Name */
    const char *name = s->cfg.product_name;
    off = tlv(out, cap, off, 5, (const uint8_t *)name, strlen(name));
    /* End of LLDPDU */
    off = tlv(out, cap, off, 0, NULL, 0);

    s->lldp_last_frame_len = off;
    s->lldp_last_change_sec = s->lldp_sys_uptime_sec;
    return (int)off;
}

void eip_lldp_poll(eip_stack_t *s)
{
    if (!(s->lldp_enable_flags & 0x1)) {
        return;
    }
    uint64_t now = eip_now_ns();
    uint64_t period = (uint64_t)s->lldp_tx_interval_sec * 1000000000ull;
    if (period == 0) {
        period = 30ull * 1000000000ull;
    }
    if (s->lldp_uptime_anchor_ns == 0) {
        s->lldp_uptime_anchor_ns = now;
    }
    if (now - s->lldp_uptime_anchor_ns >= 1000000000ull) {
        s->lldp_sys_uptime_sec +=
            (uint32_t)((now - s->lldp_uptime_anchor_ns) / 1000000000ull);
        s->lldp_uptime_anchor_ns = now;
    }
    if (s->lldp_last_tx_ns != 0 && now - s->lldp_last_tx_ns < period) {
        return;
    }
    if (eip_lldp_build(s) > 0) {
        s->lldp_last_tx_ns = now;
        /* Real NIC TX is optional — frame is available via CIP/tests.
         * Avoid AF_PACKET in the 8ms hot path by default. */
    }
}
