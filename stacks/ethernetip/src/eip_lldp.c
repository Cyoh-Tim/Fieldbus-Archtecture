#include "eip_endian.h"
#include "eip_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "logger.h"

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

    /* Ethernet header: dst nearest-bridge mcast. Source is the iface
     * MAC when the NIC could be opened, otherwise the placeholder. */
    static const uint8_t dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
    uint8_t src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    if (s->lldp_mac_set) {
        memcpy(src, s->lldp_mac, 6);
    }
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

static void lldp_tx_warn(eip_stack_t *s, const char *what, int err)
{
    if (s->lldp_tx_error_logged) {
        return;
    }
    s->lldp_tx_error_logged = 1;
    LOG_WARN("ethernetip", "LLDP %s failed (%d)", what, err);
}

/* Open AF_PACKET once and remember the interface MAC. Failures are
 * logged once; the in-memory frame is still built for CIP/tests. */
static int eip_lldp_nic_open(eip_stack_t *s)
{
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int fd;

    if (s->lldp_fd >= 0) {
        return 0;
    }
    if (s->cfg.mock || !s->cfg.iface[0]) {
        return -ENODEV;
    }
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        return -errno;
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", s->cfg.iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    s->lldp_ifindex = ifr.ifr_ifindex;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", s->cfg.iface);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(s->lldp_mac, ifr.ifr_hwaddr.sa_data, 6);
        s->lldp_mac_set = 1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = s->lldp_ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    s->lldp_fd = fd;
    return 0;
}

static int eip_lldp_nic_send(eip_stack_t *s)
{
    struct sockaddr_ll sll;
    ssize_t n;

    if (s->lldp_fd < 0 || s->lldp_last_frame_len < 6) {
        return -ENOTCONN;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = s->lldp_ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, s->lldp_last_frame, 6);
    n = sendto(s->lldp_fd, s->lldp_last_frame, s->lldp_last_frame_len, 0,
               (struct sockaddr *)&sll, sizeof(sll));
    return n < 0 ? -errno : 0;
}

void eip_lldp_close(eip_stack_t *s)
{
    if (!s) {
        return;
    }
    if (s->lldp_fd >= 0) {
        close(s->lldp_fd);
        s->lldp_fd = -1;
    }
}

void eip_lldp_poll(eip_stack_t *s)
{
    int use_hook;
    uint64_t now;
    uint64_t period;

    if (!(s->lldp_enable_flags & 0x1)) {
        return;
    }
    now = eip_now_ns();
    period = (uint64_t)s->lldp_tx_interval_sec * 1000000000ull;
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
    use_hook = s->tops_set && s->tops.l2_send != NULL;
    if (!use_hook && !s->cfg.mock && s->cfg.iface[0]) {
        int rc = eip_lldp_nic_open(s);
        if (rc != 0) {
            lldp_tx_warn(s, "socket", rc);
        }
    }
    if (eip_lldp_build(s) <= 0) {
        return;
    }
    s->lldp_last_tx_ns = now;
    if (use_hook) {
        int rc = s->tops.l2_send(s->tops.ctx, s->lldp_last_frame,
                                 s->lldp_last_frame_len);
        if (rc != 0) {
            lldp_tx_warn(s, "l2_send", rc);
        }
        return;
    }
    if (s->lldp_fd >= 0) {
        int rc = eip_lldp_nic_send(s);
        if (rc != 0) {
            lldp_tx_warn(s, "sendto", rc);
        }
    }
}
