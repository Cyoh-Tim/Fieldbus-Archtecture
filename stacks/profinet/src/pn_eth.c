#define _GNU_SOURCE

#include "pn_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "logger.h"
#include "pn_endian.h"

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -errno;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0 ? 0 : -errno;
}

uint64_t pn_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

size_t pn_eth_build(uint8_t *out, size_t cap, const uint8_t dst[6],
                    const uint8_t src[6], uint16_t ethertype,
                    const uint8_t *payload, size_t plen)
{
    return pn_eth_build_vlan(out, cap, dst, src, 0xFFFFu, ethertype, payload,
                             plen);
}

size_t pn_eth_build_vlan(uint8_t *out, size_t cap, const uint8_t dst[6],
                         const uint8_t src[6], uint16_t tci, uint16_t ethertype,
                         const uint8_t *payload, size_t plen)
{
    int tagged = (tci != 0xFFFFu);
    size_t hdr = tagged ? 18u : 14u;
    if (cap < hdr + plen) {
        return 0;
    }
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    if (tagged) {
        pn_wr_be16(out + 12, PN_ETHTYPE_VLAN);
        pn_wr_be16(out + 14, tci);
        pn_wr_be16(out + 16, ethertype);
        memcpy(out + 18, payload, plen);
    } else {
        pn_wr_be16(out + 12, ethertype);
        memcpy(out + 14, payload, plen);
    }
    return hdr + plen;
}

int pn_eth_parse(const uint8_t *frame, size_t len, const uint8_t **payload,
                 size_t *plen, uint16_t *ethertype, const uint8_t **dst,
                 const uint8_t **src)
{
    if (len < 14) {
        return -EINVAL;
    }
    *dst = frame;
    *src = frame + 6;
    uint16_t et = pn_rd_be16(frame + 12);
    size_t off = 14;
    if (et == PN_ETHTYPE_VLAN) {
        if (len < 18) {
            return -EINVAL;
        }
        et = pn_rd_be16(frame + 16);
        off = 18;
    }
    *ethertype = et;
    *payload = frame + off;
    *plen = len - off;
    return 0;
}

int pn_eth_open(pn_stack_t *s)
{
    if (s->use_eth_ops) {
        return 0;
    }
    if (!s->cfg.iface[0] || strcmp(s->cfg.iface, "mock") == 0) {
        s->use_eth_ops = 1;
        return 0;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        LOG_ERROR("pn_eth", "AF_PACKET socket 실패: %s (CAP_NET_RAW 필요)",
                  strerror(errno));
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", s->cfg.iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        LOG_ERROR("pn_eth", "iface %s 없음", s->cfg.iface);
        close(fd);
        return -errno;
    }
    s->ifindex = ifr.ifr_ifindex;

    if (!s->cfg.mac_set) {
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(s->cfg.mac, ifr.ifr_hwaddr.sa_data, 6);
            s->cfg.mac_set = 1;
        }
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = s->ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR("pn_eth", "bind 실패: %s", strerror(errno));
        close(fd);
        return -errno;
    }
    set_nonblock(fd);
    s->fd_eth = fd;
    return 0;
}

void pn_eth_close(pn_stack_t *s)
{
    if (s->fd_eth >= 0) {
        close(s->fd_eth);
        s->fd_eth = -1;
    }
}

int pn_eth_send(pn_stack_t *s, const uint8_t *frame, size_t len)
{
    if (s->use_eth_ops) {
        if (!s->eth_ops.send) {
            return 0;
        }
        return s->eth_ops.send(s->eth_ops.ctx, frame, len);
    }
    if (s->fd_eth < 0) {
        return -ENOTCONN;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = s->ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);
    ssize_t n = sendto(s->fd_eth, frame, len, 0, (struct sockaddr *)&sll,
                       sizeof(sll));
    return n < 0 ? -errno : 0;
}

int pn_eth_recv(pn_stack_t *s, uint8_t *frame, size_t cap)
{
    if (s->use_eth_ops) {
        if (!s->eth_ops.recv) {
            return -EAGAIN;
        }
        return s->eth_ops.recv(s->eth_ops.ctx, frame, cap, 0);
    }
    if (s->fd_eth < 0) {
        return -ENOTCONN;
    }
    ssize_t n = recv(s->fd_eth, frame, cap, MSG_DONTWAIT);
    if (n < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? -EAGAIN : -errno;
    }
    return (int)n;
}

int pn_udp_open(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    set_nonblock(fd);
    return fd;
}

int pn_if_apply_ipv4(const char *iface, uint32_t ip, uint32_t netmask,
                     uint32_t gateway)
{
    if (!iface || !iface[0] || strcmp(iface, "mock") == 0) {
        return 0;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(ip);
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
        int e = errno;
        LOG_WARN("pn_eth", "SIOCSIFADDR %s 실패: %s", iface, strerror(e));
        close(fd);
        return -e;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(netmask ? netmask : 0xFFFFFF00u);
    if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
        LOG_WARN("pn_eth", "SIOCSIFNETMASK %s 실패: %s", iface, strerror(errno));
    }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    if (gateway) {
        struct rtentry rt;
        memset(&rt, 0, sizeof(rt));
        struct sockaddr_in *dst = (struct sockaddr_in *)&rt.rt_dst;
        struct sockaddr_in *gw = (struct sockaddr_in *)&rt.rt_gateway;
        struct sockaddr_in *mask = (struct sockaddr_in *)&rt.rt_genmask;
        dst->sin_family = AF_INET;
        gw->sin_family = AF_INET;
        mask->sin_family = AF_INET;
        gw->sin_addr.s_addr = htonl(gateway);
        rt.rt_flags = RTF_UP | RTF_GATEWAY;
        if (ioctl(fd, SIOCADDRT, &rt) < 0 && errno != EEXIST) {
            LOG_WARN("pn_eth", "default gw 실패: %s", strerror(errno));
        }
    }
    close(fd);
    LOG_INFO("pn_eth", "OS IP applied on %s", iface);
    return 0;
}
