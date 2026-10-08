#define _GNU_SOURCE

#include "pn_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
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
    if (cap < 14 + plen) {
        return 0;
    }
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    pn_wr_be16(out + 12, ethertype);
    memcpy(out + 14, payload, plen);
    return 14 + plen;
}

size_t pn_eth_build_vlan(uint8_t *out, size_t cap, const uint8_t dst[6],
                         const uint8_t src[6], uint16_t tci, uint16_t ethertype,
                         const uint8_t *payload, size_t plen)
{
    if (tci == 0) {
        return pn_eth_build(out, cap, dst, src, ethertype, payload, plen);
    }
    if (cap < 18 + plen) {
        return 0;
    }
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    pn_wr_be16(out + 12, PN_ETHTYPE_VLAN);
    pn_wr_be16(out + 14, tci);
    pn_wr_be16(out + 16, ethertype);
    memcpy(out + 18, payload, plen);
    return 18 + plen;
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
