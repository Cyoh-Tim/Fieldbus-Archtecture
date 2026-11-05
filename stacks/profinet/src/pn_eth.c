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

/* Host-order IPv4. iface "mock" or empty does not touch the NIC.
 * Needs CAP_NET_ADMIN. Default routes already on this device are
 * removed with SIOCDELRT before the new one is added. Gateway 0
 * deletes the previous route and does not add another. */

struct pn_route_apply {
    int fd;
    char dev[IFNAMSIZ];
};

static int pn_route_ioctl(void *ctx, unsigned long req, uint32_t gw_host)
{
    struct pn_route_apply *a = ctx;
    struct rtentry rt;
    memset(&rt, 0, sizeof(rt));
    struct sockaddr_in *dst = (struct sockaddr_in *)&rt.rt_dst;
    struct sockaddr_in *gw = (struct sockaddr_in *)&rt.rt_gateway;
    struct sockaddr_in *gen = (struct sockaddr_in *)&rt.rt_genmask;
    dst->sin_family = AF_INET;
    gw->sin_family = AF_INET;
    gw->sin_addr.s_addr = htonl(gw_host);
    gen->sin_family = AF_INET;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    rt.rt_dev = a->dev;
    if (ioctl(a->fd, req, &rt) < 0) {
        return -errno;
    }
    return 0;
}

static int pn_os_read_default_gws(const char *iface, uint32_t *gws, int cap)
{
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        return -errno;
    }
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) {
        return -EIO;
    }
    buf[n] = '\0';
    if (n == sizeof(buf) - 1) {
        LOG_WARN("pn_eth", "기본 경로 표가 잘림 iface=%s", iface);
    }
    return pn_os_parse_proc_routes(buf, iface, gws, cap);
}

int pn_os_apply_ip_default(const char *iface, uint32_t ip, uint32_t netmask,
                           uint32_t gateway)
{
    if (!iface || !iface[0] || strcmp(iface, "mock") == 0) {
        return -ENODEV;
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
        close(fd);
        return -e;
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(netmask);
    if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_UP);
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
            int e = errno;
            close(fd);
            return -e;
        }
    }
    uint32_t prev[8];
    int nprev = pn_os_read_default_gws(iface, prev, 8);
    if (nprev == -E2BIG) {
        LOG_WARN("pn_eth", "기본 경로가 많아 앞의 8개만 삭제 iface=%s", iface);
        nprev = 8;
    } else if (nprev < 0) {
        LOG_WARN("pn_eth", "기본 경로 조회 실패 (%d) iface=%s", nprev, iface);
        nprev = 0;
    }
    struct pn_route_apply ra;
    ra.fd = fd;
    snprintf(ra.dev, sizeof(ra.dev), "%s", iface);
    int rc = pn_os_install_default_route(iface, prev, nprev, gateway,
                                        pn_route_ioctl, &ra);
    close(fd);
    return rc;
}

int pn_os_parse_proc_routes(const char *text, const char *iface, uint32_t *gws,
                            int cap)
{
    if (!text || !iface || !iface[0] || !gws || cap <= 0) {
        return -EINVAL;
    }
    int n = 0;
    int extra = 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char line[256];
        if (len >= sizeof(line)) {
            len = sizeof(line) - 1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        char ifn[IFNAMSIZ];
        unsigned int dest = 0;
        unsigned int gw = 0;
        unsigned int flags = 0;
        unsigned int mask = 0;
        int got = sscanf(line, "%15s %x %x %x %*u %*u %*u %x", ifn, &dest, &gw,
                         &flags, &mask);
        if (got == 5 && strcmp(ifn, iface) == 0 && dest == 0 && mask == 0 &&
            (flags & RTF_GATEWAY) != 0) {
            if (n < cap) {
                gws[n++] = ntohl(gw);
            } else {
                extra = 1;
            }
        }
        if (!nl) {
            break;
        }
        p = nl + 1;
    }
    if (extra) {
        return -E2BIG;
    }
    return n;
}

int pn_os_install_default_route(const char *iface, const uint32_t *prev,
                                int nprev, uint32_t new_gw,
                                int (*ioctl_rt)(void *ctx, unsigned long req,
                                                uint32_t gw_host),
                                void *ctx)
{
    if (!iface || !iface[0] || !ioctl_rt || nprev < 0 || (nprev > 0 && !prev)) {
        return -EINVAL;
    }
    for (int i = 0; i < nprev; i++) {
        int rc = ioctl_rt(ctx, SIOCDELRT, prev[i]);
        if (rc != 0 && rc != -ESRCH && rc != -ENOENT) {
            return rc;
        }
    }
    if (new_gw == 0) {
        return 0;
    }
    int rc = ioctl_rt(ctx, SIOCADDRT, new_gw);
    if (rc != 0 && rc != -EEXIST) {
        return rc;
    }
    return 0;
}
