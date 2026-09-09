#define _GNU_SOURCE

#include "transport.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "logger.h"

static const uint8_t k_ctl_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

void ctt_opts_init(ctt_opts_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->transport = CTT_TRANSPORT_MOCK;
}

int ctt_opts_parse_transport(const char *s, ctt_transport_kind_t *out)
{
    if (!s || !out) {
        return -EINVAL;
    }
    if (strcmp(s, "mock") == 0) {
        *out = CTT_TRANSPORT_MOCK;
        return 0;
    }
    if (strcmp(s, "af_packet") == 0 || strcmp(s, "af-packet") == 0) {
        *out = CTT_TRANSPORT_AF_PACKET;
        return 0;
    }
    return -EINVAL;
}

void ctt_opts_apply_env(ctt_opts_t *opts)
{
    const char *t = getenv("CTT_TRANSPORT");
    if (t && t[0]) {
        if (ctt_opts_parse_transport(t, &opts->transport) != 0) {
            LOG_WARN("ctt", "CTT_TRANSPORT=%s ignored (use mock|af_packet)", t);
        }
    }
    const char *i = getenv("CTT_IFACE");
    if (i && i[0]) {
        snprintf(opts->iface, sizeof(opts->iface), "%s", i);
    }
    const char *d = getenv("CTT_DUT_IFACE");
    if (d && d[0]) {
        snprintf(opts->dut_iface, sizeof(opts->dut_iface), "%s", d);
    }
    const char *c = getenv("CTT_CAPTURE");
    if (c && c[0]) {
        snprintf(opts->capture, sizeof(opts->capture), "%s", c);
    }
    const char *r = getenv("CTT_REPORT");
    if (r && r[0]) {
        snprintf(opts->report, sizeof(opts->report), "%s", r);
    }
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -errno;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0 ? 0 : -errno;
}

static int af_open(ctt_run_t *run)
{
#ifndef CTT_ENABLE_AF_PACKET
    LOG_ERROR("ctt",
              "AF_PACKET lab transport not compiled in; rebuild with "
              "-DENABLE_CTT_AF_PACKET=ON");
    return -ENOTSUP;
#else
    if (!run->opts.iface[0]) {
        LOG_ERROR("ctt",
                  "transport=af_packet requires --iface (controller veth)");
        return -EINVAL;
    }
    if (!run->opts.dut_iface[0]) {
        LOG_ERROR("ctt",
                  "transport=af_packet requires --dut-iface (DUT veth)");
        return -EINVAL;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        LOG_ERROR("ctt",
                  "AF_PACKET socket failed: %s (need CAP_NET_RAW / sudo)",
                  strerror(errno));
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", run->opts.iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        LOG_ERROR("ctt", "iface %s not found", run->opts.iface);
        close(fd);
        return -errno;
    }
    run->af_ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(run->ctl_mac, ifr.ifr_hwaddr.sa_data, 6);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = run->af_ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR("ctt", "AF_PACKET bind %s: %s", run->opts.iface,
                  strerror(errno));
        close(fd);
        return -errno;
    }
    set_nonblock(fd);
    run->af_fd = fd;
    LOG_INFO("ctt",
             "lab transport=af_packet ctl=%s dut=%s (CAP_NET_RAW; not CI mock)",
             run->opts.iface, run->opts.dut_iface);
    return 0;
#endif
}

int ctt_transport_open(ctt_run_t *run)
{
    memcpy(run->ctl_mac, k_ctl_mac, 6);
    run->af_fd = -1;
    run->af_ifindex = 0;
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        return af_open(run);
    }
    return 0;
}

void ctt_transport_close(ctt_run_t *run)
{
    if (run->af_fd >= 0) {
        close(run->af_fd);
        run->af_fd = -1;
    }
}

int ctt_ctl_send(ctt_run_t *run, const uint8_t *frame, size_t len)
{
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
#ifndef CTT_ENABLE_AF_PACKET
        return -ENOTSUP;
#else
        if (run->af_fd < 0) {
            return -ENOTCONN;
        }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = run->af_ifindex;
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, frame, 6);
        ssize_t n = sendto(run->af_fd, frame, len, 0, (struct sockaddr *)&sll,
                           sizeof(sll));
        if (n < 0) {
            LOG_ERROR("ctt", "AF_PACKET send: %s", strerror(errno));
            return -errno;
        }
        return 0;
#endif
    }
    return ctt_ring_push(&run->mock.to_dut, frame, len, ctt_now_ns());
}

void ctt_ctl_harvest(ctt_run_t *run)
{
    if (run->opts.transport != CTT_TRANSPORT_AF_PACKET || run->af_fd < 0) {
        return;
    }
#ifndef CTT_ENABLE_AF_PACKET
    return;
#else
    uint8_t buf[CTT_FRAME_MAX];
    for (;;) {
        ssize_t n = recv(run->af_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            break;
        }
        if (n < 14) {
            continue;
        }
        if (memcmp(buf + 6, run->ctl_mac, 6) == 0) {
            continue; /* our own TX, if reflected */
        }
        (void)ctt_ring_push(&run->mock.to_ctl, buf, (size_t)n, ctt_now_ns());
    }
#endif
}

void ctt_ctl_clear_rx(ctt_run_t *run)
{
    ctt_ring_clear(&run->mock.to_ctl);
}

int ctt_mock_run_send(void *ctx, const uint8_t *frame, size_t len)
{
    ctt_run_t *run = ctx;
    return ctt_ring_push(&run->mock.to_ctl, frame, len, ctt_now_ns());
}

int ctt_mock_run_recv(void *ctx, uint8_t *frame, size_t cap, int timeout_ms)
{
    ctt_run_t *run = ctx;
    (void)timeout_ms;
    return ctt_ring_pop(&run->mock.to_dut, frame, cap, NULL);
}
