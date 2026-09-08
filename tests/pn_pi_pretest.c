#define _GNU_SOURCE

/*
 * Lab pretest modeled on PI Test Bundle RT Device groups (public Readme:
 * https://www.profibus.com/download/profinet-test-bundle ).
 * This is not ART (CC-A/B) / SPIRTA (CC-C IRT) / PITL certification.
 * Official ETS is PI-member-only. IRT reject is a CC-C not-supported check.
 */

#include "pn_endian.h"
#include "pn_types.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

static int g_pass;
static int g_fail;
static int g_saw_lldp;
static int g_saw_lldp_pn;
static int g_saw_hello;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void check(int cond, const char *id, const char *msg)
{
    if (cond) {
        fprintf(stderr, "PASS  %s  %s\n", id, msg);
        g_pass++;
    } else {
        fprintf(stderr, "FAIL  %s  %s\n", id, msg);
        g_fail++;
    }
}

static int contains(const uint8_t *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    if (m == 0 || m > n) {
        return 0;
    }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return 1;
        }
    }
    return 0;
}

static int contains_mem(const uint8_t *hay, size_t n, const void *needle,
                        size_t m)
{
    if (!hay || m == 0 || m > n) {
        return 0;
    }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return 1;
        }
    }
    return 0;
}

static size_t wr_pn_block(uint8_t *p, uint16_t type, const uint8_t *body,
                          uint16_t body_len)
{
    uint16_t blen = (uint16_t)(2 + body_len);
    pn_wr_be16(p, type);
    pn_wr_be16(p + 2, blen);
    p[4] = 1;
    p[5] = 0;
    memcpy(p + 6, body, body_len);
    size_t n = 4u + blen;
    if (n & 1u) {
        p[n++] = 0;
    }
    return n;
}

static size_t ndr_wrap_le(uint8_t *out, const uint8_t *blocks, size_t n)
{
    pn_wr_le32(out, (uint32_t)n);
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

static size_t rpc_req(uint8_t *pdu, uint16_t op, const uint8_t *stub, size_t slen)
{
    memset(pdu, 0, 80 + slen);
    pdu[0] = 4;
    pdu[1] = 0;
    pdu[4] = 0x10;
    pn_wr_le16(pdu + 68, op);
    pn_wr_le16(pdu + 74, (uint16_t)slen);
    memcpy(pdu + 80, stub, slen);
    return 80 + slen;
}

static int open_packet(const char *iface, int *ifindex, uint8_t mac[6])
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = *ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

static int send_raw(int fd, int ifindex, const uint8_t *frame, size_t len)
{
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);
    return sendto(fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0
               ? -1
               : 0;
}

static void note_frame(const uint8_t *rx, int n, const char *expect_name)
{
    if (n < 14) {
        return;
    }
    uint16_t et = pn_rd_be16(rx + 12);
    size_t off = 14;
    if (et == PN_ETHTYPE_VLAN && n >= 18) {
        et = pn_rd_be16(rx + 16);
        off = 18;
    }
    if (et == PN_ETHTYPE_PN && n >= (int)off + 2 &&
        pn_rd_be16(rx + off) == PN_FRAMEID_DCP_HELLO &&
        contains(rx, (size_t)n, expect_name)) {
        g_saw_hello = 1;
    }
    if (et == PN_ETHTYPE_LLDP) {
        if (contains(rx, (size_t)n, expect_name)) {
            g_saw_lldp = 1;
        }
        for (int i = 14; i + 3 <= n; i++) {
            if (rx[i] == 0x00 && rx[i + 1] == 0x0C && rx[i + 2] == 0xCF) {
                g_saw_lldp_pn = 1;
                break;
            }
        }
    }
}

static int wait_recv(int fd, uint8_t *buf, size_t cap, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        return rc == 0 ? -ETIMEDOUT : -errno;
    }
    ssize_t n = recv(fd, buf, cap, 0);
    return n < 0 ? -errno : (int)n;
}

static uint32_t iface_ipv4(const char *iface)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    return ntohl(sa->sin_addr.s_addr);
}

static int udp_bind(uint32_t ip_host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ip_host ? htonl(ip_host) : htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int rpc_call(int fd, uint32_t dst_ip, const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t cap, int timeout_ms)
{
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(PN_RPC_PORT);
    dst.sin_addr.s_addr = htonl(dst_ip);
    if (sendto(fd, req, req_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        return -1;
    }
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }
        ssize_t n = recv(fd, resp, cap, 0);
        if (n < 80) {
            continue;
        }
        if (resp[1] == 2) {
            return (int)n;
        }
        if (resp[1] == 0) {
            uint8_t ack[1024];
            memcpy(ack, resp, (size_t)n);
            ack[1] = 2;
            sendto(fd, ack, (size_t)n, 0, (struct sockaddr *)&dst, sizeof(dst));
        }
    }
    return -ETIMEDOUT;
}

static size_t dcp_ident_all(uint8_t *frame, const uint8_t *src, uint32_t xid)
{
    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);
    memcpy(frame, k_dcp_mc, 6);
    memcpy(frame + 6, src, 6);
    pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
    memcpy(frame + 14, pay, 16);
    return 30;
}

static int dcp_wait_ident(int fd, uint8_t *rx, size_t cap, int timeout_ms,
                          const char *expect_name)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline) {
        int n = wait_recv(fd, rx, cap, 150);
        if (n < 14) {
            continue;
        }
        note_frame(rx, n, expect_name);
        if (n >= 26 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == PN_FRAMEID_DCP_ID_RES) {
            return n;
        }
    }
    return -1;
}

static int dcp_wait_getset(int fd, uint8_t *rx, size_t cap, int timeout_ms,
                           const char *expect_name, uint32_t xid)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline) {
        int n = wait_recv(fd, rx, cap, 150);
        if (n < 14) {
            continue;
        }
        note_frame(rx, n, expect_name);
        if (n >= 26 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == PN_FRAMEID_DCP_GETSET && rx[17] != 0 &&
            pn_rd_be32(rx + 18) == xid) {
            return n;
        }
    }
    return -1;
}

static size_t dcp_put_getset(uint8_t *frame, const uint8_t dst[6],
                             const uint8_t src[6], uint8_t sid, uint32_t xid,
                             const uint8_t *blocks, size_t blen)
{
    uint8_t pay[256];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = sid;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)blen);
    memcpy(pay + 12, blocks, blen);
    memcpy(frame, dst, 6);
    memcpy(frame + 6, src, 6);
    pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
    memcpy(frame + 14, pay, 12 + blen);
    size_t n = 14 + 12 + blen;
    while (n < 60) {
        frame[n++] = 0;
    }
    return n;
}

static size_t dcp_name_set_block(uint8_t *blk, const char *name)
{
    size_t nlen = strlen(name);
    blk[0] = PN_DCP_OPT_DEV;
    blk[1] = PN_DCP_SUB_DEV_NAME;
    pn_wr_be16(blk + 2, (uint16_t)(2 + nlen));
    pn_wr_be16(blk + 4, 1); /* qualifier */
    memcpy(blk + 6, name, nlen);
    size_t n = 6 + nlen;
    if (n & 1u) {
        blk[n++] = 0;
    }
    return n;
}

static uint32_t dcp_parse_ip(const uint8_t *rx, int n)
{
    if (n < 26) {
        return 0;
    }
    uint16_t dlen = pn_rd_be16(rx + 14 + 10);
    const uint8_t *blocks = rx + 26;
    size_t off = 0;
    while (off + 4 <= dlen && 26 + (int)off + 4 <= n) {
        uint8_t opt = blocks[off];
        uint8_t sub = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        if (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM && bl >= 12) {
            return pn_rd_be32(blocks + off + 4);
        }
        off += 4u + bl + (bl & 1u);
    }
    return 0;
}

static size_t snmp_build(uint8_t *out, uint8_t rid, uint8_t pdu_tag,
                         const uint8_t *oid, size_t olen)
{
    uint8_t vb[80];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x05;
    vb[i++] = 0x00;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);

    uint8_t vbl[96];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;

    uint8_t pdu[160];
    size_t p = 0;
    pdu[p++] = pdu_tag;
    size_t pdu_len_at = p++;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = rid;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);

    size_t m = 0;
    out[m++] = 0x30;
    size_t msg_len_at = m++;
    out[m++] = 0x02;
    out[m++] = 0x01;
    out[m++] = 0x00;
    out[m++] = 0x04;
    out[m++] = 0x06;
    memcpy(out + m, "public", 6);
    m += 6;
    memcpy(out + m, pdu, p);
    m += p;
    out[msg_len_at] = (uint8_t)(m - msg_len_at - 1);
    return m;
}

static size_t snmp_build_bulk(uint8_t *out, uint8_t rid, uint8_t max_rep,
                              const uint8_t *oid, size_t olen)
{
    uint8_t vb[80];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x05;
    vb[i++] = 0x00;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);

    uint8_t vbl[96];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;

    uint8_t pdu[160];
    size_t p = 0;
    pdu[p++] = 0xA5;
    size_t pdu_len_at = p++;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = rid;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = max_rep;
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);

    size_t m = 0;
    out[m++] = 0x30;
    size_t msg_len_at = m++;
    out[m++] = 0x02;
    out[m++] = 0x01;
    out[m++] = 0x00;
    out[m++] = 0x04;
    out[m++] = 0x06;
    memcpy(out + m, "public", 6);
    m += 6;
    memcpy(out + m, pdu, p);
    m += p;
    out[msg_len_at] = (uint8_t)(m - msg_len_at - 1);
    return m;
}

static int snmp_exchange(uint32_t dst_ip, uint8_t pdu_tag, const uint8_t *oid,
                         size_t olen, uint8_t rid, uint8_t *srx, size_t cap)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || !dst_ip) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    uint8_t req[256];
    size_t rn = snmp_build(req, rid, pdu_tag, oid, olen);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(PN_SNMP_PORT);
    dst.sin_addr.s_addr = htonl(dst_ip);
    sendto(fd, req, rn, 0, (struct sockaddr *)&dst, sizeof(dst));
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    int n = -1;
    if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0) {
        ssize_t sn = recv(fd, srx, cap, 0);
        n = sn < 0 ? -1 : (int)sn;
    }
    close(fd);
    return n;
}

static int snmp_query(uint32_t dst_ip, const uint8_t *oid, size_t olen,
                      uint8_t rid, const char *expect)
{
    uint8_t srx[512];
    int sn = snmp_exchange(dst_ip, 0xa0, oid, olen, rid, srx, sizeof(srx));
    return sn > 0 && contains(srx, (size_t)sn, expect);
}

static int snmp_query_next(uint32_t dst_ip, const uint8_t *oid, size_t olen,
                           uint8_t rid, const char *expect)
{
    uint8_t srx[512];
    int sn = snmp_exchange(dst_ip, 0xa1, oid, olen, rid, srx, sizeof(srx));
    return sn > 0 && contains(srx, (size_t)sn, expect);
}

static int snmp_has_bytes(uint32_t dst_ip, uint8_t pdu_tag, const uint8_t *oid,
                          size_t olen, uint8_t rid, const uint8_t *needle,
                          size_t nlen)
{
    uint8_t srx[512];
    int sn = snmp_exchange(dst_ip, pdu_tag, oid, olen, rid, srx, sizeof(srx));
    if (sn <= 0 || nlen == 0 || (size_t)sn < nlen) {
        return 0;
    }
    for (int i = 0; i + (int)nlen <= sn; i++) {
        if (memcmp(srx + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

static int snmp_set_oct(uint32_t dst_ip, const uint8_t *oid, size_t olen,
                        uint8_t rid, const char *str, uint8_t *srx, size_t cap)
{
    size_t sl = strlen(str);
    uint8_t vb[120];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x04;
    vb[i++] = (uint8_t)sl;
    memcpy(vb + i, str, sl);
    i += sl;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);
    uint8_t vbl[136];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;
    uint8_t spdu[180];
    size_t p = 0;
    spdu[p++] = 0xA3;
    size_t pdu_len_at = p++;
    spdu[p++] = 0x02;
    spdu[p++] = 0x01;
    spdu[p++] = rid;
    spdu[p++] = 0x02;
    spdu[p++] = 0x01;
    spdu[p++] = 0x00;
    spdu[p++] = 0x02;
    spdu[p++] = 0x01;
    spdu[p++] = 0x00;
    memcpy(spdu + p, vbl, v);
    p += v;
    spdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);
    uint8_t req[220];
    size_t m = 0;
    req[m++] = 0x30;
    size_t msg_len_at = m++;
    req[m++] = 0x02;
    req[m++] = 0x01;
    req[m++] = 0x00;
    req[m++] = 0x04;
    req[m++] = 0x06;
    memcpy(req + m, "public", 6);
    m += 6;
    memcpy(req + m, spdu, p);
    m += p;
    req[msg_len_at] = (uint8_t)(m - msg_len_at - 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || !dst_ip) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(PN_SNMP_PORT);
    dst.sin_addr.s_addr = htonl(dst_ip);
    sendto(fd, req, m, 0, (struct sockaddr *)&dst, sizeof(dst));
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int n = (int)recv(fd, srx, cap, 0);
    close(fd);
    return n;
}

static void send_lldp_neighbor(int raw, int ifindex, const uint8_t dst[6],
                               const uint8_t src[6], const char *sysname)
{
    uint8_t pdu[128];
    size_t n = 0;
    pdu[n++] = 0x02;
    pdu[n++] = 0x07;
    pdu[n++] = 4;
    memcpy(pdu + n, src, 6);
    n += 6;
    pdu[n++] = 0x04;
    pdu[n++] = 0x07;
    pdu[n++] = 3;
    memcpy(pdu + n, src, 6);
    n += 6;
    pdu[n++] = 0x06;
    pdu[n++] = 0x02;
    pdu[n++] = 0x00;
    pdu[n++] = 0x14;
    size_t nlen = strlen(sysname);
    uint16_t th = (uint16_t)((5u << 9) | (nlen & 0x1FFu));
    pdu[n++] = (uint8_t)(th >> 8);
    pdu[n++] = (uint8_t)th;
    memcpy(pdu + n, sysname, nlen);
    n += nlen;
    pdu[n++] = 0x00;
    pdu[n++] = 0x00;
    uint8_t frame[256];
    memcpy(frame, dst, 6);
    memcpy(frame + 6, src, 6);
    pn_wr_be16(frame + 12, PN_ETHTYPE_LLDP);
    memcpy(frame + 14, pdu, n);
    send_raw(raw, ifindex, frame, 14 + n);
}

static int pn_frame_fid(const uint8_t *rx, int n, uint16_t *fid, size_t *off)
{
    if (n < 16) {
        return -1;
    }
    uint16_t et = pn_rd_be16(rx + 12);
    size_t o = 14;
    if (et == PN_ETHTYPE_VLAN) {
        if (n < 20) {
            return -1;
        }
        et = pn_rd_be16(rx + 16);
        o = 18;
    }
    if (et != PN_ETHTYPE_PN) {
        return -1;
    }
    *fid = pn_rd_be16(rx + o);
    *off = o;
    return 0;
}

static void send_rta_ack(int raw, int ifindex, const uint8_t *data, int n,
                         size_t pay_off, const uint8_t mymac[6])
{
    if (n < (int)pay_off + 14) {
        return;
    }
    const uint8_t *p = data + pay_off;
    uint16_t fid = pn_rd_be16(p);
    uint16_t dst_ref = pn_rd_be16(p + 2);
    uint16_t src_ref = pn_rd_be16(p + 4);
    uint16_t send_seq = pn_rd_be16(p + 8);
    uint8_t ack[64];
    memset(ack, 0, sizeof(ack));
    memcpy(ack, data + 6, 6);
    memcpy(ack + 6, mymac, 6);
    pn_wr_be16(ack + 12, PN_ETHTYPE_PN);
    pn_wr_be16(ack + 14, fid);
    pn_wr_be16(ack + 16, src_ref);
    pn_wr_be16(ack + 18, dst_ref);
    ack[20] = 0x13;
    ack[21] = 0x21;
    pn_wr_be16(ack + 22, 0xFFFF);
    pn_wr_be16(ack + 24, send_seq);
    pn_wr_be16(ack + 26, 0);
    send_raw(raw, ifindex, ack, 60);
}

static size_t put_iod_write_hdr(uint8_t *p, uint16_t seq, uint32_t api,
                                uint16_t slot, uint16_t sub, uint16_t index,
                                uint32_t dlen)
{
    pn_wr_be16(p, PN_BLOCK_WRITE_REQ);
    pn_wr_be16(p + 2, 60);
    p[4] = 1;
    p[5] = 0;
    memset(p + 6, 0, 58);
    pn_wr_be16(p + 6, seq);
    pn_wr_be32(p + 6 + 18, api);
    pn_wr_be16(p + 6 + 22, slot);
    pn_wr_be16(p + 6 + 24, sub);
    pn_wr_be16(p + 6 + 28, index);
    pn_wr_be32(p + 6 + 30, dlen);
    return 64;
}

static size_t build_connect(uint8_t *pdu, const uint8_t mac[6],
                            uint32_t iocr_props)
{
    static const uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                                     9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t ar[56];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    memcpy(ar + 2, uuid, 16);
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, mac, 6);
    ar[26] = 0xDE;
    ar[27] = 0xA0;
    ar[28] = 0x00;
    ar[29] = 0x02;
    pn_wr_be32(ar + 42, 0x00000001);
    pn_wr_be16(ar + 46, 1000);
    pn_wr_be16(ar + 48, 0x8892);
    pn_wr_be16(ar + 50, 4);
    memcpy(ar + 52, "plc1", 4);

    uint8_t iin[60], iout[60], exp[36], pdev[40];
    memset(iin, 0, sizeof(iin));
    pn_wr_be16(iin + 0, PN_IOCR_INPUT);
    pn_wr_be16(iin + 2, 1);
    pn_wr_be16(iin + 4, 0x8892);
    pn_wr_be32(iin + 6, iocr_props);
    pn_wr_be16(iin + 10, 40);
    pn_wr_be16(iin + 12, 0x8123);
    pn_wr_be16(iin + 14, 32);
    pn_wr_be16(iin + 16, 8);
    pn_wr_be16(iin + 18, 1);
    pn_wr_be32(iin + 22, 0xffffffffu);
    pn_wr_be16(iin + 26, 3);
    pn_wr_be16(iin + 28, 3);
    pn_wr_be16(iin + 30, 0xC000);
    pn_wr_be16(iin + 38, 1);
    pn_wr_be16(iin + 44, 1);
    pn_wr_be16(iin + 46, 1);
    pn_wr_be16(iin + 48, 1);
    pn_wr_be16(iin + 52, 1);
    pn_wr_be16(iin + 54, 1);
    pn_wr_be16(iin + 56, 1);
    pn_wr_be16(iin + 58, 33);
    memset(iout, 0, sizeof(iout));
    memcpy(iout, iin, sizeof(iout));
    pn_wr_be16(iout + 0, PN_IOCR_OUTPUT);
    pn_wr_be16(iout + 2, 2);
    pn_wr_be16(iout + 12, 0xFFFF);
    pn_wr_be16(iout + 58, 9);

    memset(exp, 0, sizeof(exp));
    pn_wr_be16(exp + 0, 1);
    pn_wr_be16(exp + 6, 1);
    pn_wr_be32(exp + 8, 0x10);
    pn_wr_be16(exp + 14, 1);
    pn_wr_be16(exp + 16, 1);
    pn_wr_be32(exp + 18, 0x11);
    pn_wr_be16(exp + 22, 0x0003);
    pn_wr_be16(exp + 24, 1);
    pn_wr_be16(exp + 26, 32);
    exp[28] = 1;
    exp[29] = 1;
    pn_wr_be16(exp + 30, 2);
    pn_wr_be16(exp + 32, 8);
    exp[34] = 1;
    exp[35] = 1;

    memset(pdev, 0, sizeof(pdev));
    pn_wr_be16(pdev + 0, 1);
    pn_wr_be16(pdev + 6, 0);
    pn_wr_be32(pdev + 8, 1);
    pn_wr_be16(pdev + 14, 3);
    pn_wr_be16(pdev + 16, 1);
    pn_wr_be32(pdev + 18, 1);
    pn_wr_be16(pdev + 24, 0x8000);
    pn_wr_be32(pdev + 26, 2);
    pn_wr_be16(pdev + 32, 0x8001);
    pn_wr_be32(pdev + 34, 3);

    uint8_t blocks[512];
    size_t n = 0;
    uint8_t alarmcr[20];
    memset(alarmcr, 0, sizeof(alarmcr));
    pn_wr_be16(alarmcr + 0, 1);
    pn_wr_be16(alarmcr + 2, 0x8892);
    pn_wr_be32(alarmcr + 4, 0);
    pn_wr_be16(alarmcr + 8, 1);
    pn_wr_be16(alarmcr + 10, 3);
    pn_wr_be16(alarmcr + 12, 3); /* controller LocalAlarmReference */
    pn_wr_be16(alarmcr + 14, 200);
    pn_wr_be16(alarmcr + 16, 0xC000);
    pn_wr_be16(alarmcr + 18, 0xA000);

    n += wr_pn_block(blocks + n, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iin, sizeof(iin));
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iout, sizeof(iout));
    n += wr_pn_block(blocks + n, PN_BLOCK_ALARMCR_REQ, alarmcr, sizeof(alarmcr));
    n += wr_pn_block(blocks + n, PN_BLOCK_EXPSUB_REQ, pdev, sizeof(pdev));
    n += wr_pn_block(blocks + n, PN_BLOCK_EXPSUB_REQ, exp, sizeof(exp));
    uint8_t stub[600];
    size_t sn = ndr_wrap_le(stub, blocks, n);
    return rpc_req(pdu, 0, stub, sn);
}

static size_t build_prmend(uint8_t *pdu)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body + 22, PN_CTRL_PRM_END);
    uint8_t blk[64];
    size_t bn = wr_pn_block(blk, PN_BLOCK_PRMEND_REQ, body, 26);
    uint8_t stub[128];
    size_t sn = ndr_wrap_le(stub, blk, bn);
    return rpc_req(pdu, 4, stub, sn);
}

static size_t build_release(uint8_t *pdu)
{
    uint8_t z[4] = {0};
    uint8_t stub[32];
    size_t sn = ndr_wrap_le(stub, z, 4);
    return rpc_req(pdu, 1, stub, sn);
}

static size_t build_read(uint8_t *pdu, uint16_t slot, uint16_t sub,
                         uint16_t index)
{
    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body + 22, slot);
    pn_wr_be16(body + 24, sub);
    pn_wr_be16(body + 28, index);
    uint8_t blk[80];
    size_t bn = wr_pn_block(blk, PN_BLOCK_READ_REQ, body, 58);
    uint8_t stub[160];
    size_t sn = ndr_wrap_le(stub, blk, bn);
    return rpc_req(pdu, 2, stub, sn);
}

static int count_block(const uint8_t *resp, size_t n, uint16_t want)
{
    if (n < 100) {
        return 0;
    }
    const uint8_t *p = resp + 100;
    size_t left = n - 100;
    size_t off = 0;
    int c = 0;
    while (off + 6 <= left) {
        uint16_t type = pn_rd_be16(p + off);
        uint16_t blen = pn_rd_be16(p + off + 2);
        if (type == want) {
            c++;
        }
        if (blen < 2 || off + 4u + blen > left) {
            break;
        }
        off += 4u + blen;
        if (off & 1u) {
            off++;
        }
    }
    return c;
}

static uint16_t parse_out_frame_id(const uint8_t *resp, size_t n)
{
    if (n < 100) {
        return 0x8000;
    }
    const uint8_t *p = resp + 100;
    size_t left = n - 100;
    size_t off = 0;
    uint16_t out_fid = 0x8000;
    while (off + 12 <= left) {
        uint16_t type = pn_rd_be16(p + off);
        uint16_t blen = pn_rd_be16(p + off + 2);
        if (blen < 2 || off + 4u + blen > left) {
            break;
        }
        if (type == PN_BLOCK_IOCR_RES && blen >= 8) {
            uint16_t iocr = pn_rd_be16(p + off + 6);
            uint16_t fid = pn_rd_be16(p + off + 10);
            if (iocr == PN_IOCR_OUTPUT) {
                out_fid = fid;
            }
        }
        off += 4u + blen;
        if (off & 1u) {
            off++;
        }
    }
    return out_fid;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <iface> [expect-name]\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    const char *expect_name = argc > 2 ? argv[2] : "sensor-line1";

    fprintf(stderr,
            "PI lab pretest (not ART/PITL). RT Device groups from public "
            "Test Bundle Readme.\n");

    int ifindex = 0;
    uint8_t mymac[6];
    memset(mymac, 0, sizeof(mymac));
    int raw = open_packet(iface, &ifindex, mymac);
    if (raw < 0) {
        fprintf(stderr, "FAIL  LAB-SETUP  AF_PACKET\n");
        return 1;
    }

    uint8_t frame[256], rx[1518];
    size_t flen = dcp_ident_all(frame, mymac, 0xA1000001);
    send_raw(raw, ifindex, frame, flen);
    int n = dcp_wait_ident(raw, rx, sizeof(rx), 1500, expect_name);
    check(n > 26 && contains(rx, (size_t)n, expect_name), "LAB-DCP-IDENT-ALL",
          "Identify AllSelector returns NameOfStation");
    uint8_t devmac[6];
    memset(devmac, 0, sizeof(devmac));
    uint32_t dev_ip = 0;
    if (n > 26) {
        memcpy(devmac, rx + 6, 6);
        uint16_t dlen = pn_rd_be16(rx + 14 + 10);
        const uint8_t *blocks = rx + 14 + 12;
        size_t off = 0;
        while (off + 4 <= dlen && 14 + 12 + off + 4 <= (size_t)n) {
            uint8_t opt = blocks[off];
            uint8_t sub = blocks[off + 1];
            uint16_t bl = pn_rd_be16(blocks + off + 2);
            if (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM && bl >= 12) {
                dev_ip = pn_rd_be32(blocks + off + 4);
            }
            off += 4u + bl + (bl & 1u);
        }
    }
    check(dev_ip != 0, "LAB-DCP-IDENT-IP", "Identify.Res includes IPParameter");

    /* Name match */
    uint8_t pay[48];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xA1000002);
    pn_wr_be16(pay + 8, 0);
    size_t nlen = strlen(expect_name);
    pay[12] = PN_DCP_OPT_DEV;
    pay[13] = PN_DCP_SUB_DEV_NAME;
    pn_wr_be16(pay + 14, (uint16_t)nlen);
    memcpy(pay + 16, expect_name, nlen);
    pn_wr_be16(pay + 10, (uint16_t)(4 + nlen + (nlen & 1)));
    memcpy(frame, k_dcp_mc, 6);
    memcpy(frame + 6, mymac, 6);
    pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
    memcpy(frame + 14, pay, 16 + nlen);
    send_raw(raw, ifindex, frame, 14 + 16 + nlen);
    n = dcp_wait_ident(raw, rx, sizeof(rx), 800, expect_name);
    check(n > 26, "LAB-DCP-IDENT-NAME-OK", "Identify NameOfStation match");

    memcpy(pay + 16, "no-such-station", 15);
    pn_wr_be16(pay + 14, 15);
    pn_wr_be16(pay + 10, 20);
    memcpy(frame + 14, pay, 32);
    send_raw(raw, ifindex, frame, 14 + 32);
    n = dcp_wait_ident(raw, rx, sizeof(rx), 400, expect_name);
    check(n < 0, "LAB-DCP-IDENT-NAME-NG", "wrong NameOfStation is ignored");

    /* DeviceID match / mismatch */
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xA1000003);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 8);
    pay[12] = PN_DCP_OPT_DEV;
    pay[13] = PN_DCP_SUB_DEV_ID;
    pn_wr_be16(pay + 14, 4);
    pn_wr_be16(pay + 16, 0xABCD);
    pn_wr_be16(pay + 18, 0x0001);
    memcpy(frame + 14, pay, 20);
    send_raw(raw, ifindex, frame, 34);
    n = dcp_wait_ident(raw, rx, sizeof(rx), 800, expect_name);
    check(n > 26, "LAB-DCP-IDENT-DEVID-OK", "Identify DeviceID match");

    pn_wr_be16(pay + 16, 0x0001);
    pn_wr_be32(pay + 4, 0xA1000004);
    memcpy(frame + 14, pay, 20);
    send_raw(raw, ifindex, frame, 34);
    n = dcp_wait_ident(raw, rx, sizeof(rx), 400, expect_name);
    check(n < 0, "LAB-DCP-IDENT-DEVID-NG", "wrong DeviceID is ignored");

    /* DCP Get Name / IP / ID — unicast */
    if (devmac[0] | devmac[5]) {
        uint8_t gpay[20];
        pn_wr_be16(gpay, PN_FRAMEID_DCP_GETSET);
        gpay[2] = PN_DCP_GET;
        gpay[3] = PN_DCP_REQ;
        pn_wr_be32(gpay + 4, 0xA1000010);
        pn_wr_be16(gpay + 8, 0);
        pn_wr_be16(gpay + 10, 4);
        gpay[12] = PN_DCP_OPT_DEV;
        gpay[13] = PN_DCP_SUB_DEV_NAME;
        pn_wr_be16(gpay + 14, 0);
        memcpy(frame, devmac, 6);
        memcpy(frame + 6, mymac, 6);
        pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
        memcpy(frame + 14, gpay, 16);
        send_raw(raw, ifindex, frame, 30);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, expect_name, 0xA1000010);
        check(n > 26 && contains(rx, (size_t)n, expect_name), "LAB-DCP-GET-NAME",
              "Get NameOfStation");

        gpay[13] = PN_DCP_SUB_DEV_ID;
        pn_wr_be32(gpay + 4, 0xA1000011);
        memcpy(frame + 14, gpay, 16);
        send_raw(raw, ifindex, frame, 30);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, expect_name, 0xA1000011);
        int saw_vid = 0;
        if (n > 20) {
            for (int i = 0; i + 4 <= n; i++) {
                if (pn_rd_be16(rx + i) == 0xABCD &&
                    pn_rd_be16(rx + i + 2) == 0x0001) {
                    saw_vid = 1;
                    break;
                }
            }
        }
        check(saw_vid, "LAB-DCP-GET-ID", "Get DeviceID 0xABCD/0x0001");

        gpay[12] = PN_DCP_OPT_IP;
        gpay[13] = PN_DCP_SUB_IP_PARAM;
        pn_wr_be32(gpay + 4, 0xA1000012);
        memcpy(frame + 14, gpay, 16);
        send_raw(raw, ifindex, frame, 30);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, expect_name, 0xA1000012);
        uint32_t got_ip = dcp_parse_ip(rx, n);
        check(got_ip != 0 && got_ip == dev_ip, "LAB-DCP-GET-IP",
              "Get IPParameter matches Identify");
    }

    /* LLDP: device sends at start and every 5s. Frames may have been seen
     * already while waiting for DCP. */
    uint64_t lldp_end =
        now_ms() + ((g_saw_lldp && g_saw_lldp_pn && g_saw_hello) ? 0 : 5500);
    while ((!g_saw_lldp || !g_saw_lldp_pn || !g_saw_hello) &&
           now_ms() < lldp_end) {
        n = wait_recv(raw, rx, sizeof(rx), 200);
        note_frame(rx, n, expect_name);
    }
    check(g_saw_lldp, "LAB-LLDP-SYSNAME", "LLDP chassis/sysName");
    check(g_saw_lldp_pn, "LAB-LLDP-PN-TLV", "LLDP PN OUI 00:0C:CF");
    check(g_saw_hello, "LAB-DCP-HELLO", "DCP Hello.req on start");

    static const uint8_t oid_sysname[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                          0x05, 0x00};
    static const uint8_t oid_sysdescr[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                           0x01, 0x00};
    static const uint8_t oid_lldp_loc[] = {0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
                                           0x01, 0x03, 0x03, 0x00};
    static const uint8_t oid_lldp_rem[] = {0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
                                           0x01, 0x04, 0x01, 0x01, 0x09, 0x00,
                                           0x01, 0x01};
    static const uint8_t oid_sys[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01};
    static const uint8_t oid_sysuptime[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                            0x03, 0x00};
    static const uint8_t oid_ifnumber[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                           0x01, 0x00};
    static const uint8_t oid_ifphys[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                         0x02, 0x01, 0x06, 0x01};
    static const uint8_t oid_ifoper[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                         0x02, 0x01, 0x08, 0x01};
    static const uint8_t oid_lldp_last[] = {0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
                                            0x01, 0x02, 0x06, 0x00};
    static const uint8_t oid_lldp_port[] = {0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
                                            0x01, 0x03, 0x07, 0x01, 0x03, 0x01};
    static const uint8_t mac_dev[] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    check(snmp_query(dev_ip, oid_sysname, sizeof(oid_sysname), 0x2a,
                     expect_name),
          "LAB-SNMP-SYSNAME", "SNMP Get sysName");
    check(snmp_query(dev_ip, oid_sysdescr, sizeof(oid_sysdescr), 0x2b,
                     "Fieldbus PN Device"),
          "LAB-SNMP-SYSDESCR", "SNMP Get sysDescr / MIB-II");
    check(snmp_query_next(dev_ip, oid_sys, sizeof(oid_sys), 0x2e,
                         "Fieldbus PN Device"),
          "LAB-SNMP-GETNEXT-SYS", "GetNext 1.3.6.1.2.1.1 → sysDescr");
    check(snmp_has_bytes(dev_ip, 0xa0, oid_ifnumber, sizeof(oid_ifnumber), 0x2f,
                         (const uint8_t *)"\x02\x01\x01", 3),
          "LAB-SNMP-IFNUMBER", "MIB-II ifNumber=1");
    check(snmp_has_bytes(dev_ip, 0xa0, oid_ifphys, sizeof(oid_ifphys), 0x30,
                         mac_dev, sizeof(mac_dev)),
          "LAB-SNMP-IFPHYS", "ifPhysAddress = device MAC");
    check(snmp_has_bytes(dev_ip, 0xa0, oid_ifoper, sizeof(oid_ifoper), 0x31,
                         (const uint8_t *)"\x02\x01\x01", 3),
          "LAB-SNMP-IFOPER", "ifOperStatus up (matches PDPort)");
    check(snmp_has_bytes(dev_ip, 0xa0, oid_sysuptime, sizeof(oid_sysuptime),
                         0x32, (const uint8_t *)"\x43", 1),
          "LAB-SNMP-UPTIME", "sysUpTime TimeTicks");
    static const uint8_t oid_ifinoct[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                          0x02, 0x01, 0x0a, 0x01};
    check(snmp_has_bytes(dev_ip, 0xa0, oid_ifinoct, sizeof(oid_ifinoct), 0x34,
                         (const uint8_t *)"\x41", 1),
          "LAB-SNMP-IFINOCT", "ifInOctets Counter32");
    static const uint8_t oid_sysloc[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                         0x06, 0x00};
    {
        uint8_t srx[512];
        int sn = snmp_set_oct(dev_ip, oid_sysloc, sizeof(oid_sysloc), 0x35,
                              "lab-rack", srx, sizeof(srx));
        check(sn > 0 && !contains(srx, (size_t)sn, "lab-rack"),
              "LAB-SNMP-SET-SYSLOC", "SNMP Set sysLocation read-only (SC1)");
        check(!snmp_query(dev_ip, oid_sysloc, sizeof(oid_sysloc), 0x36,
                          "lab-rack"),
              "LAB-SNMP-GET-SYSLOC", "sysLocation unchanged after Set");
    }
    check(snmp_query(dev_ip, oid_lldp_loc, sizeof(oid_lldp_loc), 0x2c,
                     expect_name),
          "LAB-SNMP-LLDP-LOC", "SNMP lldpLocSysName");
    check(snmp_query(dev_ip, oid_lldp_port, sizeof(oid_lldp_port), 0x33,
                     "port-001"),
          "LAB-SNMP-LLDP-PORT", "lldpLocPortId port-001");

    static const uint8_t lldp_mc[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    send_lldp_neighbor(raw, ifindex, lldp_mc, mymac, "ctl-lab1");
    if (devmac[0] | devmac[5]) {
        send_lldp_neighbor(raw, ifindex, devmac, mymac, "ctl-lab1");
    }
    usleep(80000);
    check(snmp_query(dev_ip, oid_lldp_rem, sizeof(oid_lldp_rem), 0x2d,
                     "ctl-lab1"),
          "LAB-SNMP-LLDP-REM", "SNMP lldpRemSysName after LLDP RX");
    check(snmp_has_bytes(dev_ip, 0xa0, oid_lldp_last, sizeof(oid_lldp_last),
                         0x34, (const uint8_t *)"\x43", 1),
          "LAB-SNMP-LLDP-LASTCHG", "lldpStatsRemTablesLastChangeTime");
    {
        uint8_t ipoid[24];
        static const uint8_t pre[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x14,
                                      0x01, 0x01};
        memcpy(ipoid, pre, sizeof(pre));
        size_t on = sizeof(pre);
        uint8_t b[4] = {(uint8_t)(dev_ip >> 24), (uint8_t)(dev_ip >> 16),
                        (uint8_t)(dev_ip >> 8), (uint8_t)dev_ip};
        uint8_t expect_ip[4];
        memcpy(expect_ip, b, 4);
        for (int i = 0; i < 4; i++) {
            if (b[i] >= 128) {
                ipoid[on++] = (uint8_t)(0x80u | (b[i] >> 7));
                ipoid[on++] = (uint8_t)(b[i] & 0x7f);
            } else {
                ipoid[on++] = b[i];
            }
        }
        check(snmp_has_bytes(dev_ip, 0xa0, ipoid, on, 0x37, expect_ip, 4),
              "LAB-SNMP-IPADDR", "ipAddrTable ipAdEntAddr");
    }
    static const uint8_t oid_icmp[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x01,
                                       0x00};
    check(snmp_has_bytes(dev_ip, 0xa0, oid_icmp, sizeof(oid_icmp), 0x38,
                         (const uint8_t *)"\x41", 1),
          "LAB-SNMP-ICMP", "icmpInMsgs Counter32");
    {
        uint8_t req[256], srx[1024];
        size_t rn = snmp_build_bulk(req, 0x39, 3, oid_sys, sizeof(oid_sys));
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        int ok = 0;
        if (fd >= 0 && dev_ip) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_port = htons(PN_SNMP_PORT);
            dst.sin_addr.s_addr = htonl(dev_ip);
            sendto(fd, req, rn, 0, (struct sockaddr *)&dst, sizeof(dst));
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
            if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0) {
                ssize_t sn = recv(fd, srx, sizeof(srx), 0);
                int n_oid = 0;
                if (sn > 0) {
                    for (int i = 0; i + 1 < sn; i++) {
                        if (srx[i] == 0x06) {
                            n_oid++;
                        }
                    }
                    ok = n_oid >= 3 && contains(srx, (size_t)sn, "Fieldbus PN Device");
                }
            }
            close(fd);
        }
        check(ok, "LAB-SNMP-GETBULK", "GetBulk max-repetitions=3 on system");
    }

    /* DCP Set NameOfStation round-trip (unsigned; lab security_class 0). */
    if (devmac[0] | devmac[5]) {
        const char *tmp_name = "lab-tmp1";
        uint8_t nblk[64];
        size_t nblen = dcp_name_set_block(nblk, tmp_name);
        size_t slen =
            dcp_put_getset(frame, devmac, mymac, PN_DCP_SET, 0xA1000020, nblk,
                           nblen);
        send_raw(raw, ifindex, frame, slen);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, tmp_name, 0xA1000020);
        check(n > 26, "LAB-DCP-SET-ACK", "Set NameOfStation ACK");

        uint8_t npay[48];
        pn_wr_be16(npay, PN_FRAMEID_DCP_ID_REQ);
        npay[2] = PN_DCP_IDENTIFY;
        npay[3] = PN_DCP_REQ;
        pn_wr_be32(npay + 4, 0xA1000021);
        pn_wr_be16(npay + 8, 0);
        size_t tn = strlen(tmp_name);
        npay[12] = PN_DCP_OPT_DEV;
        npay[13] = PN_DCP_SUB_DEV_NAME;
        pn_wr_be16(npay + 14, (uint16_t)tn);
        memcpy(npay + 16, tmp_name, tn);
        pn_wr_be16(npay + 10, (uint16_t)(4 + tn + (tn & 1)));
        memcpy(frame, k_dcp_mc, 6);
        memcpy(frame + 6, mymac, 6);
        pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
        memcpy(frame + 14, npay, 16 + tn);
        send_raw(raw, ifindex, frame, 14 + 16 + tn);
        n = dcp_wait_ident(raw, rx, sizeof(rx), 800, tmp_name);
        check(n > 26 && contains(rx, (size_t)n, tmp_name), "LAB-DCP-SET-NAME",
              "Identify sees renamed station");

        nblen = dcp_name_set_block(nblk, expect_name);
        slen = dcp_put_getset(frame, devmac, mymac, PN_DCP_SET, 0xA1000022,
                              nblk, nblen);
        send_raw(raw, ifindex, frame, slen);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, expect_name, 0xA1000022);
        check(n > 26, "LAB-DCP-SET-RESTORE", "Set NameOfStation back");
    }

    int rpc = udp_bind(iface_ipv4(iface), PN_RPC_PORT);
    uint8_t pdu[1200], resp[2048];
    size_t plen;
    int rn;
    if (rpc < 0 || !dev_ip) {
        check(0, "LAB-CM-SETUP", "RPC/UDP bind");
        close(raw);
        return 1;
    }

    plen = build_connect(pdu, mymac, PN_RT_CLASS_3);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 0 && count_block(resp, (size_t)rn, PN_BLOCK_ARSERVER_RES) == 0,
          "LAB-CM-NO-IRT", "CC-C: Connect RT_CLASS_3 rejected");

    plen = build_connect(pdu, mymac, PN_RT_CLASS_1);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, expect_name),
          "LAB-CM-CONNECT-ARSERVER", "Connect.res ARServerBlock station name");
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_ALARMCR_RES) >= 1,
          "LAB-CM-CONNECT-ALARMCR", "Connect.res AlarmCRBlockRes 0x8103");
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_MODDIFF) == 0,
          "LAB-CM-CONNECT-NO-MODDIFF", "no ModuleDiff on matching ExpectedSub");
    uint16_t out_fid = parse_out_frame_id(resp, rn > 0 ? (size_t)rn : 0);
    check(out_fid == 0x8000, "LAB-CM-CONNECT-OUT-FID",
          "device-assigned output FrameID 0x8000");

    if (devmac[0] | devmac[5]) {
        const char *hijack = "hijack1";
        uint8_t nblk[64];
        size_t nblen = dcp_name_set_block(nblk, hijack);
        size_t slen = dcp_put_getset(frame, devmac, mymac, PN_DCP_SET,
                                     0xA10000A0, nblk, nblen);
        send_raw(raw, ifindex, frame, slen);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, expect_name, 0xA10000A0);
        int blkerr = -1;
        if (n >= 34) {
            uint16_t dlen = pn_rd_be16(rx + 24);
            const uint8_t *b = rx + 26;
            if (dlen >= 7 && b[0] == PN_DCP_OPT_CTRL &&
                b[1] == PN_DCP_SUB_CTRL_RESP) {
                blkerr = b[6];
            }
        }
        check(n > 26 && blkerr == PN_DCP_BLOCK_ERROR_SET_NOT_POSSIBLE,
              "LAB-DCP-SET-AR-LOCK",
              "Set Name during AR: BlockError SET not possible");

        uint8_t ipay[16];
        pn_wr_be16(ipay, PN_FRAMEID_DCP_ID_REQ);
        ipay[2] = PN_DCP_IDENTIFY;
        ipay[3] = PN_DCP_REQ;
        pn_wr_be32(ipay + 4, 0xA10000A1);
        pn_wr_be16(ipay + 8, 0);
        pn_wr_be16(ipay + 10, 4);
        ipay[12] = PN_DCP_OPT_ALL;
        ipay[13] = 0xFF;
        pn_wr_be16(ipay + 14, 0);
        memcpy(frame, k_dcp_mc, 6);
        memcpy(frame + 6, mymac, 6);
        pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
        memcpy(frame + 14, ipay, 16);
        send_raw(raw, ifindex, frame, 30);
        n = dcp_wait_ident(raw, rx, sizeof(rx), 800, expect_name);
        check(n > 26 && contains(rx, (size_t)n, expect_name) &&
                  !contains(rx, (size_t)n, hijack),
              "LAB-DCP-IDENT-AR", "Identify during AR still original name");
    }

    plen = put_iod_write_hdr(pdu, 1, 0, 1, 1, 1, 4);
    memcpy(pdu + plen, "\x00\x00\x00\x00", 4);
    plen += 4;
    {
        uint8_t stub[200];
        size_t sn = ndr_wrap_le(stub, pdu, plen);
        plen = rpc_req(frame, 3, stub, sn);
    }
    rn = rpc_call(rpc, dev_ip, frame, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_WRITE_RES) == 1,
          "LAB-CM-WRITE", "IODWriteRes");

    {
        uint8_t data[4] = {0};
        uint8_t inner[160];
        size_t in = 0;
        in += put_iod_write_hdr(inner + in, 2, 0, 0, 0x8000, 0x8071, 4);
        memcpy(inner + in, data, 4);
        in += 4;
        in += put_iod_write_hdr(inner + in, 3, 0, 0, 0x8001, 0x802F, 4);
        memcpy(inner + in, data, 4);
        in += 4;
        uint8_t multi[256];
        size_t mn = put_iod_write_hdr(multi, 1, 0xffffffffu, 0xffff, 0xffff,
                                      PN_INDEX_WRITE_MULTI, (uint32_t)in);
        memcpy(multi + mn, inner, in);
        mn += in;
        uint8_t stub[320];
        size_t sn = ndr_wrap_le(stub, multi, mn);
        plen = rpc_req(pdu, 3, stub, sn);
    }
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_WRITE_RES) == 3,
          "LAB-CM-WRITEMULTI", "WriteMultiple 0xE040 three IODWriteRes");

    plen = build_read(pdu, 0, 1, PN_INDEX_IM0);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, "FB-ARCH-PN-DEV"),
          "LAB-CM-READ-IM0", "I&M0 OrderID");

    {
        uint8_t im1[60];
        memset(im1, ' ', sizeof(im1));
        pn_wr_be16(im1, PN_BLOCK_IM1);
        pn_wr_be16(im1 + 2, 56);
        im1[4] = 1;
        im1[5] = 0;
        memcpy(im1 + 6, "LINE-A", 6);
        memcpy(im1 + 38, "CAB-1", 5);
        uint8_t blocks[128];
        size_t bn = put_iod_write_hdr(blocks, 5, 0, 0, 1, PN_INDEX_IM1,
                                      sizeof(im1));
        memcpy(blocks + bn, im1, sizeof(im1));
        bn += sizeof(im1);
        uint8_t stub[220];
        size_t sn = ndr_wrap_le(stub, blocks, bn);
        plen = rpc_req(pdu, 3, stub, sn);
    }
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_WRITE_RES) == 1,
          "LAB-CM-WRITE-IM1", "I&M1 Write.res");
    plen = build_read(pdu, 0, 1, PN_INDEX_IM1);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, "LINE-A") &&
              contains(resp, (size_t)rn, "CAB-1"),
          "LAB-CM-READ-IM1", "I&M1 TagFunction/Location");
    plen = build_read(pdu, 0, 1, PN_INDEX_IM2);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, "2020-01-01"),
          "LAB-CM-READ-IM2", "I&M2 date");

    plen = build_read(pdu, 0, 1, PN_INDEX_REALIDENT_API);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_REALIDENT) == 1,
          "LAB-CM-READ-REALIDENT", "RealIdentification 0xF000");

    plen = build_read(pdu, 0, 0x8001, PN_INDEX_PDPORT_REAL);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, "port-001"), "LAB-CM-READ-PDPORT",
          "PDPortDataReal stub");
    check(rn > 80 && contains_mem(resp, (size_t)rn, mymac, 6),
          "LAB-CM-READ-PDPORT-PEER", "PDPortDataReal peer chassis after LLDP");

    plen = build_read(pdu, 0, 0x8001, PN_INDEX_PDPORT_CHECK);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_PDPORT_CHECK) >= 1,
          "LAB-CM-READ-PDCHECK", "PDPortDataCheck CheckPeers default");

    plen = build_read(pdu, 0, 0x8000, PN_INDEX_PDIF_FSU);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "LAB-CM-READ-FSU", "PDInterface FSU empty success");

    plen = build_read(pdu, 0, 0x8000, PN_INDEX_PDIF_REAL);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, expect_name),
          "LAB-CM-READ-PDIF", "PDInterfaceDataReal station name");

    plen = build_read(pdu, 0, 1, 0x1234);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && resp[1] == 2 &&
              count_block(resp, (size_t)rn, PN_BLOCK_READ_RES) >= 1,
          "LAB-CM-READ-UNKNOWN", "unknown record index empty success");

    plen = build_prmend(pdu);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "LAB-CM-PRMEND", "PrmEnd.res");

    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(rpc, &rfds);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 400000};
        if (select(rpc + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t ap[1024];
            ssize_t an = recv(rpc, ap, sizeof(ap), 0);
            if (an >= 80 && ap[1] == 0) {
                uint8_t ack[1024];
                memcpy(ack, ap, (size_t)an);
                ack[1] = 2;
                struct sockaddr_in dst;
                memset(&dst, 0, sizeof(dst));
                dst.sin_family = AF_INET;
                dst.sin_port = htons(PN_RPC_PORT);
                dst.sin_addr.s_addr = htonl(dev_ip);
                sendto(rpc, ack, (size_t)an, 0, (struct sockaddr *)&dst,
                       sizeof(dst));
                check(1, "LAB-CM-APPRDY", "ApplicationReady.req acked");
            } else {
                check(0, "LAB-CM-APPRDY", "ApplicationReady.req missing");
            }
        } else {
            check(0, "LAB-CM-APPRDY", "ApplicationReady.req timeout");
        }
    }

    int cyclic_in = 0, iops_ok = 0, saw_rta = 0, sent_rta_ack = 0;
    uint64_t end = now_ms() + 400;
    uint64_t last_out = 0;
    while (now_ms() < end) {
        uint64_t t = now_ms();
        if (t - last_out >= 8) {
            uint8_t opay[48];
            memset(opay, 0, sizeof(opay));
            pn_wr_be16(opay, out_fid);
            memset(opay + 2, 0xA5, 8);
            opay[10] = PN_IOPS_GOOD;
            pn_wr_be16(opay + 42, (uint16_t)t);
            opay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                       PN_DATASTATUS_RUN;
            uint8_t fr[64];
            memcpy(fr, devmac, 6);
            memcpy(fr + 6, mymac, 6);
            pn_wr_be16(fr + 12, PN_ETHTYPE_PN);
            memcpy(fr + 14, opay, 46);
            send_raw(raw, ifindex, fr, 60);
            last_out = t;
        }
        ssize_t rnraw = recv(raw, rx, sizeof(rx), MSG_DONTWAIT);
        if (rnraw >= 16) {
            uint16_t fid = 0;
            size_t poff = 0;
            if (pn_frame_fid(rx, (int)rnraw, &fid, &poff) == 0) {
                if (fid == 0x8123) {
                    cyclic_in++;
                    if ((size_t)rnraw > poff + 2 + 32 &&
                        rx[poff + 2 + 32] == PN_IOPS_GOOD) {
                        iops_ok = 1;
                    }
                } else if ((fid == PN_FRAMEID_ALARM_HIGH ||
                            fid == PN_FRAMEID_ALARM_LOW) &&
                           (size_t)rnraw >= poff + 14) {
                    uint8_t kind = (uint8_t)(rx[poff + 6] & 0x0Fu);
                    if (kind == 1 && !saw_rta) {
                        saw_rta = 1;
                        if ((size_t)rnraw >= poff + 42 &&
                            pn_rd_be16(rx + poff + 14 + 26) ==
                                PN_USI_CHANNEL_DIAG) {
                            saw_rta = 2;
                        }
                        send_rta_ack(raw, ifindex, rx, (int)rnraw, poff, mymac);
                        sent_rta_ack = 1;
                    }
                }
            }
        } else if (rnraw < 0) {
            usleep(1000);
        }
    }
    check(cyclic_in >= 3, "LAB-RT-CYCLIC", "RTC1 input frames");
    check(iops_ok, "LAB-RT-IOPS", "IOPS GOOD");
    check(saw_rta >= 1, "LAB-CM-RTA-DATA", "RTA AlarmNotification after DATAEX");
    check(saw_rta == 2, "LAB-CM-RTA-USI", "RTA ChannelDiagnosis USI 0x8000");
    check(sent_rta_ack, "LAB-CM-RTA-ACK", "RTA ACK sent for device Data");

    {
        uint8_t opay[48];
        memset(opay, 0, sizeof(opay));
        pn_wr_be16(opay, out_fid);
        opay[10] = PN_IOPS_GOOD;
        opay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                   PN_DATASTATUS_RUN;
        uint8_t fr[64];
        memcpy(fr, devmac, 6);
        memcpy(fr + 6, mymac, 6);
        pn_wr_be16(fr + 12, PN_ETHTYPE_PN);
        memcpy(fr + 14, opay, 46);
        send_raw(raw, ifindex, fr, 60);
    }

    plen = build_read(pdu, 0, 0x8001, PN_INDEX_CHAN_DIAG);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_DIAGNOSIS) >= 1,
          "LAB-CM-DIAG-CHAN", "ChannelDiagnosis 0x800A after RTA");
    plen = build_read(pdu, 0, 0x8001, PN_INDEX_EXT_CHAN_DIAG);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_DIAGNOSIS) >= 1,
          "LAB-CM-DIAG-EXT", "ExtChannelDiagnosis 0x8010");
    {
        uint8_t opay[48];
        memset(opay, 0, sizeof(opay));
        pn_wr_be16(opay, out_fid);
        opay[10] = PN_IOPS_GOOD;
        opay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                   PN_DATASTATUS_RUN;
        uint8_t fr[64];
        memcpy(fr, devmac, 6);
        memcpy(fr + 6, mymac, 6);
        pn_wr_be16(fr + 12, PN_ETHTYPE_PN);
        memcpy(fr + 14, opay, 46);
        send_raw(raw, ifindex, fr, 60);
    }
    plen = build_read(pdu, 0, 0x8001, PN_INDEX_QUAL_CHAN_DIAG);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_DIAGNOSIS) >= 1,
          "LAB-CM-DIAG-QUAL", "QualifiedChannelDiagnosis 0x8011");
    plen = build_read(pdu, 0, 0x8001, PN_INDEX_PDPORT_STAT);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_PDPORT_STAT) >= 1,
          "LAB-CM-PDPORT-STAT", "PDPortStatistic counters");

    for (int i = 0; i < 400; i++) {
        uint8_t junk[64];
        memset(junk, 0xA5, sizeof(junk));
        memcpy(junk, devmac, 6);
        memcpy(junk + 6, mymac, 6);
        pn_wr_be16(junk + 12, (i & 1) ? PN_ETHTYPE_MRP : 0x0800);
        send_raw(raw, ifindex, junk, 60);
        if ((i % 16) == 0) {
            uint8_t opay[48];
            memset(opay, 0, sizeof(opay));
            pn_wr_be16(opay, out_fid);
            memset(opay + 2, 0xA5, 8);
            opay[10] = PN_IOPS_GOOD;
            opay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                       PN_DATASTATUS_RUN;
            uint8_t fr[64];
            memcpy(fr, devmac, 6);
            memcpy(fr + 6, mymac, 6);
            pn_wr_be16(fr + 12, PN_ETHTYPE_PN);
            memcpy(fr + 14, opay, 46);
            send_raw(raw, ifindex, fr, 60);
        }
    }
    int after_load = 0;
    uint64_t load_end = now_ms() + 250;
    last_out = 0;
    while (now_ms() < load_end) {
        uint64_t t = now_ms();
        if (t - last_out >= 8) {
            uint8_t opay[48];
            memset(opay, 0, sizeof(opay));
            pn_wr_be16(opay, out_fid);
            memset(opay + 2, 0xA5, 8);
            opay[10] = PN_IOPS_GOOD;
            pn_wr_be16(opay + 42, (uint16_t)t);
            opay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                       PN_DATASTATUS_RUN;
            uint8_t fr[64];
            memcpy(fr, devmac, 6);
            memcpy(fr + 6, mymac, 6);
            pn_wr_be16(fr + 12, PN_ETHTYPE_PN);
            memcpy(fr + 14, opay, 46);
            send_raw(raw, ifindex, fr, 60);
            last_out = t;
        }
        ssize_t rnraw = recv(raw, rx, sizeof(rx), MSG_DONTWAIT);
        if (rnraw >= 18 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == 0x8123) {
            after_load++;
        } else if (rnraw < 0) {
            usleep(1000);
        }
    }
    check(after_load >= 1, "LAB-RT-NETLOAD",
          "RTC1 continues under ingress flood");

    plen = build_release(pdu);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "LAB-CM-RELEASE", "Release.res");
    usleep(20000);
    int after_rel = 0;
    uint64_t rel_end = now_ms() + 80;
    while (now_ms() < rel_end) {
        ssize_t rnraw = recv(raw, rx, sizeof(rx), MSG_DONTWAIT);
        if (rnraw >= 18 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == 0x8123) {
            after_rel++;
        }
    }
    check(after_rel == 0, "LAB-CM-RELEASE-CYCLIC-STOP",
          "no input CR after Release");

    plen = build_connect(pdu, mymac, PN_RT_CLASS_1);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "LAB-CM-RECONNECT", "Connect after Release");

    close(rpc);
    close(raw);
    fprintf(stderr, "\nPI lab pretest %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
