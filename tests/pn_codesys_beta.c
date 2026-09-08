#define _GNU_SOURCE

/*
 * CODESYS Control SL (2-hour demo) Controller profile against this Device.
 *
 * This is not the CODESYS binary. Store packages and the Windows IDE are not
 * available in this environment. The sequence matches the public CODESYS
 * PROFINET Controller path: DCP scan / Set Name / Connect with AlarmCR /
 * sequential record Write / PrmEnd / ApplicationReady ACK / 8 ms RTC1 /
 * Release.
 */

#include "pn_endian.h"
#include "pn_types.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
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

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t now_ms(void)
{
    return now_ns() / 1000000ull;
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
    pn_wr_be16(blk + 4, 1);
    memcpy(blk + 6, name, nlen);
    size_t n = 6 + nlen;
    if (n & 1u) {
        blk[n++] = 0;
    }
    return n;
}

static int dcp_wait_ident(int fd, uint8_t *rx, size_t cap, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline) {
        int n = wait_recv(fd, rx, cap, 150);
        if (n >= 26 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == PN_FRAMEID_DCP_ID_RES) {
            return n;
        }
    }
    return -1;
}

static int dcp_wait_getset(int fd, uint8_t *rx, size_t cap, int timeout_ms,
                           uint32_t xid)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    while (now_ms() < deadline) {
        int n = wait_recv(fd, rx, cap, 150);
        if (n >= 26 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == PN_FRAMEID_DCP_GETSET && rx[17] != 0 &&
            pn_rd_be32(rx + 18) == xid) {
            return n;
        }
    }
    return -1;
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

static int count_block(const uint8_t *resp, size_t n, uint16_t want)
{
    if (n < 100) {
        return 0;
    }
    const uint8_t *p = resp + 80 + 20;
    size_t left = n - 100;
    size_t off = 0;
    int c = 0;
    while (off + 4 <= left) {
        uint16_t type = pn_rd_be16(p + off);
        uint16_t blen = pn_rd_be16(p + off + 2);
        if (blen < 2 || off + 4u + blen > left) {
            break;
        }
        if (type == want) {
            c++;
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
    const uint8_t *p = resp + 80 + 20;
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

static size_t build_write(uint8_t *pdu, uint16_t seq, uint16_t slot,
                          uint16_t sub, uint16_t index, const uint8_t *data,
                          uint32_t dlen)
{
    uint8_t blocks[256];
    size_t n = put_iod_write_hdr(blocks, seq, 0, slot, sub, index, dlen);
    memcpy(blocks + n, data, dlen);
    n += dlen;
    uint8_t stub[320];
    size_t sn = ndr_wrap_le(stub, blocks, n);
    return rpc_req(pdu, 3, stub, sn);
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

static size_t build_connect(uint8_t *pdu, const uint8_t mac[6])
{
    static const uint8_t uuid[16] = {0xC0, 0xDE, 0x59, 0x00, 0x00, 0x00, 0x00,
                                     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x01};
    uint8_t ar[59];
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
    pn_wr_be16(ar + 50, 7);
    memcpy(ar + 52, "codesys", 7);

    uint8_t iin[60], iout[60], exp[36], pdev[40];
    memset(iin, 0, sizeof(iin));
    pn_wr_be16(iin + 0, PN_IOCR_INPUT);
    pn_wr_be16(iin + 2, 1);
    pn_wr_be16(iin + 4, 0x8892);
    pn_wr_be32(iin + 6, 0x00000001);
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

    uint8_t alarmcr[20];
    memset(alarmcr, 0, sizeof(alarmcr));
    pn_wr_be16(alarmcr + 0, 1);
    pn_wr_be16(alarmcr + 2, 0x8892);
    pn_wr_be32(alarmcr + 4, 0);
    pn_wr_be16(alarmcr + 8, 1);
    pn_wr_be16(alarmcr + 10, 3);
    pn_wr_be16(alarmcr + 12, 3);
    pn_wr_be16(alarmcr + 14, 200);
    pn_wr_be16(alarmcr + 16, 0xC000);
    pn_wr_be16(alarmcr + 18, 0xA000);

    uint8_t blocks[512];
    size_t n = 0;
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

static int snmp_sysname(uint32_t dst_ip)
{
    static const uint8_t oid[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
    uint8_t req[128];
    size_t i = 0;
    req[i++] = 0x30;
    size_t outer = i++;
    req[i++] = 0x02;
    req[i++] = 0x01;
    req[i++] = 0x01;
    req[i++] = 0x04;
    req[i++] = 0x06;
    memcpy(req + i, "public", 6);
    i += 6;
    req[i++] = 0xa0;
    size_t pdu_len_at = i++;
    req[i++] = 0x02;
    req[i++] = 0x01;
    req[i++] = 0x41;
    req[i++] = 0x02;
    req[i++] = 0x01;
    req[i++] = 0x00;
    req[i++] = 0x02;
    req[i++] = 0x01;
    req[i++] = 0x00;
    req[i++] = 0x30;
    size_t vbl_at = i++;
    req[i++] = 0x30;
    size_t vb_at = i++;
    req[i++] = 0x06;
    req[i++] = (uint8_t)sizeof(oid);
    memcpy(req + i, oid, sizeof(oid));
    i += sizeof(oid);
    req[i++] = 0x05;
    req[i++] = 0x00;
    req[vb_at] = (uint8_t)(i - vb_at - 1);
    req[vbl_at] = (uint8_t)(i - vbl_at - 1);
    req[pdu_len_at] = (uint8_t)(i - pdu_len_at - 1);
    req[outer] = (uint8_t)(i - outer - 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(PN_SNMP_PORT);
    dst.sin_addr.s_addr = htonl(dst_ip);
    sendto(fd, req, i, 0, (struct sockaddr *)&dst, sizeof(dst));
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    uint8_t rx[512];
    int ok = 0;
    if (select(fd + 1, &rfds, NULL, NULL, &tv) > 0) {
        ssize_t n = recv(fd, rx, sizeof(rx), 0);
        if (n > 0 && contains(rx, (size_t)n, "sensor-line1")) {
            ok = 1;
        }
    }
    close(fd);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <iface> [expect-name]\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    const char *expect_name = argc > 2 ? argv[2] : "sensor-line1";

    int ifindex = 0;
    uint8_t mymac[6];
    memset(mymac, 0, sizeof(mymac));
    int raw = open_packet(iface, &ifindex, mymac);
    if (raw < 0) {
        fprintf(stderr, "FAIL  CDS-SETUP  AF_PACKET\n");
        return 1;
    }

    uint8_t frame[256], rx[1518];
    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xC0DE0001);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);
    memcpy(frame, k_dcp_mc, 6);
    memcpy(frame + 6, mymac, 6);
    pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
    memcpy(frame + 14, pay, 16);
    send_raw(raw, ifindex, frame, 30);
    int n = dcp_wait_ident(raw, rx, sizeof(rx), 1500);
    uint8_t devmac[6];
    memset(devmac, 0, sizeof(devmac));
    if (n >= 20) {
        memcpy(devmac, rx + 6, 6);
    }
    uint32_t dev_ip = dcp_parse_ip(rx, n);
    check(n > 26 && contains(rx, (size_t)n, expect_name), "CDS-DCP-SCAN",
          "CODESYS Scan for Devices: Identify All");
    check(dev_ip != 0, "CDS-DCP-IP", "Identify.Res IPParameter");

    if (devmac[0] | devmac[5]) {
        uint8_t nblk[64];
        size_t nblen = dcp_name_set_block(nblk, expect_name);
        size_t slen =
            dcp_put_getset(frame, devmac, mymac, PN_DCP_SET, 0xC0DE0010, nblk,
                           nblen);
        send_raw(raw, ifindex, frame, slen);
        n = dcp_wait_getset(raw, rx, sizeof(rx), 800, 0xC0DE0010);
        check(n > 26, "CDS-DCP-NOMINATE", "CODESYS Nominate: Set NameOfStation");
    } else {
        check(0, "CDS-DCP-NOMINATE", "no device MAC");
    }

    check(snmp_sysname(dev_ip), "CDS-SNMP-SYSNAME",
          "CODESYS topology SNMP Get sysName");

    int rpc = udp_bind(iface_ipv4(iface), PN_RPC_PORT);
    uint8_t pdu[1200], resp[2048];
    if (rpc < 0 || !dev_ip) {
        check(0, "CDS-CM-SETUP", "RPC bind");
        close(raw);
        fprintf(stderr, "CODESYS beta %d pass / %d fail\n", g_pass, g_fail);
        return 1;
    }

    size_t plen = build_connect(pdu, mymac);
    int rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, expect_name),
          "CDS-CM-CONNECT", "Connect.res ARServer (CODESYS CM)");
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_ALARMCR_RES) >= 1,
          "CDS-CM-ALARMCR", "AlarmCRBlockRes (CODESYS always configures AlarmCR)");
    uint16_t out_fid = parse_out_frame_id(resp, rn > 0 ? (size_t)rn : 0);

    uint8_t zeros[8];
    memset(zeros, 0, sizeof(zeros));
    plen = build_write(pdu, 1, 0, 0x8000, PN_INDEX_PDIF_ADJUST, zeros, 8);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_WRITE_RES) == 1,
          "CDS-CM-WRITE-PDIF", "sequential Write PDInterfaceAdjust");

    plen = build_write(pdu, 2, 0, 0x8001, PN_INDEX_PDPORT_ADJUST, zeros, 8);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_WRITE_RES) == 1,
          "CDS-CM-WRITE-PDPORT", "sequential Write PDPortDataAdjust");

    uint8_t im1[60];
    memset(im1, ' ', sizeof(im1));
    pn_wr_be16(im1, PN_BLOCK_IM1);
    pn_wr_be16(im1 + 2, 56);
    im1[4] = 1;
    im1[5] = 0;
    memcpy(im1 + 6, "CODESYS", 7);
    memcpy(im1 + 38, "BETA", 4);
    plen = build_write(pdu, 3, 0, 1, PN_INDEX_IM1, im1, sizeof(im1));
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_WRITE_RES) == 1,
          "CDS-CM-WRITE-IM1", "I&M1 Write (CODESYS identification)");

    plen = build_read(pdu, 0, 1, PN_INDEX_IM0);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, "FB-ARCH-PN-DEV"),
          "CDS-CM-READ-IM0", "I&M0 OrderID for device catalog");

    plen = build_prmend(pdu);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "CDS-CM-PRMEND", "PrmEnd.res");

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
            }
        }
    }

    int cyclic_in = 0;
    int iops_ok = 0;
    int pattern_ok = 0;
    uint64_t cyclic_ms = 1200;
    {
        const char *e = getenv("PN_BETA_CYCLIC_MS");
        if (e && atoi(e) > 0) {
            cyclic_ms = (uint64_t)atoi(e);
        }
    }
    uint64_t end = now_ms() + cyclic_ms;
    uint64_t last_out = 0;
    uint64_t last_in_ns = 0;
    const uint64_t period = 8000000ull;
    const int warmup = 5;
    int nint = 0;
    uint64_t sum = 0;
    uint64_t min_i = UINT64_MAX;
    uint64_t max_i = 0;
    uint64_t max_late = 0;
    while (now_ms() < end) {
        uint64_t t = now_ms();
        if (t - last_out >= 8) {
            uint8_t cpay[48];
            memset(cpay, 0, sizeof(cpay));
            pn_wr_be16(cpay, out_fid);
            cpay[2] = 0x5A;
            cpay[10] = PN_IOPS_GOOD;
            pn_wr_be16(cpay + 42, (uint16_t)t);
            cpay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                       PN_DATASTATUS_RUN;
            uint8_t fr[64];
            memcpy(fr, devmac, 6);
            memcpy(fr + 6, mymac, 6);
            pn_wr_be16(fr + 12, PN_ETHTYPE_PN);
            memcpy(fr + 14, cpay, 46);
            send_raw(raw, ifindex, fr, 60);
            last_out = t;
        }
        int rnraw = wait_recv(raw, rx, sizeof(rx), 4);
        if (rnraw >= 18 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == 0x8123) {
            uint64_t ts = now_ns();
            cyclic_in++;
            if (cyclic_in > warmup && last_in_ns != 0) {
                uint64_t dt = ts - last_in_ns;
                sum += dt;
                nint++;
                if (dt < min_i) {
                    min_i = dt;
                }
                if (dt > max_i) {
                    max_i = dt;
                }
                if (dt > period && dt - period > max_late) {
                    max_late = dt - period;
                }
            }
            last_in_ns = ts;
            if ((size_t)rnraw > 14 + 2 + 32 &&
                rx[14 + 2 + 32] == PN_IOPS_GOOD) {
                iops_ok = 1;
            }
            if (contains(rx, (size_t)rnraw, "BETA-PN-IN")) {
                pattern_ok = 1;
            }
        }
    }
    check(cyclic_in >= 100, "CDS-RTC1-CYCLIC",
          "8 ms input CR (>=100 frames / 1.2s)");
    check(iops_ok, "CDS-RTC1-IOPS", "IOPS GOOD on input");
    check(pattern_ok, "CDS-RTC1-INPUT", "process input BETA-PN-IN (PLC_PRG mapping)");

    {
        uint64_t mean = nint ? sum / nint : 0;
        char jmsg[160];
        snprintf(jmsg, sizeof(jmsg),
                 "mean=%lluus min=%lluus max=%lluus late_max=%lluus n=%d",
                 (unsigned long long)(mean / 1000ull),
                 (unsigned long long)(min_i == UINT64_MAX ? 0 : min_i / 1000ull),
                 (unsigned long long)(max_i / 1000ull),
                 (unsigned long long)(max_late / 1000ull), nint);
        /* Non-PREEMPT_RT cloud VMs are not guaranteed 0.1 ms. Gate on
         * phase-lock: mean near 8 ms, late_max well under the old ~1 ms. */
        check(nint >= 80 && mean >= 7600000ull && mean <= 8400000ull &&
                  max_late < 500000ull,
              "CDS-RTC1-JITTER", jmsg);
    }

    plen = build_release(pdu);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "CDS-CM-RELEASE", "Release.res");

    close(rpc);
    close(raw);
    fprintf(stderr, "CODESYS-profile beta %d pass / %d fail (not CODESYS binary)\n",
            g_pass, g_fail);
    return g_fail ? 1 : 0;
}
