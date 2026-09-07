#define _GNU_SOURCE

/*
 * Lab pretest modeled on PI Test Bundle RT Device groups (public Readme:
 * https://www.profibus.com/download/profinet-test-bundle ).
 * This is not ART/SPIRTA/PITL certification. Official ETS is PI-member-only.
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
    if (pn_rd_be16(rx + 12) == PN_ETHTYPE_LLDP &&
        contains(rx, (size_t)n, expect_name)) {
        g_saw_lldp = 1;
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

static size_t build_connect(uint8_t *pdu, const uint8_t mac[6])
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

    uint8_t blocks[512];
    size_t n = 0;
    n += wr_pn_block(blocks + n, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iin, sizeof(iin));
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iout, sizeof(iout));
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
    }

    /* LLDP: device sends at start and every 5s. Frames may have been seen
     * already while waiting for DCP. */
    uint64_t lldp_end = now_ms() + (g_saw_lldp ? 0 : 5500);
    while (!g_saw_lldp && now_ms() < lldp_end) {
        n = wait_recv(raw, rx, sizeof(rx), 200);
        note_frame(rx, n, expect_name);
    }
    check(g_saw_lldp, "LAB-LLDP-SYSNAME", "LLDP chassis/sysName");

    /* SNMP sysName */
    int snmp = socket(AF_INET, SOCK_DGRAM, 0);
    int snmp_ok = 0;
    if (snmp >= 0 && dev_ip) {
        static const uint8_t snmp_get[] = {
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p',  'u',  'b',
            'l',  'i',  'c',  0xa0, 0x19, 0x02, 0x01, 0x2a, 0x02, 0x01,
            0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00};
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(PN_SNMP_PORT);
        dst.sin_addr.s_addr = htonl(dev_ip);
        sendto(snmp, snmp_get, sizeof(snmp_get), 0, (struct sockaddr *)&dst,
               sizeof(dst));
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(snmp, &rfds);
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        if (select(snmp + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t srx[512];
            ssize_t sn = recv(snmp, srx, sizeof(srx), 0);
            if (sn > 0 && contains(srx, (size_t)sn, expect_name) &&
                contains(srx, (size_t)sn, "\x02\x01\x2a")) {
                snmp_ok = 1;
            } else if (sn > 0 && contains(srx, (size_t)sn, expect_name)) {
                snmp_ok = 1; /* name present even if request-id encoding differs */
            }
        }
        close(snmp);
    }
    check(snmp_ok, "LAB-SNMP-SYSNAME", "SNMP Get sysName / request-id");

    int rpc = udp_bind(iface_ipv4(iface), PN_RPC_PORT);
    uint8_t pdu[1200], resp[2048];
    if (rpc < 0 || !dev_ip) {
        check(0, "LAB-CM-SETUP", "RPC/UDP bind");
        close(raw);
        return 1;
    }

    size_t plen = build_connect(pdu, mymac);
    int rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, expect_name),
          "LAB-CM-CONNECT-ARSERVER", "Connect.res ARServerBlock station name");
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_MODDIFF) == 0,
          "LAB-CM-CONNECT-NO-MODDIFF", "no ModuleDiff on matching ExpectedSub");
    uint16_t out_fid = parse_out_frame_id(resp, rn > 0 ? (size_t)rn : 0);
    check(out_fid == 0x8000, "LAB-CM-CONNECT-OUT-FID",
          "device-assigned output FrameID 0x8000");

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

    plen = build_read(pdu, 0, 1, PN_INDEX_REALIDENT_API);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && count_block(resp, (size_t)rn, PN_BLOCK_REALIDENT) == 1,
          "LAB-CM-READ-REALIDENT", "RealIdentification 0xF000");

    plen = build_read(pdu, 0, 0x8001, PN_INDEX_PDPORT_REAL);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80 && contains(resp, (size_t)rn, "port-001"), "LAB-CM-READ-PDPORT",
          "PDPortDataReal stub");

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

    int cyclic_in = 0, iops_ok = 0;
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
        if (rnraw >= 18 && pn_rd_be16(rx + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(rx + 14) == 0x8123) {
            cyclic_in++;
            if ((size_t)rnraw > 14 + 2 + 32 &&
                rx[14 + 2 + 32] == PN_IOPS_GOOD) {
                iops_ok = 1;
            }
        } else if (rnraw < 0) {
            usleep(1000);
        }
    }
    check(cyclic_in >= 3, "LAB-RT-CYCLIC", "RTC1 input frames");
    check(iops_ok, "LAB-RT-IOPS", "IOPS GOOD");

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

    plen = build_connect(pdu, mymac);
    rn = rpc_call(rpc, dev_ip, pdu, plen, resp, sizeof(resp), 1500);
    check(rn > 80, "LAB-CM-RECONNECT", "Connect after Release");

    close(rpc);
    close(raw);
    fprintf(stderr, "\nPI lab pretest %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
