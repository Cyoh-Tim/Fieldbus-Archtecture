/*
 * T11-10: standard CIP object attributes.
 *
 * Identity Status after an Exclusive Owner connection is Owned (bit 0),
 * not Configured (bit 2). ACD is a Status fault bit, not Identity State 2.
 * QoS attributes follow Vol 2 numbering and Class 1 T->O carries the
 * Scheduled DSCP. TCP/IP Interface, Port, class revision, and a read-only
 * Set use the status codes in docs/protocols/ethernetip.md §4.
 *
 * Attr 17 is Geographic_Location. This test does not assign Protection Mode
 * a replacement attribute number.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static uint32_t test_register(eip_stack_t *s)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[64];
    size_t n = 0;

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp), &n) !=
            0 ||
        n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static int parse_ucmm(const uint8_t *resp, size_t resp_len, uint8_t *status,
                      uint8_t *data, size_t *data_len)
{
    const uint8_t *b;
    size_t bl;
    size_t off;
    uint16_t items;

    if (!resp || resp_len < EIP_ENCAP_HDR_SIZE + 8 || !status || !data_len) {
        return -1;
    }
    b = resp + EIP_ENCAP_HDR_SIZE;
    bl = resp_len - EIP_ENCAP_HDR_SIZE;
    off = 6;
    if (off + 2 > bl) {
        return -1;
    }
    items = eip_rd_le16(b + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        uint16_t type;
        uint16_t length;
        if (off + 4 > bl) {
            return -1;
        }
        type = eip_rd_le16(b + off);
        length = eip_rd_le16(b + off + 2);
        off += 4;
        if (off + length > bl) {
            return -1;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA && length >= 4) {
            size_t n = length - 4;
            *status = b[off + 2];
            if (data && n > *data_len) {
                n = *data_len;
            }
            if (data && n > 0) {
                memcpy(data, b + off + 4, n);
            }
            *data_len = (b[off + 2] == 0) ? (length - 4) : 0;
            return 0;
        }
        off += length;
    }
    return -1;
}

/* Get_Attribute_Single. On success *data_len is the attribute payload.
 * *status is the CIP general status. Returns 0 when a CIP reply was parsed. */
static int get_attr(eip_stack_t *s, uint16_t class_id, uint16_t inst,
                    uint16_t attr, uint8_t *data, size_t *data_len,
                    uint8_t *status)
{
    uint8_t path[8];
    size_t pu = 0;
    uint8_t cip[16];
    uint8_t body[64];
    size_t boff = 0;
    uint8_t req[EIP_ENCAP_HDR_SIZE + 80];
    uint8_t resp[512];
    size_t resp_len = 0;
    uint32_t session;

    path[pu++] = 0x20;
    path[pu++] = (uint8_t)class_id;
    path[pu++] = 0x24;
    path[pu++] = (uint8_t)inst;
    path[pu++] = 0x30;
    path[pu++] = (uint8_t)attr;
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = (uint8_t)(pu / 2);
    memcpy(cip + 2, path, pu);

    session = test_register(s);
    if (session == 0) {
        return -1;
    }
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)(2 + pu));
    boff += 2;
    memcpy(body + boff, cip, 2 + pu);
    boff += 2 + pu;

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, session);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return -1;
    }
    return parse_ucmm(resp, resp_len, status, data, data_len);
}

static int set_attr(eip_stack_t *s, uint16_t class_id, uint16_t inst,
                    uint16_t attr, const uint8_t *value, size_t value_len,
                    uint8_t *status)
{
    uint8_t cip[32];
    uint8_t body[80];
    size_t boff = 0;
    uint8_t req[EIP_ENCAP_HDR_SIZE + 96];
    uint8_t resp[256];
    size_t resp_len = 0;
    size_t cip_len;
    uint8_t dummy[8];
    size_t dummy_len = 0;
    uint32_t session;

    if (value_len > 16) {
        return -1;
    }
    cip[0] = CIP_SVC_SET_ATTR_SINGLE;
    cip[1] = 3;
    cip[2] = 0x20;
    cip[3] = (uint8_t)class_id;
    cip[4] = 0x24;
    cip[5] = (uint8_t)inst;
    cip[6] = 0x30;
    cip[7] = (uint8_t)attr;
    memcpy(cip + 8, value, value_len);
    cip_len = 8 + value_len;

    session = test_register(s);
    if (session == 0) {
        return -1;
    }
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, session);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return -1;
    }
    return parse_ucmm(resp, resp_len, status, dummy, &dummy_len);
}

static eip_stack_t *make_stack(int acd, const char *bind_ip)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.acd_enable = acd;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.vendor_id = 0xABCD;
    if (bind_ip) {
        snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", bind_ip);
    }
    return eip_stack_create(&cfg);
}

static int forward_open(eip_stack_t *s, uint16_t out_sz, uint16_t in_sz)
{
    uint8_t fo[64];
    size_t off = 0;
    uint8_t cip[80];
    size_t cip_len;
    uint8_t body[128];
    size_t boff = 0;
    uint8_t req[EIP_ENCAP_HDR_SIZE + 160];
    uint8_t resp[512];
    size_t resp_len = 0;
    uint8_t status = 0xFF;
    uint8_t data[8];
    size_t data_len = 0;
    uint32_t session;

    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0x1000);
    off += 4;
    eip_wr_le16(fo + off, 0x2210);
    off += 2;
    eip_wr_le16(fo + off, 0x1337);
    off += 2;
    eip_wr_le32(fo + off, 0xCAFEBABE);
    off += 4;
    fo[off++] = 1; /* timeout multiplier */
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, (uint16_t)((2u << 13) | out_sz));
    off += 2;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, (uint16_t)((2u << 13) | in_sz));
    off += 2;
    fo[off++] = 0x01; /* class 1 cyclic */
    fo[off++] = 4;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = 100;
    fo[off++] = 0x2C;
    fo[off++] = 101;
    fo[off++] = 0x2C;
    fo[off++] = 150;

    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);
    cip_len = 6 + off;

    session = test_register(s);
    if (session == 0) {
        return -1;
    }
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, session);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return -1;
    }
    if (parse_ucmm(resp, resp_len, &status, data, &data_len) != 0) {
        return -1;
    }
    return status == 0 ? 0 : -1;
}

static void test_identity_owned_and_acd_state(void)
{
    eip_stack_t *s = make_stack(1, NULL);
    uint8_t data[8];
    size_t n;
    uint8_t st = 0xFF;
    uint16_t status;

    expect(s != NULL, "identity stack");
    if (!s) {
        return;
    }
    expect(forward_open(s, 4, 8) == 0, "exclusive owner forward open");
    expect(eip_stack_class1_up(s) == 1, "class1 up");
    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_IDENTITY, 1, 5, data, &n, &st) == 0 &&
               st == 0,
           "identity status get");
    status = (n >= 2) ? eip_rd_le16(data) : 0;
    expect((status & 0x0001u) != 0, "Identity Status Owned bit 0 after FO");
    expect((status & 0x0004u) == 0,
           "Identity Status does not use Configured bit 2 for ownership");

    expect(eip_stack_acd_conflict(s, 1) == 0, "inject ACD");
    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_IDENTITY, 1, 8, data, &n, &st) == 0 &&
               st == 0 && n >= 1 && data[0] == 3,
           "ACD keeps Identity State Operational (2 is Standby, not a fault)");
    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_IDENTITY, 1, 5, data, &n, &st) == 0 &&
               st == 0 && n >= 2,
           "identity status after ACD");
    status = (n >= 2) ? eip_rd_le16(data) : 0;
    expect((status & 0x0100u) != 0, "ACD sets Status minor recoverable fault");
    eip_stack_destroy(s);
}

static void test_identity_attr17_not_protection_mode(void)
{
    eip_cfg_t cfg;
    eip_stack_t *s;
    uint8_t data[8];
    size_t n = sizeof(data);
    uint8_t st = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.protection_mode = 0x1;
    cfg.input_size = 8;
    cfg.output_size = 4;
    s = eip_stack_create(&cfg);
    expect(s != NULL, "attr17 stack");
    if (!s) {
        return;
    }
    expect(get_attr(s, CIP_CLASS_IDENTITY, 1, 17, data, &n, &st) == 0,
           "identity attr 17 reply");
    expect(st == 0x14, "attr 17 is not Protection Mode (attribute not supported)");
    eip_stack_destroy(s);
}

static void test_qos_numbers(void)
{
    eip_stack_t *s = make_stack(0, NULL);
    static const struct {
        uint16_t attr;
        uint8_t value;
    } want[] = {
        {1, 0},  /* 802.1Q Tag Enable */
        {4, 55}, /* DSCP Urgent */
        {5, 47}, /* DSCP Scheduled */
        {6, 43}, /* DSCP High */
        {7, 31}, /* DSCP Low */
        {8, 27}, /* DSCP Explicit */
    };
    expect(s != NULL, "qos stack");
    if (!s) {
        return;
    }
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        uint8_t data[4];
        size_t n = sizeof(data);
        uint8_t st = 0xFF;
        char msg[64];
        int ok = get_attr(s, CIP_CLASS_QOS, 1, want[i].attr, data, &n, &st) ==
                     0 &&
                 st == 0 && n >= 1 && data[0] == want[i].value;
        snprintf(msg, sizeof(msg), "QoS attr %u == %u", want[i].attr,
                 want[i].value);
        expect(ok, msg);
    }
    eip_stack_destroy(s);
}

static void test_tcpip_and_port(void)
{
    eip_stack_t *s = make_stack(1, "192.0.2.10");
    uint8_t data[64];
    size_t n;
    uint8_t st;
    uint32_t cap;
    uint16_t dlen;

    expect(s != NULL, "tcpip stack");
    if (!s) {
        return;
    }
    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_TCPIP, 1, 2, data, &n, &st) == 0 && st == 0 &&
               n >= 4,
           "TCP/IP capability get");
    cap = (n >= 4) ? eip_rd_le32(data) : 0;
    expect((cap & 0x80u) != 0, "TCP/IP attr 2 ACD capable is bit 7");
    expect((cap & 0x04u) == 0, "TCP/IP attr 2 does not use DHCP bit for ACD");

    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_TCPIP, 1, 10, data, &n, &st) == 0 && st == 0 &&
               n == 1 && data[0] == 1,
           "TCP/IP attr 10 SelectAcd is one BOOL byte");
    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_TCPIP, 1, 11, data, &n, &st) == 0 && st == 0 &&
               n == 35,
           "TCP/IP attr 11 LastConflictDetected is 35 bytes");

    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_TCPIP, 1, 5, data, &n, &st) == 0 && st == 0 &&
               n >= 22,
           "TCP/IP attr 5 Interface Configuration");
    dlen = (n >= 22) ? eip_rd_le16(data + 20) : 0xFFFF;
    expect(n == (size_t)(22 + dlen) || n == (size_t)(22 + dlen + (dlen & 1)),
           "TCP/IP attr 5 domain STRING length");
    expect(n >= 4 && eip_rd_le32(data) == 0xC000020Au,
           "TCP/IP attr 5 IP is the bind address");

    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_TCPIP, 1, 13, data, &n, &st) == 0 && st == 0 &&
               n >= 2 && eip_rd_le16(data) == 120,
           "TCP/IP attr 13 Encapsulation Inactivity Timeout default 120 s");

    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_PORT, 1, 1, data, &n, &st) == 0 && st == 0 &&
               n >= 2 && eip_rd_le16(data) == 4,
           "Port attr 1 type TCP/IP is 4");

    n = sizeof(data);
    expect(get_attr(s, CIP_CLASS_IDENTITY, 0, 1, data, &n, &st) == 0 &&
               st == 0 && n >= 2 && eip_rd_le16(data) >= 1,
           "Identity class attr 1 Revision");

    {
        uint8_t vendor[2];
        eip_wr_le16(vendor, 0x1111);
        st = 0;
        expect(set_attr(s, CIP_CLASS_IDENTITY, 1, 1, vendor, sizeof(vendor),
                        &st) == 0 &&
                   st == 0x0E,
               "Set of read-only Identity Vendor ID is 0x0E");
    }
    eip_stack_destroy(s);
}

static int reserve_port(int type)
{
    int fd = socket(AF_INET, type, 0);
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    if (fd < 0) {
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return (int)ntohs(a.sin_port);
}

static int tcp_exchange(eip_stack_t *s, int fd, const uint8_t *req,
                        size_t req_len, uint8_t *resp, size_t cap,
                        size_t *resp_len)
{
    size_t got = 0;
    size_t need = EIP_ENCAP_HDR_SIZE;
    if (send(fd, req, req_len, 0) != (ssize_t)req_len) {
        return -1;
    }
    for (int spin = 0; spin < 200 && got < need; spin++) {
        ssize_t n;
        eip_stack_poll(s);
        n = recv(fd, resp + got, need - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
            if (got >= EIP_ENCAP_HDR_SIZE) {
                uint16_t body = eip_rd_le16(resp + 2);
                need = (size_t)EIP_ENCAP_HDR_SIZE + body;
                if (need > cap) {
                    return -1;
                }
            }
            continue;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            return -1;
        }
        usleep(1000);
    }
    if (got < need) {
        return -1;
    }
    *resp_len = got;
    return 0;
}

static int recv_tos(int fd, int *tos_out)
{
    uint8_t buf[256];
    char cbuf[64];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    if (recvmsg(fd, &msg, 0) <= 0) {
        return -1;
    }
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS &&
            cmsg->cmsg_len >= CMSG_LEN(1)) {
            *tos_out = *(unsigned char *)CMSG_DATA(cmsg);
            return 0;
        }
    }
    *tos_out = -1;
    return 0;
}

static void test_t2o_dscp_scheduled(void)
{
    int tcp_port = reserve_port(SOCK_STREAM);
    int udp_port = reserve_port(SOCK_DGRAM);
    int rx = -1;
    int tcp = -1;
    uint16_t rx_port = 0;
    eip_cfg_t cfg;
    eip_stack_t *s = NULL;
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    struct timeval tv;
    int yes = 1;
    uint8_t req[256];
    uint8_t resp[512];
    size_t resp_len = 0;
    uint8_t fo[80];
    size_t off = 0;
    uint8_t cip[96];
    size_t cip_len;
    uint8_t body[160];
    size_t boff = 0;
    uint32_t session = 0;
    uint8_t st = 0xFF;
    int tos = -1;
    int got = 0;

    expect(tcp_port > 0 && udp_port > 0, "reserve ports");
    rx = socket(AF_INET, SOCK_DGRAM, 0);
    expect(rx >= 0, "T->O socket");
    if (rx < 0) {
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    expect(bind(rx, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind T->O");
    expect(getsockname(rx, (struct sockaddr *)&addr, &alen) == 0, "T->O port");
    rx_port = ntohs(addr.sin_port);
    setsockopt(rx, IPPROTO_IP, IP_RECVTOS, &yes, sizeof(yes));
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_port;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.security_class = 0;
    s = eip_stack_create(&cfg);
    expect(s != NULL && eip_stack_start(s) == 0, "live adapter");
    if (!s) {
        close(rx);
        return;
    }

    tcp = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)tcp_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    expect(connect(tcp, (struct sockaddr *)&addr, sizeof(addr)) == 0,
           "TCP connect");

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    if (tcp_exchange(s, tcp, req, EIP_ENCAP_HDR_SIZE + 4, resp, sizeof(resp),
                    &resp_len) == 0 &&
        resp_len >= 8) {
        session = eip_rd_le32(resp + 4);
    }
    expect(session != 0, "live session");

    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0x1001);
    off += 4;
    eip_wr_le16(fo + off, 0x2211);
    off += 2;
    eip_wr_le16(fo + off, 0x1337);
    off += 2;
    eip_wr_le32(fo + off, 0xCAFEBABE);
    off += 4;
    fo[off++] = 5;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, (uint16_t)((2u << 13) | 4u));
    off += 2;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, (uint16_t)((2u << 13) | 8u));
    off += 2;
    fo[off++] = 0x01;
    fo[off++] = 4;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = 100;
    fo[off++] = 0x2C;
    fo[off++] = 101;
    fo[off++] = 0x2C;
    fo[off++] = 150;

    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);
    cip_len = 6 + off;

    /* CPF: null address, unconnected data, Sockaddr Info T->O (0x8001). */
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 3);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;
    eip_wr_le16(body + boff, EIP_ITEM_SOCKADDR_TO);
    boff += 2;
    eip_wr_le16(body + boff, 16);
    boff += 2;
    body[boff++] = 0x00;
    body[boff++] = 0x02;
    body[boff++] = (uint8_t)((rx_port >> 8) & 0xff);
    body[boff++] = (uint8_t)(rx_port & 0xff);
    body[boff++] = 127;
    body[boff++] = 0;
    body[boff++] = 0;
    body[boff++] = 1;
    memset(body + boff, 0, 8);
    boff += 8;

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, session);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    expect(tcp_exchange(s, tcp, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                        sizeof(resp), &resp_len) == 0,
           "live forward open exchange");
    {
        size_t ignore = 0;
        expect(parse_ucmm(resp, resp_len, &st, NULL, &ignore) == 0 && st == 0,
               "live forward open success");
    }

    for (int i = 0; i < 20 && !got; i++) {
        eip_stack_poll(s);
        if (recv_tos(rx, &tos) == 0) {
            got = 1;
        }
    }
    expect(got, "T->O packet arrived");
    expect(tos >= 0 && (tos >> 2) == 47, "T->O TOS carries DSCP Scheduled 47");

    if (tcp >= 0) {
        close(tcp);
    }
    close(rx);
    eip_stack_destroy(s);
}

int main(void)
{
    test_identity_owned_and_acd_state();
    test_identity_attr17_not_protection_mode();
    test_qos_numbers();
    test_tcpip_and_port();
    test_t2o_dscp_scheduled();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_10: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_10: ok\n");
    return 0;
}
