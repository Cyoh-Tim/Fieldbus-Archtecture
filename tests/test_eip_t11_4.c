/*
 * T11-4: UDP encapsulation port (ListIdentity browse), ListIdentity
 * socket address / Status / State, and ListInterfaces.
 *
 * RSLinx / Studio 5000 discover a device by broadcasting ListIdentity to
 * UDP 44818. The reply's Socket Address is a big-endian sockaddr_in
 * (family 2, encapsulation port, device IP). Status and State are Identity
 * attr 5 and attr 8. ListInterfaces succeeds with an item list (CIP
 * devices usually have zero non-CIP interfaces).
 *
 * Wire layout is CIP Vol 2 ListIdentity / ListInterfaces as described in
 * docs/protocols/ethernetip.md (5.2.3, 5.2.4). This file does not include
 * the stack's private headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
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

static void encap_req(uint8_t *req, uint16_t cmd)
{
    memset(req, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(req, cmd);
}

static int reserve_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
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

/* Get_Attribute_Single via UCMM. Returns CIP data length, or -1. */
static int get_attr(eip_stack_t *s, uint32_t session, uint16_t attr,
                    uint8_t *out, size_t cap)
{
    uint8_t cip[8];
    uint8_t body[32];
    uint8_t req[EIP_ENCAP_HDR_SIZE + sizeof(body)];
    uint8_t resp[512];
    size_t boff = 0;
    size_t resp_len = 0;
    const uint8_t *p;
    size_t bl;
    uint16_t items;
    size_t off;

    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = 3;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_IDENTITY;
    cip[4] = 0x24;
    cip[5] = 1;
    cip[6] = 0x30;
    cip[7] = (uint8_t)attr;

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
    eip_wr_le16(body + boff, sizeof(cip));
    boff += 2;
    memcpy(body + boff, cip, sizeof(cip));
    boff += sizeof(cip);

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, session);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0 ||
        resp_len < EIP_ENCAP_HDR_SIZE + 8) {
        return -1;
    }
    p = resp + EIP_ENCAP_HDR_SIZE;
    bl = resp_len - EIP_ENCAP_HDR_SIZE;
    off = 6;
    if (off + 2 > bl) {
        return -1;
    }
    items = eip_rd_le16(p + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        uint16_t type;
        uint16_t length;
        if (off + 4 > bl) {
            return -1;
        }
        type = eip_rd_le16(p + off);
        length = eip_rd_le16(p + off + 2);
        off += 4;
        if (off + length > bl) {
            return -1;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA && length >= 4 &&
            p[off] == (uint8_t)(CIP_SVC_GET_ATTR_SINGLE | CIP_SVC_REPLY) &&
            p[off + 2] == 0) {
            size_t data_at = 4u + (size_t)p[off + 3] * 2u;
            if (data_at > length) {
                return -1;
            }
            size_t n = length - data_at;
            if (n > cap) {
                n = cap;
            }
            memcpy(out, p + off + data_at, n);
            return (int)n;
        }
        off += length;
    }
    return -1;
}

/*
 * ListIdentity item body after the 6-byte CPF item header:
 * version(2) sockaddr(16) vendor(2) type(2) code(2) rev(2) status(2)
 * serial(4) name(1+n) state(1).
 */
static int parse_list_identity(const uint8_t *resp, size_t n, uint16_t *family,
                               uint16_t *port, uint32_t *ip, uint16_t *status,
                               uint8_t *state, char *name, size_t name_cap)
{
    const uint8_t *b;
    uint16_t ilen;
    uint8_t nlen;
    if (!resp || n < EIP_ENCAP_HDR_SIZE + 8 ||
        eip_rd_le16(resp) != EIP_CMD_LISTIDENTITY ||
        eip_rd_le32(resp + 8) != 0) {
        return -1;
    }
    if (eip_rd_le16(resp + 24) != 1 || eip_rd_le16(resp + 26) != 0x000C) {
        return -1;
    }
    ilen = eip_rd_le16(resp + 28);
    if ((size_t)EIP_ENCAP_HDR_SIZE + 6u + ilen > n || ilen < 33) {
        return -1;
    }
    b = resp + EIP_ENCAP_HDR_SIZE + 6;
    if (eip_rd_le16(b) != 1) {
        return -1;
    }
    *family = (uint16_t)(((uint16_t)b[2] << 8) | b[3]);
    *port = (uint16_t)(((uint16_t)b[4] << 8) | b[5]);
    *ip = ((uint32_t)b[6] << 24) | ((uint32_t)b[7] << 16) |
          ((uint32_t)b[8] << 8) | (uint32_t)b[9];
    *status = eip_rd_le16(b + 26);
    nlen = b[32];
    if ((size_t)33u + nlen + 1u > ilen) {
        return -1;
    }
    if (name && name_cap > 0) {
        size_t c = nlen;
        if (c >= name_cap) {
            c = name_cap - 1;
        }
        memcpy(name, b + 33, c);
        name[c] = '\0';
    }
    *state = b[33 + nlen];
    return 0;
}

static eip_stack_t *make_mock(const char *ip, int acd)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    if (ip) {
        snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", ip);
    }
    cfg.tcp_port = 44818;
    cfg.udp_io_port = 2222;
    cfg.vendor_id = 0xABCD;
    cfg.device_type = 12;
    cfg.product_code = 1;
    cfg.major_rev = 1;
    cfg.minor_rev = 1;
    cfg.serial_number = 0x12345678u;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "FieldbusOracle");
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.security_class = 0;
    cfg.lldp_enable = 0;
    cfg.acd_enable = acd;
    return eip_stack_create(&cfg);
}

static void test_list_identity_sockaddr_status_state(void)
{
    eip_stack_t *s = make_mock("192.168.0.10", 1);
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[256];
    uint8_t attr[8];
    size_t n = 0;
    uint16_t family = 0, port = 0, id_status = 0xFFFF;
    uint32_t ip = 0;
    uint8_t state = 0xAA;
    char name[40];
    uint32_t session;

    expect(s != NULL, "mock stack");
    if (!s) {
        return;
    }
    encap_req(req, EIP_CMD_LISTIDENTITY);
    expect(eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                  &n) == 0,
           "ListIdentity");
    memset(name, 0, sizeof(name));
    expect(parse_list_identity(resp, n, &family, &port, &ip, &id_status, &state,
                               name, sizeof(name)) == 0,
           "parse ListIdentity");
    expect(family == 2, "sin_family 2");
    expect(port == 44818, "sin_port encapsulation port");
    expect(ip == 0xC0A8000Au, "sin_addr 192.168.0.10 big-endian");
    expect(strcmp(name, "FieldbusOracle") == 0, "product name");

    session = test_register(s);
    expect(session != 0, "session");
    expect(get_attr(s, session, 5, attr, sizeof(attr)) == 2, "Identity status");
    expect(get_attr(s, session, 8, attr + 4, 1) == 1, "Identity state");
    expect(id_status == eip_rd_le16(attr), "ListIdentity status == attr 5");
    expect(state == attr[4], "ListIdentity state == attr 8");

    expect(eip_stack_acd_conflict(s, 1) == 0, "inject ACD");
    n = 0;
    encap_req(req, EIP_CMD_LISTIDENTITY);
    expect(eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                  &n) == 0,
           "ListIdentity after ACD");
    expect(parse_list_identity(resp, n, &family, &port, &ip, &id_status, &state,
                               name, sizeof(name)) == 0,
           "parse ListIdentity after ACD");
    expect(get_attr(s, session, 5, attr, sizeof(attr)) == 2,
           "Identity status after ACD");
    expect(get_attr(s, session, 8, attr + 4, 1) == 1, "Identity state after ACD");
    expect(id_status == eip_rd_le16(attr) && id_status != 0,
           "ACD ListIdentity status tracks attr 5 and is not stuck at 0");
    expect(state == attr[4] && state != 0xFF,
           "ACD ListIdentity state tracks attr 8 and is not stuck at 0xFF");
    eip_stack_destroy(s);
}

static void test_list_interfaces(void)
{
    eip_stack_t *s = make_mock("127.0.0.1", 0);
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[64];
    size_t n = 0;
    uint16_t count;
    size_t off;

    expect(s != NULL, "listinterfaces stack");
    if (!s) {
        return;
    }
    encap_req(req, EIP_CMD_LISTINTERFACES);
    expect(eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                  &n) == 0,
           "ListInterfaces");
    expect(n >= EIP_ENCAP_HDR_SIZE + 2, "ListInterfaces body");
    expect(eip_rd_le16(resp) == EIP_CMD_LISTINTERFACES, "ListInterfaces cmd");
    expect(eip_rd_le32(resp + 8) == 0, "ListInterfaces status 0");
    expect(eip_rd_le16(resp + 2) >= 2, "ListInterfaces length");
    count = eip_rd_le16(resp + 24);
    off = 26;
    for (uint16_t i = 0; i < count; i++) {
        uint16_t ln;
        expect(off + 4 <= n, "ListInterfaces item header");
        if (off + 4 > n) {
            break;
        }
        ln = eip_rd_le16(resp + off + 2);
        off += 4u + ln;
    }
    expect(off == (size_t)EIP_ENCAP_HDR_SIZE + eip_rd_le16(resp + 2),
           "ListInterfaces items fill the body");
    expect(count == 0, "CIP device lists no non-CIP interfaces");
    eip_stack_destroy(s);
}

static eip_stack_t *start_live(const char *ip, int tcp_port, int udp_port)
{
    eip_cfg_t cfg;
    eip_stack_t *s;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 0;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "%s", ip);
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_port;
    cfg.vendor_id = 0xABCD;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.security_class = 0;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "FieldbusOracle");
    s = eip_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    if (eip_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: live start %s tcp=%d udp=%d\n", ip, tcp_port,
                udp_port);
        g_fail = 1;
        eip_stack_destroy(s);
        return NULL;
    }
    return s;
}

/* 0 = reply, -1 = no reply, -2 = could not send. */
static int udp_exchange(eip_stack_t *s, int fd, int tcp_port, uint16_t cmd,
                        const char *dst_ip, uint8_t *resp, size_t cap,
                        size_t *out_n)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    struct sockaddr_in dst;
    encap_req(req, cmd);
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)tcp_port);
    if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) {
        return -2;
    }
    if (sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&dst, sizeof(dst)) !=
        (ssize_t)sizeof(req)) {
        return -2;
    }
    for (int i = 0; i < 200; i++) {
        ssize_t n;
        eip_stack_poll(s);
        n = recv(fd, resp, cap, MSG_DONTWAIT);
        if (n > 0) {
            *out_n = (size_t)n;
            return 0;
        }
        usleep(2000);
    }
    return -1;
}

static void test_udp_44818_list_identity(void)
{
    int tcp_port = reserve_port();
    int udp_port = reserve_port();
    int fd;
    eip_stack_t *s;
    uint8_t resp[512];
    size_t n = 0;
    uint16_t family = 0, port = 0, status = 0;
    uint32_t ip = 0;
    uint8_t state = 0;
    char name[40];
    struct sockaddr_in local;

    expect(tcp_port > 0 && udp_port > 0 && tcp_port != udp_port, "free ports");
    s = start_live("127.0.0.1", tcp_port, udp_port);
    if (!s) {
        return;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    expect(fd >= 0, "udp client");
    if (fd < 0) {
        eip_stack_destroy(s);
        return;
    }
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    expect(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0,
           "udp client bind");

    if (udp_exchange(s, fd, tcp_port, EIP_CMD_LISTIDENTITY, "127.0.0.1", resp,
                     sizeof(resp), &n) != 0) {
        fprintf(stderr,
                "FAIL: UDP %d ListIdentity 무응답 (encapsulation 수신 소켓 없음)\n",
                tcp_port);
        g_fail = 1;
    } else {
        memset(name, 0, sizeof(name));
        expect(parse_list_identity(resp, n, &family, &port, &ip, &status,
                                   &state, name, sizeof(name)) == 0,
               "UDP ListIdentity parse");
        expect(strcmp(name, "FieldbusOracle") == 0, "UDP product name");
        expect(family == 2 && port == (uint16_t)tcp_port && ip == 0x7F000001u,
               "UDP ListIdentity sockaddr 127.0.0.1:tcp");
        expect(state != 0xFF, "UDP ListIdentity state is not 0xFF");
    }

    n = 0;
    if (udp_exchange(s, fd, tcp_port, EIP_CMD_LISTSERVICES, "127.0.0.1", resp,
                     sizeof(resp), &n) != 0) {
        fprintf(stderr, "FAIL: UDP ListServices 무응답\n");
        g_fail = 1;
    } else {
        expect(n >= 24 && eip_rd_le16(resp) == EIP_CMD_LISTSERVICES &&
                   eip_rd_le32(resp + 8) == 0,
               "UDP ListServices status 0");
    }

    n = 0;
    if (udp_exchange(s, fd, tcp_port, EIP_CMD_LISTINTERFACES, "127.0.0.1", resp,
                     sizeof(resp), &n) != 0) {
        fprintf(stderr, "FAIL: UDP ListInterfaces 무응답\n");
        g_fail = 1;
    } else {
        expect(n >= 26 && eip_rd_le16(resp) == EIP_CMD_LISTINTERFACES &&
                   eip_rd_le32(resp + 8) == 0 && eip_rd_le16(resp + 24) == 0,
               "UDP ListInterfaces status 0 item count 0");
    }

    n = 0;
    if (udp_exchange(s, fd, tcp_port, EIP_CMD_REGISTERSESSION, "127.0.0.1",
                     resp, sizeof(resp), &n) == 0) {
        fprintf(stderr,
                "FAIL: UDP RegisterSession got a reply (sessions are TCP)\n");
        g_fail = 1;
    }

    close(fd);
    eip_stack_destroy(s);
}

static void test_wildcard_bind_reports_arrival_address(void)
{
    int tcp_port = reserve_port();
    int udp_port = reserve_port();
    int fd;
    eip_stack_t *s;
    uint8_t resp[512];
    size_t n = 0;
    uint16_t family = 0, port = 0, status = 0;
    uint32_t ip = 1;
    uint8_t state = 0;
    char name[40];
    struct sockaddr_in local;
    int bcast = 1;

    expect(tcp_port > 0 && udp_port > 0 && tcp_port != udp_port, "wild ports");
    s = start_live("0.0.0.0", tcp_port, udp_port);
    if (!s) {
        return;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    expect(fd >= 0, "wild udp client");
    if (fd < 0) {
        eip_stack_destroy(s);
        return;
    }
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    expect(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0,
           "wild client bind");

    if (udp_exchange(s, fd, tcp_port, EIP_CMD_LISTIDENTITY, "127.0.0.1", resp,
                     sizeof(resp), &n) != 0) {
        fprintf(stderr, "FAIL: wildcard UDP ListIdentity 무응답\n");
        g_fail = 1;
    } else {
        memset(name, 0, sizeof(name));
        expect(parse_list_identity(resp, n, &family, &port, &ip, &status,
                                   &state, name, sizeof(name)) == 0,
               "wildcard ListIdentity parse");
        expect(family == 2 && port == (uint16_t)tcp_port && ip == 0x7F000001u,
               "wildcard bind reports 127.0.0.1, not 0.0.0.0");
    }

    /* Limited broadcast is the RSLinx browse path. A send refusal is the
     * environment; a sent request with no reply is the missing socket. */
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast)) != 0) {
        fprintf(stderr, "note: SO_BROADCAST unavailable\n");
    } else {
        int br = udp_exchange(s, fd, tcp_port, EIP_CMD_LISTIDENTITY,
                              "255.255.255.255", resp, sizeof(resp), &n);
        if (br == -2) {
            fprintf(stderr,
                    "note: broadcast ListIdentity send refused in this environment\n");
        } else if (br != 0) {
            fprintf(stderr, "FAIL: broadcast UDP ListIdentity 무응답\n");
            g_fail = 1;
        } else {
            memset(name, 0, sizeof(name));
            expect(parse_list_identity(resp, n, &family, &port, &ip, &status,
                                       &state, name, sizeof(name)) == 0,
                   "broadcast ListIdentity parse");
            expect(family == 2 && port == (uint16_t)tcp_port && ip != 0 &&
                       ip != 0xFFFFFFFFu,
                   "broadcast ListIdentity sockaddr is a device address");
            expect(strcmp(name, "FieldbusOracle") == 0,
                   "broadcast product name");
        }
    }

    close(fd);
    eip_stack_destroy(s);
}

int main(void)
{
    test_list_identity_sockaddr_status_state();
    test_list_interfaces();
    test_udp_44818_list_identity();
    test_wildcard_bind_reports_arrival_address();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_4: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_4: ok\n");
    return 0;
}
