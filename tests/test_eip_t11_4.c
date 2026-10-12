/*
 * T11-4: UDP 44818 ListIdentity, sockaddr/Status/State, ListInterfaces.
 *
 * RSLinx / Studio 5000 browse sends ListIdentity on UDP encapsulation
 * (default 44818). The adapter must bind that port, reply, fill Socket
 * Address in network byte order, copy Identity Status/State, and accept
 * ListInterfaces with status 0 (typically zero CPF items).
 *
 * Before the fix:
 *   - no UDP encapsulation socket → recvfrom timeout
 *   - sockaddr 16 bytes are 0, Status 0, State 0xFF
 *   - ListInterfaces encapsulation status 0x0001
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

static uint32_t test_register(eip_stack_t *s)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t n = 0;
    if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp), &n) !=
        0) {
        return 0;
    }
    if (n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static int sendrr_get(eip_stack_t *s, uint16_t attr, uint8_t *cip_data,
                      size_t *cip_data_len)
{
    uint8_t cip[8];
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = 3;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_IDENTITY;
    cip[4] = 0x24;
    cip[5] = 1;
    cip[6] = 0x30;
    cip[7] = (uint8_t)attr;

    uint8_t body[64];
    size_t boff = 0;
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
    eip_wr_le16(body + boff, 8);
    boff += 2;
    memcpy(body + boff, cip, 8);
    boff += 8;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 64];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, test_register(s));
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    uint8_t resp[256];
    size_t resp_len = 0;
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return -1;
    }
    if (resp_len < EIP_ENCAP_HDR_SIZE + 8) {
        return -1;
    }
    const uint8_t *b = resp + EIP_ENCAP_HDR_SIZE;
    size_t bl = resp_len - EIP_ENCAP_HDR_SIZE;
    size_t off = 6;
    uint16_t items = eip_rd_le16(b + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > bl) {
            return -1;
        }
        uint16_t type = eip_rd_le16(b + off);
        uint16_t length = eip_rd_le16(b + off + 2);
        off += 4;
        if (off + length > bl) {
            return -1;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA && length >= 4) {
            if (b[off + 2] != 0) {
                return -2;
            }
            size_t n = length - 4;
            if (n > *cip_data_len) {
                n = *cip_data_len;
            }
            memcpy(cip_data, b + off + 4, n);
            *cip_data_len = n;
            return 0;
        }
        off += length;
    }
    return -1;
}

static int list_identity(eip_stack_t *s, uint8_t *resp, size_t cap,
                         size_t *out_len)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTIDENTITY);
    *out_len = 0;
    return eip_stack_handle_encap(s, req, sizeof(req), resp, cap, out_len);
}

/* CPF Identity item starts at payload+0. Socket Address is 16 bytes BE. */
static int parse_list_identity(const uint8_t *resp, size_t n, uint16_t *family,
                               uint16_t *port, uint32_t *addr_be,
                               uint16_t *status, uint8_t *state)
{
    if (n < EIP_ENCAP_HDR_SIZE + 8) {
        return -1;
    }
    if (eip_rd_le16(resp + 0) != EIP_CMD_LISTIDENTITY) {
        return -1;
    }
    if (eip_rd_le32(resp + 8) != 0) {
        return -1;
    }
    const uint8_t *p = resp + EIP_ENCAP_HDR_SIZE;
    size_t bl = n - EIP_ENCAP_HDR_SIZE;
    if (bl < 8 || eip_rd_le16(p) < 1 || eip_rd_le16(p + 2) != 0x000C) {
        return -1;
    }
    uint16_t item_len = eip_rd_le16(p + 4);
    if ((size_t)6 + item_len > bl || item_len < 33) {
        return -1;
    }
    const uint8_t *id = p + 6;
    /* Identity item: version(2) + sockaddr(16 BE) + vendor... */
    const uint8_t *sa = id + 2;
    *family = (uint16_t)(((uint16_t)sa[0] << 8) | sa[1]);
    *port = (uint16_t)(((uint16_t)sa[2] << 8) | sa[3]);
    *addr_be = ((uint32_t)sa[4] << 24) | ((uint32_t)sa[5] << 16) |
               ((uint32_t)sa[6] << 8) | (uint32_t)sa[7];
    const uint8_t *after_sa = sa + 16;
    *status = eip_rd_le16(after_sa + 8);
    uint8_t name_len = after_sa[14];
    size_t state_at = (size_t)(after_sa - p) + 15 + name_len;
    if (state_at >= bl) {
        return -1;
    }
    *state = p[state_at];
    return 0;
}

static eip_stack_t *make_mock(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = 44818;
    cfg.udp_io_port = 2222;
    cfg.vendor_id = 0xABCD;
    cfg.device_type = 0x0C;
    cfg.product_code = 1;
    cfg.major_rev = 1;
    cfg.minor_rev = 0;
    cfg.serial_number = 0x12345678u;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "FieldbusSensor");
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        eip_stack_destroy(s);
        return NULL;
    }
    return s;
}

static void test_list_identity_sockaddr_status_state(void)
{
    eip_stack_t *s = make_mock();
    expect(s != NULL, "mock stack");
    if (!s) {
        return;
    }

    uint8_t resp[256];
    size_t n = 0;
    expect(list_identity(s, resp, sizeof(resp), &n) == 0, "ListIdentity rc");
    expect(n > EIP_ENCAP_HDR_SIZE, "ListIdentity body");

    uint16_t family = 0, port = 0, status = 0;
    uint32_t addr_be = 0;
    uint8_t state = 0;
    expect(parse_list_identity(resp, n, &family, &port, &addr_be, &status,
                               &state) == 0,
           "parse ListIdentity");
    expect(family == 2, "sin_family AF_INET (2, big-endian)");
    expect(port == 44818, "sin_port encapsulation 44818");
    expect(addr_be == 0x7F000001u, "sin_addr 127.0.0.1");

    uint8_t attr[8];
    size_t alen = sizeof(attr);
    expect(sendrr_get(s, 5, attr, &alen) == 0, "Identity attr 5");
    uint16_t id_status = (alen >= 2) ? eip_rd_le16(attr) : 0xFFFFu;
    alen = sizeof(attr);
    expect(sendrr_get(s, 8, attr, &alen) == 0, "Identity attr 8");
    uint8_t id_state = (alen >= 1) ? attr[0] : 0xFE;
    expect(status == id_status, "ListIdentity Status == Identity attr 5");
    expect(state == id_state, "ListIdentity State == Identity attr 8");
    expect(state != 0xFF, "State is not the 0xFF stub");

    eip_stack_destroy(s);
}

static void test_list_identity_status_state_follow_acd(void)
{
    eip_stack_t *s = make_mock();
    expect(s != NULL, "acd mock");
    if (!s) {
        return;
    }
    expect(eip_stack_acd_conflict(s, 1) == 0, "inject ACD");

    uint8_t resp[256];
    size_t n = 0;
    expect(list_identity(s, resp, sizeof(resp), &n) == 0, "ListIdentity ACD");
    uint16_t family = 0, port = 0, status = 0;
    uint32_t addr_be = 0;
    uint8_t state = 0;
    expect(parse_list_identity(resp, n, &family, &port, &addr_be, &status,
                               &state) == 0,
           "parse ListIdentity ACD");

    uint8_t attr[8];
    size_t alen = sizeof(attr);
    expect(sendrr_get(s, 5, attr, &alen) == 0, "attr 5 after ACD");
    uint16_t id_status = (alen >= 2) ? eip_rd_le16(attr) : 0xFFFFu;
    alen = sizeof(attr);
    expect(sendrr_get(s, 8, attr, &alen) == 0, "attr 8 after ACD");
    uint8_t id_state = (alen >= 1) ? attr[0] : 0xFE;
    expect(status == id_status, "Status tracks Identity after ACD");
    expect(state == id_state, "State tracks Identity after ACD");

    eip_stack_destroy(s);
}

static void test_list_interfaces_zero_items(void)
{
    eip_stack_t *s = make_mock();
    expect(s != NULL, "interfaces mock");
    if (!s) {
        return;
    }
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTINTERFACES);
    uint8_t resp[128];
    size_t n = 0;
    expect(eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                  &n) == 0,
           "ListInterfaces rc");
    expect(n >= EIP_ENCAP_HDR_SIZE + 2, "ListInterfaces has item count");
    expect(eip_rd_le16(resp) == EIP_CMD_LISTINTERFACES, "cmd 0x0064");
    uint32_t status = eip_rd_le32(resp + 8);
    expect(status == 0, "ListInterfaces encap status 0 (not 1)");
    uint16_t length = eip_rd_le16(resp + 2);
    expect((size_t)EIP_ENCAP_HDR_SIZE + length == n, "length matches body");
    uint16_t count = eip_rd_le16(resp + EIP_ENCAP_HDR_SIZE);
    size_t off = EIP_ENCAP_HDR_SIZE + 2;
    for (uint16_t i = 0; i < count; i++) {
        if (off + 4 > n) {
            expect(0, "ListInterfaces CPF overrun");
            break;
        }
        uint16_t ln = eip_rd_le16(resp + off + 2);
        off += 4 + ln;
    }
    expect(off == EIP_ENCAP_HDR_SIZE + length, "ListInterfaces CPF end");
    eip_stack_destroy(s);
}

static int ephemeral_port(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t alen = sizeof(a);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return -1;
    }
    int port = ntohs(a.sin_port);
    close(fd);
    return port;
}

static void test_list_identity_over_udp(void)
{
    int tcp_port = ephemeral_port();
    int udp_io = ephemeral_port();
    if (tcp_port <= 0 || udp_io <= 0 || tcp_port == udp_io) {
        tcp_port = 16218;
        udp_io = 16219;
    }

    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 0;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_io;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "UdpBrowse");
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "udp stack create");
    if (!s) {
        return;
    }
    if (eip_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: udp stack start (ports %d/%d busy?)\n", tcp_port,
                udp_io);
        g_fail = 1;
        eip_stack_destroy(s);
        return;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    expect(fd >= 0, "client udp socket");
    if (fd < 0) {
        eip_stack_destroy(s);
        return;
    }
    struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in self;
    memset(&self, 0, sizeof(self));
    self.sin_family = AF_INET;
    self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    self.sin_port = 0;
    expect(bind(fd, (struct sockaddr *)&self, sizeof(self)) == 0,
           "client bind");

    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTIDENTITY);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)tcp_port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    expect(sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&dst,
                  sizeof(dst)) == (ssize_t)sizeof(req),
           "UDP ListIdentity send");

    uint8_t resp[256];
    ssize_t got = -1;
    for (int i = 0; i < 40; i++) {
        eip_stack_poll(s);
        got = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
        if (got > 0) {
            break;
        }
        usleep(5000);
    }
    if (got < (ssize_t)EIP_ENCAP_HDR_SIZE) {
        fprintf(stderr,
                "FAIL: UDP ListIdentity no reply on 127.0.0.1:%d (n=%zd errno=%d)\n",
                tcp_port, got, errno);
        g_fail = 1;
    } else {
        expect(eip_rd_le16(resp) == EIP_CMD_LISTIDENTITY, "UDP cmd 0x0063");
        expect(eip_rd_le32(resp + 8) == 0, "UDP encap status 0");
        int found = 0;
        for (ssize_t i = 0; i + 9 <= got; i++) {
            if (memcmp(resp + i, "UdpBrowse", 9) == 0) {
                found = 1;
                break;
            }
        }
        expect(found, "product name in UDP ListIdentity");
        uint16_t family = 0, port = 0, status = 0;
        uint32_t addr_be = 0;
        uint8_t state = 0;
        expect(parse_list_identity(resp, (size_t)got, &family, &port, &addr_be,
                                   &status, &state) == 0,
               "parse UDP ListIdentity");
        expect(family == 2, "UDP sin_family 2");
        expect(port == (uint16_t)tcp_port, "UDP sin_port = encap port");
        expect(addr_be == 0x7F000001u, "UDP sin_addr 127.0.0.1");
    }
    close(fd);
    eip_stack_destroy(s);
}

int main(void)
{
    test_list_identity_sockaddr_status_state();
    test_list_identity_status_state_follow_acd();
    test_list_interfaces_zero_items();
    test_list_identity_over_udp();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_4: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_4: ok\n");
    return 0;
}
