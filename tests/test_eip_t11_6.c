/*
 * T11-6: Target-chosen O→T Connection ID, T→O produce destination, and
 * O→T source-IP check.
 *
 * CIP Vol 1: a point-to-point O→T Network Connection ID is chosen by the
 * Target (the request value is meaningless). This stack hands them out
 * from 0x20000001 and skips an ID that is already in use. Point-to-point
 * T→O keeps the Originator's non-zero choice.
 *
 * Vol 2: after Forward Open the Target produces T→O immediately. The
 * destination is Sockaddr Info T→O (CPF 0x8001) when the request carries
 * one, otherwise the Originator IP at UDP 2222. An O→T packet does not
 * rewrite that destination, and a packet whose source IP is not the
 * Originator is discarded.
 *
 * Before the fix this file fails: the request O→T ID is echoed, T→O stays
 * silent until the first O→T, and that packet's source becomes the T→O
 * destination with no source-IP check.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define O2T_PROPOSAL 0x13572468u
#define T2O_CHOICE   0x44332211u
#define T2O_PORT     2222

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
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

static eip_stack_t *make_adapter(int tcp_port, int udp_port)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_port;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.rpi_us = 2000;
    cfg.security_class = 0;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        eip_stack_destroy(s);
        return NULL;
    }
    uint8_t in[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    eip_stack_write_input(s, 0, in, sizeof(in));
    return s;
}

static int tcp_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    if (fd < 0) {
        return -1;
    }
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int udp_bind(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    int yes = 1;
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int udp_port_of(int fd)
{
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    if (getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        return -1;
    }
    return (int)ntohs(a.sin_port);
}

/* Send one encapsulation request and read one reply, pumping the stack. */
static int encap_exchange(eip_stack_t *s, int fd, const uint8_t *req,
                          size_t req_len, uint8_t *resp, size_t cap,
                          size_t *out_len)
{
    size_t got = 0;
    int waited = 0;
    if (send(fd, req, req_len, MSG_NOSIGNAL) != (ssize_t)req_len) {
        return -1;
    }
    while (waited < 1000) {
        eip_stack_poll(s);
        if (got < cap) {
            ssize_t n = recv(fd, resp + got, cap - got, MSG_DONTWAIT);
            if (n > 0) {
                got += (size_t)n;
            }
        }
        if (got >= EIP_ENCAP_HDR_SIZE) {
            uint16_t len = eip_rd_le16(resp + 2);
            if (got >= (size_t)EIP_ENCAP_HDR_SIZE + len) {
                *out_len = (size_t)EIP_ENCAP_HDR_SIZE + len;
                return 0;
            }
        }
        usleep(1000);
        waited++;
    }
    return -1;
}

static uint32_t register_session(eip_stack_t *s, int fd)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[64];
    size_t n = 0;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + EIP_ENCAP_HDR_SIZE, 1);
    if (encap_exchange(s, fd, req, sizeof(req), resp, sizeof(resp), &n) != 0 ||
        n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static size_t build_fo(uint8_t *fo, uint32_t o2t_id, uint32_t t2o_id,
                       uint16_t serial)
{
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, o2t_id);
    off += 4;
    eip_wr_le32(fo + off, t2o_id);
    off += 4;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, 0x1337);
    off += 2;
    eip_wr_le32(fo + off, 0xCAFEBABEu);
    off += 4;
    fo[off++] = 7; /* timeout multiplier: watchdog = 4 * RPI * 2^7 */
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 2000);
    off += 4;
    eip_wr_le16(fo + off, 6); /* O→T = output 4 + sequence 2 */
    off += 2;
    eip_wr_le32(fo + off, 2000);
    off += 4;
    eip_wr_le16(fo + off, 10); /* T→O = input 8 + sequence 2 */
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
    return off;
}

static void wr_sockaddr(uint8_t *p, uint32_t ip_host, uint16_t port)
{
    memset(p, 0, 16);
    p[1] = 2;
    p[2] = (uint8_t)(port >> 8);
    p[3] = (uint8_t)port;
    p[4] = (uint8_t)(ip_host >> 24);
    p[5] = (uint8_t)(ip_host >> 16);
    p[6] = (uint8_t)(ip_host >> 8);
    p[7] = (uint8_t)ip_host;
}

static size_t build_sendrr(uint8_t *req, uint32_t session, const uint8_t *cip,
                           size_t cip_len, const uint8_t *sa)
{
    uint8_t *body = req + EIP_ENCAP_HDR_SIZE;
    size_t boff = 0;
    uint16_t items = sa ? 3 : 2;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, items);
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
    if (sa) {
        eip_wr_le16(body + boff, EIP_ITEM_SOCKADDR_TO);
        boff += 2;
        eip_wr_le16(body + boff, 16);
        boff += 2;
        memcpy(body + boff, sa, 16);
        boff += 16;
    }
    memset(req, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, session);
    return (size_t)EIP_ENCAP_HDR_SIZE + boff;
}

static const uint8_t *cip_in_reply(const uint8_t *resp, size_t n, size_t *cip_len)
{
    size_t off;
    uint16_t items;
    if (n < (size_t)EIP_ENCAP_HDR_SIZE + 8) {
        return NULL;
    }
    off = (size_t)EIP_ENCAP_HDR_SIZE + 6;
    items = eip_rd_le16(resp + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        uint16_t typ;
        uint16_t ln;
        if (off + 4 > n) {
            return NULL;
        }
        typ = eip_rd_le16(resp + off);
        ln = eip_rd_le16(resp + off + 2);
        off += 4;
        if (off + ln > n) {
            return NULL;
        }
        if (typ == EIP_ITEM_UNCONNECTED_DATA) {
            *cip_len = ln;
            return resp + off;
        }
        off += ln;
    }
    return NULL;
}

/* Returns 0 and writes the two connection IDs from a successful Forward Open. */
static int forward_open(eip_stack_t *s, int fd, uint32_t session,
                        uint32_t o2t_proposal, uint32_t t2o_choice,
                        uint16_t serial, const uint8_t *sa, uint32_t *o2t_id,
                        uint32_t *t2o_id)
{
    uint8_t fo[80];
    uint8_t cip[96];
    uint8_t req[256];
    uint8_t resp[512];
    size_t fo_len = build_fo(fo, o2t_proposal, t2o_choice, serial);
    size_t cip_len = 6 + fo_len;
    size_t req_len;
    size_t resp_len = 0;
    size_t reply_len = 0;
    const uint8_t *reply;
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, fo_len);
    req_len = build_sendrr(req, session, cip, cip_len, sa);
    if (encap_exchange(s, fd, req, req_len, resp, sizeof(resp), &resp_len) !=
        0) {
        fprintf(stderr, "FAIL: Forward Open exchange timed out\n");
        g_fail = 1;
        return -1;
    }
    reply = cip_in_reply(resp, resp_len, &reply_len);
    if (!reply || reply_len < 12 || reply[0] != (CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) ||
        reply[2] != 0) {
        fprintf(stderr, "FAIL: Forward Open rejected");
        if (reply) {
            fprintf(stderr, " (");
            for (size_t i = 0; i < reply_len && i < 16; i++) {
                fprintf(stderr, " %02X", reply[i]);
            }
            fprintf(stderr, " )");
        }
        fprintf(stderr, "\n");
        g_fail = 1;
        return -1;
    }
    *o2t_id = eip_rd_le32(reply + 4);
    *t2o_id = eip_rd_le32(reply + 8);
    return 0;
}

/* Close the Exclusive Owner so the next Forward Open is not 0x0106 (T11-5). */
static int forward_close(eip_stack_t *s, int fd, uint32_t session,
                        uint16_t serial)
{
    uint8_t fc[12];
    uint8_t cip[32];
    uint8_t req[128];
    uint8_t resp[256];
    size_t req_len;
    size_t resp_len = 0;
    size_t reply_len = 0;
    const uint8_t *reply;

    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, serial);
    eip_wr_le16(fc + 4, 0x1337);
    eip_wr_le32(fc + 6, 0xCAFEBABEu);
    fc[10] = 0;
    fc[11] = 0;
    cip[0] = CIP_SVC_FORWARD_CLOSE;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fc, sizeof(fc));
    req_len = build_sendrr(req, session, cip, 6 + sizeof(fc), NULL);
    if (encap_exchange(s, fd, req, req_len, resp, sizeof(resp), &resp_len) !=
        0) {
        fprintf(stderr, "FAIL: Forward Close exchange timed out\n");
        g_fail = 1;
        return -1;
    }
    reply = cip_in_reply(resp, resp_len, &reply_len);
    if (!reply || reply_len < 4 ||
        reply[0] != (CIP_SVC_FORWARD_CLOSE | CIP_SVC_REPLY) || reply[2] != 0) {
        fprintf(stderr, "FAIL: Forward Close rejected\n");
        g_fail = 1;
        return -1;
    }
    return 0;
}

static int pump_for(eip_stack_t *s, int ms)
{
    int waited = 0;
    while (waited < ms) {
        eip_stack_poll(s);
        usleep(1000);
        waited++;
    }
    return 0;
}

/* 1 if a Class 1 packet with this connection ID is waiting or arrives. */
static int wait_conn(eip_stack_t *s, int fd, uint32_t conn_id, int ms)
{
    int waited = 0;
    while (waited < ms) {
        uint8_t buf[512];
        ssize_t n;
        eip_stack_poll(s);
        while ((n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
            if (n >= 14 && eip_rd_le16(buf) == 2 &&
                eip_rd_le16(buf + 2) == EIP_ITEM_SEQ_ADDR &&
                eip_rd_le32(buf + 6) == conn_id) {
                return 1;
            }
        }
        usleep(2000);
        waited += 2;
    }
    return 0;
}

static void send_o2t(int fd, int udp_port, uint32_t o2t_id, uint32_t seq,
                     const uint8_t data[4])
{
    uint8_t pkt[32];
    size_t off = 0;
    struct sockaddr_in dst;
    eip_wr_le16(pkt + off, 2);
    off += 2;
    eip_wr_le16(pkt + off, EIP_ITEM_SEQ_ADDR);
    off += 2;
    eip_wr_le16(pkt + off, 8);
    off += 2;
    eip_wr_le32(pkt + off, o2t_id);
    off += 4;
    eip_wr_le32(pkt + off, seq);
    off += 4;
    eip_wr_le16(pkt + off, EIP_ITEM_CONNECTED_DATA);
    off += 2;
    eip_wr_le16(pkt + off, 6);
    off += 2;
    eip_wr_le16(pkt + off, (uint16_t)seq);
    off += 2;
    memcpy(pkt + off, data, 4);
    off += 4;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)udp_port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)sendto(fd, pkt, off, 0, (struct sockaddr *)&dst, sizeof(dst));
}

static int output_is(eip_stack_t *s, const uint8_t data[4])
{
    uint8_t got[4];
    if (eip_stack_read_output(s, 0, got, 4) != 4) {
        return 0;
    }
    return memcmp(got, data, 4) == 0;
}

static void test_o2t_id_chosen_sequential(void)
{
    int tcp = reserve_port();
    int udp = reserve_port();
    eip_stack_t *s = NULL;
    int fd = -1;
    uint32_t session;
    uint32_t o2t1 = 0, t2o1 = 0, o2t2 = 0, t2o2 = 0;
    char msg[128];

    expect(tcp > 0 && udp > 0, "reserve ports");
    s = make_adapter(tcp, udp);
    expect(s != NULL, "adapter start");
    if (!s) {
        return;
    }
    fd = tcp_connect(tcp);
    expect(fd >= 0, "tcp connect");
    if (fd < 0) {
        eip_stack_destroy(s);
        return;
    }
    session = register_session(s, fd);
    expect(session != 0, "register session");
    if (session == 0) {
        close(fd);
        eip_stack_destroy(s);
        return;
    }
    expect(forward_open(s, fd, session, O2T_PROPOSAL, T2O_CHOICE, 0x6101, NULL,
                        &o2t1, &t2o1) == 0,
           "first Forward Open");
    snprintf(msg, sizeof(msg),
             "O->T id %#x echoed request %#x (Target must choose 0x20000001)",
             o2t1, O2T_PROPOSAL);
    expect(o2t1 == 0x20000001u, msg);
    snprintf(msg, sizeof(msg), "T->O id %#x (Originator choice %#x)", t2o1,
             T2O_CHOICE);
    expect(t2o1 == T2O_CHOICE, msg);

    /* A second Exclusive Owner of the same output is 0x0106 (T11-5).
     * The next Target O->T ID is checked after that owner is closed. */
    expect(forward_close(s, fd, session, 0x6101) == 0,
           "close first owner before the next Connection ID");
    expect(forward_open(s, fd, session, O2T_PROPOSAL, T2O_CHOICE ^ 0x01000000u,
                        0x6102, NULL, &o2t2, &t2o2) == 0,
           "second Forward Open");
    snprintf(msg, sizeof(msg),
             "second O->T id %#x (want 0x20000002, distinct from %#x)", o2t2,
             o2t1);
    expect(o2t2 == 0x20000002u && o2t2 != o2t1 && o2t2 != O2T_PROPOSAL, msg);

    close(fd);
    eip_stack_destroy(s);
}

static void test_t2o_sockaddr_without_o2t(void)
{
    int tcp = reserve_port();
    int udp = reserve_port();
    eip_stack_t *s = NULL;
    int fd = -1;
    int io = -1;
    uint8_t sa[16];
    uint32_t session;
    uint32_t o2t = 0, t2o = 0;

    expect(tcp > 0 && udp > 0, "sockaddr test ports");
    s = make_adapter(tcp, udp);
    expect(s != NULL, "sockaddr adapter");
    if (!s) {
        return;
    }
    io = udp_bind("127.0.0.1", 0);
    expect(io >= 0, "sockaddr socket");
    if (io < 0) {
        eip_stack_destroy(s);
        return;
    }
    wr_sockaddr(sa, 0x7f000001u, (uint16_t)udp_port_of(io));
    fd = tcp_connect(tcp);
    expect(fd >= 0, "sockaddr tcp");
    if (fd < 0) {
        close(io);
        eip_stack_destroy(s);
        return;
    }
    session = register_session(s, fd);
    expect(session != 0, "sockaddr session");
    if (session != 0 &&
        forward_open(s, fd, session, 0, T2O_CHOICE, 0x6201, sa, &o2t, &t2o) ==
            0) {
        expect(wait_conn(s, io, t2o, 400),
               "T->O not produced to 0x8001 sockaddr before any O->T");
        (void)o2t;
    }
    close(fd);
    close(io);
    eip_stack_destroy(s);
}

static void test_t2o_originator_2222_without_o2t(void)
{
    int tcp = reserve_port();
    int udp = reserve_port();
    eip_stack_t *s = NULL;
    int fd = -1;
    int io = -1;
    uint32_t session;
    uint32_t o2t = 0, t2o = 0;

    expect(tcp > 0 && udp > 0 && udp != T2O_PORT, "2222 test ports");
    io = udp_bind("127.0.0.1", T2O_PORT);
    expect(io >= 0, "bind originator UDP 2222");
    if (io < 0) {
        fprintf(stderr, "FAIL: UDP 2222 bind: %s\n", strerror(errno));
        g_fail = 1;
        return;
    }
    s = make_adapter(tcp, udp);
    expect(s != NULL, "2222 adapter");
    if (!s) {
        close(io);
        return;
    }
    fd = tcp_connect(tcp);
    expect(fd >= 0, "2222 tcp");
    if (fd < 0) {
        close(io);
        eip_stack_destroy(s);
        return;
    }
    session = register_session(s, fd);
    expect(session != 0, "2222 session");
    if (session != 0 &&
        forward_open(s, fd, session, 0, T2O_CHOICE, 0x6301, NULL, &o2t,
                     &t2o) == 0) {
        expect(wait_conn(s, io, t2o, 400),
               "T->O not produced to Originator:2222 before any O->T");
        (void)o2t;
    }
    close(fd);
    close(io);
    eip_stack_destroy(s);
}

static void test_source_ip_and_no_redirect(void)
{
    int tcp = reserve_port();
    int udp = reserve_port();
    eip_stack_t *s = NULL;
    int fd = -1;
    int legit = -1;
    int spoof = -1;
    uint8_t sa[16];
    uint8_t a[4] = {0xA1, 0xA2, 0xA3, 0xA4};
    uint8_t b[4] = {0xB1, 0xB2, 0xB3, 0xB4};
    uint32_t session;
    uint32_t o2t = 0, t2o = 0;
    int got_legit;

    expect(tcp > 0 && udp > 0, "spoof test ports");
    s = make_adapter(tcp, udp);
    expect(s != NULL, "spoof adapter");
    if (!s) {
        return;
    }
    legit = udp_bind("127.0.0.1", 0);
    spoof = udp_bind("127.0.0.2", 0);
    expect(legit >= 0 && spoof >= 0, "legit and spoof sockets");
    if (legit < 0 || spoof < 0) {
        if (legit >= 0) {
            close(legit);
        }
        if (spoof >= 0) {
            close(spoof);
        }
        eip_stack_destroy(s);
        return;
    }
    wr_sockaddr(sa, 0x7f000001u, (uint16_t)udp_port_of(legit));
    fd = tcp_connect(tcp);
    expect(fd >= 0, "spoof tcp");
    if (fd < 0) {
        close(legit);
        close(spoof);
        eip_stack_destroy(s);
        return;
    }
    session = register_session(s, fd);
    expect(session != 0, "spoof session");
    if (session == 0 ||
        forward_open(s, fd, session, 0, T2O_CHOICE, 0x6401, sa, &o2t, &t2o) !=
            0) {
        close(fd);
        close(legit);
        close(spoof);
        eip_stack_destroy(s);
        return;
    }

    send_o2t(legit, udp, o2t, 1, a);
    pump_for(s, 50);
    expect(output_is(s, a), "Originator O->T did not reach the output image");

    send_o2t(spoof, udp, o2t, 2, b);
    pump_for(s, 50);
    expect(output_is(s, a),
           "O->T from 127.0.0.2 overwrote the output image");

    /* Drop anything already queued, then see who receives the next T→O. */
    {
        uint8_t junk[512];
        while (recv(legit, junk, sizeof(junk), MSG_DONTWAIT) > 0) {
        }
        while (recv(spoof, junk, sizeof(junk), MSG_DONTWAIT) > 0) {
        }
    }
    got_legit = wait_conn(s, legit, t2o, 300);
    expect(got_legit, "T->O stopped arriving at the Forward Open sockaddr");
    expect(!wait_conn(s, spoof, t2o, 80),
           "T->O was redirected to the other IP");

    close(fd);
    close(legit);
    close(spoof);
    eip_stack_destroy(s);
}

int main(void)
{
    test_o2t_id_chosen_sequential();
    test_t2o_sockaddr_without_o2t();
    test_t2o_originator_2222_without_o2t();
    test_source_ip_and_no_redirect();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_6: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_6: ok\n");
    return 0;
}
