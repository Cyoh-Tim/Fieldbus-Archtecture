/*
 * T11-9: Encapsulation deviations.
 *
 * NOP has no reply. UnRegisterSession for a session this connection owns
 * has no reply and closes that TCP connection. A missing or foreign
 * session handle is status 0x0064: nothing is deleted and this TCP stays
 * open. RegisterSession protocol version != 1 and option flags != 0 are
 * both status 0x0069, with body version 1, option flags 0, and session
 * handle 0. A non-zero encapsulation header Options field is discarded.
 * SendUnitData on a registered session has no encapsulation reply. An
 * invalid session handle is status 0x0064. ListInterfaces is status 0
 * and an empty item list.
 *
 * Wire values follow docs/protocols/ethernetip.md 5.1–5.2 and the T11-9 row
 * of docs/reports/structure_handoff_20260930.md. This file does not include
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

static void expect_u32(uint32_t got, uint32_t want, const char *msg)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s (got %#x want %#x)\n", msg, got, want);
        g_fail = 1;
    }
}

static eip_stack_t *make_stack(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 4;
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        eip_stack_destroy(s);
        return NULL;
    }
    return s;
}

/* Zero the whole request, including command data past the 24-byte header. */
static void fill_hdr(uint8_t *req, size_t req_len, uint16_t cmd, uint16_t length,
                     uint32_t session)
{
    memset(req, 0, req_len);
    eip_wr_le16(req + 0, cmd);
    eip_wr_le16(req + 2, length);
    eip_wr_le32(req + 4, session);
    memcpy(req + 12, "ctx-t119", 8);
}

static int exchange(eip_stack_t *s, uint32_t owner, const uint8_t *req,
                    size_t req_len, uint8_t *resp, size_t cap, size_t *out_n)
{
    size_t n = 0;
    int rc = eip_stack_handle_encap_owned(s, owner, req, req_len, resp, cap, &n);
    *out_n = n;
    return rc;
}

static uint32_t register_ok(eip_stack_t *s, uint32_t owner)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[64];
    size_t n = 0;
    fill_hdr(req, sizeof(req), EIP_CMD_REGISTERSESSION, 4, 0);
    eip_wr_le16(req + 24, 1);
    eip_wr_le16(req + 26, 0);
    if (exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n) != 0 ||
        n < 28) {
        return 0;
    }
    if (eip_rd_le32(resp + 8) != 0) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static void test_nop_has_no_reply(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[64];
    size_t n = 99;
    expect(s != NULL, "nop stack");
    if (!s) {
        return;
    }
    fill_hdr(req, sizeof(req), EIP_CMD_NOP, 4, 0);
    memset(req + 24, 0xAB, 4);
    memset(resp, 0xCC, sizeof(resp));
    int rc = exchange(s, 0xA0000001u, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "NOP returns success with no reply");
    expect(n == 0, "NOP encapsulation reply length is 0");
    eip_stack_destroy(s);
}

static void test_unregister_owned_closes_without_reply(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[64];
    size_t n = 99;
    uint32_t owner = 0xA0000001u;
    expect(s != NULL, "unregister stack");
    if (!s) {
        return;
    }
    uint32_t h = register_ok(s, owner);
    expect(h != 0, "register before unregister");
    expect(eip_stack_session_count(s) == 1, "one session before unregister");
    fill_hdr(req, sizeof(req), EIP_CMD_UNREGISTERSESSION, 0, h);
    memset(resp, 0xCC, sizeof(resp));
    int rc = exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == -ECONNRESET, "Unregister asks the caller to close TCP");
    expect(n == 0, "Unregister encapsulation reply length is 0");
    expect(eip_stack_session_count(s) == 0, "owned session dropped");
    eip_stack_destroy(s);
}

static void test_unregister_foreign_keeps_session(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[64];
    size_t n = 99;
    expect(s != NULL, "foreign unregister stack");
    if (!s) {
        return;
    }
    uint32_t ha = register_ok(s, 0xA0000001u);
    uint32_t hb = register_ok(s, 0xA0000002u);
    expect(ha != 0 && hb != 0 && ha != hb, "two sessions");
    fill_hdr(req, sizeof(req), EIP_CMD_UNREGISTERSESSION, 0, ha);
    memset(resp, 0xCC, sizeof(resp));
    int rc = exchange(s, 0xA0000002u, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "foreign Unregister leaves the sender TCP open");
    expect(n == EIP_ENCAP_HDR_SIZE, "foreign Unregister encapsulation reply");
    expect_u32(eip_rd_le32(resp + 8), 0x0064, "foreign Unregister status 0x0064");
    expect(eip_stack_session_count(s) == 2, "unowned session is not dropped");

    fill_hdr(req, sizeof(req), EIP_CMD_UNREGISTERSESSION, 0, 0);
    n = 99;
    memset(resp, 0xCC, sizeof(resp));
    rc = exchange(s, 0xA0000002u, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "missing Unregister handle leaves TCP open");
    expect(n == EIP_ENCAP_HDR_SIZE, "missing Unregister handle reply");
    expect_u32(eip_rd_le32(resp + 8), 0x0064, "missing Unregister handle 0x0064");
    expect(eip_stack_session_count(s) == 2, "missing handle drops nothing");
    expect(register_ok(s, 0xA0000001u) == ha, "owner A session remains");
    expect(register_ok(s, 0xA0000002u) == hb, "owner B session remains");
    eip_stack_destroy(s);
}

static void test_register_version_and_options(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[64];
    size_t n = 0;
    uint32_t owner = 0xA0000001u;
    expect(s != NULL, "register checks stack");
    if (!s) {
        return;
    }

    fill_hdr(req, sizeof(req), EIP_CMD_REGISTERSESSION, 4, 0);
    eip_wr_le16(req + 24, 2);
    eip_wr_le16(req + 26, 0);
    expect(exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n) == 0,
           "bad version encap rc");
    expect(n == EIP_ENCAP_HDR_SIZE + 4, "bad version reply has 4 data bytes");
    expect_u32(eip_rd_le32(resp + 8), 0x0069, "version != 1 status");
    expect_u32(eip_rd_le32(resp + 4), 0, "bad version does not issue a handle");
    expect(eip_rd_le16(resp + 24) == 1, "rejected register reports version 1");
    expect(eip_rd_le16(resp + 26) == 0, "rejected register option flags are 0");
    expect(eip_stack_session_count(s) == 0, "bad version allocates no session");

    fill_hdr(req, sizeof(req), EIP_CMD_REGISTERSESSION, 4, 0);
    eip_wr_le16(req + 24, 1);
    eip_wr_le16(req + 26, 1);
    n = 0;
    expect(exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n) == 0,
           "bad options encap rc");
    expect(n == EIP_ENCAP_HDR_SIZE + 4, "bad options reply has 4 data bytes");
    expect_u32(eip_rd_le32(resp + 8), 0x0069, "option flags != 0 status");
    expect_u32(eip_rd_le32(resp + 4), 0, "bad options does not issue a handle");
    expect(eip_rd_le16(resp + 24) == 1, "bad options reports version 1");
    expect(eip_rd_le16(resp + 26) == 0, "bad options reports option flags 0");
    expect(eip_stack_session_count(s) == 0, "bad options allocates no session");

    fill_hdr(req, sizeof(req), EIP_CMD_REGISTERSESSION, 4, 0);
    eip_wr_le16(req + 24, 2);
    eip_wr_le16(req + 26, 1);
    n = 0;
    expect(exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n) == 0,
           "version and options encap rc");
    expect(n == EIP_ENCAP_HDR_SIZE + 4, "both wrong reply has 4 data bytes");
    expect_u32(eip_rd_le32(resp + 8), 0x0069, "version and options both wrong");
    expect_u32(eip_rd_le32(resp + 4), 0, "both wrong does not issue a handle");
    expect(eip_rd_le16(resp + 24) == 1, "both wrong reports version 1");
    expect(eip_rd_le16(resp + 26) == 0, "both wrong reports option flags 0");
    expect(eip_stack_session_count(s) == 0, "both wrong allocates no session");

    uint32_t h = register_ok(s, owner);
    expect(h != 0, "version 1 options 0 still registers");
    expect(eip_stack_session_count(s) == 1, "one good session");

    fill_hdr(req, sizeof(req), EIP_CMD_REGISTERSESSION, 4, 0);
    eip_wr_le16(req + 24, 2);
    eip_wr_le16(req + 26, 0);
    n = 0;
    expect(exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n) == 0,
           "bad version after a session");
    expect_u32(eip_rd_le32(resp + 8), 0x0069,
               "bad version does not replace a session");
    expect(eip_stack_session_count(s) == 1, "existing session kept");
    expect(register_ok(s, owner) == h, "re-register returns the same handle");
    eip_stack_destroy(s);
}

static void test_header_options_discarded(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[128];
    size_t n = 99;
    expect(s != NULL, "header options stack");
    if (!s) {
        return;
    }
    fill_hdr(req, sizeof(req), EIP_CMD_LISTSERVICES, 0, 0);
    eip_wr_le32(req + 20, 1);
    memset(resp, 0xCC, sizeof(resp));
    int rc = exchange(s, 0xA0000001u, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "non-zero header Options is not a hard error");
    expect(n == 0, "non-zero header Options is discarded");

    fill_hdr(req, sizeof(req), EIP_CMD_LISTSERVICES, 0, 0);
    n = 0;
    expect(exchange(s, 0xA0000001u, req, sizeof(req), resp, sizeof(resp), &n) ==
               0,
           "ListServices after discarded Options");
    expect(n == EIP_ENCAP_HDR_SIZE + 26, "ListServices still answers");
    expect_u32(eip_rd_le32(resp + 8), 0, "ListServices status 0");
    eip_stack_destroy(s);
}

static void test_sendunitdata_has_no_encap_reply(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[64];
    size_t n = 99;
    uint32_t owner = 0xA0000001u;
    expect(s != NULL, "sendunitdata stack");
    if (!s) {
        return;
    }
    fill_hdr(req, sizeof(req), EIP_CMD_SENDUNITDATA, 0, 0);
    memset(resp, 0xCC, sizeof(resp));
    int rc = exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "unregistered SendUnitData stays connected");
    expect(n == EIP_ENCAP_HDR_SIZE, "unregistered SendUnitData reply");
    expect_u32(eip_rd_le32(resp + 8), 0x0064, "unregistered SendUnitData 0x0064");
    expect(eip_stack_session_count(s) == 0, "unregistered SendUnitData adds no session");

    uint32_t h = register_ok(s, owner);
    expect(h != 0, "session before SendUnitData");
    uint32_t hb = register_ok(s, 0xA0000002u);
    expect(hb != 0 && hb != h, "second session before SendUnitData");
    fill_hdr(req, sizeof(req), EIP_CMD_SENDUNITDATA, 0, h);
    memset(resp, 0xCC, sizeof(resp));
    rc = exchange(s, owner, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "SendUnitData does not close the connection");
    expect(n == 0, "registered SendUnitData has no encapsulation reply");
    expect(eip_stack_session_count(s) == 2, "SendUnitData keeps the session");

    fill_hdr(req, sizeof(req), EIP_CMD_SENDUNITDATA, 0, h);
    n = 99;
    memset(resp, 0xCC, sizeof(resp));
    rc = exchange(s, 0xA0000002u, req, sizeof(req), resp, sizeof(resp), &n);
    expect(rc == 0, "foreign SendUnitData stays connected");
    expect(n == EIP_ENCAP_HDR_SIZE, "foreign SendUnitData reply");
    expect_u32(eip_rd_le32(resp + 8), 0x0064, "foreign SendUnitData 0x0064");
    expect(eip_stack_session_count(s) == 2, "foreign SendUnitData drops nothing");
    eip_stack_destroy(s);
}

static void test_list_interfaces_empty(void)
{
    eip_stack_t *s = make_stack();
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[64];
    size_t n = 0;
    expect(s != NULL, "listinterfaces stack");
    if (!s) {
        return;
    }
    fill_hdr(req, sizeof(req), EIP_CMD_LISTINTERFACES, 0, 0);
    expect(exchange(s, 0xA0000001u, req, sizeof(req), resp, sizeof(resp), &n) ==
               0,
           "ListInterfaces rc");
    expect(n == EIP_ENCAP_HDR_SIZE + 2, "ListInterfaces item-count only");
    expect(eip_rd_le16(resp) == EIP_CMD_LISTINTERFACES, "ListInterfaces cmd");
    expect_u32(eip_rd_le32(resp + 8), 0, "ListInterfaces status 0");
    expect(eip_rd_le16(resp + 24) == 0, "ListInterfaces item count 0");
    eip_stack_destroy(s);
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

/* 0 = reply, 1 = peer closed, -1 = timeout (still open), -2 = send error. */
static int tcp_round(eip_stack_t *s, int fd, const uint8_t *req, size_t req_len,
                     uint8_t *resp, size_t cap, size_t *out_n)
{
    if (send(fd, req, req_len, MSG_NOSIGNAL) != (ssize_t)req_len) {
        return -2;
    }
    for (int i = 0; i < 250; i++) {
        ssize_t n;
        eip_stack_poll(s);
        n = recv(fd, resp, cap, MSG_DONTWAIT);
        if (n > 0) {
            *out_n = (size_t)n;
            return 0;
        }
        if (n == 0) {
            *out_n = 0;
            return 1;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -2;
        }
        usleep(2000);
    }
    *out_n = 0;
    return -1;
}

static void test_live_nop_and_unregister(void)
{
    int tcp_port = reserve_port();
    int udp_port = reserve_port();
    eip_cfg_t cfg;
    eip_stack_t *s;
    int fd;
    struct sockaddr_in dst;
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[128];
    size_t n = 0;
    int rc;
    uint32_t sess = 0;

    expect(tcp_port > 0 && udp_port > 0 && tcp_port != udp_port, "live ports");
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 0;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_port;
    cfg.vendor_id = 0xABCD;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.security_class = 0;
    s = eip_stack_create(&cfg);
    expect(s != NULL && eip_stack_start(s) == 0, "live start");
    if (!s) {
        return;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    expect(fd >= 0, "tcp client");
    if (fd < 0) {
        eip_stack_destroy(s);
        return;
    }
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)tcp_port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
    expect(connect(fd, (struct sockaddr *)&dst, sizeof(dst)) == 0, "connect");

    fill_hdr(req, sizeof(req), EIP_CMD_REGISTERSESSION, 4, 0);
    eip_wr_le16(req + 24, 1);
    eip_wr_le16(req + 26, 0);
    rc = tcp_round(s, fd, req, sizeof(req), resp, sizeof(resp), &n);
    if (rc == 0 && n >= 8) {
        sess = eip_rd_le32(resp + 4);
    }
    expect(rc == 0 && sess != 0, "live register");

    fill_hdr(req, sizeof(req), EIP_CMD_NOP, 0, sess);
    rc = tcp_round(s, fd, req, EIP_ENCAP_HDR_SIZE, resp, sizeof(resp), &n);
    if (rc == 0) {
        fprintf(stderr, "FAIL: live NOP got a %zu-byte reply\n", n);
        g_fail = 1;
    } else {
        expect(rc == -1, "live NOP leaves the TCP connection open");
    }

    fill_hdr(req, sizeof(req), EIP_CMD_LISTSERVICES, 0, 0);
    rc = tcp_round(s, fd, req, EIP_ENCAP_HDR_SIZE, resp, sizeof(resp), &n);
    expect(rc == 0 && n >= 24 && eip_rd_le32(resp + 8) == 0,
           "ListServices after NOP (connection still open)");

    fill_hdr(req, sizeof(req), EIP_CMD_UNREGISTERSESSION, 0, sess);
    rc = tcp_round(s, fd, req, EIP_ENCAP_HDR_SIZE, resp, sizeof(resp), &n);
    if (rc == 0) {
        fprintf(stderr,
                "FAIL: live Unregister got a %zu-byte reply (status %#x) "
                "and left TCP open\n",
                n, n >= 12 ? eip_rd_le32(resp + 8) : 0);
        g_fail = 1;
    } else {
        expect(rc == 1 && n == 0, "live Unregister closes TCP with no reply");
    }

    close(fd);
    eip_stack_destroy(s);
}

int main(void)
{
    test_nop_has_no_reply();
    test_unregister_owned_closes_without_reply();
    test_unregister_foreign_keeps_session();
    test_register_version_and_options();
    test_header_options_discarded();
    test_sendunitdata_has_no_encap_reply();
    test_list_interfaces_empty();
    test_live_nop_and_unregister();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_9: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_9: ok\n");
    return 0;
}
