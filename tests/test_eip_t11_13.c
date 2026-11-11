/*
 * T11-13: first-packet watchdog grace, Identity Reset type, UCMM buffer,
 * encapsulation larger than 8 KB, and LLDP transmit.
 *
 * These checks fail on the pre-fix stack:
 *   - Forward Open arms RPI×multiplier immediately, so a 400 ms gap
 *     before the first O->T drops an 80 ms watchdog.
 *   - Identity Reset type 0xFF is accepted.
 *   - A 1000-byte Assembly Get comes back as CIP 0x02 (568-byte UCMM buf).
 *   - An encapsulation message over 8 KB closes the TCP session.
 *   - LLDP is built in memory and never handed to a transmitter.
 *
 * Wire values follow docs/protocols/ethernetip.md and the T11-13 oracle
 * (tests/oracle/test_eip_oracle.py). This file does not include private
 * stack headers.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
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
            0 ||
        n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static eip_stack_t *make_mock(uint16_t input_size, uint32_t rpi_us)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = input_size;
    cfg.output_size = 4;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.rpi_us = rpi_us;
    cfg.vendor_id = 0xABCD;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        eip_stack_destroy(s);
        return NULL;
    }
    return s;
}

/* Exclusive-owner path: Assembly / config 100 / O->T 101 / T->O 150. */
static size_t append_path(uint8_t *fo, size_t off)
{
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

/* Class 1 cyclic, timeout multiplier 0, RPI 20 ms. O->T size is
 * output(4)+sequence(2). Watchdog without grace is 80 ms. */
static size_t build_fo(uint8_t *fo)
{
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0x44332211u);
    off += 4;
    eip_wr_le16(fo + off, 0x1313);
    off += 2;
    eip_wr_le16(fo + off, 0x1337);
    off += 2;
    eip_wr_le32(fo + off, 0xCAFEBABEu);
    off += 4;
    fo[off++] = 0; /* timeout multiplier → ×4 */
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, 6);
    off += 2;
    eip_wr_le32(fo + off, 20000);
    off += 4;
    eip_wr_le16(fo + off, 10);
    off += 2;
    fo[off++] = 0x01; /* class 1, cyclic */
    return append_path(fo, off);
}

static const uint8_t *unconnected_cip(const uint8_t *resp, size_t resp_len,
                                      size_t *cip_len)
{
    if (resp_len < EIP_ENCAP_HDR_SIZE + 8) {
        return NULL;
    }
    const uint8_t *b = resp + EIP_ENCAP_HDR_SIZE;
    size_t blen = resp_len - EIP_ENCAP_HDR_SIZE;
    uint16_t count = eip_rd_le16(b + 6);
    size_t off = 8;
    for (uint16_t i = 0; i < count; i++) {
        if (off + 4 > blen) {
            return NULL;
        }
        uint16_t typ = eip_rd_le16(b + off);
        uint16_t ln = eip_rd_le16(b + off + 2);
        off += 4;
        if (off + ln > blen) {
            return NULL;
        }
        if (typ == EIP_ITEM_UNCONNECTED_DATA) {
            *cip_len = ln;
            return b + off;
        }
        off += ln;
    }
    return NULL;
}

static size_t send_cip(eip_stack_t *s, uint32_t sess, const uint8_t *cip,
                       size_t cip_len, uint8_t *cip_out, size_t cip_cap)
{
    uint8_t body[160];
    if (cip_len > 80) {
        return 0;
    }
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
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 160];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);

    uint8_t resp[EIP_ASSEMBLY_SIZE_MAX + 256];
    size_t resp_len = 0;
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return 0;
    }
    size_t n = 0;
    const uint8_t *out = unconnected_cip(resp, resp_len, &n);
    if (!out || n > cip_cap) {
        return 0;
    }
    memcpy(cip_out, out, n);
    return n;
}

static void test_first_o2t_grace(void)
{
    eip_stack_t *s = make_mock(8, 20000);
    expect(s != NULL, "grace stack");
    if (!s) {
        return;
    }
    uint32_t sess = test_register(s);
    expect(sess != 0, "grace session");
    uint8_t fo[64];
    size_t fo_len = build_fo(fo);
    uint8_t cip[80];
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, fo_len);
    uint8_t reply[64];
    size_t n = send_cip(s, sess, cip, 6 + fo_len, reply, sizeof(reply));
    expect(n >= 8 && reply[0] == (CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) &&
               reply[2] == 0,
           "grace Forward Open");
    expect(eip_stack_class1_up(s) == 1, "class1 up after Forward Open");
    uint32_t o2t = n >= 8 ? eip_rd_le32(reply + 4) : 0;

    /* Oracle: 400 ms with no O->T must not drop an 80 ms watchdog. */
    usleep(400000);
    eip_stack_poll(s);
    expect(eip_stack_class1_up(s) == 1,
           "class1 still up 400 ms after Forward Open with no O->T");

    if (eip_stack_class1_up(s) == 1 && o2t != 0) {
        uint8_t io[32];
        size_t ioff = 0;
        eip_wr_le16(io + ioff, 2);
        ioff += 2;
        eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
        ioff += 2;
        eip_wr_le16(io + ioff, 8);
        ioff += 2;
        eip_wr_le32(io + ioff, o2t);
        ioff += 4;
        eip_wr_le32(io + ioff, 1);
        ioff += 4;
        eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
        ioff += 2;
        eip_wr_le16(io + ioff, 6);
        ioff += 2;
        eip_wr_le16(io + ioff, 1);
        ioff += 2;
        memset(io + ioff, 0x11, 4);
        ioff += 4;
        expect(eip_stack_handle_io(s, io, ioff) == 0, "first O->T");
        usleep(200000); /* > 80 ms RPI×4 watchdog */
        eip_stack_poll(s);
        expect(eip_stack_class1_up(s) == 0,
               "class1 closed by RPI watchdog after the first O->T");
    }
    eip_stack_destroy(s);
}

static void test_reset_type(void)
{
    eip_stack_t *s = make_mock(8, 8000);
    expect(s != NULL, "reset stack");
    if (!s) {
        return;
    }
    uint8_t seed[8];
    memset(seed, 0xA5, sizeof(seed));
    expect(eip_stack_write_input(s, 0, seed, 8) == 8, "reset seed");
    uint32_t sess = test_register(s);
    expect(sess != 0, "reset session");

    uint8_t bad[7] = {CIP_SVC_RESET, 2, 0x20, CIP_CLASS_IDENTITY, 0x24, 1, 0xFF};
    uint8_t reply[16];
    size_t n = send_cip(s, sess, bad, sizeof(bad), reply, sizeof(reply));
    expect(n >= 3 && reply[0] == (CIP_SVC_RESET | CIP_SVC_REPLY) &&
               reply[2] == CIP_STATUS_INVALID_PARAM,
           "Identity Reset type 0xFF status want 0x20");
    uint8_t in[8];
    expect(eip_stack_read_input(s, 0, in, 8) == 8, "read after rejected reset");
    expect(in[0] == 0xA5 && in[7] == 0xA5, "rejected reset left the I/O image");

    uint8_t ok[6] = {CIP_SVC_RESET, 2, 0x20, CIP_CLASS_IDENTITY, 0x24, 1};
    n = send_cip(s, sess, ok, sizeof(ok), reply, sizeof(reply));
    expect(n >= 3 && reply[2] == CIP_STATUS_SUCCESS, "Reset type omitted succeeds");
    expect(eip_stack_read_input(s, 0, in, 8) == 8, "read after type 0");
    expect(in[0] == 0 && in[7] == 0, "type 0 cleared the I/O image");
    eip_stack_destroy(s);
}

static void test_large_assembly_get(void)
{
    eip_stack_t *s = make_mock(1000, 8000);
    expect(s != NULL, "assembly stack");
    if (!s) {
        return;
    }
    for (int i = 0; i < 1000; i++) {
        uint8_t b = (uint8_t)((i + 1) & 0xFF);
        if (eip_stack_write_input(s, (size_t)i, &b, 1) != 1) {
            expect(0, "seed assembly byte");
            eip_stack_destroy(s);
            return;
        }
    }
    uint32_t sess = test_register(s);
    uint8_t get[8] = {CIP_SVC_GET_ATTR_SINGLE, 3, 0x20, CIP_CLASS_ASSEMBLY,
                      0x24, 150, 0x30, 3};
    uint8_t reply[EIP_ASSEMBLY_SIZE_MAX + 16];
    size_t n = send_cip(s, sess, get, sizeof(get), reply, sizeof(reply));
    int full = n == 4 + 1000 && reply[2] == CIP_STATUS_SUCCESS;
    int too_big = n >= 3 && reply[2] == 0x11;
    if (!full && !too_big) {
        fprintf(stderr,
                "FAIL: Assembly 1000 Get status/len (n=%zu status=0x%02x)\n",
                n, n >= 3 ? reply[2] : 0);
        g_fail = 1;
    }
    if (full) {
        int match = 1;
        for (int i = 0; i < 1000; i++) {
            if (reply[4 + i] != (uint8_t)((i + 1) & 0xFF)) {
                match = 0;
                break;
            }
        }
        expect(match, "Assembly 1000 Get bytes");
    }
    eip_stack_destroy(s);
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int exchange(eip_stack_t *s, int fd, const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    size_t sent = 0;
    int spins = 0;
    while (sent < req_len && spins < 500) {
        ssize_t n = send(fd, req + sent, req_len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -1;
        }
        eip_stack_poll(s);
        usleep(2000);
        spins++;
    }
    if (sent < req_len) {
        return -1;
    }
    uint8_t hdr[EIP_ENCAP_HDR_SIZE];
    size_t got = 0;
    spins = 0;
    while (got < EIP_ENCAP_HDR_SIZE && spins < 500) {
        eip_stack_poll(s);
        ssize_t n = recv(fd, hdr + got, EIP_ENCAP_HDR_SIZE - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -1;
        }
        usleep(2000);
        spins++;
    }
    if (got < EIP_ENCAP_HDR_SIZE) {
        return -1;
    }
    uint16_t length = eip_rd_le16(hdr + 2);
    if ((size_t)EIP_ENCAP_HDR_SIZE + length > resp_cap) {
        return -1;
    }
    memcpy(resp, hdr, EIP_ENCAP_HDR_SIZE);
    got = 0;
    spins = 0;
    while (got < length && spins < 500) {
        eip_stack_poll(s);
        ssize_t n =
            recv(fd, resp + EIP_ENCAP_HDR_SIZE + got, length - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -1;
        }
        usleep(2000);
        spins++;
    }
    if (got < length) {
        return -1;
    }
    *resp_len = (size_t)EIP_ENCAP_HDR_SIZE + length;
    return 0;
}

static eip_stack_t *start_live(int *port_out)
{
    int base = 25000 + (int)(getpid() % 10000);
    for (int n = 0; n < 30; n++) {
        int port = base + n * 2;
        eip_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.role = EIP_ROLE_ADAPTER;
        cfg.mock = 0;
        snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
        cfg.tcp_port = port;
        cfg.udp_io_port = port + 1;
        cfg.input_size = 8;
        cfg.output_size = 4;
        cfg.vendor_id = 0xABCD;
        cfg.lldp_enable = 0;
        cfg.acd_enable = 0;
        eip_stack_t *s = eip_stack_create(&cfg);
        if (!s) {
            return NULL;
        }
        if (eip_stack_start(s) == 0) {
            *port_out = port;
            return s;
        }
        eip_stack_destroy(s);
    }
    return NULL;
}

static void test_large_encapsulation(void)
{
    int port = 0;
    eip_stack_t *s = start_live(&port);
    expect(s != NULL, "live stack");
    if (!s) {
        return;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    expect(fd >= 0, "tcp socket");
    if (fd < 0) {
        eip_stack_destroy(s);
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    /* Accept runs inside poll, so connect can race the listen backlog.
     * Localhost connect usually completes before the first poll. */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        expect(0, "tcp connect");
        close(fd);
        eip_stack_destroy(s);
        return;
    }
    expect(set_nonblock(fd) == 0, "nonblock");

    uint8_t reg[EIP_ENCAP_HDR_SIZE + 4];
    memset(reg, 0, sizeof(reg));
    eip_wr_le16(reg, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(reg + 2, 4);
    eip_wr_le16(reg + 24, 1);
    uint8_t resp[256];
    size_t resp_len = 0;
    int rc = exchange(s, fd, reg, sizeof(reg), resp, sizeof(resp), &resp_len);
    expect(rc == 0 && resp_len >= 8, "RegisterSession");
    uint32_t sess = rc == 0 && resp_len >= 8 ? eip_rd_le32(resp + 4) : 0;
    expect(sess != 0, "session handle");

    /* Set Assembly 101 attr 3 with 9000 bytes. Encapsulation total is
     * past the 8192-byte TCP buffer and under the 65511 spec maximum. */
    const size_t data_len = 9000;
    uint8_t path[6] = {0x20, CIP_CLASS_ASSEMBLY, 0x24, 101, 0x30, 3};
    size_t cip_len = 2 + sizeof(path) + data_len;
    size_t rr_len = 8 + 4 + 4 + cip_len;
    size_t req_len = EIP_ENCAP_HDR_SIZE + rr_len;
    uint8_t *req = calloc(1, req_len);
    expect(req != NULL, "big request alloc");
    if (req && sess != 0) {
        uint8_t *body = req + EIP_ENCAP_HDR_SIZE;
        uint8_t *cip = body + 16;
        size_t b = 0;
        cip[0] = CIP_SVC_SET_ATTR_SINGLE;
        cip[1] = (uint8_t)(sizeof(path) / 2);
        memcpy(cip + 2, path, sizeof(path));
        eip_wr_le16(req, EIP_CMD_SENDRRDATA);
        eip_wr_le16(req + 2, (uint16_t)rr_len);
        eip_wr_le32(req + 4, sess);
        eip_wr_le32(body + b, 0);
        b += 4;
        eip_wr_le16(body + b, 0);
        b += 2;
        eip_wr_le16(body + b, 2);
        b += 2;
        eip_wr_le16(body + b, EIP_ITEM_NULL_ADDR);
        b += 2;
        eip_wr_le16(body + b, 0);
        b += 2;
        eip_wr_le16(body + b, EIP_ITEM_UNCONNECTED_DATA);
        b += 2;
        eip_wr_le16(body + b, (uint16_t)cip_len);
        resp_len = 0;
        rc = exchange(s, fd, req, req_len, resp, sizeof(resp), &resp_len);
        expect(rc == 0 && resp_len >= 2 && eip_rd_le16(resp) == EIP_CMD_SENDRRDATA,
               "encapsulation over 8KB closed the TCP session");
    }
    free(req);

    if (sess != 0) {
        uint8_t get[8] = {CIP_SVC_GET_ATTR_SINGLE, 3, 0x20, CIP_CLASS_IDENTITY,
                          0x24, 1, 0x30, 1};
        uint8_t small[EIP_ENCAP_HDR_SIZE + 64];
        memset(small, 0, sizeof(small));
        size_t boff = 0;
        uint8_t *body = small + EIP_ENCAP_HDR_SIZE;
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
        eip_wr_le16(body + boff, (uint16_t)sizeof(get));
        boff += 2;
        memcpy(body + boff, get, sizeof(get));
        boff += sizeof(get);
        eip_wr_le16(small, EIP_CMD_SENDRRDATA);
        eip_wr_le16(small + 2, (uint16_t)boff);
        eip_wr_le32(small + 4, sess);
        resp_len = 0;
        rc = exchange(s, fd, small, EIP_ENCAP_HDR_SIZE + boff, resp, sizeof(resp),
                      &resp_len);
        size_t cn = 0;
        const uint8_t *cr = rc == 0 ? unconnected_cip(resp, resp_len, &cn) : NULL;
        expect(cr && cn >= 6 && cr[2] == 0 && eip_rd_le16(cr + 4) == 0xABCD,
               "session still serves Identity vendor after the large PDU");
    }
    close(fd);
    eip_stack_destroy(s);
}

static uint8_t g_tx[512];
static size_t g_txlen;
static int g_ntx;

static int capture_l2(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (len <= sizeof(g_tx)) {
        memcpy(g_tx, frame, len);
        g_txlen = len;
    }
    g_ntx++;
    return 0;
}

static void test_lldp_transmit(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.lldp_enable = 1;
    cfg.lldp_tx_interval_sec = 30;
    snprintf(cfg.iface, sizeof(cfg.iface), "eth0");
    snprintf(cfg.product_name, sizeof(cfg.product_name), "LLDPSensor");
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "lldp stack");
    if (!s) {
        return;
    }
    g_ntx = 0;
    g_txlen = 0;
    eip_transport_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.l2_send = capture_l2;
    eip_stack_set_transport_ops(s, ops);
    expect(eip_stack_start(s) == 0, "lldp start");
    eip_stack_poll(s);
    expect(g_ntx == 1, "LLDP poll did not hand a frame to l2_send");
    static const uint8_t dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
    expect(g_txlen > 14 && memcmp(g_tx, dst, 6) == 0, "LLDP dest multicast");
    expect(g_txlen > 14 && g_tx[12] == 0x88 && g_tx[13] == 0xcc,
           "LLDP ethertype");
    int found = 0;
    for (size_t i = 0; i + 10 < g_txlen; i++) {
        if (memcmp(g_tx + i, "LLDPSensor", 10) == 0) {
            found = 1;
            break;
        }
    }
    expect(found, "product name in transmitted LLDP");
    eip_stack_poll(s);
    expect(g_ntx == 1, "second poll inside the TX interval sent again");
    eip_stack_destroy(s);
}

int main(void)
{
    test_first_o2t_grace();
    test_reset_type();
    test_large_assembly_get();
    test_large_encapsulation();
    test_lldp_transmit();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_13: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_13: ok\n");
    return 0;
}
