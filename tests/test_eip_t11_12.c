/*
 * T11-12: Originator Logix tag services, TCP reassembly, integrity MAC.
 *
 * A fake Logix target (this file, not the stack) accepts Read Tag 0x4C /
 * Write Tag 0x4D on an ANSI symbol path. Before the fix the originator
 * sends Get/Set_Attribute_Single, takes one recv(), and never appends the
 * repository integrity item 0x00C1. See structure_handoff T11-12 and
 * docs/protocols/ethernetip.md 7.3 and 9.5.
 */
#include "eip_crypto.h"
#include "eip_endian.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FAKE_MAX_RR 6
#define FAKE_PKT    1024
#define FAKE_TAG    1
#define FAKE_GET    2
#define FAKE_SEC    3

static int g_fail;
static uint8_t g_psk[EIP_PSK_LEN];

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

typedef struct {
    int lfd;
    int mode;
    int split;
    int n_rr;
    size_t rr_len[FAKE_MAX_RR];
    uint8_t rr[FAKE_MAX_RR][FAKE_PKT];
    uint16_t tag_type;
    uint8_t tag_val[16];
    size_t tag_val_len;
} fake_t;

static int listen_loopback(int *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t alen = sizeof(a);
    int yes = 1;
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
        close(fd);
        return -1;
    }
    *port = (int)ntohs(a.sin_port);
    return fd;
}

static int recv_full(int fd, uint8_t *buf, size_t need)
{
    size_t got = 0;
    while (got < need) {
        ssize_t n = recv(fd, buf + got, need - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int read_encap(int fd, uint8_t *buf, size_t cap, size_t *out_len)
{
    uint16_t body;
    if (cap < EIP_ENCAP_HDR_SIZE || recv_full(fd, buf, EIP_ENCAP_HDR_SIZE) != 0) {
        return -1;
    }
    body = eip_rd_le16(buf + 2);
    if ((size_t)EIP_ENCAP_HDR_SIZE + body > cap) {
        return -1;
    }
    if (body && recv_full(fd, buf + EIP_ENCAP_HDR_SIZE, body) != 0) {
        return -1;
    }
    *out_len = (size_t)EIP_ENCAP_HDR_SIZE + body;
    return 0;
}

static int send_all(int fd, const uint8_t *p, size_t n, int split)
{
    size_t first;
    if (!split) {
        return send(fd, p, n, MSG_NOSIGNAL) == (ssize_t)n ? 0 : -1;
    }
    first = n < 10 ? n : 10;
    if (send(fd, p, first, MSG_NOSIGNAL) != (ssize_t)first) {
        return -1;
    }
    if (first < n) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000L;
        nanosleep(&ts, NULL);
        if (send(fd, p + first, n - first, MSG_NOSIGNAL) !=
            (ssize_t)(n - first)) {
            return -1;
        }
    }
    return 0;
}

static int send_encap(int fd, uint16_t cmd, uint32_t session, const uint8_t *ctx,
                      const uint8_t *body, size_t body_len, int split)
{
    uint8_t pkt[1200];
    if (EIP_ENCAP_HDR_SIZE + body_len > sizeof(pkt)) {
        return -1;
    }
    memset(pkt, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(pkt + 0, cmd);
    eip_wr_le16(pkt + 2, (uint16_t)body_len);
    eip_wr_le32(pkt + 4, session);
    if (ctx) {
        memcpy(pkt + 12, ctx, 8);
    }
    if (body_len) {
        memcpy(pkt + EIP_ENCAP_HDR_SIZE, body, body_len);
    }
    return send_all(fd, pkt, EIP_ENCAP_HDR_SIZE + body_len, split);
}

static size_t wrap_rr(uint8_t *out, size_t cap, const uint8_t *cip, size_t cip_len)
{
    size_t n = 16 + cip_len;
    size_t o = 0;
    if (n > cap) {
        return 0;
    }
    eip_wr_le32(out + o, 0);
    o += 4;
    eip_wr_le16(out + o, 0);
    o += 2;
    eip_wr_le16(out + o, 2);
    o += 2;
    eip_wr_le16(out + o, 0x0000);
    o += 2;
    eip_wr_le16(out + o, 0);
    o += 2;
    eip_wr_le16(out + o, 0x00B2);
    o += 2;
    eip_wr_le16(out + o, (uint16_t)cip_len);
    o += 2;
    memcpy(out + o, cip, cip_len);
    return n;
}

static void record_rr(fake_t *f, const uint8_t *pkt, size_t len)
{
    size_t n;
    if (f->n_rr >= FAKE_MAX_RR) {
        return;
    }
    n = len < FAKE_PKT ? len : FAKE_PKT;
    memcpy(f->rr[f->n_rr], pkt, n);
    f->rr_len[f->n_rr] = n;
    f->n_rr++;
}

static void reply_cip(fake_t *f, int fd, const uint8_t *req, const uint8_t *cip,
                      size_t cip_len)
{
    uint8_t body[256];
    size_t n = wrap_rr(body, sizeof(body), cip, cip_len);
    if (n == 0) {
        return;
    }
    send_encap(fd, EIP_CMD_SENDRRDATA, 0x1234ABCDu, req + 12, body, n, f->split);
}

static void handle_cip(fake_t *f, int fd, const uint8_t *req, const uint8_t *cip,
                       size_t cip_len)
{
    uint8_t rsp[64];
    uint8_t svc;
    size_t words;
    size_t plen;
    const uint8_t *data;
    size_t dlen;
    if (cip_len < 2) {
        return;
    }
    svc = cip[0];
    words = cip[1];
    plen = words * 2;
    if (2 + plen > cip_len) {
        return;
    }
    data = cip + 2 + plen;
    dlen = cip_len - 2 - plen;
    memset(rsp, 0, sizeof(rsp));

    if (f->mode == FAKE_GET && svc == 0x0E) {
        rsp[0] = (uint8_t)(0x0E | 0x80);
        eip_wr_le16(rsp + 4, 0x0001);
        reply_cip(f, fd, req, rsp, 6);
        return;
    }
    if (f->mode == FAKE_SEC) {
        rsp[0] = (uint8_t)(svc | 0x80);
        reply_cip(f, fd, req, rsp, 4);
        return;
    }
    if (f->mode == FAKE_TAG && svc == 0x4C && plen >= 2 && cip[2] == 0x91 &&
        cip[3] == 7 && memcmp(cip + 4, "Sensor1", 7) == 0) {
        rsp[0] = (uint8_t)(0x4C | 0x80);
        eip_wr_le16(rsp + 4, f->tag_type);
        memcpy(rsp + 6, f->tag_val, f->tag_val_len);
        reply_cip(f, fd, req, rsp, 6 + f->tag_val_len);
        return;
    }
    if (f->mode == FAKE_TAG && svc == 0x4D && plen >= 2 && cip[2] == 0x91 &&
        dlen >= 4) {
        uint16_t typ = eip_rd_le16(data);
        uint16_t count = eip_rd_le16(data + 2);
        if (typ == f->tag_type && count == 1) {
            size_t vlen = dlen - 4;
            if (vlen > sizeof(f->tag_val)) {
                vlen = sizeof(f->tag_val);
            }
            memcpy(f->tag_val, data + 4, vlen);
            f->tag_val_len = vlen;
            rsp[0] = (uint8_t)(0x4D | 0x80);
            reply_cip(f, fd, req, rsp, 4);
            return;
        }
        rsp[0] = (uint8_t)(0x4D | 0x80);
        rsp[2] = 0xFF;
        rsp[3] = 1;
        eip_wr_le16(rsp + 4, 0x2107);
        reply_cip(f, fd, req, rsp, 6);
        return;
    }
    rsp[0] = (uint8_t)(svc | 0x80);
    rsp[2] = 0x08;
    reply_cip(f, fd, req, rsp, 4);
}

static void *server_main(void *arg)
{
    fake_t *f = arg;
    int fd = accept(f->lfd, NULL, NULL);
    struct timeval tv;
    if (fd < 0) {
        return NULL;
    }
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        uint8_t pkt[2048];
        size_t len = 0;
        uint16_t cmd;
        if (read_encap(fd, pkt, sizeof(pkt), &len) != 0) {
            break;
        }
        cmd = eip_rd_le16(pkt);
        if (cmd == EIP_CMD_REGISTERSESSION) {
            uint8_t body[4];
            eip_wr_le16(body, 1);
            eip_wr_le16(body + 2, 0);
            if (send_encap(fd, EIP_CMD_REGISTERSESSION, 0x1234ABCDu, pkt + 12,
                           body, 4, f->split) != 0) {
                break;
            }
            continue;
        }
        if (cmd != EIP_CMD_SENDRRDATA || len < 24 + 8) {
            break;
        }
        record_rr(f, pkt, len);
        {
            const uint8_t *cip = NULL;
            size_t cip_len = 0;
            size_t off = 24 + 6;
            uint16_t items;
            uint16_t i;
            if (off + 2 > len) {
                break;
            }
            items = eip_rd_le16(pkt + off);
            off += 2;
            for (i = 0; i < items; i++) {
                uint16_t typ;
                uint16_t ilen;
                if (off + 4 > len) {
                    cip = NULL;
                    break;
                }
                typ = eip_rd_le16(pkt + off);
                ilen = eip_rd_le16(pkt + off + 2);
                off += 4;
                if (off + ilen > len) {
                    cip = NULL;
                    break;
                }
                if (typ == 0x00B2) {
                    cip = pkt + off;
                    cip_len = ilen;
                }
                off += ilen;
            }
            if (!cip) {
                break;
            }
            handle_cip(f, fd, pkt, cip, cip_len);
        }
    }
    close(fd);
    return NULL;
}

static int start_fake(fake_t *f, int mode, int split, pthread_t *th, int *port)
{
    memset(f, 0, sizeof(*f));
    f->mode = mode;
    f->split = split;
    f->tag_type = 0x00C4;
    f->tag_val_len = 4;
    eip_wr_le32(f->tag_val, 42);
    f->lfd = listen_loopback(port);
    if (f->lfd < 0) {
        return -1;
    }
    if (pthread_create(th, NULL, server_main, f) != 0) {
        close(f->lfd);
        f->lfd = -1;
        return -1;
    }
    return 0;
}

static void stop_fake(fake_t *f, pthread_t th)
{
    if (f->lfd >= 0) {
        shutdown(f->lfd, SHUT_RDWR);
        close(f->lfd);
        f->lfd = -1;
    }
    pthread_join(th, NULL);
}

static int open_originator(int port, int sec, eip_stack_t **out)
{
    eip_cfg_t cfg;
    eip_stack_t *s;
    int rc;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ORIGINATOR;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    cfg.remote_port = port;
    cfg.security_class = sec;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    if (sec >= EIP_SECURITY_CLASS_1) {
        memcpy(cfg.psk, g_psk, EIP_PSK_LEN);
        cfg.psk_set = 1;
    }
    s = eip_stack_create(&cfg);
    if (!s) {
        *out = NULL;
        return -ENOMEM;
    }
    rc = eip_stack_start(s);
    if (rc != 0) {
        eip_stack_destroy(s);
        *out = NULL;
        return rc;
    }
    *out = s;
    return 0;
}

static int parse_rr(const uint8_t *pkt, size_t len, const uint8_t **cip,
                    size_t *cip_len, const uint8_t **mac, size_t *mac_len,
                    uint16_t *nitems)
{
    size_t off;
    uint16_t items;
    uint16_t i;
    *cip = NULL;
    *cip_len = 0;
    *mac = NULL;
    *mac_len = 0;
    *nitems = 0;
    if (len < 24 + 8) {
        return -1;
    }
    off = 24 + 6;
    items = eip_rd_le16(pkt + off);
    off += 2;
    *nitems = items;
    for (i = 0; i < items; i++) {
        uint16_t typ;
        uint16_t ilen;
        if (off + 4 > len) {
            return -1;
        }
        typ = eip_rd_le16(pkt + off);
        ilen = eip_rd_le16(pkt + off + 2);
        off += 4;
        if (off + ilen > len) {
            return -1;
        }
        if (typ == 0x00B2) {
            *cip = pkt + off;
            *cip_len = ilen;
        } else if (typ == 0x00C1) {
            *mac = pkt + off;
            *mac_len = ilen;
        }
        off += ilen;
    }
    return *cip ? 0 : -1;
}

static void dump_rr(const fake_t *f)
{
    int i;
    fprintf(stderr, "  recorded SendRRData: %d\n", f->n_rr);
    for (i = 0; i < f->n_rr; i++) {
        const uint8_t *cip = NULL;
        const uint8_t *mac = NULL;
        size_t cip_len = 0;
        size_t mac_len = 0;
        uint16_t nitems = 0;
        if (parse_rr(f->rr[i], f->rr_len[i], &cip, &cip_len, &mac, &mac_len,
                     &nitems) != 0) {
            fprintf(stderr, "    [%d] unparsed len %zu\n", i, f->rr_len[i]);
            continue;
        }
        fprintf(stderr, "    [%d] service 0x%02x item_count %u cip_len %zu mac_len %zu\n",
                i, cip_len ? cip[0] : 0, nitems, cip_len, mac_len);
    }
}

static int find_svc(const fake_t *f, uint8_t svc, const uint8_t **cip,
                    size_t *cip_len)
{
    int i;
    for (i = 0; i < f->n_rr; i++) {
        const uint8_t *c = NULL;
        const uint8_t *m = NULL;
        size_t cl = 0;
        size_t ml = 0;
        uint16_t ni = 0;
        if (parse_rr(f->rr[i], f->rr_len[i], &c, &cl, &m, &ml, &ni) != 0) {
            continue;
        }
        if (cl >= 1 && c[0] == svc) {
            *cip = c;
            *cip_len = cl;
            return i;
        }
    }
    return -1;
}

static int cip_data(const uint8_t *cip, size_t cip_len, const char *name,
                    const uint8_t **data, size_t *data_len)
{
    size_t plen;
    size_t n;
    if (cip_len < 2) {
        return 0;
    }
    plen = (size_t)cip[1] * 2;
    if (2 + plen > cip_len || plen < 2) {
        return 0;
    }
    n = strlen(name);
    if (cip[2] != 0x91 || cip[3] != (uint8_t)n || plen < 2 + n) {
        return 0;
    }
    if (memcmp(cip + 4, name, n) != 0) {
        return 0;
    }
    *data = cip + 2 + plen;
    *data_len = cip_len - 2 - plen;
    return 1;
}

static void test_tag_read(void)
{
    fake_t f;
    pthread_t th;
    int port = 0;
    eip_stack_t *s = NULL;
    uint8_t out[16];
    size_t n = sizeof(out);
    uint8_t want[4];
    const uint8_t *cip = NULL;
    size_t cip_len = 0;
    const uint8_t *data = NULL;
    size_t data_len = 0;
    int rc;

    eip_wr_le32(want, 42);
    if (start_fake(&f, FAKE_TAG, 0, &th, &port) != 0) {
        expect(0, "tag-read fake target");
        return;
    }
    rc = open_originator(port, 0, &s);
    if (rc != 0 || !s) {
        fprintf(stderr, "FAIL: tag-read originator start rc=%d (%s)\n", rc,
                strerror(rc < 0 ? -rc : rc));
        g_fail = 1;
        stop_fake(&f, th);
        return;
    }
    rc = eip_stack_tag_read(s, "Sensor1", out, &n);
    if (rc != 0 || n != 4 || memcmp(out, want, 4) != 0) {
        fprintf(stderr,
                "FAIL: tag-read rc=%d (%s) n=%zu (want 0 and DINT 42). "
                "Logix Read Tag is 0x4C, element count UINT 1; "
                "returned bytes are the value, not the type prefix\n",
                rc, strerror(rc < 0 ? -rc : rc), n);
        dump_rr(&f);
        g_fail = 1;
    }
    if (find_svc(&f, 0x4C, &cip, &cip_len) < 0 ||
        !cip_data(cip, cip_len, "Sensor1", &data, &data_len) || data_len != 2 ||
        data[0] != 0x01 || data[1] != 0x00) {
        fprintf(stderr,
                "FAIL: tag-read request is not Read Tag 0x4C path Sensor1 "
                "data 01 00\n");
        dump_rr(&f);
        g_fail = 1;
    }
    eip_stack_destroy(s);
    stop_fake(&f, th);
}

static void test_tag_write(void)
{
    fake_t f;
    pthread_t th;
    int port = 0;
    eip_stack_t *s = NULL;
    uint8_t val[4];
    const uint8_t *cip = NULL;
    size_t cip_len = 0;
    const uint8_t *data = NULL;
    size_t data_len = 0;
    int rc;

    eip_wr_le32(val, 7);
    if (start_fake(&f, FAKE_TAG, 0, &th, &port) != 0) {
        expect(0, "tag-write fake target");
        return;
    }
    rc = open_originator(port, 0, &s);
    if (rc != 0 || !s) {
        fprintf(stderr, "FAIL: tag-write originator start rc=%d (%s)\n", rc,
                strerror(rc < 0 ? -rc : rc));
        g_fail = 1;
        stop_fake(&f, th);
        return;
    }
    rc = eip_stack_tag_write(s, "Sensor1", val, sizeof(val));
    if (rc != 0 || f.tag_val_len != 4 || eip_rd_le32(f.tag_val) != 7) {
        fprintf(stderr,
                "FAIL: tag-write rc=%d (%s) stored %zu bytes value %#x "
                "(want 0, DINT 7). Write Tag is 0x4D with type UINT, "
                "element count UINT 1, then the value\n",
                rc, strerror(rc < 0 ? -rc : rc), f.tag_val_len,
                f.tag_val_len >= 4 ? eip_rd_le32(f.tag_val) : 0);
        dump_rr(&f);
        g_fail = 1;
    }
    if (find_svc(&f, 0x4D, &cip, &cip_len) < 0 ||
        !cip_data(cip, cip_len, "Sensor1", &data, &data_len) || data_len < 8 ||
        eip_rd_le16(data) != 0x00C4 || eip_rd_le16(data + 2) != 1 ||
        memcmp(data + 4, val, 4) != 0) {
        fprintf(stderr,
                "FAIL: tag-write request is not Write Tag 0x4D "
                "type 0x00C4 count 1 value 07 00 00 00\n");
        dump_rr(&f);
        g_fail = 1;
    }
    eip_stack_destroy(s);
    stop_fake(&f, th);
}

static void test_split_reply(void)
{
    fake_t f;
    pthread_t th;
    int port = 0;
    eip_stack_t *s = NULL;
    uint8_t out[8];
    size_t n;
    int rc;

    if (start_fake(&f, FAKE_GET, 1, &th, &port) != 0) {
        expect(0, "split fake target");
        return;
    }
    rc = open_originator(port, 0, &s);
    if (rc != 0 || !s) {
        fprintf(stderr,
                "FAIL: split TCP reply: originator start rc=%d (%s). "
                "RegisterSession was split after 10 bytes; "
                "encapsulation length must be reassembled\n",
                rc, strerror(rc < 0 ? -rc : rc));
        g_fail = 1;
        stop_fake(&f, th);
        return;
    }
    n = sizeof(out);
    memset(out, 0, sizeof(out));
    rc = eip_stack_explicit_get(s, 1, 1, 1, out, &n);
    if (rc != 0 || n != 2 || out[0] != 0x01 || out[1] != 0x00) {
        fprintf(stderr,
                "FAIL: split TCP reply: Get_Attribute_Single rc=%d (%s) n=%zu "
                "data %02x %02x (want 0, 2, 01 00)\n",
                rc, strerror(rc < 0 ? -rc : rc), n, out[0], out[1]);
        g_fail = 1;
    }
    eip_stack_destroy(s);
    stop_fake(&f, th);
}

static void test_security_mac(void)
{
    fake_t f;
    pthread_t th;
    int port = 0;
    eip_stack_t *s = NULL;
    uint8_t data[2] = {0xAA, 0x55};
    uint8_t out[8];
    size_t n;
    int rc;
    int i;
    int saw_get = 0;
    int saw_set_mac = 0;

    if (start_fake(&f, FAKE_SEC, 0, &th, &port) != 0) {
        expect(0, "security fake target");
        return;
    }
    rc = open_originator(port, EIP_SECURITY_CLASS_1, &s);
    if (rc != 0 || !s) {
        fprintf(stderr, "FAIL: security originator start rc=%d (%s)\n", rc,
                strerror(rc < 0 ? -rc : rc));
        g_fail = 1;
        stop_fake(&f, th);
        return;
    }
    n = sizeof(out);
    rc = eip_stack_explicit_get(s, 1, 1, 1, out, &n);
    if (rc != 0) {
        fprintf(stderr, "FAIL: security Get rc=%d (%s)\n", rc,
                strerror(rc < 0 ? -rc : rc));
        dump_rr(&f);
        g_fail = 1;
    }
    rc = eip_stack_explicit_set(s, 4, 101, 3, data, sizeof(data));
    if (rc != 0) {
        fprintf(stderr, "FAIL: security Set rc=%d (%s)\n", rc,
                strerror(rc < 0 ? -rc : rc));
        dump_rr(&f);
        g_fail = 1;
    }
    for (i = 0; i < f.n_rr; i++) {
        const uint8_t *cip = NULL;
        const uint8_t *mac = NULL;
        size_t cip_len = 0;
        size_t mac_len = 0;
        uint16_t nitems = 0;
        if (parse_rr(f.rr[i], f.rr_len[i], &cip, &cip_len, &mac, &mac_len,
                     &nitems) != 0 || cip_len < 1) {
            continue;
        }
        if (cip[0] == 0x0E) {
            saw_get = 1;
            if (nitems != 2 || mac != NULL) {
                fprintf(stderr,
                        "FAIL: Get_Attribute_Single carried integrity MAC "
                        "(item_count %u mac_len %zu); Get does not need one\n",
                        nitems, mac_len);
                g_fail = 1;
            }
        }
        if (cip[0] == 0x10) {
            uint8_t material[4 + 256];
            uint8_t expect_mac[EIP_HMAC_LEN];
            uint32_t session = eip_rd_le32(f.rr[i] + 4);
            if (mac == NULL || mac_len != EIP_HMAC_LEN || nitems != 3 ||
                cip_len > 256) {
                fprintf(stderr,
                        "FAIL: Set_Attribute_Single has no integrity item "
                        "0x00C1 (item_count %u mac_len %zu). "
                        "security_class 1 must append HMAC-SHA256 over "
                        "session||CIP\n",
                        nitems, mac_len);
                g_fail = 1;
                continue;
            }
            eip_wr_le32(material, session);
            memcpy(material + 4, cip, cip_len);
            eip_hmac_sha256(g_psk, EIP_PSK_LEN, material, 4 + cip_len,
                            expect_mac);
            if (memcmp(mac, expect_mac, EIP_HMAC_LEN) != 0 ||
                session != 0x1234ABCDu) {
                fprintf(stderr,
                        "FAIL: integrity MAC mismatch session %#x "
                        "(HMAC-SHA256 PSK, msg = session LE || CIP request)\n",
                        session);
                g_fail = 1;
            } else {
                saw_set_mac = 1;
            }
        }
    }
    if (!saw_get || !saw_set_mac) {
        fprintf(stderr, "FAIL: security exchange missing Get or MAC-protected Set\n");
        dump_rr(&f);
        g_fail = 1;
    }
    eip_stack_destroy(s);
    stop_fake(&f, th);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    memset(g_psk, 0x11, sizeof(g_psk));
    test_tag_read();
    test_tag_write();
    test_split_reply();
    test_security_mac();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_12: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_12: ok\n");
    return 0;
}
