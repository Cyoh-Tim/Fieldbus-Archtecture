/*
 * T9-8: a non-blocking server send that returns EAGAIN must not drop the
 * master. The unsent tail stays on the connection and the next mb_stack_poll
 * retries it. Responses already accepted stay in order.
 *
 * The client advertises a tiny window (SO_RCVBUF) and does not read until
 * every request has been written. The request count overshoots the host TCP
 * send-buffer ceiling (tcp_wmem / wmem_max), so the server socket has to
 * return EAGAIN. Before the fix, serve_client() treats that as a hard send
 * failure and closes the fd.
 */
#include "mb_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define T9_8_REQ_LEN 12
#define T9_8_RSP_LEN 259
#define T9_8_QTY 125
#define T9_8_BUDGET_MS 20000.0

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int reserve_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return (int)ntohs(addr.sin_port);
}

/* Payload that must exceed the server send buffer while the client is not
 * reading. Linux reports SO_SNDBUF about twice the queued bytes and autotunes
 * up to tcp_wmem's max, so the count overshoots both ceilings. */
static int pipeline_count(void)
{
    long cap = 4L * 1024L * 1024L;
    long parts[3] = {0, 0, 0};
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_wmem", "r");
    if (f) {
        if (fscanf(f, "%ld %ld %ld", &parts[0], &parts[1], &parts[2]) == 3 &&
            parts[2] > cap) {
            cap = parts[2];
        }
        fclose(f);
    }
    f = fopen("/proc/sys/net/core/wmem_max", "r");
    if (f) {
        long wmax = 0;
        if (fscanf(f, "%ld", &wmax) == 1 && wmax > cap) {
            cap = wmax;
        }
        fclose(f);
    }
    long bytes = cap * 2L + 256L * 1024L;
    long frames = bytes / (long)T9_8_RSP_LEN + 64L;
    if (frames < 8000L) {
        frames = 8000L;
    }
    if (frames > 80000L) {
        frames = 80000L;
    }
    return (int)frames;
}

static void fill_fc03(uint8_t req[T9_8_REQ_LEN], uint16_t tid)
{
    wr_be16(req, tid);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 0);
    wr_be16(req + 10, T9_8_QTY);
}

static mb_stack_t *start_server(int *port_out)
{
    for (int attempt = 0; attempt < 5; attempt++) {
        int port = reserve_port();
        mb_cfg_t cfg;
        mb_stack_t *s;
        if (port <= 0) {
            continue;
        }
        memset(&cfg, 0, sizeof(cfg));
        cfg.role = MB_ROLE_SERVER;
        snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
        cfg.port = port;
        cfg.unit_id = 1;
        cfg.n_holding = T9_8_QTY;
        cfg.n_input = 8;
        cfg.n_coil = 8;
        cfg.n_discrete = 8;
        s = mb_stack_create(&cfg);
        if (!s) {
            return NULL;
        }
        for (uint16_t i = 0; i < T9_8_QTY; i++) {
            uint16_t hv = (uint16_t)(0xA000u + i);
            if (mb_stack_write_regs(s, MB_REG_HOLDING, i, &hv, 1) != 0) {
                mb_stack_destroy(s);
                return NULL;
            }
        }
        if (mb_stack_start(s) == 0) {
            *port_out = port;
            return s;
        }
        mb_stack_destroy(s);
    }
    return NULL;
}

static int connect_client(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int rcv = 4096;
    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) != 0 ||
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Peer close is the defect: EAGAIN used to make serve_client() close the fd. */
static int peer_closed(int fd)
{
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    int rc = poll(&pfd, 1, 0);
    if (rc < 0) {
        return errno != EINTR;
    }
    return (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0;
}

static int response_ok(const uint8_t *adu, int index)
{
    uint16_t tid = rd_be16(adu);
    uint16_t proto = rd_be16(adu + 2);
    uint16_t len = rd_be16(adu + 4);
    if (tid != (uint16_t)index || proto != 0 || len != 253 || adu[6] != 1 ||
        adu[7] != MB_FC_READ_HOLDING || adu[8] != 250) {
        return 0;
    }
    for (int i = 0; i < T9_8_QTY; i++) {
        uint16_t got = rd_be16(adu + 9 + i * 2);
        if (got != (uint16_t)(0xA000u + i)) {
            return 0;
        }
    }
    return 1;
}

static void release(mb_stack_t *s, int fd, void *blob)
{
    free(blob);
    if (fd >= 0) {
        close(fd);
    }
    mb_stack_destroy(s);
}

int main(void)
{
    int port = 0;
    int fd = -1;
    int n = pipeline_count();
    size_t req_total = (size_t)n * T9_8_REQ_LEN;
    size_t req_off = 0;
    uint8_t *blob = malloc(req_total);
    uint8_t acc[8192];
    size_t acc_len = 0;
    int got = 0;
    double t0;
    char msg[160];
    mb_stack_t *s = start_server(&port);

    fprintf(stderr, "T9-8 pipeline %d FC03 responses (%zu request bytes)\n", n,
            req_total);
    if (!s || !blob) {
        expect(0, "server or request buffer");
        release(s, fd, blob);
        return 1;
    }
    for (int i = 0; i < n; i++) {
        fill_fc03(blob + (size_t)i * T9_8_REQ_LEN, (uint16_t)i);
    }
    fd = connect_client(port);
    if (fd < 0) {
        expect(0, "connect");
        release(s, fd, blob);
        return 1;
    }
    for (int i = 0; i < 20; i++) {
        mb_stack_poll(s);
    }

    t0 = now_ms();
    while (req_off < req_total && !g_fail) {
        ssize_t w = send(fd, blob + req_off, req_total - req_off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0) {
            req_off += (size_t)w;
        } else if (w < 0 && errno != EINTR) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                memset(&pfd, 0, sizeof(pfd));
                pfd.fd = fd;
                pfd.events = POLLOUT;
                if (poll(&pfd, 1, 5) < 0 && errno != EINTR) {
                    expect(0, "poll for write");
                    break;
                }
                if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
                    snprintf(msg, sizeof(msg),
                             "server closed while requests were still queued "
                             "(%zu/%zu bytes, errno %d)",
                             req_off, req_total, errno);
                    expect(0, msg);
                    break;
                }
            } else {
                snprintf(msg, sizeof(msg),
                         "send failed (%zu/%zu bytes, errno %d)", req_off,
                         req_total, errno);
                expect(0, msg);
                break;
            }
        }
        mb_stack_poll(s);
        if (peer_closed(fd)) {
            snprintf(msg, sizeof(msg),
                     "server closed on a full send buffer (%zu/%zu request "
                     "bytes written)",
                     req_off, req_total);
            expect(0, msg);
            break;
        }
        if (now_ms() - t0 > T9_8_BUDGET_MS) {
            snprintf(msg, sizeof(msg),
                     "timed out writing requests (%zu/%zu bytes)", req_off,
                     req_total);
            expect(0, msg);
            break;
        }
    }
    if (g_fail) {
        release(s, fd, blob);
        return 1;
    }

    /* The bytes that did not fit stay queued. Further polls must retry,
     * not close, even though the client is still not reading. */
    for (int i = 0; i < 50; i++) {
        mb_stack_poll(s);
        if (peer_closed(fd)) {
            expect(0, "server closed while retrying a blocked send");
            release(s, fd, blob);
            return 1;
        }
    }

    t0 = now_ms();
    while (got < n && !g_fail) {
        mb_stack_poll(s);
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        int rc = poll(&pfd, 1, 5);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            expect(0, "poll for read");
            break;
        }
        if (rc == 0) {
            if (now_ms() - t0 > T9_8_BUDGET_MS) {
                snprintf(msg, sizeof(msg),
                         "timed out reading responses (%d/%d)", got, n);
                expect(0, msg);
                break;
            }
            continue;
        }
        if ((pfd.revents & POLLIN) == 0) {
            snprintf(msg, sizeof(msg),
                     "connection closed before response %d/%d (revents 0x%x)",
                     got, n, pfd.revents);
            expect(0, msg);
            break;
        }
        if (acc_len >= sizeof(acc)) {
            expect(0, "response reassembly buffer stuck");
            break;
        }
        ssize_t r = recv(fd, acc + acc_len, sizeof(acc) - acc_len, 0);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            snprintf(msg, sizeof(msg), "recv errno %d after %d/%d responses",
                     errno, got, n);
            expect(0, msg);
            break;
        }
        if (r == 0) {
            snprintf(msg, sizeof(msg),
                     "server closed after %d/%d responses", got, n);
            expect(0, msg);
            break;
        }
        acc_len += (size_t)r;
        while (acc_len >= T9_8_RSP_LEN) {
            if (!response_ok(acc, got)) {
                snprintf(msg, sizeof(msg),
                         "response %d mismatch (tid 0x%04x len %u fc 0x%02x)",
                         got, rd_be16(acc), rd_be16(acc + 4), acc[7]);
                expect(0, msg);
                break;
            }
            memmove(acc, acc + T9_8_RSP_LEN, acc_len - T9_8_RSP_LEN);
            acc_len -= T9_8_RSP_LEN;
            got++;
        }
    }
    if (!g_fail) {
        snprintf(msg, sizeof(msg), "got %d/%d responses", got, n);
        expect(got == n && acc_len == 0, msg);
    }

    release(s, fd, blob);
    if (g_fail) {
        return 1;
    }
    fprintf(stderr, "ok %d responses\n", n);
    return 0;
}
