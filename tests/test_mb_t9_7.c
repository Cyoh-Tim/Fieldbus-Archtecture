/*
 * T9-7: an accepted server socket must set TCP_NODELAY.
 *
 * The Modbus Messaging on TCP/IP Implementation Guide allows a client to
 * pipeline requests. accept_clients() used to leave Nagle on, so the second
 * small response waits for the peer's delayed ACK (~40 ms on Linux). The
 * oracle test_pipelined_responses_not_delayed_by_nagle uses the same bound:
 * after 30 round trips (past the quick-ACK window), five pipelined pairs,
 * median time for both responses under 20 ms.
 *
 * The client disables delayed ACKs (TCP_QUICKACK=0) and sets TCP_NODELAY on
 * its own socket. Only the server accept path is under test.
 */
#include "mb_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define T9_7_WARMUP 30
#define T9_7_TRIALS 5
#define T9_7_LIMIT_MS 20.0
#define T9_7_ADU 12
#define T9_7_RSP 11
#define T9_7_BUDGET_MS 250.0

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

static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Drive the non-blocking server until `need` bytes arrive or the budget ends. */
static int pump_recv(mb_stack_t *s, int fd, uint8_t *buf, size_t need,
                     double budget_ms)
{
    size_t off = 0;
    double t0 = now_ms();
    while (off < need) {
        if (now_ms() - t0 > budget_ms) {
            return -1;
        }
        mb_stack_poll(s);
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        int rc = poll(&pfd, 1, 1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0 || (pfd.revents & POLLIN) == 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                return -1;
            }
            continue;
        }
        ssize_t n = recv(fd, buf + off, need - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void fill_fc03(uint8_t req[T9_7_ADU], uint16_t tid)
{
    wr_be16(req, tid);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 0);
    wr_be16(req + 10, 1);
}

static int set_quickack_off(int fd)
{
    int off = 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &off, sizeof(off));
}

static mb_stack_t *start_server(int *port_out)
{
    for (int attempt = 0; attempt < 5; attempt++) {
        int port = reserve_port();
        if (port <= 0) {
            continue;
        }
        mb_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.role = MB_ROLE_SERVER;
        snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
        cfg.port = port;
        cfg.unit_id = 1;
        cfg.n_holding = 16;
        cfg.n_input = 8;
        cfg.n_coil = 8;
        cfg.n_discrete = 8;
        mb_stack_t *s = mb_stack_create(&cfg);
        if (!s) {
            return NULL;
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
    int one = 1;
    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int exchange_one(mb_stack_t *s, int fd, uint16_t tid)
{
    uint8_t req[T9_7_ADU];
    uint8_t resp[T9_7_RSP];
    fill_fc03(req, tid);
    if (send_all(fd, req, sizeof(req)) != 0) {
        return -1;
    }
    if (pump_recv(s, fd, resp, sizeof(resp), T9_7_BUDGET_MS) != 0) {
        return -1;
    }
    if (rd_be16(resp) != tid || resp[7] != MB_FC_READ_HOLDING) {
        return -1;
    }
    return 0;
}

/* Both responses of one pipelined pair. Returns elapsed ms, or < 0. */
static double measure_pair(mb_stack_t *s, int fd, uint16_t tid)
{
    uint8_t req[T9_7_ADU * 2];
    uint8_t first[T9_7_RSP];
    uint8_t second[T9_7_RSP];
    double t0;
    fill_fc03(req, tid);
    fill_fc03(req + T9_7_ADU, (uint16_t)(tid + 1u));
    if (set_quickack_off(fd) != 0) {
        return -1;
    }
    t0 = now_ms();
    if (send_all(fd, req, sizeof(req)) != 0) {
        return -1;
    }
    if (pump_recv(s, fd, first, sizeof(first), T9_7_BUDGET_MS) != 0) {
        return -1;
    }
    if (set_quickack_off(fd) != 0) {
        return -1;
    }
    if (pump_recv(s, fd, second, sizeof(second), T9_7_BUDGET_MS) != 0) {
        return -1;
    }
    if (rd_be16(first) != tid || first[7] != MB_FC_READ_HOLDING ||
        rd_be16(second) != (uint16_t)(tid + 1u) ||
        second[7] != MB_FC_READ_HOLDING) {
        return -1;
    }
    return now_ms() - t0;
}

static void sort_doubles(double *v, int n)
{
    for (int i = 1; i < n; i++) {
        double x = v[i];
        int j = i;
        while (j > 0 && v[j - 1] > x) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = x;
    }
}

static void test_pipelined_responses_not_delayed(void)
{
    int port = -1;
    mb_stack_t *s = start_server(&port);
    int fd = -1;
    double delays[T9_7_TRIALS];
    char msg[256];
    int nmsg;

    expect(s != NULL, "start server");
    if (!s) {
        return;
    }
    fd = connect_client(port);
    expect(fd >= 0, "connect client");
    if (fd < 0) {
        mb_stack_destroy(s);
        return;
    }
    for (int i = 0; i < T9_7_WARMUP; i++) {
        if (exchange_one(s, fd, (uint16_t)(i + 1)) != 0) {
            snprintf(msg, sizeof(msg), "warmup exchange %d", i + 1);
            expect(0, msg);
            close(fd);
            mb_stack_destroy(s);
            return;
        }
    }
    for (int k = 0; k < T9_7_TRIALS; k++) {
        delays[k] = measure_pair(s, fd, (uint16_t)(0x100 + 2 * k));
        if (delays[k] < 0) {
            snprintf(msg, sizeof(msg), "pipelined pair %d (tid 0x%x)", k,
                     0x100 + 2 * k);
            expect(0, msg);
            close(fd);
            mb_stack_destroy(s);
            return;
        }
    }
    sort_doubles(delays, T9_7_TRIALS);
    nmsg = snprintf(msg, sizeof(msg),
                    "pipelined median %.1f ms (limit %.0f); sorted",
                    delays[T9_7_TRIALS / 2], T9_7_LIMIT_MS);
    for (int k = 0; k < T9_7_TRIALS && nmsg > 0 && (size_t)nmsg < sizeof(msg);
         k++) {
        int used = snprintf(msg + nmsg, sizeof(msg) - (size_t)nmsg, " %.1f",
                            delays[k]);
        if (used < 0) {
            break;
        }
        nmsg += used;
    }
    expect(delays[T9_7_TRIALS / 2] < T9_7_LIMIT_MS, msg);
    if (!g_fail) {
        printf("test_mb_t9_7: %s\n", msg);
    }
    close(fd);
    mb_stack_destroy(s);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_pipelined_responses_not_delayed();
    if (g_fail) {
        fprintf(stderr, "test_mb_t9_7: FAILED\n");
        return 1;
    }
    printf("test_mb_t9_7: OK\n");
    return 0;
}
