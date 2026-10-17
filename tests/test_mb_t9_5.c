/*
 * T9-5: a Modbus client connect() to a host that never answers SYN must
 * return. The kernel SYN retransmit window is tens of seconds to minutes;
 * the oracle (test_client_connect_to_silent_host_is_bounded) requires
 * mb_stack_start and each mb_stack_poll to come back within 3000 ms.
 *
 * The peer is a listen(backlog 0) socket whose accept queue is already
 * full, so Linux drops further SYNs (tcp_abort_on_overflow=0). A closed
 * port would RST immediately and would not reproduce the stall.
 */
#include "mb_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define T9_5_BOUND_MS 3000
#define T9_5_STEP_BUDGET_MS 4000
#define T9_5_CLIENT_TIMEOUT_MS 300
#define T9_5_FILLERS 8

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

static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int loopback_addr(struct sockaddr_in *addr, int port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr) == 1 ? 0 : -1;
}

/* Returns the port, or -1. Filler fds stay open in keep[0..*nkeep). */
static int open_black_hole(int *keep, int keep_cap, int *nkeep)
{
    *nkeep = 0;
    if (keep_cap < T9_5_FILLERS + 1) {
        return -1;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in addr;
    if (loopback_addr(&addr, 0) != 0 ||
        bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(ls, 0) != 0) {
        close(ls);
        return -1;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(ls, (struct sockaddr *)&addr, &alen) != 0) {
        close(ls);
        return -1;
    }
    int port = ntohs(addr.sin_port);
    keep[(*nkeep)++] = ls;
    for (int i = 0; i < T9_5_FILLERS; i++) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (c < 0) {
            break;
        }
        if (set_nonblock(c) != 0) {
            close(c);
            break;
        }
        int rc = connect(c, (struct sockaddr *)&addr, sizeof(addr));
        if (rc != 0 && errno != EINPROGRESS && errno != EALREADY) {
            close(c);
            continue;
        }
        keep[(*nkeep)++] = c;
    }
    sleep_ms(200);
    return port;
}

static void close_kept(int *keep, int nkeep)
{
    for (int i = 0; i < nkeep; i++) {
        if (keep[i] >= 0) {
            close(keep[i]);
        }
    }
}

/* SO_SNDTIMEO probe: the queue must drop SYN. Success or an instant RST
 * means this process cannot reproduce T9-5. */
static int fixture_drops_syn(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "FAIL: T9-5 fixture socket\n");
        return -1;
    }
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 0;
    tv.tv_usec = 400000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    loopback_addr(&addr, port);
    double t0 = now_ms();
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    double ms = now_ms() - t0;
    close(fd);
    if (rc == 0 || ms < 200.0) {
        fprintf(stderr,
                "FAIL: T9-5 fixture did not drop SYN (rc=%d ms=%.1f)\n", rc,
                ms);
        return -1;
    }
    if (err != ETIMEDOUT && err != EINPROGRESS && err != EAGAIN &&
        err != EWOULDBLOCK) {
        fprintf(stderr, "FAIL: T9-5 fixture errno=%d (%s) ms=%.1f\n", err,
                strerror(err), ms);
        return -1;
    }
    return 0;
}

static void wrline(int fd, const char *line)
{
    size_t n = strlen(line);
    while (n > 0) {
        ssize_t w = write(fd, line, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        line += w;
        n -= (size_t)w;
    }
}

static void child_silent_connect(int wr, int port)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_CLIENT;
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.client_timeout_ms = T9_5_CLIENT_TIMEOUT_MS;
    cfg.n_holding = 8;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    mb_stack_t *s = mb_stack_create(&cfg);
    if (!s) {
        wrline(wr, "ERR create\n");
        _exit(1);
    }
    char line[128];
    double t0 = now_ms();
    int rc = mb_stack_start(s);
    snprintf(line, sizeof(line), "START %d %d %.1f\n", rc,
             mb_stack_connected(s), now_ms() - t0);
    wrline(wr, line);
    for (int i = 0; i < 2; i++) {
        t0 = now_ms();
        mb_stack_poll(s);
        snprintf(line, sizeof(line), "POLL %d %.1f\n", mb_stack_connected(s),
                 now_ms() - t0);
        wrline(wr, line);
    }
    mb_stack_destroy(s);
    wrline(wr, "DONE\n");
    _exit(0);
}

static int read_line_budget(int fd, const char *step, char *buf, size_t cap)
{
    size_t n = 0;
    double t0 = now_ms();
    while (n + 1 < cap) {
        int remain = T9_5_STEP_BUDGET_MS - (int)(now_ms() - t0);
        if (remain < 0) {
            remain = 0;
        }
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, remain);
        if (pr <= 0) {
            fprintf(stderr,
                    "FAIL: T9-5 %s did not return within %d ms "
                    "(blocking connect)\n",
                    step, T9_5_STEP_BUDGET_MS);
            return -1;
        }
        char c = 0;
        ssize_t r = read(fd, &c, 1);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            fprintf(stderr, "FAIL: T9-5 %s pipe closed\n", step);
            return -1;
        }
        if (c == '\n') {
            buf[n] = '\0';
            return 0;
        }
        buf[n++] = c;
    }
    fprintf(stderr, "FAIL: T9-5 %s line too long\n", step);
    return -1;
}

static void test_silent_host_is_bounded(void)
{
    int keep[T9_5_FILLERS + 1];
    int nkeep = 0;
    int port = open_black_hole(keep, T9_5_FILLERS + 1, &nkeep);
    if (port <= 0 || fixture_drops_syn(port) != 0) {
        if (port <= 0) {
            fprintf(stderr, "FAIL: T9-5 black-hole listen\n");
        }
        g_fail = 1;
        close_kept(keep, nkeep);
        return;
    }

    int fds[2];
    if (pipe(fds) != 0) {
        fprintf(stderr, "FAIL: T9-5 pipe\n");
        g_fail = 1;
        close_kept(keep, nkeep);
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "FAIL: T9-5 fork\n");
        g_fail = 1;
        close(fds[0]);
        close(fds[1]);
        close_kept(keep, nkeep);
        return;
    }
    if (pid == 0) {
        close(fds[0]);
        child_silent_connect(fds[1], port);
    }
    close(fds[1]);

    char line[128];
    int rc = 0;
    int connected = 1;
    double start_ms = 0;
    double poll_ms[2] = {0, 0};
    int ok = 1;
    if (read_line_budget(fds[0], "START", line, sizeof(line)) != 0) {
        ok = 0;
    } else if (sscanf(line, "START %d %d %lf", &rc, &connected, &start_ms) !=
               3) {
        fprintf(stderr, "FAIL: T9-5 bad START line '%s'\n", line);
        ok = 0;
    } else if (rc != -ETIMEDOUT || connected != 0 || start_ms < 50.0 ||
               start_ms > T9_5_BOUND_MS) {
        fprintf(stderr,
                "FAIL: T9-5 START rc=%d connected=%d ms=%.1f "
                "(want %d, connected=0, 50..%d ms)\n",
                rc, connected, start_ms, -ETIMEDOUT, T9_5_BOUND_MS);
        ok = 0;
    }
    for (int i = 0; ok && i < 2; i++) {
        char step[16];
        snprintf(step, sizeof(step), "POLL%d", i + 1);
        int pc = 1;
        if (read_line_budget(fds[0], step, line, sizeof(line)) != 0) {
            ok = 0;
            break;
        }
        if (sscanf(line, "POLL %d %lf", &pc, &poll_ms[i]) != 2) {
            fprintf(stderr, "FAIL: T9-5 bad POLL line '%s'\n", line);
            ok = 0;
            break;
        }
        int too_fast = (i == 0 && poll_ms[i] < 50.0);
        if (pc != 0 || too_fast || poll_ms[i] > T9_5_BOUND_MS) {
            fprintf(stderr,
                    "FAIL: T9-5 POLL%d connected=%d ms=%.1f "
                    "(want connected=0, <=%d ms)\n",
                    i + 1, pc, poll_ms[i], T9_5_BOUND_MS);
            ok = 0;
        }
    }
    if (!ok) {
        g_fail = 1;
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    close(fds[0]);
    close_kept(keep, nkeep);
}

static void test_refused_port_fails_fast(void)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    expect(ls >= 0, "T9-5 refused socket");
    if (ls < 0) {
        return;
    }
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in addr;
    loopback_addr(&addr, 0);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "FAIL: T9-5 refused bind\n");
        g_fail = 1;
        close(ls);
        return;
    }
    socklen_t alen = sizeof(addr);
    getsockname(ls, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);
    close(ls);

    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_CLIENT;
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.client_timeout_ms = T9_5_CLIENT_TIMEOUT_MS;
    cfg.n_holding = 8;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "T9-5 refused create");
    if (!s) {
        return;
    }
    double t0 = now_ms();
    int rc = mb_stack_start(s);
    double ms = now_ms() - t0;
    if (rc != -ECONNREFUSED || mb_stack_connected(s) || ms > 1000.0) {
        fprintf(stderr,
                "FAIL: T9-5 refused port rc=%d connected=%d ms=%.1f "
                "(want %d, connected=0, <=1000 ms)\n",
                rc, mb_stack_connected(s), ms, -ECONNREFUSED);
        g_fail = 1;
    }
    mb_stack_destroy(s);
}

static void test_listening_host_connects(void)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    expect(ls >= 0, "T9-5 listen socket");
    if (ls < 0) {
        return;
    }
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in addr;
    loopback_addr(&addr, 0);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(ls, 1) != 0) {
        fprintf(stderr, "FAIL: T9-5 success-path listen\n");
        g_fail = 1;
        close(ls);
        return;
    }
    socklen_t alen = sizeof(addr);
    getsockname(ls, (struct sockaddr *)&addr, &alen);
    int port = ntohs(addr.sin_port);

    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_CLIENT;
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.client_timeout_ms = T9_5_CLIENT_TIMEOUT_MS;
    cfg.n_holding = 8;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "T9-5 success-path create");
    if (!s) {
        close(ls);
        return;
    }
    double t0 = now_ms();
    int rc = mb_stack_start(s);
    double ms = now_ms() - t0;
    if (rc != 0 || !mb_stack_connected(s) || ms > 1000.0) {
        fprintf(stderr,
                "FAIL: T9-5 listening host rc=%d connected=%d ms=%.1f\n", rc,
                mb_stack_connected(s), ms);
        g_fail = 1;
    }
    mb_stack_destroy(s);
    close(ls);
}

int main(void)
{
    test_listening_host_connects();
    test_refused_port_fails_fast();
    test_silent_host_is_bounded();
    if (g_fail) {
        fprintf(stderr, "test_mb_t9_5: FAILED\n");
        return 1;
    }
    printf("test_mb_t9_5: OK\n");
    return 0;
}
