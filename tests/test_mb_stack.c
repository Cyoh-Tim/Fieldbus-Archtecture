#include "mb_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
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

static void test_read_holding(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.port = 1502;
    cfg.unit_id = 1;
    cfg.n_holding = 64;
    cfg.n_input = 64;
    cfg.n_coil = 64;
    cfg.n_discrete = 64;

    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "create stack");

    uint16_t vals[2] = {0x1234, 0xABCD};
    expect(mb_stack_write_regs(s, MB_REG_HOLDING, 0, vals, 2) == 0,
           "seed holding");

    uint8_t req[12];
    wr_be16(req, 0x0001);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 0);
    wr_be16(req + 10, 2);

    uint8_t resp[64];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "handle read holding");
    expect(resp_len == 13, "read holding resp len");
    expect(resp[7] == MB_FC_READ_HOLDING, "fc echo");
    expect(resp[8] == 4, "byte count");
    expect(rd_be16(resp + 9) == 0x1234, "reg0");
    expect(rd_be16(resp + 11) == 0xABCD, "reg1");

    mb_stack_destroy(s);
}

static void test_write_single_coil(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 16;
    cfg.n_input = 16;
    cfg.n_coil = 16;
    cfg.n_discrete = 16;

    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "create stack coil");

    uint8_t req[12];
    wr_be16(req, 0x0002);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_WRITE_SINGLE_COIL;
    wr_be16(req + 8, 0); /* coil 0 */
    wr_be16(req + 10, 0xFF00);

    uint8_t resp[32];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "handle write coil");
    expect(resp_len == 12, "write coil resp len");

    uint8_t bit = 0;
    expect(mb_stack_read_bits(s, MB_REG_COIL, 0, &bit, 1) == 0, "read coil");
    expect(bit == 1, "coil set");

    mb_stack_destroy(s);
}

static void test_string_bytes(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 32;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;

    mb_stack_t *s = mb_stack_create(&cfg);
    const char *barcode = "ABC123";
    expect(mb_stack_write_bytes(s, MB_REG_HOLDING, 0, (const uint8_t *)barcode,
                                6) == 0,
           "write barcode bytes");

    uint8_t out[8];
    memset(out, 0, sizeof(out));
    expect(mb_stack_read_bytes(s, MB_REG_HOLDING, 0, out, 6) == 0,
           "read barcode bytes");
    expect(memcmp(out, barcode, 6) == 0, "barcode match");

    /* Holding map packs 2 chars per register, big-endian. */
    uint16_t r0 = 0, r1 = 0, r2 = 0;
    mb_stack_read_regs(s, MB_REG_HOLDING, 0, &r0, 1);
    mb_stack_read_regs(s, MB_REG_HOLDING, 1, &r1, 1);
    mb_stack_read_regs(s, MB_REG_HOLDING, 2, &r2, 1);
    expect(r0 == 0x4142, "AB");
    expect(r1 == 0x4331, "C1");
    expect(r2 == 0x3233, "23");

    mb_stack_destroy(s);
}

static void test_exception_illegal_address(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 10;
    cfg.n_input = 10;
    cfg.n_coil = 10;
    cfg.n_discrete = 10;

    mb_stack_t *s = mb_stack_create(&cfg);
    uint8_t req[12];
    wr_be16(req, 1);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 9);
    wr_be16(req + 10, 2); /* overflows map */

    uint8_t resp[32];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "handle OOB");
    expect(resp_len == 9, "exception len");
    expect(resp[7] == (MB_FC_READ_HOLDING | 0x80), "exception fc");
    expect(resp[8] == MB_EX_ILLEGAL_ADDRESS, "exception code");

    mb_stack_destroy(s);
}

static void test_mask_write(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 16;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;
    mb_stack_t *s = mb_stack_create(&cfg);
    uint16_t seed = 0xFFFF;
    mb_stack_write_regs(s, MB_REG_HOLDING, 0, &seed, 1);

    uint8_t req[14];
    wr_be16(req, 9);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 8);
    req[6] = 1;
    req[7] = MB_FC_MASK_WRITE_REG;
    wr_be16(req + 8, 0);
    wr_be16(req + 10, 0xF0F0); /* and */
    wr_be16(req + 12, 0x000F); /* or */
    uint8_t resp[32];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "mask write");
    uint16_t out = 0;
    mb_stack_read_regs(s, MB_REG_HOLDING, 0, &out, 1);
    /* (0xFFFF & 0xF0F0) | (0x000F & ~0xF0F0) = 0xF0F0 | 0x000F = 0xF0FF */
    expect(out == 0xF0FF, "mask result");
    mb_stack_destroy(s);
}

static int mb_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_g7_mb_idle_and_per_ip(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.port = 16152;
    cfg.unit_id = 1;
    cfg.max_clients = 4;
    cfg.idle_timeout_ms = 200;
    cfg.max_conn_per_ip = 1;
    cfg.n_holding = 16;
    cfg.n_input = 16;
    cfg.n_coil = 16;
    cfg.n_discrete = 16;
    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "g7 mb create");
    if (!s) {
        return;
    }
    if (mb_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: g7 mb start\n");
        g_fail = 1;
        mb_stack_destroy(s);
        return;
    }
    int a = mb_connect(16152);
    expect(a >= 0, "g7 mb connect a");
    for (int i = 0; i < 20; i++) {
        mb_stack_poll(s);
        usleep(1000);
    }
    int b = mb_connect(16152);
    expect(b >= 0, "g7 mb connect b");
    for (int i = 0; i < 20; i++) {
        mb_stack_poll(s);
        usleep(1000);
    }
    uint8_t tmp[8];
    ssize_t n = recv(b, tmp, sizeof(tmp), MSG_DONTWAIT);
    expect(n == 0 || n < 0, "g7 mb per-ip dropped");
    if (b >= 0) {
        close(b);
    }
    usleep(250000);
    for (int i = 0; i < 20; i++) {
        mb_stack_poll(s);
        usleep(1000);
    }
    n = recv(a, tmp, sizeof(tmp), MSG_DONTWAIT);
    expect(n == 0 || n < 0, "g7 mb idle dropped");
    if (a >= 0) {
        close(a);
    }
    mb_stack_destroy(s);
}

/* T9-1: one late response must not permanently desync later transactions.
 * Measured before the fix: txn0 -ETIMEDOUT (-110), txn1..4 -EIO (-5),
 * connected stays 1. */
enum {
    T9_MODE_DELAY_ADDR0 = 0,
    T9_MODE_BAD_TID_ADDR0 = 1
};

static int g_t9_mode;
static int g_t9_late_wr = -1;

static int t9_read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
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

static int t9_write_pipe(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
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

static int t9_write_full(int fd, const uint8_t *buf, size_t len)
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

static void t9_send_read_resp(int fd, uint16_t tid, uint8_t unit, uint16_t value)
{
    uint8_t resp[11];
    wr_be16(resp, tid);
    wr_be16(resp + 2, 0);
    wr_be16(resp + 4, 5);
    resp[6] = unit;
    resp[7] = MB_FC_READ_HOLDING;
    resp[8] = 2;
    wr_be16(resp + 9, value);
    (void)t9_write_full(fd, resp, sizeof(resp));
}

static void t9_handle_conn(int fd)
{
    int did_addr0 = 0;
    for (;;) {
        uint8_t req[12];
        if (t9_read_full(fd, req, sizeof(req)) != 0) {
            break;
        }
        uint16_t tid = rd_be16(req);
        uint16_t addr = rd_be16(req + 8);
        uint16_t value = 0x2222;
        int late = 0;
        if (!did_addr0 && addr == 0) {
            did_addr0 = 1;
            if (g_t9_mode == T9_MODE_DELAY_ADDR0) {
                usleep(300000);
                value = 0x1111;
                late = 1;
            } else {
                tid = (uint16_t)(tid + 1u);
                value = 0x1111;
            }
        }
        t9_send_read_resp(fd, tid, req[6], value);
        if (late && g_t9_late_wr >= 0) {
            uint8_t b = 1;
            if (write(g_t9_late_wr, &b, 1) < 0) {
                break;
            }
        }
        /* Hold the next ADU so the client reads this response alone.
         * If the following response is already queued, one recv (up to
         * MB_ADU_MAX) swallows both and the stream can resync by accident.
         * The defect is the opposite: each later recv gets only the previous
         * TID and every transaction stays -EIO. */
        usleep(80000);
    }
    close(fd);
    _exit(0);
}

static void t9_accept_loop(int lfd)
{
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            _exit(0);
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        pid_t p = fork();
        if (p < 0) {
            close(fd);
            continue;
        }
        if (p == 0) {
            close(lfd);
            t9_handle_conn(fd);
        }
        close(fd);
    }
}

static pid_t t9_start_server(int mode, int *port, int *late_rd)
{
    int port_pipe[2];
    int late_pipe[2];
    *port = -1;
    *late_rd = -1;
    if (pipe(port_pipe) != 0 || pipe(late_pipe) != 0) {
        return -1;
    }
    g_t9_mode = mode;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        close(port_pipe[0]);
        close(port_pipe[1]);
        close(late_pipe[0]);
        close(late_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        setpgid(0, 0);
        close(port_pipe[0]);
        close(late_pipe[0]);
        g_t9_late_wr = late_pipe[1];
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            listen(lfd, 16) != 0) {
            _exit(1);
        }
        socklen_t alen = sizeof(addr);
        if (getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0) {
            _exit(1);
        }
        uint8_t raw[2];
        wr_be16(raw, ntohs(addr.sin_port));
        if (t9_write_pipe(port_pipe[1], raw, sizeof(raw)) != 0) {
            _exit(1);
        }
        close(port_pipe[1]);
        t9_accept_loop(lfd);
        _exit(0);
    }
    setpgid(pid, pid);
    close(port_pipe[1]);
    close(late_pipe[1]);
    uint8_t be[2];
    if (t9_read_full(port_pipe[0], be, sizeof(be)) != 0) {
        close(port_pipe[0]);
        close(late_pipe[0]);
        kill(-pid, SIGTERM);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return -1;
    }
    close(port_pipe[0]);
    *port = (int)rd_be16(be);
    *late_rd = late_pipe[0];
    return pid;
}

static void t9_stop_server(pid_t pid, int late_rd)
{
    if (pid > 0) {
        kill(-pid, SIGTERM);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    if (late_rd >= 0) {
        close(late_rd);
    }
}

static int t9_wait_late(int late_rd, int timeout_ms)
{
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = late_rd;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) {
        return -1;
    }
    uint8_t b = 0;
    if (read(late_rd, &b, 1) != 1) {
        return -1;
    }
    return 0;
}

static mb_stack_t *t9_start_client(int port)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_CLIENT;
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.client_timeout_ms = 200;
    cfg.n_holding = 16;
    cfg.n_input = 16;
    cfg.n_coil = 16;
    cfg.n_discrete = 16;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    mb_stack_t *s = mb_stack_create(&cfg);
    if (!s || mb_stack_start(s) != 0) {
        mb_stack_destroy(s);
        return NULL;
    }
    return s;
}

static void test_t9_1_timeout_then_permanent_eio(void)
{
    int port = -1;
    int late_rd = -1;
    pid_t pid = t9_start_server(T9_MODE_DELAY_ADDR0, &port, &late_rd);
    if (pid < 0 || port <= 0) {
        fprintf(stderr, "FAIL: T9-1 listen\n");
        g_fail = 1;
        t9_stop_server(pid, late_rd);
        return;
    }
    mb_stack_t *client = t9_start_client(port);
    if (!client) {
        fprintf(stderr, "FAIL: T9-1 client start\n");
        g_fail = 1;
        t9_stop_server(pid, late_rd);
        return;
    }

    int rc[5];
    rc[0] = mb_stack_client_read(client, MB_REG_HOLDING, 0, 1);
    int connected = mb_stack_connected(client);
    for (int i = 1; i < 5; i++) {
        rc[i] = mb_stack_client_read(client, MB_REG_HOLDING, 1, 1);
    }
    int recovered_shape = rc[0] == -ETIMEDOUT && connected == 0;
    for (int i = 1; i < 5; i++) {
        if (rc[i] != -EAGAIN) {
            recovered_shape = 0;
        }
    }
    if (!recovered_shape) {
        fprintf(stderr,
                "FAIL: T9-1 txn0=%d txn1=%d txn2=%d txn3=%d txn4=%d connected=%d "
                "(want txn0=%d, txn1..4=%d, connected=0)\n",
                rc[0], rc[1], rc[2], rc[3], rc[4], connected, -ETIMEDOUT,
                -EAGAIN);
        g_fail = 1;
    }

    if (t9_wait_late(late_rd, 1000) != 0) {
        fprintf(stderr, "FAIL: T9-1 late response was not attempted\n");
        g_fail = 1;
    }
    /* Reconnect backoff starts at 100 ms. Wait it out, then the next read
     * must open a new connection and return the fresh value, not 0x1111. */
    usleep(150000);
    int rc_ok = mb_stack_client_read(client, MB_REG_HOLDING, 1, 1);
    uint16_t reg0 = 0xFFFF;
    uint16_t reg1 = 0;
    mb_stack_read_regs(client, MB_REG_HOLDING, 0, &reg0, 1);
    mb_stack_read_regs(client, MB_REG_HOLDING, 1, &reg1, 1);
    int rc_ok2 = mb_stack_client_read(client, MB_REG_HOLDING, 1, 1);
    uint16_t reg1b = 0;
    mb_stack_read_regs(client, MB_REG_HOLDING, 1, &reg1b, 1);
    if (rc_ok != 0 || rc_ok2 != 0 || reg1 != 0x2222 || reg1b != 0x2222 ||
        reg0 == 0x1111 || !mb_stack_connected(client)) {
        fprintf(stderr,
                "FAIL: T9-1 recovery rc=%d rc2=%d reg0=0x%04x reg1=0x%04x "
                "reg1b=0x%04x connected=%d (stale delayed value is 0x1111)\n",
                rc_ok, rc_ok2, reg0, reg1, reg1b, mb_stack_connected(client));
        g_fail = 1;
    }

    mb_stack_destroy(client);
    t9_stop_server(pid, late_rd);
}

static void test_t9_1_tid_mismatch_drops(void)
{
    int port = -1;
    int late_rd = -1;
    pid_t pid = t9_start_server(T9_MODE_BAD_TID_ADDR0, &port, &late_rd);
    if (pid < 0 || port <= 0) {
        fprintf(stderr, "FAIL: T9-1 mismatch listen\n");
        g_fail = 1;
        t9_stop_server(pid, late_rd);
        return;
    }
    mb_stack_t *client = t9_start_client(port);
    if (!client) {
        fprintf(stderr, "FAIL: T9-1 mismatch client start\n");
        g_fail = 1;
        t9_stop_server(pid, late_rd);
        return;
    }

    int rc = mb_stack_client_read(client, MB_REG_HOLDING, 0, 1);
    int connected = mb_stack_connected(client);
    int rc_again = mb_stack_client_read(client, MB_REG_HOLDING, 1, 1);
    if (rc != -EIO || connected != 0 || rc_again != -EAGAIN) {
        fprintf(stderr,
                "FAIL: T9-1 mismatch rc=%d connected=%d immediate=%d "
                "(want %d, connected=0, %d)\n",
                rc, connected, rc_again, -EIO, -EAGAIN);
        g_fail = 1;
    }
    usleep(150000);
    int rc_ok = mb_stack_client_read(client, MB_REG_HOLDING, 1, 1);
    uint16_t reg0 = 0xFFFF;
    uint16_t reg1 = 0;
    mb_stack_read_regs(client, MB_REG_HOLDING, 0, &reg0, 1);
    mb_stack_read_regs(client, MB_REG_HOLDING, 1, &reg1, 1);
    if (rc_ok != 0 || reg1 != 0x2222 || reg0 == 0x1111 ||
        !mb_stack_connected(client)) {
        fprintf(stderr,
                "FAIL: T9-1 mismatch recovery rc=%d reg0=0x%04x reg1=0x%04x "
                "connected=%d\n",
                rc_ok, reg0, reg1, mb_stack_connected(client));
        g_fail = 1;
    }

    mb_stack_destroy(client);
    t9_stop_server(pid, late_rd);
}

int main(void)
{
    test_read_holding();
    test_write_single_coil();
    test_string_bytes();
    test_exception_illegal_address();
    test_mask_write();
    test_g7_mb_idle_and_per_ip();
    test_t9_1_timeout_then_permanent_eio();
    test_t9_1_tid_mismatch_drops();
    if (g_fail) {
        fprintf(stderr, "test_mb_stack: FAILED\n");
        return 1;
    }
    printf("test_mb_stack: OK\n");
    return 0;
}
