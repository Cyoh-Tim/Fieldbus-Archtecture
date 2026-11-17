/*
 * T9-9: the client TID counter is three function-level statics
 * (client_txn, mb_stack_client_write_regs, mb_stack_client_write_bits).
 * Each starts at 1 and every stack instance shares them, so one connection's
 * read, register write, and coil write all reuse TID 1, and a second
 * instance's first TID moves with the first instance's traffic.
 *
 * After the fix one counter lives on the stack instance. Four transactions
 * on instance 0 are TID 1,2,3,4. Instance 1's first TID is 1.
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
#include <sys/wait.h>
#include <unistd.h>

#define T9_9_REQ_LEN 12
#define T9_9_NREC 5

static int g_fail;

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int read_full(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
    size_t off = 0;
    while (off < len) {
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            return -1;
        }
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

static int write_full(int fd, const uint8_t *buf, size_t len)
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

/* FC03/04: one register. FC05/06: echo the 12-byte request. */
static int reply_req(int fd, const uint8_t req[T9_9_REQ_LEN])
{
    uint8_t fc = req[7];
    if (fc == MB_FC_READ_HOLDING || fc == MB_FC_READ_INPUT) {
        uint8_t resp[11];
        memcpy(resp, req, 4);
        wr_be16(resp + 4, 5);
        resp[6] = req[6];
        resp[7] = fc;
        resp[8] = 2;
        wr_be16(resp + 9, 0x1234);
        return write_full(fd, resp, sizeof(resp));
    }
    return write_full(fd, req, T9_9_REQ_LEN);
}

static void handle_conn(int fd, int conn, int rec_wr)
{
    for (;;) {
        uint8_t req[T9_9_REQ_LEN];
        uint8_t rec[4];
        if (read_full(fd, req, sizeof(req), 2000) != 0) {
            break;
        }
        rec[0] = (uint8_t)conn;
        rec[1] = req[7];
        rec[2] = req[0];
        rec[3] = req[1];
        if (write_full(rec_wr, rec, sizeof(rec)) != 0) {
            break;
        }
        if (reply_req(fd, req) != 0) {
            break;
        }
    }
    close(fd);
    _exit(0);
}

static void accept_loop(int lfd, int rec_wr, int acc_wr)
{
    int conn = 0;
    signal(SIGCHLD, SIG_IGN);
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        uint8_t note = 1;
        int one = 1;
        pid_t p;
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            _exit(0);
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (write_full(acc_wr, &note, 1) != 0) {
            close(fd);
            _exit(0);
        }
        p = fork();
        if (p < 0) {
            close(fd);
            continue;
        }
        if (p == 0) {
            close(lfd);
            handle_conn(fd, conn, rec_wr);
        }
        conn++;
        close(fd);
    }
}

static pid_t start_server(int *port, int *rec_rd, int *acc_rd)
{
    int port_pipe[2];
    int rec_pipe[2];
    int acc_pipe[2];
    pid_t pid;
    *port = -1;
    *rec_rd = -1;
    *acc_rd = -1;
    if (pipe(port_pipe) != 0 || pipe(rec_pipe) != 0 || pipe(acc_pipe) != 0) {
        return -1;
    }
    fflush(NULL);
    pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        int lfd;
        int one = 1;
        struct sockaddr_in addr;
        socklen_t alen;
        uint8_t raw[2];
        setpgid(0, 0);
        signal(SIGPIPE, SIG_IGN);
        close(port_pipe[0]);
        close(rec_pipe[0]);
        close(acc_pipe[0]);
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
            listen(lfd, 8) != 0) {
            _exit(1);
        }
        alen = sizeof(addr);
        if (getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0) {
            _exit(1);
        }
        wr_be16(raw, ntohs(addr.sin_port));
        if (write_full(port_pipe[1], raw, sizeof(raw)) != 0) {
            _exit(1);
        }
        close(port_pipe[1]);
        accept_loop(lfd, rec_pipe[1], acc_pipe[1]);
        _exit(0);
    }
    setpgid(pid, pid);
    close(port_pipe[1]);
    close(rec_pipe[1]);
    close(acc_pipe[1]);
    {
        uint8_t be[2];
        if (read_full(port_pipe[0], be, sizeof(be), 1000) != 0) {
            close(port_pipe[0]);
            close(rec_pipe[0]);
            close(acc_pipe[0]);
            kill(-pid, SIGTERM);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            return -1;
        }
        close(port_pipe[0]);
        *port = (int)rd_be16(be);
        *rec_rd = rec_pipe[0];
        *acc_rd = acc_pipe[0];
    }
    return pid;
}

static void stop_server(pid_t pid, int rec_rd, int acc_rd)
{
    if (pid > 0) {
        kill(-pid, SIGTERM);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    if (rec_rd >= 0) {
        close(rec_rd);
    }
    if (acc_rd >= 0) {
        close(acc_rd);
    }
}

static mb_stack_t *start_client(int port)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_CLIENT;
    cfg.port = port;
    cfg.unit_id = 1;
    cfg.client_timeout_ms = 1000;
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

static void test_tid_per_instance(void)
{
    int port = -1;
    int rec_rd = -1;
    int acc_rd = -1;
    pid_t pid = start_server(&port, &rec_rd, &acc_rd);
    mb_stack_t *a;
    mb_stack_t *b;
    uint16_t reg = 0x04D2;
    uint8_t bit = 1;
    int rc[T9_9_NREC];
    uint8_t raw[T9_9_NREC * 4];
    uint8_t note = 0;
    unsigned tid[T9_9_NREC];
    unsigned conn[T9_9_NREC];
    int i;
    int unique;

    if (pid < 0 || port <= 0) {
        fprintf(stderr, "FAIL: T9-9 listen\n");
        g_fail = 1;
        stop_server(pid, rec_rd, acc_rd);
        return;
    }
    a = start_client(port);
    if (!a || read_full(acc_rd, &note, 1, 1000) != 0) {
        fprintf(stderr, "FAIL: T9-9 client 0 start\n");
        g_fail = 1;
        mb_stack_destroy(a);
        stop_server(pid, rec_rd, acc_rd);
        return;
    }
    b = start_client(port);
    if (!b || read_full(acc_rd, &note, 1, 1000) != 0) {
        fprintf(stderr, "FAIL: T9-9 client 1 start\n");
        g_fail = 1;
        mb_stack_destroy(a);
        mb_stack_destroy(b);
        stop_server(pid, rec_rd, acc_rd);
        return;
    }

    rc[0] = mb_stack_client_read(a, MB_REG_HOLDING, 1, 1);
    rc[1] = mb_stack_client_read(a, MB_REG_HOLDING, 2, 1);
    rc[2] = mb_stack_client_write_regs(a, 5, &reg, 1);
    rc[3] = mb_stack_client_write_bits(a, 6, &bit, 1);
    rc[4] = mb_stack_client_read(b, MB_REG_HOLDING, 3, 1);
    if (rc[0] != 0 || rc[1] != 0 || rc[2] != 0 || rc[3] != 0 || rc[4] != 0) {
        fprintf(stderr,
                "FAIL: T9-9 rc read=%d read2=%d wregs=%d wbits=%d read_b=%d\n",
                rc[0], rc[1], rc[2], rc[3], rc[4]);
        g_fail = 1;
    }
    if (read_full(rec_rd, raw, sizeof(raw), 1000) != 0) {
        fprintf(stderr, "FAIL: T9-9 captured %d requests\n", T9_9_NREC);
        g_fail = 1;
        mb_stack_destroy(a);
        mb_stack_destroy(b);
        stop_server(pid, rec_rd, acc_rd);
        return;
    }
    for (i = 0; i < T9_9_NREC; i++) {
        conn[i] = raw[i * 4];
        tid[i] = (unsigned)rd_be16(raw + i * 4 + 2);
    }
    unique = 1;
    for (i = 0; i < 4; i++) {
        int j;
        if (conn[i] != 0) {
            unique = 0;
        }
        for (j = i + 1; j < 4; j++) {
            if (tid[i] == tid[j]) {
                unique = 0;
            }
        }
    }
    if (!unique || tid[0] != 1 || tid[1] != 2 || tid[2] != 3 || tid[3] != 4) {
        fprintf(stderr,
                "FAIL: T9-9 instance 0 TID conn=%u/%u/%u/%u tid=%u,%u,%u,%u "
                "(want conn 0 and TID 1,2,3,4)\n",
                conn[0], conn[1], conn[2], conn[3], tid[0], tid[1], tid[2],
                tid[3]);
        g_fail = 1;
    }
    if (conn[4] != 1 || tid[4] != tid[0]) {
        fprintf(stderr,
                "FAIL: T9-9 first TID instance0=%u instance1=%u (conn %u) "
                "(want the same first TID on a fresh instance)\n",
                tid[0], tid[4], conn[4]);
        g_fail = 1;
    }

    mb_stack_destroy(a);
    mb_stack_destroy(b);
    stop_server(pid, rec_rd, acc_rd);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_tid_per_instance();
    if (g_fail) {
        fprintf(stderr, "test_mb_t9_9: FAILED\n");
        return 1;
    }
    printf("test_mb_t9_9: OK\n");
    return 0;
}
