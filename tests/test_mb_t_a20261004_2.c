/*
 * A20261004-2: a client read whose response Byte Count does not match the
 * requested quantity must fail and leave the local mirror unchanged.
 *
 *   fc03-short: FC03 qty 3, response is one register (Byte Count 2)
 *   fc03-long:  FC03 qty 2, response is four registers (Byte Count 8)
 *   fc01-short: FC01 qty 16, response is one data byte (Byte Count 1)
 *
 * Spec V1.1b3 §6.1–§6.4: FC01/02 Byte Count = ceil(qty/8), FC03/04 = 2×qty.
 * The fake server answers with those PDUs regardless of the request, and
 * echoes the request TID and Unit ID so the failure is the byte count.
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

#define MIRROR_REGS 16
#define MIRROR_COILS 32

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

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
    size_t off = 0;
    while (off < len) {
        struct pollfd pfd;
        ssize_t n;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (pr == 0) {
            return -1;
        }
        n = read(fd, buf + off, len - off);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* One accept, one fixed PDU. TID and Unit ID are copied from the request. */
static void serve_one(int lfd, const uint8_t *pdu, size_t pdu_len)
{
    int fd;
    int one = 1;
    uint8_t req[12];
    uint8_t adu[64];
    size_t adu_len;

    signal(SIGPIPE, SIG_IGN);
    fd = accept(lfd, NULL, NULL);
    if (fd < 0 || pdu_len + 7 > sizeof(adu)) {
        _exit(1);
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (read_full(fd, req, sizeof(req), 2000) != 0) {
        _exit(1);
    }
    adu_len = 7 + pdu_len;
    wr_be16(adu, rd_be16(req));
    wr_be16(adu + 2, 0);
    wr_be16(adu + 4, (uint16_t)(1u + pdu_len));
    adu[6] = req[6];
    memcpy(adu + 7, pdu, pdu_len);
    if (write_full(fd, adu, adu_len) != 0) {
        _exit(1);
    }
    /* Hold the socket until the client closes, so the ADU is not reset. */
    (void)read_full(fd, req, 1, 1000);
    close(fd);
    close(lfd);
    _exit(0);
}

static pid_t start_server(const uint8_t *pdu, size_t pdu_len, int *port)
{
    int lfd;
    int one = 1;
    int port_pipe[2];
    struct sockaddr_in addr;
    socklen_t alen;
    pid_t pid;

    *port = -1;
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        return -1;
    }
    if (pipe(port_pipe) != 0) {
        close(lfd);
        return -1;
    }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(lfd, 1) != 0) {
        close(lfd);
        close(port_pipe[0]);
        close(port_pipe[1]);
        return -1;
    }
    alen = sizeof(addr);
    if (getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0) {
        close(lfd);
        close(port_pipe[0]);
        close(port_pipe[1]);
        return -1;
    }
    fflush(NULL);
    pid = fork();
    if (pid < 0) {
        close(lfd);
        close(port_pipe[0]);
        close(port_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        uint8_t raw[2];
        close(port_pipe[0]);
        wr_be16(raw, ntohs(addr.sin_port));
        if (write_full(port_pipe[1], raw, sizeof(raw)) != 0) {
            _exit(1);
        }
        close(port_pipe[1]);
        serve_one(lfd, pdu, pdu_len);
    }
    close(lfd);
    close(port_pipe[1]);
    {
        uint8_t be[2];
        if (read_full(port_pipe[0], be, sizeof(be), 1000) != 0) {
            close(port_pipe[0]);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
            return -1;
        }
        close(port_pipe[0]);
        *port = (int)rd_be16(be);
    }
    return pid;
}

static void stop_server(pid_t pid)
{
    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
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
    cfg.n_holding = MIRROR_REGS;
    cfg.n_input = MIRROR_REGS;
    cfg.n_coil = MIRROR_COILS;
    cfg.n_discrete = MIRROR_COILS;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    mb_stack_t *s = mb_stack_create(&cfg);
    if (!s || mb_stack_start(s) != 0) {
        mb_stack_destroy(s);
        return NULL;
    }
    return s;
}

static void seed_mirror(mb_stack_t *s, uint16_t *regs, uint8_t *coils)
{
    uint16_t i;
    for (i = 0; i < MIRROR_REGS; i++) {
        regs[i] = (uint16_t)(0xA100u + i);
    }
    for (i = 0; i < MIRROR_COILS; i++) {
        coils[i] = 1;
    }
    if (mb_stack_write_regs(s, MB_REG_HOLDING, 0, regs, MIRROR_REGS) != 0 ||
        mb_stack_write_bits(s, MB_REG_COIL, 0, coils, MIRROR_COILS) != 0) {
        fprintf(stderr, "FAIL: seed mirror\n");
        g_fail = 1;
    }
}

static void expect_unchanged(const char *name, int rc, const uint16_t *regs,
                             const uint16_t *regs_now, const uint8_t *coils,
                             const uint8_t *coils_now)
{
    int i;
    int mirror_ok = 1;
    if (rc != -EIO) {
        fprintf(stderr, "FAIL: %s rc=%d (want %d)\n", name, rc, -EIO);
        g_fail = 1;
    }
    for (i = 0; i < MIRROR_REGS; i++) {
        if (regs_now[i] != regs[i]) {
            mirror_ok = 0;
        }
    }
    for (i = 0; i < MIRROR_COILS; i++) {
        if (coils_now[i] != coils[i]) {
            mirror_ok = 0;
        }
    }
    if (mirror_ok) {
        return;
    }
    fprintf(stderr, "FAIL: %s mirror changed\n  holding", name);
    for (i = 0; i < MIRROR_REGS; i++) {
        fprintf(stderr, " %04x", regs_now[i]);
    }
    fprintf(stderr, "\n  coils  ");
    for (i = 0; i < MIRROR_COILS; i++) {
        fprintf(stderr, " %u", coils_now[i]);
    }
    fprintf(stderr, "\n");
    g_fail = 1;
}

static void run_case(const char *name, mb_reg_type_t type, uint16_t addr,
                     uint16_t qty, const uint8_t *pdu, size_t pdu_len)
{
    int port = -1;
    pid_t pid = start_server(pdu, pdu_len, &port);
    mb_stack_t *client;
    uint16_t regs[MIRROR_REGS];
    uint16_t regs_now[MIRROR_REGS];
    uint8_t coils[MIRROR_COILS];
    uint8_t coils_now[MIRROR_COILS];
    int rc;

    if (pid < 0 || port <= 0) {
        fprintf(stderr, "FAIL: %s listen\n", name);
        g_fail = 1;
        stop_server(pid);
        return;
    }
    client = start_client(port);
    if (!client) {
        fprintf(stderr, "FAIL: %s client start\n", name);
        g_fail = 1;
        stop_server(pid);
        return;
    }
    seed_mirror(client, regs, coils);
    rc = mb_stack_client_read(client, type, addr, qty);
    if (mb_stack_read_regs(client, MB_REG_HOLDING, 0, regs_now, MIRROR_REGS) !=
            0 ||
        mb_stack_read_bits(client, MB_REG_COIL, 0, coils_now, MIRROR_COILS) !=
            0) {
        fprintf(stderr, "FAIL: %s read back mirror\n", name);
        g_fail = 1;
    } else {
        expect_unchanged(name, rc, regs, regs_now, coils, coils_now);
    }
    mb_stack_destroy(client);
    stop_server(pid);
}

int main(void)
{
    static const uint8_t fc03_short[] = {0x03, 0x02, 0xC0, 0x05};
    static const uint8_t fc03_long[] = {0x03, 0x08, 0xC0, 0x05, 0xC0, 0x06,
                                        0xC0, 0x07, 0xC0, 0x08};
    static const uint8_t fc01_short[] = {0x01, 0x01, 0x00};

    signal(SIGPIPE, SIG_IGN);
    /* 3 registers requested, 1 returned. */
    run_case("fc03-short", MB_REG_HOLDING, 5, 3, fc03_short, sizeof(fc03_short));
    /* 2 registers requested, 4 returned (would overwrite the next addresses). */
    run_case("fc03-long", MB_REG_HOLDING, 5, 2, fc03_long, sizeof(fc03_long));
    /* 16 coils requested, 1 data byte returned. */
    run_case("fc01-short", MB_REG_COIL, 0, 16, fc01_short, sizeof(fc01_short));
    if (g_fail) {
        fprintf(stderr, "test_mb_t_a20261004_2: FAILED\n");
        return 1;
    }
    printf("test_mb_t_a20261004_2: OK\n");
    return 0;
}
