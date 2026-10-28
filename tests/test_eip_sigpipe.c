/*
 * A20261025-1: a peer that writes several encapsulation requests and closes
 * without reading must not kill the process. Before the fix, the second
 * TCP response send raises SIGPIPE (default disposition terminates).
 *
 * The originator case is the same socket: after the target closes, three
 * explicit Gets must return a negative errno and leave the process alive.
 * The TLS case is SSL_write on the secure port, which uses a socket write
 * inside OpenSSL.
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define BURST_N 8

static unsigned char g_psk[EIP_PSK_LEN];

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

static int tcp_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    int one = 1;
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
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

static void fill_adapter(eip_cfg_t *cfg, int tcp_port, int udp_port)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->role = EIP_ROLE_ADAPTER;
    snprintf(cfg->bind_ip, sizeof(cfg->bind_ip), "127.0.0.1");
    cfg->tcp_port = tcp_port;
    cfg->udp_io_port = udp_port;
    cfg->security_class = 0;
    cfg->lldp_enable = 0;
    cfg->acd_enable = 0;
    cfg->input_size = 8;
    cfg->output_size = 4;
}

static void list_identity_req(uint8_t *req)
{
    memset(req, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(req, EIP_CMD_LISTIDENTITY);
}

/* Peer writes several requests and closes. Returns 0 if this process is
 * still alive afterwards — the pre-fix failure is SIGPIPE, not a return. */
static int peer_burst_and_close(eip_stack_t *s, int port)
{
    uint8_t burst[BURST_N * EIP_ENCAP_HDR_SIZE];
    int fd;
    int i;
    for (i = 0; i < BURST_N; i++) {
        list_identity_req(burst + (size_t)i * EIP_ENCAP_HDR_SIZE);
    }
    fd = tcp_connect(port);
    if (fd < 0) {
        fprintf(stderr, "FAIL: burst connect\n");
        return -1;
    }
    if (send(fd, burst, sizeof(burst), MSG_NOSIGNAL) != (ssize_t)sizeof(burst)) {
        fprintf(stderr, "FAIL: burst send\n");
        close(fd);
        return -1;
    }
    close(fd);
    /* Let the FIN land so the following response sends observe a closed peer. */
    usleep(5000);
    for (i = 0; i < 20; i++) {
        eip_stack_poll(s);
        usleep(1000);
    }
    return 0;
}

static int read_list_identity(eip_stack_t *s, int port)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[512];
    size_t got = 0;
    int fd;
    int i;
    list_identity_req(req);
    fd = tcp_connect(port);
    if (fd < 0) {
        return -1;
    }
    if (send(fd, req, sizeof(req), MSG_NOSIGNAL) != (ssize_t)sizeof(req)) {
        close(fd);
        return -1;
    }
    for (i = 0; i < 500 && got < EIP_ENCAP_HDR_SIZE; i++) {
        ssize_t n;
        eip_stack_poll(s);
        n = recv(fd, resp + got, sizeof(resp) - got, MSG_DONTWAIT);
        if (n > 0) {
            got += (size_t)n;
        }
        if (got >= EIP_ENCAP_HDR_SIZE) {
            uint16_t len = eip_rd_le16(resp + 2);
            if (got >= (size_t)EIP_ENCAP_HDR_SIZE + len &&
                eip_rd_le16(resp) == EIP_CMD_LISTIDENTITY) {
                close(fd);
                return 0;
            }
        }
        usleep(1000);
    }
    close(fd);
    return -1;
}

static int adapter_child(void)
{
    int tcp_port = reserve_port();
    int udp_port = reserve_port();
    eip_cfg_t cfg;
    eip_stack_t *s;
    int i;
    if (tcp_port <= 0 || udp_port <= 0 || tcp_port == udp_port) {
        fprintf(stderr, "FAIL: adapter ports\n");
        return 1;
    }
    fill_adapter(&cfg, tcp_port, udp_port);
    s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: adapter start\n");
        eip_stack_destroy(s);
        return 1;
    }
    for (i = 0; i < 5; i++) {
        if (peer_burst_and_close(s, tcp_port) != 0) {
            eip_stack_destroy(s);
            return 1;
        }
    }
    if (read_list_identity(s, tcp_port) != 0) {
        fprintf(stderr, "FAIL: adapter did not answer ListIdentity after peer close\n");
        eip_stack_destroy(s);
        return 1;
    }
    eip_stack_destroy(s);
    return 0;
}

static void *register_and_close(void *arg)
{
    int lfd = (int)(intptr_t)arg;
    int fd = accept(lfd, NULL, NULL);
    uint8_t buf[64];
    size_t got = 0;
    uint8_t resp[EIP_ENCAP_HDR_SIZE + 4];
    close(lfd);
    if (fd < 0) {
        return NULL;
    }
    while (got < EIP_ENCAP_HDR_SIZE + 4) {
        ssize_t n = recv(fd, buf + got, (EIP_ENCAP_HDR_SIZE + 4) - got, 0);
        if (n <= 0) {
            close(fd);
            return NULL;
        }
        got += (size_t)n;
    }
    memset(resp, 0, sizeof(resp));
    eip_wr_le16(resp, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(resp + 2, 4);
    eip_wr_le32(resp + 4, 0x1234ABCDu);
    eip_wr_le16(resp + 24, 1);
    if (send(fd, resp, sizeof(resp), MSG_NOSIGNAL) != (ssize_t)sizeof(resp)) {
        close(fd);
        return NULL;
    }
    close(fd);
    return NULL;
}

static int originator_child(void)
{
    int port = 0;
    int lfd = listen_loopback(&port);
    pthread_t th;
    eip_cfg_t cfg;
    eip_stack_t *s;
    int bad = 0;
    int i;
    if (lfd < 0) {
        fprintf(stderr, "FAIL: originator listen\n");
        return 1;
    }
    if (pthread_create(&th, NULL, register_and_close, (void *)(intptr_t)lfd) !=
        0) {
        fprintf(stderr, "FAIL: originator thread\n");
        close(lfd);
        return 1;
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ORIGINATOR;
    snprintf(cfg.remote_ip, sizeof(cfg.remote_ip), "127.0.0.1");
    cfg.remote_port = port;
    cfg.security_class = 0;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: originator start\n");
        shutdown(lfd, SHUT_RDWR);
        pthread_join(th, NULL);
        eip_stack_destroy(s);
        return 1;
    }
    for (i = 0; i < 3; i++) {
        uint8_t out[8];
        size_t n = sizeof(out);
        int rc = eip_stack_explicit_get(s, 1, 1, 1, out, &n);
        fprintf(stderr, "originator get[%d]=%d\n", i, rc);
        if (rc >= 0) {
            fprintf(stderr, "FAIL: originator get[%d] rc=%d, want negative errno\n",
                    i, rc);
            bad = 1;
        }
    }
    pthread_join(th, NULL);
    eip_stack_destroy(s);
    return bad;
}

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk, unsigned int max_psk_len)
{
    (void)ssl;
    (void)hint;
    if (max_identity_len < 4 || max_psk_len < EIP_PSK_LEN) {
        return 0;
    }
    memcpy(identity, "eip", 4);
    memcpy(psk, g_psk, EIP_PSK_LEN);
    return EIP_PSK_LEN;
}

static void log_ssl(const char *what)
{
    char buf[256];
    unsigned long err = ERR_get_error();
    if (err == 0) {
        fprintf(stderr, "FAIL: %s\n", what);
        return;
    }
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "FAIL: %s: %s\n", what, buf);
}

static int pump_ssl_connect(eip_stack_t *s, SSL *ssl)
{
    int i;
    for (i = 0; i < 2000; i++) {
        int rc = SSL_connect(ssl);
        int err;
        if (rc == 1) {
            return 0;
        }
        err = SSL_get_error(ssl, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            log_ssl("TLS connect");
            return -1;
        }
        eip_stack_poll(s);
        usleep(1000);
    }
    fprintf(stderr, "FAIL: TLS connect timeout\n");
    return -1;
}

static int pump_ssl_write_all(eip_stack_t *s, SSL *ssl, const uint8_t *buf,
                              size_t len)
{
    size_t off = 0;
    int i;
    for (i = 0; i < 2000 && off < len; i++) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        int err;
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        err = SSL_get_error(ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            log_ssl("TLS write");
            return -1;
        }
        eip_stack_poll(s);
        usleep(1000);
    }
    return off == len ? 0 : -1;
}

static int pump_ssl_read_encap(eip_stack_t *s, SSL *ssl, uint8_t *buf, size_t cap)
{
    size_t got = 0;
    size_t need = EIP_ENCAP_HDR_SIZE;
    int i;
    for (i = 0; i < 2000 && got < need; i++) {
        int n = SSL_read(ssl, buf + got, (int)(cap - got));
        int err;
        if (n > 0) {
            got += (size_t)n;
            if (got >= EIP_ENCAP_HDR_SIZE) {
                need = (size_t)EIP_ENCAP_HDR_SIZE + eip_rd_le16(buf + 2);
                if (need > cap) {
                    return -1;
                }
            }
            continue;
        }
        err = SSL_get_error(ssl, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            log_ssl("TLS read");
            return -1;
        }
        eip_stack_poll(s);
        usleep(1000);
    }
    if (got < need || eip_rd_le16(buf) != EIP_CMD_LISTIDENTITY) {
        return -1;
    }
    return 0;
}

static SSL_CTX *client_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_set_cipher_list(
            ctx, "PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA") != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    return ctx;
}

static int tls_handshake(eip_stack_t *s, SSL_CTX *ctx, int port, SSL **out,
                         int *fd_out)
{
    int fd = tcp_connect(port);
    int flags;
    SSL *ssl;
    *out = NULL;
    *fd_out = -1;
    if (fd < 0) {
        fprintf(stderr, "FAIL: TLS TCP connect\n");
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }
    ssl = SSL_new(ctx);
    if (!ssl) {
        close(fd);
        return -1;
    }
    SSL_set_fd(ssl, fd);
    if (pump_ssl_connect(s, ssl) != 0) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    *out = ssl;
    *fd_out = fd;
    return 0;
}

static int tls_child(void)
{
    int tcp_port = reserve_port();
    int udp_port = reserve_port();
    int sec_port = reserve_port();
    eip_cfg_t cfg;
    eip_stack_t *s;
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int fd = -1;
    uint8_t burst[BURST_N * EIP_ENCAP_HDR_SIZE];
    uint8_t resp[512];
    int i;
    if (tcp_port <= 0 || udp_port <= 0 || sec_port <= 0 || tcp_port == udp_port ||
        sec_port == tcp_port) {
        fprintf(stderr, "FAIL: TLS ports\n");
        return 1;
    }
    memset(g_psk, 0x11, sizeof(g_psk));
    fill_adapter(&cfg, tcp_port, udp_port);
    cfg.security_class = EIP_SECURITY_CLASS_2;
    cfg.secure_tcp_port = sec_port;
    memcpy(cfg.psk, g_psk, EIP_PSK_LEN);
    cfg.psk_set = 1;
    s = eip_stack_create(&cfg);
    if (!s || eip_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: TLS adapter start\n");
        eip_stack_destroy(s);
        return 1;
    }
    ctx = client_ctx();
    if (!ctx) {
        log_ssl("TLS client context");
        eip_stack_destroy(s);
        return 1;
    }
    if (tls_handshake(s, ctx, sec_port, &ssl, &fd) != 0) {
        SSL_CTX_free(ctx);
        eip_stack_destroy(s);
        return 1;
    }
    for (i = 0; i < BURST_N; i++) {
        list_identity_req(burst + (size_t)i * EIP_ENCAP_HDR_SIZE);
    }
    if (pump_ssl_write_all(s, ssl, burst, sizeof(burst)) != 0) {
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        eip_stack_destroy(s);
        return 1;
    }
    /* Unclean TCP close: no close_notify, so the adapter still has requests
     * to answer and the response write hits a dead peer. */
    SSL_set_quiet_shutdown(ssl, 1);
    SSL_free(ssl);
    close(fd);
    usleep(5000);
    for (i = 0; i < 30; i++) {
        eip_stack_poll(s);
        usleep(1000);
    }
    if (tls_handshake(s, ctx, sec_port, &ssl, &fd) != 0) {
        SSL_CTX_free(ctx);
        eip_stack_destroy(s);
        return 1;
    }
    list_identity_req(burst);
    if (pump_ssl_write_all(s, ssl, burst, EIP_ENCAP_HDR_SIZE) != 0 ||
        pump_ssl_read_encap(s, ssl, resp, sizeof(resp)) != 0) {
        fprintf(stderr, "FAIL: TLS ListIdentity after peer close\n");
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        eip_stack_destroy(s);
        return 1;
    }
    SSL_set_quiet_shutdown(ssl, 1);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    eip_stack_destroy(s);
    return 0;
}

static int wait_child(pid_t pid, const char *name)
{
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "FAIL: %s waitpid: %s\n", name, strerror(errno));
        return 1;
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        fprintf(stderr, "FAIL: %s child died with signal %d (%s)\n", name, sig,
                strsignal(sig));
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: %s child exit %d\n", name,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }
    fprintf(stderr, "PASS: %s\n", name);
    return 0;
}

static int run_case(const char *name, int (*fn)(void))
{
    pid_t pid;
    fflush(NULL);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "FAIL: %s fork: %s\n", name, strerror(errno));
        return 1;
    }
    if (pid == 0) {
        signal(SIGPIPE, SIG_DFL);
        _exit(fn() == 0 ? 0 : 1);
    }
    return wait_child(pid, name);
}

int main(void)
{
    int fail = 0;
    fail |= run_case("adapter", adapter_child);
    fail |= run_case("originator", originator_child);
    fail |= run_case("tls", tls_child);
    return fail ? 1 : 0;
}
