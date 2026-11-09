/*
 * T11-11: logs name the repository security profile.
 *
 * The profile is "자체 보안 프로파일 (HMAC 무결성 / TLS-PSK, ODVA CIP
 * Security 아님, 인증 주장 아님)". Logs must not call it Security Class
 * or ODVA CIP Security.
 *
 * Wire behavior is unchanged. security_class >= 1 still rejects a mutating
 * UCMM with no HMAC or a bad HMAC (CIP status 0x0F). security_class >= 2
 * still opens a TLS-PSK listener and accepts a PSK handshake. The config
 * key security_class and EIP_SECURITY_CLASS_* stay.
 */
#include "eip_crypto.h"
#include "eip_endian.h"
#include "eip_sec.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PROFILE_NAME                                                         \
    "자체 보안 프로파일 (HMAC 무결성 / TLS-PSK, ODVA CIP Security 아님, " \
    "인증 주장 아님)"

static int g_fail;
static int g_saved_stderr = -1;
static int g_pipe_r = -1;
static uint8_t g_psk[EIP_PSK_LEN];

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static int capture_on(void)
{
    int fds[2];
    fflush(stderr);
    if (pipe(fds) != 0) {
        return -1;
    }
    g_saved_stderr = dup(fileno(stderr));
    if (g_saved_stderr < 0 || dup2(fds[1], fileno(stderr)) < 0) {
        close(fds[0]);
        close(fds[1]);
        if (g_saved_stderr >= 0) {
            close(g_saved_stderr);
            g_saved_stderr = -1;
        }
        return -1;
    }
    close(fds[1]);
    g_pipe_r = fds[0];
    return 0;
}

static void capture_off(char *buf, size_t cap)
{
    size_t n = 0;
    fflush(stderr);
    if (g_saved_stderr >= 0) {
        dup2(g_saved_stderr, fileno(stderr));
        close(g_saved_stderr);
        g_saved_stderr = -1;
    }
    if (g_pipe_r >= 0) {
        int flags = fcntl(g_pipe_r, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(g_pipe_r, F_SETFL, flags | O_NONBLOCK);
        }
        while (n + 1 < cap) {
            ssize_t r = read(g_pipe_r, buf + n, cap - 1 - n);
            if (r <= 0) {
                break;
            }
            n += (size_t)r;
        }
        close(g_pipe_r);
        g_pipe_r = -1;
    }
    buf[n] = '\0';
}

/* Old names that claimed ODVA CIP Security or "Security Class". */
static void expect_profile_log(const char *log, const char *what)
{
    static const char *banned[] = {
        "Security Class",
        "CIP Security confidentiality",
        "CIP Security port",
        "CIP Security–",
        "CIP Security-",
        "sec class",
    };
    size_t i;
    if (!strstr(log, PROFILE_NAME)) {
        fprintf(stderr, "FAIL: %s log missing profile name:\n%s\n", what, log);
        g_fail = 1;
    }
    for (i = 0; i < sizeof(banned) / sizeof(banned[0]); i++) {
        if (strstr(log, banned[i])) {
            fprintf(stderr, "FAIL: %s log still says \"%s\":\n%s\n", what,
                    banned[i], log);
            g_fail = 1;
        }
    }
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

static uint32_t test_register(eip_stack_t *s)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    uint8_t resp[64];
    size_t n = 0;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp), &n) !=
            0 ||
        n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

/* SendRRData carrying Forward Open. mac_len 0 omits the integrity item. */
static int send_fo(eip_stack_t *s, uint32_t sess, const uint8_t *mac,
                   size_t mac_len, uint8_t *resp, size_t resp_cap,
                   size_t *resp_len)
{
    uint8_t cip[2];
    uint8_t body[128];
    uint8_t req[EIP_ENCAP_HDR_SIZE + 128];
    size_t boff = 0;
    uint16_t items = mac ? 3 : 2;
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, items);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    memcpy(body + boff, cip, 2);
    boff += 2;
    if (mac) {
        eip_wr_le16(body + boff, EIP_SEC_ITEM_INTEGRITY);
        boff += 2;
        eip_wr_le16(body + boff, (uint16_t)mac_len);
        boff += 2;
        memcpy(body + boff, mac, mac_len);
        boff += mac_len;
    }
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    return eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  resp_cap, resp_len);
}

static int saw_privilege(const uint8_t *resp, size_t n)
{
    size_t i;
    for (i = EIP_ENCAP_HDR_SIZE; i + 3 < n; i++) {
        if ((resp[i] & 0x7f) == CIP_SVC_FORWARD_OPEN && (resp[i] & 0x80) &&
            resp[i + 2] == CIP_STATUS_PRIVILEGE) {
            return 1;
        }
    }
    return 0;
}

static eip_stack_t *make_sec1(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.security_class = EIP_SECURITY_CLASS_1;
    memset(cfg.psk, 0x11, EIP_PSK_LEN);
    cfg.psk_set = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    return eip_stack_create(&cfg);
}

static void test_missing_and_bad_mac(void)
{
    eip_stack_t *s = make_sec1();
    uint32_t sess;
    uint8_t resp[256];
    uint8_t mac[EIP_HMAC_LEN];
    uint8_t cip[2] = {CIP_SVC_FORWARD_OPEN, 0};
    uint8_t material[6];
    char log[2048];
    size_t n = 0;
    expect(s != NULL, "sec1 stack");
    if (!s) {
        return;
    }
    sess = test_register(s);
    expect(sess != 0, "session");

    expect(capture_on() == 0, "capture missing mac");
    n = 0;
    expect(send_fo(s, sess, NULL, 0, resp, sizeof(resp), &n) == 0,
           "FO without mac");
    capture_off(log, sizeof(log));
    expect(saw_privilege(resp, n), "missing MAC still privilege 0x0F");
    expect_profile_log(log, "missing MAC");

    eip_wr_le32(material, sess);
    memcpy(material + 4, cip, 2);
    eip_hmac_sha256(s ? eip_stack_cfg(s)->psk : g_psk, EIP_PSK_LEN, material,
                    sizeof(material), mac);
    mac[0] ^= 0xff;
    expect(capture_on() == 0, "capture bad mac");
    n = 0;
    expect(send_fo(s, sess, mac, sizeof(mac), resp, sizeof(resp), &n) == 0,
           "FO bad mac");
    capture_off(log, sizeof(log));
    expect(saw_privilege(resp, n), "bad MAC still privilege 0x0F");
    expect_profile_log(log, "bad MAC");
    eip_stack_destroy(s);
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

static int pump_connect(eip_stack_t *s, SSL *ssl)
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
            return -1;
        }
        eip_stack_poll(s);
        usleep(1000);
    }
    return -1;
}

static void test_tls_logs(void)
{
    int tcp_port = reserve_port();
    int udp_port = reserve_port();
    int sec_port = reserve_port();
    eip_cfg_t cfg;
    eip_stack_t *s;
    char log[4096];
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
    struct sockaddr_in a;
    int flags;
    expect(tcp_port > 0 && udp_port > 0 && sec_port > 0, "ports");
    expect(tcp_port != udp_port && sec_port != tcp_port &&
               sec_port != udp_port,
           "distinct ports");
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = tcp_port;
    cfg.udp_io_port = udp_port;
    cfg.secure_tcp_port = sec_port;
    cfg.security_class = EIP_SECURITY_CLASS_2;
    memset(cfg.psk, 0x22, EIP_PSK_LEN);
    cfg.psk_set = 1;
    memset(g_psk, 0x22, sizeof(g_psk));
    cfg.input_size = 8;
    cfg.output_size = 4;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    s = eip_stack_create(&cfg);
    expect(s != NULL, "sec2 stack");
    if (!s) {
        return;
    }
    expect(capture_on() == 0, "capture tls listen");
    expect(eip_stack_start(s) == 0, "sec2 start");
    capture_off(log, sizeof(log));
    expect_profile_log(log, "TLS listen");

    ctx = SSL_CTX_new(TLS_client_method());
    expect(ctx != NULL, "tls client ctx");
    if (!ctx) {
        eip_stack_destroy(s);
        return;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    expect(SSL_CTX_set_cipher_list(
               ctx, "PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA") == 1,
           "psk cipher");
    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    expect(fd >= 0, "tls socket");
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)sec_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        expect(0, "tls connect");
        if (fd >= 0) {
            close(fd);
        }
        SSL_CTX_free(ctx);
        eip_stack_destroy(s);
        return;
    }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    ssl = SSL_new(ctx);
    expect(ssl != NULL, "ssl new");
    if (!ssl) {
        close(fd);
        SSL_CTX_free(ctx);
        eip_stack_destroy(s);
        return;
    }
    SSL_set_fd(ssl, fd);
    expect(capture_on() == 0, "capture tls accept");
    expect(pump_connect(s, ssl) == 0, "tls handshake");
    capture_off(log, sizeof(log));
    expect_profile_log(log, "TLS accept");
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    eip_stack_destroy(s);
}

int main(void)
{
    test_missing_and_bad_mac();
    test_tls_logs();
    if (g_fail) {
        fprintf(stderr, "test_eip_t11_11: FAILED\n");
        return 1;
    }
    printf("test_eip_t11_11: OK\n");
    return 0;
}
