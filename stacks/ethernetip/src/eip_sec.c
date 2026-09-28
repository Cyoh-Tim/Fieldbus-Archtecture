#include "eip_sec.h"

#include "eip_crypto.h"
#include "eip_endian.h"
#include "eip_internal.h"
#include "logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int eip_sec_required(const eip_stack_t *s)
{
    return s && s->cfg.security_class >= EIP_SECURITY_CLASS_1;
}

int eip_sec_confidentiality(const eip_stack_t *s)
{
    return s && s->cfg.security_class >= EIP_SECURITY_CLASS_2;
}

int eip_sec_service_needs_mac(uint8_t service)
{
    switch (service) {
    case CIP_SVC_SET_ATTR_SINGLE:
    case CIP_SVC_RESET:
    case CIP_SVC_FORWARD_OPEN:
    case CIP_SVC_LARGE_FORWARD_OPEN:
    case CIP_SVC_FORWARD_CLOSE:
        return 1;
    default:
        return 0;
    }
}

static void mac_input(uint32_t session, const uint8_t *cip, size_t cip_len,
                      uint8_t *buf, size_t *out_len, size_t cap)
{
    size_t n = 4 + cip_len;
    if (n > cap) {
        n = cap;
    }
    eip_wr_le32(buf, session);
    if (cip_len && n > 4) {
        size_t c = n - 4;
        if (c > cip_len) {
            c = cip_len;
        }
        memcpy(buf + 4, cip, c);
    }
    *out_len = n;
}

int eip_sec_check_ucmm(eip_stack_t *s, uint32_t session, const uint8_t *cip,
                       size_t cip_len, const uint8_t *mac_item, size_t mac_len)
{
    if (!eip_sec_required(s)) {
        return 0;
    }
    if (!cip || cip_len < 2) {
        return -EINVAL;
    }
    if (!eip_sec_service_needs_mac(cip[0])) {
        return 0;
    }
    if (!s->cfg.psk_set) {
        LOG_ERROR("ethernetip", "security_class>=1 인데 PSK 없음");
        return -EPERM;
    }
    if (!mac_item || mac_len < EIP_HMAC_LEN) {
        LOG_WARN("ethernetip",
                 "Security Class %d: mutating UCMM 에 integrity MAC 없음 — 거부",
                 s->cfg.security_class);
        return -EPERM;
    }
    uint8_t material[4 + EIP_EXPLICIT_DATA_MAX + 64];
    size_t mlen = 0;
    mac_input(session, cip, cip_len, material, &mlen, sizeof(material));
    if (eip_hmac_verify(s->cfg.psk, EIP_PSK_LEN, material, mlen, mac_item) !=
        0) {
        LOG_WARN("ethernetip", "Security Class %d: integrity MAC 검증 실패",
                 s->cfg.security_class);
        return -EPERM;
    }
    return 0;
}

size_t eip_sec_append_mac_item(eip_stack_t *s, uint32_t session,
                               const uint8_t *cip, size_t cip_len, uint8_t *out,
                               size_t cap)
{
    if (!eip_sec_required(s) || !s->cfg.psk_set || !out ||
        cap < 4 + EIP_HMAC_LEN) {
        return 0;
    }
    uint8_t material[4 + EIP_EXPLICIT_DATA_MAX + 64];
    size_t mlen = 0;
    mac_input(session, cip, cip_len, material, &mlen, sizeof(material));
    uint8_t mac[EIP_HMAC_LEN];
    eip_hmac_sha256(s->cfg.psk, EIP_PSK_LEN, material, mlen, mac);
    eip_wr_le16(out + 0, EIP_SEC_ITEM_INTEGRITY);
    eip_wr_le16(out + 2, EIP_HMAC_LEN);
    memcpy(out + 4, mac, EIP_HMAC_LEN);
    return 4 + EIP_HMAC_LEN;
}

/* ---- TLS confidentiality listener (port 2221) ---- */

static unsigned int psk_server_cb(SSL *ssl, const char *identity,
                                 unsigned char *psk, unsigned int max_psk_len)
{
    eip_stack_t *s = SSL_get_ex_data(ssl, 0);
    (void)identity;
    if (!s || !s->cfg.psk_set || max_psk_len < EIP_PSK_LEN) {
        return 0;
    }
    memcpy(psk, s->cfg.psk, EIP_PSK_LEN);
    return EIP_PSK_LEN;
}

int eip_sec_tls_start(eip_stack_t *s)
{
    if (!eip_sec_confidentiality(s) || s->cfg.mock) {
        return 0;
    }
    if (!s->cfg.psk_set) {
        LOG_ERROR("ethernetip",
                  "security_class>=2 이면 protocol_params.psk_hex 필요");
        return -EINVAL;
    }

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    s->tls_ctx = SSL_CTX_new(TLS_server_method());
    if (!s->tls_ctx) {
        return -ENOMEM;
    }
    SSL_CTX_set_min_proto_version(s->tls_ctx, TLS1_2_VERSION);
    /* Prefer PSK suites for CIP Security–style shared secret. */
    if (SSL_CTX_set_cipher_list(
            s->tls_ctx, "PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA") != 1) {
        LOG_WARN("ethernetip", "PSK cipher list 설정 실패 — 기본 cipher 사용");
    }
    SSL_CTX_set_psk_server_callback(s->tls_ctx, psk_server_cb);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        SSL_CTX_free(s->tls_ctx);
        s->tls_ctx = NULL;
        return -errno;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.secure_tcp_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 8) < 0) {
        int e = errno;
        close(fd);
        SSL_CTX_free(s->tls_ctx);
        s->tls_ctx = NULL;
        return -e;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    s->tls_listen_fd = fd;
    LOG_INFO("ethernetip",
             "CIP Security confidentiality: TLS PSK listen port %d",
             s->cfg.secure_tcp_port);
    return 0;
}

void eip_sec_tls_stop(eip_stack_t *s)
{
    if (!s) {
        return;
    }
    for (int i = 0; i < EIP_TLS_CLIENTS_MAX; i++) {
        if (s->tls_clients[i].ssl) {
            SSL_shutdown(s->tls_clients[i].ssl);
            SSL_free(s->tls_clients[i].ssl);
            s->tls_clients[i].ssl = NULL;
        }
        if (s->tls_clients[i].fd >= 0) {
            close(s->tls_clients[i].fd);
            s->tls_clients[i].fd = -1;
        }
        s->tls_clients[i].active = 0;
    }
    if (s->tls_listen_fd >= 0) {
        close(s->tls_listen_fd);
        s->tls_listen_fd = -1;
    }
    if (s->tls_ctx) {
        SSL_CTX_free(s->tls_ctx);
        s->tls_ctx = NULL;
    }
}

static int tls_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void tls_drop(eip_tls_client_t *c)
{
    if (c->ssl) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->active = 0;
    c->hs_done = 0;
    c->rx_len = 0;
}

static void tls_accept(eip_stack_t *s, int budget)
{
    if (s->tls_listen_fd < 0 || !s->tls_ctx) {
        return;
    }
    while (budget-- > 0) {
        int fd = accept(s->tls_listen_fd, NULL, NULL);
        if (fd < 0) {
            break;
        }
        int slot = -1;
        for (int i = 0; i < EIP_TLS_CLIENTS_MAX; i++) {
            if (!s->tls_clients[i].active) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            close(fd);
            continue;
        }
        if (tls_set_nonblock(fd) != 0) {
            close(fd);
            continue;
        }
        SSL *ssl = SSL_new(s->tls_ctx);
        if (!ssl) {
            close(fd);
            continue;
        }
        SSL_set_fd(ssl, fd);
        SSL_set_ex_data(ssl, 0, s);
        SSL_set_accept_state(ssl);
        SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                              SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        memset(&s->tls_clients[slot], 0, sizeof(s->tls_clients[slot]));
        s->tls_clients[slot].fd = fd;
        s->tls_clients[slot].ssl = ssl;
        s->tls_clients[slot].active = 1;
        s->tls_clients[slot].hs_done = 0;
    }
}

static int tls_handshake(eip_tls_client_t *c)
{
    int n = SSL_accept(c->ssl);
    if (n == 1) {
        c->hs_done = 1;
        LOG_INFO("ethernetip", "TLS session accepted (CIP Security port)");
        return 0;
    }
    int err = SSL_get_error(c->ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0;
    }
    tls_drop(c);
    return -1;
}

static void tls_service(eip_stack_t *s, eip_tls_client_t *c, int budget)
{
    if (!c->hs_done) {
        if (tls_handshake(c) != 0 || !c->hs_done) {
            return;
        }
    }
    uint8_t tmp[2048];
    while (budget-- > 0) {
        int n = SSL_read(c->ssl, tmp, (int)sizeof(tmp));
        if (n <= 0) {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                break;
            }
            tls_drop(c);
            break;
        }
        if (c->rx_len + (size_t)n > sizeof(c->rx)) {
            tls_drop(c);
            break;
        }
        memcpy(c->rx + c->rx_len, tmp, (size_t)n);
        c->rx_len += (size_t)n;
        while (c->rx_len >= EIP_ENCAP_HDR_SIZE) {
            uint16_t length = eip_rd_le16(c->rx + 2);
            size_t need = EIP_ENCAP_HDR_SIZE + length;
            if (c->rx_len < need) {
                break;
            }
            uint8_t resp[EIP_TCP_BUF_MAX];
            size_t resp_len = 0;
            memset(resp, 0, sizeof(resp));
            pthread_mutex_lock(&s->lock);
            int rc = eip_encap_process(s, c->rx, need, resp, sizeof(resp),
                                       &resp_len);
            pthread_mutex_unlock(&s->lock);
            if (rc == 0 && resp_len > 0) {
                int w = SSL_write(c->ssl, resp, (int)resp_len);
                if (w <= 0) {
                    int err = SSL_get_error(c->ssl, w);
                    if (err != SSL_ERROR_WANT_READ &&
                        err != SSL_ERROR_WANT_WRITE) {
                        tls_drop(c);
                        return;
                    }
                }
            }
            memmove(c->rx, c->rx + need, c->rx_len - need);
            c->rx_len -= need;
        }
    }
}

void eip_sec_tls_poll(eip_stack_t *s)
{
    if (!eip_sec_confidentiality(s) || s->cfg.mock) {
        return;
    }
    int budget = EIP_POLL_TLS_BUDGET;
    tls_accept(s, budget);
    for (int i = 0; i < EIP_TLS_CLIENTS_MAX && budget > 0; i++) {
        if (s->tls_clients[i].active) {
            tls_service(s, &s->tls_clients[i], budget);
            budget--;
        }
    }
}
