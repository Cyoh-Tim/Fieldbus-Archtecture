#include "eip_endian.h"
#include "eip_internal.h"
#include "eip_sec.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logger.h"

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint32_t parse_ipv4_host(const char *s)
{
    if (!s || !s[0]) {
        return 0;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) {
        return 0;
    }
    return ntohl(a.s_addr);
}

eip_stack_t *eip_stack_create(const eip_cfg_t *cfg)
{
    if (!cfg) {
        return NULL;
    }
    eip_stack_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->cfg = *cfg;
    if (s->cfg.tcp_port <= 0) {
        s->cfg.tcp_port = EIP_TCP_PORT_DEFAULT;
    }
    if (s->cfg.udp_io_port <= 0) {
        s->cfg.udp_io_port = EIP_UDP_IO_PORT_DEFAULT;
    }
    if (s->cfg.remote_port <= 0) {
        s->cfg.remote_port = EIP_TCP_PORT_DEFAULT;
    }
    if (s->cfg.input_assembly == 0) {
        s->cfg.input_assembly = EIP_ASM_INPUT_DEFAULT;
    }
    if (s->cfg.output_assembly == 0) {
        s->cfg.output_assembly = EIP_ASM_OUTPUT_DEFAULT;
    }
    if (s->cfg.config_assembly == 0) {
        s->cfg.config_assembly = EIP_ASM_CONFIG_DEFAULT;
    }
    if (s->cfg.input_size == 0) {
        s->cfg.input_size = 32;
    }
    if (s->cfg.output_size == 0) {
        s->cfg.output_size = 32;
    }
    if (s->cfg.config_size == 0) {
        s->cfg.config_size = 0;
        /* still allocate 1-byte config asm for path completeness */
        s->cfg.config_size = 1;
    }
    if (s->cfg.rpi_us == 0) {
        s->cfg.rpi_us = 8000;
    }
    if (s->cfg.secure_tcp_port <= 0) {
        s->cfg.secure_tcp_port = EIP_SECURE_PORT_DEFAULT;
    }
    if (s->cfg.security_class < 0 || s->cfg.security_class > 2) {
        free(s);
        return NULL;
    }
    if (s->cfg.security_class >= EIP_SECURITY_CLASS_1 && !s->cfg.psk_set) {
        free(s);
        return NULL;
    }
    if (s->cfg.vendor_id == 0) {
        s->cfg.vendor_id = 0xABCD;
    }
    if (s->cfg.device_type == 0) {
        s->cfg.device_type = 0x0C; /* communications adapter-ish */
    }
    if (s->cfg.product_code == 0) {
        s->cfg.product_code = 1;
    }
    if (s->cfg.major_rev == 0) {
        s->cfg.major_rev = 1;
    }
    if (s->cfg.product_name[0] == '\0') {
        snprintf(s->cfg.product_name, sizeof(s->cfg.product_name),
                 "FieldbusEIP");
    }
    if (s->cfg.serial_number == 0) {
        s->cfg.serial_number = 0x12345678;
    }
    if (s->cfg.idle_timeout_ms <= 0) {
        s->cfg.idle_timeout_ms = EIP_IDLE_TIMEOUT_MS_DEFAULT;
    }
    if (s->cfg.max_conn_per_ip <= 0) {
        s->cfg.max_conn_per_ip = EIP_MAX_CONN_PER_IP_DEFAULT;
    }
    if (s->cfg.input_size > EIP_ASSEMBLY_SIZE_MAX ||
        s->cfg.output_size > EIP_ASSEMBLY_SIZE_MAX ||
        s->cfg.config_size > EIP_ASSEMBLY_SIZE_MAX) {
        free(s);
        return NULL;
    }

    s->listen_fd = -1;
    s->udp_fd = -1;
    s->udp_encap_fd = -1;
    s->originator_fd = -1;
    s->bind_ip_host = parse_ipv4_host(s->cfg.bind_ip);
    s->tls_listen_fd = -1;
    s->device_state = 3;
    s->config_consistency = 1;
    s->dscp_urgent = EIP_DSCP_URGENT;
    s->dscp_scheduled = EIP_DSCP_SCHEDULED;
    s->dscp_high = EIP_DSCP_HIGH;
    s->dscp_low = EIP_DSCP_LOW;
    s->dscp_explicit = EIP_DSCP_EXPLICIT;
    if (s->cfg.lldp_tx_interval_sec == 0) {
        s->cfg.lldp_tx_interval_sec = 30;
    }
    /* Caller defaults: adapter sets lldp_enable/acd_enable=1 unless overridden */
    s->lldp_enable_flags = s->cfg.lldp_enable ? 0x1u : 0;
    s->lldp_tx_interval_sec = s->cfg.lldp_tx_interval_sec;
    s->lldp_tx_hold = 4;
    for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
        s->clients[i].fd = -1;
    }
    for (int i = 0; i < EIP_TLS_CLIENTS_MAX; i++) {
        s->tls_clients[i].fd = -1;
    }
    s->next_session = 1;
    if (getrandom(&s->session_secret, sizeof(s->session_secret), 0) !=
        (ssize_t)sizeof(s->session_secret)) {
        s->session_secret = (uint32_t)(eip_now_ns() ^ (uintptr_t)s);
    }
    if (s->session_secret == 0) {
        s->session_secret = 0xA5C311E7u;
    }
    s->next_conn_id = 0x20000001;
    pthread_mutex_init(&s->lock, NULL);

    if (eip_assembly_init(s) != 0) {
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }
    return s;
}

void eip_stack_destroy(eip_stack_t *s)
{
    if (!s) {
        return;
    }
    eip_stack_stop(s);
    eip_assembly_fini(s);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

const eip_cfg_t *eip_stack_cfg(const eip_stack_t *s)
{
    return s ? &s->cfg : NULL;
}

void eip_stack_set_transport_ops(eip_stack_t *s, eip_transport_ops_t ops)
{
    if (!s) {
        return;
    }
    s->tops = ops;
    s->tops_set = 1;
}

static int bind_udp(eip_stack_t *s)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.udp_io_port);
    uint32_t ip = parse_ipv4_host(s->cfg.bind_ip);
    addr.sin_addr.s_addr = ip ? htonl(ip) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    set_nonblock(fd);
    s->udp_fd = fd;
    return 0;
}

/* Encapsulation UDP (same port as TCP). RSLinx broadcasts ListIdentity here. */
static int bind_udp_encap(eip_stack_t *s)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) != 0) {
        LOG_WARN("ethernetip", "IP_PKTINFO unavailable (%d)", errno);
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.tcp_port);
    addr.sin_addr.s_addr =
        s->bind_ip_host ? htonl(s->bind_ip_host) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    set_nonblock(fd);
    s->udp_encap_fd = fd;
    return 0;
}

uint32_t eip_ipv4_local(int fd)
{
    struct sockaddr_in local;
    socklen_t llen = sizeof(local);
    if (fd < 0) {
        return 0;
    }
    memset(&local, 0, sizeof(local));
    if (getsockname(fd, (struct sockaddr *)&local, &llen) != 0 ||
        local.sin_family != AF_INET) {
        return 0;
    }
    return ntohl(local.sin_addr.s_addr);
}

static int bind_tcp_listen(eip_stack_t *s)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.tcp_port);
    uint32_t ip = parse_ipv4_host(s->cfg.bind_ip);
    addr.sin_addr.s_addr = ip ? htonl(ip) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    if (listen(fd, EIP_TCP_CLIENTS_MAX) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    set_nonblock(fd);
    s->listen_fd = fd;
    return 0;
}

static int connect_originator(eip_stack_t *s)
{
    if (!s->cfg.remote_ip[0]) {
        return -EINVAL;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.remote_port);
    if (inet_pton(AF_INET, s->cfg.remote_ip, &addr.sin_addr) != 1) {
        close(fd);
        return -EINVAL;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    set_nonblock(fd);
    s->originator_fd = fd;

    /* RegisterSession */
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    eip_wr_le16(req + 26, 0);
    if (send(fd, req, sizeof(req), 0) < 0) {
        int e = errno;
        close(fd);
        s->originator_fd = -1;
        return -e;
    }
    /* Blocking wait briefly for register reply */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
        close(fd);
        s->originator_fd = -1;
        return -ETIMEDOUT;
    }
    uint8_t resp[EIP_ENCAP_HDR_SIZE + 4];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    if (n < EIP_ENCAP_HDR_SIZE) {
        close(fd);
        s->originator_fd = -1;
        return -EIO;
    }
    s->clients[0].active = 1;
    s->clients[0].fd = fd;
    s->clients[0].session = eip_rd_le32(resp + 4);
    return 0;
}

int eip_stack_start(eip_stack_t *s)
{
    if (!s) {
        return -EINVAL;
    }
    if (s->running) {
        return 0;
    }
    if (s->cfg.mock) {
        s->running = 1;
        return 0;
    }

    int rc = 0;
    if (s->cfg.role == EIP_ROLE_ADAPTER) {
        rc = bind_tcp_listen(s);
        if (rc != 0) {
            snprintf(s->last_error, sizeof(s->last_error),
                     "TCP bind failed (%d)", rc);
            LOG_ERROR("ethernetip", "%s", s->last_error);
            return rc;
        }
        rc = bind_udp(s);
        if (rc != 0) {
            snprintf(s->last_error, sizeof(s->last_error),
                     "UDP bind failed (%d)", rc);
            LOG_ERROR("ethernetip", "%s", s->last_error);
            close(s->listen_fd);
            s->listen_fd = -1;
            return rc;
        }
        rc = bind_udp_encap(s);
        if (rc != 0) {
            snprintf(s->last_error, sizeof(s->last_error),
                     "UDP encapsulation bind failed (%d)", rc);
            LOG_ERROR("ethernetip", "%s", s->last_error);
            close(s->listen_fd);
            s->listen_fd = -1;
            close(s->udp_fd);
            s->udp_fd = -1;
            return rc;
        }
        LOG_INFO("ethernetip",
                 "adapter listening TCP:%d UDP-ENCAP:%d UDP-IO:%d in_asm=%u(%u) out_asm=%u(%u) sec=%d",
                 s->cfg.tcp_port, s->cfg.tcp_port, s->cfg.udp_io_port,
                 s->cfg.input_assembly, s->cfg.input_size,
                 s->cfg.output_assembly, s->cfg.output_size,
                 s->cfg.security_class);
        rc = eip_sec_tls_start(s);
        if (rc != 0) {
            snprintf(s->last_error, sizeof(s->last_error),
                     "TLS secure port start failed (%d)", rc);
            LOG_ERROR("ethernetip", "%s", s->last_error);
            close(s->listen_fd);
            s->listen_fd = -1;
            close(s->udp_fd);
            s->udp_fd = -1;
            close(s->udp_encap_fd);
            s->udp_encap_fd = -1;
            return rc;
        }
    } else {
        rc = connect_originator(s);
        if (rc != 0) {
            snprintf(s->last_error, sizeof(s->last_error),
                     "originator connect failed (%d)", rc);
            LOG_ERROR("ethernetip", "%s", s->last_error);
            return rc;
        }
        LOG_INFO("ethernetip", "originator connected to %s:%d session=%u",
                 s->cfg.remote_ip, s->cfg.remote_port, s->clients[0].session);
    }
    s->running = 1;
    return 0;
}

void eip_stack_stop(eip_stack_t *s)
{
    if (!s) {
        return;
    }
    s->running = 0;
    eip_sec_tls_stop(s);
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    if (s->udp_fd >= 0) {
        close(s->udp_fd);
        s->udp_fd = -1;
    }
    if (s->udp_encap_fd >= 0) {
        close(s->udp_encap_fd);
        s->udp_encap_fd = -1;
    }
    pthread_mutex_lock(&s->lock);
    s->n_sessions = 0;
    pthread_mutex_unlock(&s->lock);
    for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
        if (s->clients[i].fd >= 0 && s->clients[i].active) {
            if (s->cfg.role == EIP_ROLE_ADAPTER || i > 0) {
                close(s->clients[i].fd);
            }
        }
        s->clients[i].active = 0;
        s->clients[i].fd = -1;
        s->clients[i].rx_len = 0;
        s->clients[i].session = 0;
        s->clients[i].peer_ip = 0;
        s->clients[i].last_rx_ns = 0;
    }
    if (s->originator_fd >= 0) {
        close(s->originator_fd);
        s->originator_fd = -1;
    }
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        s->class1[i].in_use = 0;
    }
}

static int eip_count_ip(const eip_stack_t *s, uint32_t ip)
{
    int n = 0;
    for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
        if (s->clients[i].active && s->clients[i].peer_ip == ip) {
            n++;
        }
    }
    return n;
}

static void accept_clients(eip_stack_t *s, int budget)
{
    if (s->listen_fd < 0) {
        return;
    }
    while (budget-- > 0) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(s->listen_fd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            break;
        }
        uint32_t ip = ntohl(peer.sin_addr.s_addr);
        if (eip_count_ip(s, ip) >= s->cfg.max_conn_per_ip) {
            LOG_WARN("ethernetip", "per-IP limit %d from %u.%u.%u.%u",
                     s->cfg.max_conn_per_ip, (ip >> 24) & 0xff,
                     (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
            close(fd);
            continue;
        }
        int slot = -1;
        for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
            if (!s->clients[i].active) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            close(fd);
            continue;
        }
        set_nonblock(fd);
        memset(&s->clients[slot], 0, sizeof(s->clients[slot]));
        s->clients[slot].fd = fd;
        s->clients[slot].active = 1;
        s->clients[slot].peer_ip = ip;
        s->clients[slot].last_rx_ns = eip_now_ns();
    }
}

static uint32_t tcp_client_owner(eip_stack_t *s, eip_tcp_client_t *c)
{
    ptrdiff_t slot = c - s->clients;
    if (slot < 0 || slot >= EIP_TCP_CLIENTS_MAX) {
        return 0;
    }
    return eip_tcp_owner_id((int)slot);
}

static void tcp_client_drop(eip_stack_t *s, eip_tcp_client_t *c)
{
    uint32_t owner = tcp_client_owner(s, c);
    pthread_mutex_lock(&s->lock);
    eip_encap_drop_owner(s, owner);
    pthread_mutex_unlock(&s->lock);
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->active = 0;
    c->rx_len = 0;
    c->session = 0;
    c->peer_ip = 0;
    c->last_rx_ns = 0;
}

static void service_tcp_client(eip_stack_t *s, eip_tcp_client_t *c)
{
    uint8_t tmp[2048];
    uint32_t owner = tcp_client_owner(s, c);
    for (;;) {
        ssize_t n = recv(c->fd, tmp, sizeof(tmp), 0);
        if (n <= 0) {
            if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                tcp_client_drop(s, c);
            }
            break;
        }
        if (c->rx_len + (size_t)n > sizeof(c->rx)) {
            tcp_client_drop(s, c);
            break;
        }
        memcpy(c->rx + c->rx_len, tmp, (size_t)n);
        c->rx_len += (size_t)n;
        c->last_rx_ns = eip_now_ns();

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
            s->encap_local_ip = eip_ipv4_local(c->fd);
            int rc = eip_encap_process(s, c->rx, need, resp, sizeof(resp),
                                       &resp_len, owner);
            s->encap_local_ip = 0;
            uint32_t sess = 0;
            uint16_t cmd = eip_rd_le16(c->rx + 0);
            if (rc == 0 && resp_len >= 8) {
                sess = eip_rd_le32(resp + 4);
            }
            if (rc == 0 && cmd == EIP_CMD_REGISTERSESSION) {
                c->session = sess;
            }
            pthread_mutex_unlock(&s->lock);
            if (resp_len > 0 && rc == 0) {
                if (s->tops_set && s->tops.tcp_send) {
                    s->tops.tcp_send(s->tops.ctx, resp, resp_len);
                } else {
                    (void)send(c->fd, resp, resp_len, 0);
                }
            }
            memmove(c->rx, c->rx + need, c->rx_len - need);
            c->rx_len -= need;
        }
    }
}

static int udp_discovery_cmd(uint16_t cmd)
{
    return cmd == EIP_CMD_LISTIDENTITY || cmd == EIP_CMD_LISTSERVICES ||
           cmd == EIP_CMD_LISTINTERFACES;
}

static uint32_t pktinfo_spec_dst(struct msghdr *msg)
{
    struct cmsghdr *c;
    for (c = CMSG_FIRSTHDR(msg); c != NULL; c = CMSG_NXTHDR(msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(c);
            return ntohl(pi->ipi_spec_dst.s_addr);
        }
    }
    return 0;
}

static void service_udp_encap(eip_stack_t *s, int budget)
{
    if (s->udp_encap_fd < 0) {
        return;
    }
    while (budget-- > 0) {
        uint8_t buf[2048];
        uint8_t resp[2048];
        char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        struct sockaddr_in peer;
        struct iovec iov;
        struct msghdr msg;
        ssize_t n;
        uint16_t cmd;
        uint16_t length;
        uint32_t local_ip;
        size_t resp_len = 0;
        int rc;

        memset(&peer, 0, sizeof(peer));
        memset(&msg, 0, sizeof(msg));
        memset(cbuf, 0, sizeof(cbuf));
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_name = &peer;
        msg.msg_namelen = sizeof(peer);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        n = recvmsg(s->udp_encap_fd, &msg, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0 || (msg.msg_flags & MSG_TRUNC) != 0) {
            continue;
        }
        if ((size_t)n < EIP_ENCAP_HDR_SIZE) {
            continue;
        }
        cmd = eip_rd_le16(buf);
        length = eip_rd_le16(buf + 2);
        if (!udp_discovery_cmd(cmd) ||
            (size_t)EIP_ENCAP_HDR_SIZE + (size_t)length > (size_t)n) {
            continue;
        }
        local_ip = pktinfo_spec_dst(&msg);
        pthread_mutex_lock(&s->lock);
        s->encap_local_ip = local_ip;
        rc = eip_encap_process(s, buf, (size_t)n, resp, sizeof(resp), &resp_len,
                               0);
        s->encap_local_ip = 0;
        pthread_mutex_unlock(&s->lock);
        if (rc == 0 && resp_len > 0 &&
            sendto(s->udp_encap_fd, resp, resp_len, 0, (struct sockaddr *)&peer,
                   sizeof(peer)) < 0) {
            LOG_WARN("ethernetip", "UDP encapsulation sendto failed (%d)",
                     errno);
        }
    }
}

static void service_udp(eip_stack_t *s, int budget)
{
    if (s->udp_fd < 0) {
        return;
    }
    while (budget-- > 0) {
        uint8_t buf[EIP_ASSEMBLY_SIZE_MAX + 64];
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        ssize_t n =
            recvfrom(s->udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer,
                     &plen);
        if (n <= 0) {
            break;
        }
        pthread_mutex_lock(&s->lock);
        eip_io_handle_udp(s, buf, (size_t)n, ntohl(peer.sin_addr.s_addr),
                          ntohs(peer.sin_port));
        pthread_mutex_unlock(&s->lock);
    }
}

static void flush_produces(eip_stack_t *s)
{
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        if (!c->in_use || !c->produce_ready || c->peer_udp_port == 0) {
            continue;
        }
        if (s->udp_fd >= 0) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_port = htons(c->peer_udp_port);
            dst.sin_addr.s_addr = htonl(c->peer_ip);
            (void)sendto(s->udp_fd, c->last_produce, c->last_produce_len, 0,
                         (struct sockaddr *)&dst, sizeof(dst));
        }
        c->produce_ready = 0;
    }
}

void eip_stack_poll(eip_stack_t *s)
{
    if (!s || !s->running) {
        return;
    }
    uint64_t t0 = eip_now_ns();
    if (s->cfg.mock) {
        pthread_mutex_lock(&s->lock);
        eip_io_watchdog(s);
        eip_io_produce(s);
        eip_lldp_poll(s);
        pthread_mutex_unlock(&s->lock);
    } else if (s->cfg.role == EIP_ROLE_ADAPTER) {
        accept_clients(s, EIP_POLL_TCP_BUDGET);
        int tcp_left = EIP_POLL_TCP_BUDGET;
        for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
            if (s->clients[i].active && tcp_left > 0) {
                service_tcp_client(s, &s->clients[i]);
                tcp_left--;
            }
        }
        uint64_t now = eip_now_ns();
        uint64_t idle_ns = (uint64_t)s->cfg.idle_timeout_ms * 1000000ull;
        for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
            uint64_t last = s->clients[i].last_rx_ns;
            if (s->clients[i].active && idle_ns > 0 && last != 0 && now > last &&
                now - last > idle_ns) {
                LOG_INFO("ethernetip", "idle timeout TCP slot %d", i);
                tcp_client_drop(s, &s->clients[i]);
            }
        }
        service_udp(s, EIP_POLL_UDP_BUDGET);
        service_udp_encap(s, EIP_POLL_UDP_BUDGET);
        pthread_mutex_lock(&s->lock);
        eip_io_watchdog(s);
        eip_io_produce(s);
        flush_produces(s);
        eip_lldp_poll(s);
        pthread_mutex_unlock(&s->lock);
        eip_sec_tls_poll(s);
    }
    uint64_t dt = eip_now_ns() - t0;
    s->last_poll_ns = dt;
    if (dt > s->max_poll_ns) {
        s->max_poll_ns = dt;
    }
    /* Soft RT guard: warn if poll itself approaches 8ms budget */
    if (dt > 7000000ull) {
        LOG_WARN("ethernetip", "poll_cycle slow: %llu ns (target <8ms)",
                 (unsigned long long)dt);
    }
}

int eip_stack_acd_conflict(eip_stack_t *s, int conflict)
{
    if (!s) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    if (!s->cfg.acd_enable && conflict) {
        pthread_mutex_unlock(&s->lock);
        return 0;
    }
    s->acd_conflict = conflict ? 1 : 0;
    if (conflict) {
        s->acd_activity++;
        s->device_state = 2; /* minor recoverable fault */
        LOG_WARN("ethernetip", "ACD conflict detected — Identity state=MinorRF");
    } else if (s->device_state == 2) {
        s->device_state = 3;
    }
    pthread_mutex_unlock(&s->lock);
    return 0;
}

void eip_stack_rt_stats(const eip_stack_t *s, uint64_t *last_poll_ns,
                        uint64_t *max_poll_ns, uint32_t *class1_timeouts)
{
    if (!s) {
        return;
    }
    if (last_poll_ns) {
        *last_poll_ns = s->last_poll_ns;
    }
    if (max_poll_ns) {
        *max_poll_ns = s->max_poll_ns;
    }
    if (class1_timeouts) {
        *class1_timeouts = s->class1_timeouts;
    }
}

int eip_stack_lldp_frame(eip_stack_t *s, uint8_t *out, size_t cap)
{
    if (!s || !out) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    if (s->lldp_last_frame_len == 0) {
        eip_lldp_build(s);
    }
    if (s->lldp_last_frame_len == 0 || s->lldp_last_frame_len > cap) {
        pthread_mutex_unlock(&s->lock);
        return -ENOSPC;
    }
    memcpy(out, s->lldp_last_frame, s->lldp_last_frame_len);
    int n = (int)s->lldp_last_frame_len;
    pthread_mutex_unlock(&s->lock);
    return n;
}

int eip_stack_class1_up(const eip_stack_t *s)
{
    if (!s) {
        return 0;
    }
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        if (s->class1[i].in_use) {
            return 1;
        }
    }
    return 0;
}

int eip_stack_session_up(const eip_stack_t *s)
{
    if (!s) {
        return 0;
    }
    for (int i = 0; i < EIP_TCP_CLIENTS_MAX; i++) {
        if (s->clients[i].active && s->clients[i].session != 0) {
            return 1;
        }
    }
    return s->running && s->cfg.mock;
}

int eip_stack_read_input(eip_stack_t *s, size_t off, uint8_t *dst, size_t len)
{
    if (!s || !dst) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    if (off >= s->input_size) {
        pthread_mutex_unlock(&s->lock);
        return -EINVAL;
    }
    size_t n = len;
    if (off + n > s->input_size) {
        n = s->input_size - off;
    }
    memcpy(dst, s->input_data + off, n);
    pthread_mutex_unlock(&s->lock);
    return (int)n;
}

int eip_stack_write_input(eip_stack_t *s, size_t off, const uint8_t *src,
                          size_t len)
{
    if (!s || !src) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    if (off >= s->input_size) {
        pthread_mutex_unlock(&s->lock);
        return -EINVAL;
    }
    size_t n = len;
    if (off + n > s->input_size) {
        n = s->input_size - off;
    }
    memcpy(s->input_data + off, src, n);
    pthread_mutex_unlock(&s->lock);
    return (int)n;
}

int eip_stack_read_output(eip_stack_t *s, size_t off, uint8_t *dst, size_t len)
{
    if (!s || !dst) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    if (off >= s->output_size) {
        pthread_mutex_unlock(&s->lock);
        return -EINVAL;
    }
    size_t n = len;
    if (off + n > s->output_size) {
        n = s->output_size - off;
    }
    memcpy(dst, s->output_data + off, n);
    pthread_mutex_unlock(&s->lock);
    return (int)n;
}

int eip_stack_write_output(eip_stack_t *s, size_t off, const uint8_t *src,
                           size_t len)
{
    if (!s || !src) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    if (off >= s->output_size) {
        pthread_mutex_unlock(&s->lock);
        return -EINVAL;
    }
    size_t n = len;
    if (off + n > s->output_size) {
        n = s->output_size - off;
    }
    memcpy(s->output_data + off, src, n);
    pthread_mutex_unlock(&s->lock);
    return (int)n;
}

int eip_stack_handle_encap_owned(eip_stack_t *s, uint32_t owner_id,
                                 const uint8_t *req, size_t req_len,
                                 uint8_t *resp, size_t resp_cap,
                                 size_t *resp_len)
{
    if (!s) {
        return -EINVAL;
    }
    if (owner_id == 0) {
        owner_id = EIP_ENCAP_OWNER_MOCK;
    }
    pthread_mutex_lock(&s->lock);
    int rc = eip_encap_process(s, req, req_len, resp, resp_cap, resp_len,
                               owner_id);
    pthread_mutex_unlock(&s->lock);
    return rc;
}

int eip_stack_handle_encap(eip_stack_t *s, const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    return eip_stack_handle_encap_owned(s, EIP_ENCAP_OWNER_MOCK, req, req_len,
                                        resp, resp_cap, resp_len);
}

void eip_stack_drop_encap_owner(eip_stack_t *s, uint32_t owner_id)
{
    if (!s) {
        return;
    }
    pthread_mutex_lock(&s->lock);
    eip_encap_drop_owner(s, owner_id);
    pthread_mutex_unlock(&s->lock);
}

int eip_stack_session_count(const eip_stack_t *s)
{
    return s ? s->n_sessions : 0;
}

int eip_stack_handle_io(eip_stack_t *s, const uint8_t *frame, size_t len)
{
    if (!s) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->lock);
    int rc = eip_io_handle_udp(s, frame, len, 0x7f000001, 2222);
    pthread_mutex_unlock(&s->lock);
    return rc;
}
