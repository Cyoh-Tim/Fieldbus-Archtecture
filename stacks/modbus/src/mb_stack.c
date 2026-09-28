#include "mb_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logger.h"

#include <time.h>

#define MB_RX_CAP (MB_ADU_MAX * 2)

struct mb_client {
    int fd;
    uint32_t peer_ip;
    uint64_t last_rx_ns;
    uint8_t rx[MB_RX_CAP];
    size_t rx_len;
};

struct mb_stack {
    mb_cfg_t cfg;
    int listen_fd;
    int client_fd; /* client-role remote socket */
    struct mb_client clients[MB_CLIENTS_MAX];
    int max_clients;
    int connected;
    char last_error[128];

    uint16_t *holding;
    uint16_t *input;
    uint8_t *coils;    /* packed bits, ceil(n/8) bytes */
    uint8_t *discrete; /* packed bits */
    uint16_t n_holding;
    uint16_t n_input;
    uint16_t n_coil;
    uint16_t n_discrete;
};

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static int send_all(int fd, const uint8_t *buf, size_t len);
static int client_recv_adu(mb_stack_t *s, uint16_t expect_tid, uint8_t *resp,
                           size_t resp_cap, size_t *resp_len);

static uint64_t mb_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static size_t bit_bytes(uint16_t nbits)
{
    return ((size_t)nbits + 7u) / 8u;
}

static int get_bit(const uint8_t *map, uint16_t addr)
{
    return (map[addr / 8] >> (addr % 8)) & 1;
}

static void set_bit(uint8_t *map, uint16_t addr, int val)
{
    uint8_t mask = (uint8_t)(1u << (addr % 8));
    if (val) {
        map[addr / 8] |= mask;
    } else {
        map[addr / 8] &= (uint8_t)~mask;
    }
}

static int map_ok_regs(const mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint16_t qty)
{
    if (qty == 0) {
        return 0;
    }
    uint32_t end = (uint32_t)addr + (uint32_t)qty;
    if (type == MB_REG_HOLDING) {
        return end <= s->n_holding;
    }
    if (type == MB_REG_INPUT) {
        return end <= s->n_input;
    }
    return 0;
}

static int map_ok_bits(const mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint16_t qty)
{
    if (qty == 0) {
        return 0;
    }
    uint32_t end = (uint32_t)addr + (uint32_t)qty;
    if (type == MB_REG_COIL) {
        return end <= s->n_coil;
    }
    if (type == MB_REG_DISCRETE) {
        return end <= s->n_discrete;
    }
    return 0;
}

static size_t build_exception(uint8_t *resp, uint16_t tid, uint8_t unit,
                              uint8_t fc, uint8_t code)
{
    wr_be16(resp, tid);
    wr_be16(resp + 2, 0);
    wr_be16(resp + 4, 3);
    resp[6] = unit;
    resp[7] = (uint8_t)(fc | 0x80);
    resp[8] = code;
    return 9;
}

static size_t handle_pdu(mb_stack_t *s, uint16_t tid, uint8_t unit,
                         const uint8_t *pdu, size_t pdu_len, uint8_t *resp,
                         size_t resp_cap)
{
    if (pdu_len < 1 || resp_cap < 9) {
        return 0;
    }
    if (!s->cfg.unit_id_any && unit != (uint8_t)s->cfg.unit_id && unit != 0) {
        /* Wrong unit — ignore (no response) for TCP multi-drop style. */
        return 0;
    }

    uint8_t fc = pdu[0];
    uint8_t out_pdu[MB_PDU_MAX];
    size_t out_len = 0;

    switch (fc) {
    case MB_FC_READ_COILS:
    case MB_FC_READ_DISCRETE: {
        if (pdu_len < 5) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t qty = rd_be16(pdu + 3);
        mb_reg_type_t t =
            (fc == MB_FC_READ_COILS) ? MB_REG_COIL : MB_REG_DISCRETE;
        if (qty < 1 || qty > 2000 || !map_ok_bits(s, t, addr, qty)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        uint8_t nbytes = (uint8_t)((qty + 7) / 8);
        out_pdu[0] = fc;
        out_pdu[1] = nbytes;
        memset(out_pdu + 2, 0, nbytes);
        const uint8_t *map =
            (t == MB_REG_COIL) ? s->coils : s->discrete;
        for (uint16_t i = 0; i < qty; i++) {
            if (get_bit(map, (uint16_t)(addr + i))) {
                out_pdu[2 + i / 8] |= (uint8_t)(1u << (i % 8));
            }
        }
        out_len = 2u + nbytes;
        break;
    }
    case MB_FC_READ_HOLDING:
    case MB_FC_READ_INPUT: {
        if (pdu_len < 5) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t qty = rd_be16(pdu + 3);
        mb_reg_type_t t =
            (fc == MB_FC_READ_HOLDING) ? MB_REG_HOLDING : MB_REG_INPUT;
        if (qty < 1 || qty > 125 || !map_ok_regs(s, t, addr, qty)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        const uint16_t *map =
            (t == MB_REG_HOLDING) ? s->holding : s->input;
        out_pdu[0] = fc;
        out_pdu[1] = (uint8_t)(qty * 2);
        for (uint16_t i = 0; i < qty; i++) {
            wr_be16(out_pdu + 2 + i * 2, map[addr + i]);
        }
        out_len = 2u + (size_t)qty * 2u;
        break;
    }
    case MB_FC_WRITE_SINGLE_COIL: {
        if (pdu_len < 5) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t val = rd_be16(pdu + 3);
        if (val != 0x0000 && val != 0xFF00) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        if (!map_ok_bits(s, MB_REG_COIL, addr, 1)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        set_bit(s->coils, addr, val == 0xFF00);
        memcpy(out_pdu, pdu, 5);
        out_len = 5;
        break;
    }
    case MB_FC_WRITE_SINGLE_REG: {
        if (pdu_len < 5) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t val = rd_be16(pdu + 3);
        if (!map_ok_regs(s, MB_REG_HOLDING, addr, 1)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        s->holding[addr] = val;
        memcpy(out_pdu, pdu, 5);
        out_len = 5;
        break;
    }
    case MB_FC_WRITE_MULTI_COILS: {
        if (pdu_len < 6) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t qty = rd_be16(pdu + 3);
        uint8_t nbytes = pdu[5];
        if (qty < 1 || qty > 1968 || nbytes != (uint8_t)((qty + 7) / 8) ||
            pdu_len < 6u + nbytes) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        if (!map_ok_bits(s, MB_REG_COIL, addr, qty)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        for (uint16_t i = 0; i < qty; i++) {
            int bit = (pdu[6 + i / 8] >> (i % 8)) & 1;
            set_bit(s->coils, (uint16_t)(addr + i), bit);
        }
        out_pdu[0] = fc;
        wr_be16(out_pdu + 1, addr);
        wr_be16(out_pdu + 3, qty);
        out_len = 5;
        break;
    }
    case MB_FC_WRITE_MULTI_REGS: {
        if (pdu_len < 6) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t qty = rd_be16(pdu + 3);
        uint8_t nbytes = pdu[5];
        if (qty < 1 || qty > 123 || nbytes != (uint8_t)(qty * 2) ||
            pdu_len < 6u + nbytes) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        if (!map_ok_regs(s, MB_REG_HOLDING, addr, qty)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        for (uint16_t i = 0; i < qty; i++) {
            s->holding[addr + i] = rd_be16(pdu + 6 + i * 2);
        }
        out_pdu[0] = fc;
        wr_be16(out_pdu + 1, addr);
        wr_be16(out_pdu + 3, qty);
        out_len = 5;
        break;
    }
    case MB_FC_MASK_WRITE_REG: {
        /* result = (current & and_mask) | (or_mask & ~and_mask) */
        if (pdu_len < 7) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t addr = rd_be16(pdu + 1);
        uint16_t and_m = rd_be16(pdu + 3);
        uint16_t or_m = rd_be16(pdu + 5);
        if (!map_ok_regs(s, MB_REG_HOLDING, addr, 1)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        uint16_t cur = s->holding[addr];
        s->holding[addr] =
            (uint16_t)((cur & and_m) | (or_m & (uint16_t)~and_m));
        memcpy(out_pdu, pdu, 7);
        out_len = 7;
        break;
    }
    case MB_FC_READ_WRITE_REGS: {
        /* read_addr, read_qty, write_addr, write_qty, bc, data */
        if (pdu_len < 10) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        uint16_t raddr = rd_be16(pdu + 1);
        uint16_t rqty = rd_be16(pdu + 3);
        uint16_t waddr = rd_be16(pdu + 5);
        uint16_t wqty = rd_be16(pdu + 7);
        uint8_t nbytes = pdu[9];
        if (rqty < 1 || rqty > 125 || wqty < 1 || wqty > 121 ||
            nbytes != (uint8_t)(wqty * 2) || pdu_len < 10u + nbytes) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_VALUE);
        }
        if (!map_ok_regs(s, MB_REG_HOLDING, raddr, rqty) ||
            !map_ok_regs(s, MB_REG_HOLDING, waddr, wqty)) {
            return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_ADDRESS);
        }
        for (uint16_t i = 0; i < wqty; i++) {
            s->holding[waddr + i] = rd_be16(pdu + 10 + i * 2);
        }
        out_pdu[0] = fc;
        out_pdu[1] = (uint8_t)(rqty * 2);
        for (uint16_t i = 0; i < rqty; i++) {
            wr_be16(out_pdu + 2 + i * 2, s->holding[raddr + i]);
        }
        out_len = 2u + (size_t)rqty * 2u;
        break;
    }
    default:
        return build_exception(resp, tid, unit, fc, MB_EX_ILLEGAL_FUNCTION);
    }

    size_t total = MB_MBAP_LEN + out_len;
    if (total > resp_cap) {
        return 0;
    }
    wr_be16(resp, tid);
    wr_be16(resp + 2, 0);
    wr_be16(resp + 4, (uint16_t)(1 + out_len));
    resp[6] = unit;
    memcpy(resp + 7, out_pdu, out_len);
    return total;
}

int mb_stack_handle_adu(mb_stack_t *s, const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    if (!s || !req || !resp || !resp_len || req_len < MB_MBAP_LEN + 1) {
        return -EINVAL;
    }
    uint16_t tid = rd_be16(req);
    uint16_t proto = rd_be16(req + 2);
    uint16_t len = rd_be16(req + 4);
    if (proto != 0 || len < 2 || (size_t)(MB_MBAP_LEN - 1 + len) > req_len) {
        return -EINVAL;
    }
    uint8_t unit = req[6];
    const uint8_t *pdu = req + 7;
    size_t pdu_len = (size_t)len - 1u;
    size_t n = handle_pdu(s, tid, unit, pdu, pdu_len, resp, resp_cap);
    if (n == 0) {
        *resp_len = 0;
        return 0;
    }
    *resp_len = n;
    return 0;
}

mb_stack_t *mb_stack_create(const mb_cfg_t *cfg)
{
    if (!cfg) {
        return NULL;
    }
    mb_stack_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->cfg = *cfg;
    if (s->cfg.port <= 0) {
        s->cfg.port = MB_TCP_DEFAULT_PORT;
    }
    if (s->cfg.unit_id <= 0) {
        s->cfg.unit_id = MB_UNIT_ID_DEFAULT;
    }
    if (s->cfg.client_timeout_ms <= 0) {
        s->cfg.client_timeout_ms = 200;
    }
    s->max_clients = cfg->max_clients;
    if (s->max_clients < 1) {
        s->max_clients = 4;
    }
    if (s->max_clients > MB_CLIENTS_MAX) {
        s->max_clients = MB_CLIENTS_MAX;
    }
    if (s->cfg.idle_timeout_ms <= 0) {
        s->cfg.idle_timeout_ms = MB_IDLE_TIMEOUT_MS_DEFAULT;
    }
    if (s->cfg.max_conn_per_ip <= 0) {
        s->cfg.max_conn_per_ip = MB_MAX_CONN_PER_IP_DEFAULT;
    }
    s->n_holding = cfg->n_holding ? cfg->n_holding : MB_MAP_REGS_MAX;
    s->n_input = cfg->n_input ? cfg->n_input : MB_MAP_REGS_MAX;
    s->n_coil = cfg->n_coil ? cfg->n_coil : MB_MAP_BITS_MAX;
    s->n_discrete = cfg->n_discrete ? cfg->n_discrete : MB_MAP_BITS_MAX;
    if (s->n_holding > MB_MAP_REGS_MAX) {
        s->n_holding = MB_MAP_REGS_MAX;
    }
    if (s->n_input > MB_MAP_REGS_MAX) {
        s->n_input = MB_MAP_REGS_MAX;
    }
    if (s->n_coil > MB_MAP_BITS_MAX) {
        s->n_coil = MB_MAP_BITS_MAX;
    }
    if (s->n_discrete > MB_MAP_BITS_MAX) {
        s->n_discrete = MB_MAP_BITS_MAX;
    }

    s->holding = calloc(s->n_holding, sizeof(uint16_t));
    s->input = calloc(s->n_input, sizeof(uint16_t));
    s->coils = calloc(bit_bytes(s->n_coil), 1);
    s->discrete = calloc(bit_bytes(s->n_discrete), 1);
    s->listen_fd = -1;
    s->client_fd = -1;
    for (int i = 0; i < MB_CLIENTS_MAX; i++) {
        s->clients[i].fd = -1;
        s->clients[i].peer_ip = 0;
        s->clients[i].last_rx_ns = 0;
        s->clients[i].rx_len = 0;
    }
    if (!s->holding || !s->input || !s->coils || !s->discrete) {
        mb_stack_destroy(s);
        return NULL;
    }
    return s;
}

void mb_stack_destroy(mb_stack_t *s)
{
    if (!s) {
        return;
    }
    mb_stack_stop(s);
    free(s->holding);
    free(s->input);
    free(s->coils);
    free(s->discrete);
    free(s);
}

static int server_listen(mb_stack_t *s)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(s->last_error, sizeof(s->last_error), "socket: %s",
                 strerror(errno));
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (set_nonblock(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.port);
    if (!s->cfg.bind_ip[0] || strcmp(s->cfg.bind_ip, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, s->cfg.bind_ip, &addr.sin_addr) != 1) {
        snprintf(s->last_error, sizeof(s->last_error), "invalid bind_ip");
        close(fd);
        return -EINVAL;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        snprintf(s->last_error, sizeof(s->last_error), "bind: %s",
                 strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 4) != 0) {
        snprintf(s->last_error, sizeof(s->last_error), "listen: %s",
                 strerror(errno));
        close(fd);
        return -1;
    }
    s->listen_fd = fd;
    s->connected = 1;
    LOG_INFO("modbus-stack", "listening on %s:%d unit_id=%d",
             s->cfg.bind_ip[0] ? s->cfg.bind_ip : "0.0.0.0", s->cfg.port,
             s->cfg.unit_id);
    return 0;
}

static int client_connect(mb_stack_t *s)
{
    if (!s->cfg.remote_ip[0]) {
        snprintf(s->last_error, sizeof(s->last_error), "remote_ip missing");
        return -EINVAL;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.port);
    if (inet_pton(AF_INET, s->cfg.remote_ip, &addr.sin_addr) != 1) {
        close(fd);
        snprintf(s->last_error, sizeof(s->last_error), "invalid remote_ip");
        return -EINVAL;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        snprintf(s->last_error, sizeof(s->last_error), "connect: %s",
                 strerror(errno));
        close(fd);
        return -1;
    }
    set_nonblock(fd);
    s->client_fd = fd;
    s->connected = 1;
    LOG_INFO("modbus-stack", "connected to %s:%d", s->cfg.remote_ip,
             s->cfg.port);
    return 0;
}

int mb_stack_start(mb_stack_t *s)
{
    if (!s) {
        return -EINVAL;
    }
    if (s->cfg.role == MB_ROLE_CLIENT) {
        return client_connect(s);
    }
    return server_listen(s);
}

void mb_stack_stop(mb_stack_t *s)
{
    if (!s) {
        return;
    }
    for (int i = 0; i < MB_CLIENTS_MAX; i++) {
        if (s->clients[i].fd >= 0) {
            close(s->clients[i].fd);
            s->clients[i].fd = -1;
            s->clients[i].rx_len = 0;
            s->clients[i].peer_ip = 0;
            s->clients[i].last_rx_ns = 0;
        }
    }
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    if (s->client_fd >= 0) {
        close(s->client_fd);
        s->client_fd = -1;
    }
    s->connected = 0;
}

static void close_client(struct mb_client *c)
{
    if (c->fd >= 0) {
        close(c->fd);
    }
    c->fd = -1;
    c->rx_len = 0;
    c->peer_ip = 0;
    c->last_rx_ns = 0;
}

static int mb_count_ip(const mb_stack_t *s, uint32_t ip)
{
    int n = 0;
    for (int i = 0; i < MB_CLIENTS_MAX; i++) {
        if (s->clients[i].fd >= 0 && s->clients[i].peer_ip == ip) {
            n++;
        }
    }
    return n;
}

static void accept_clients(mb_stack_t *s)
{
    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(s->listen_fd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            break;
        }
        set_nonblock(fd);
        uint32_t ip = ntohl(peer.sin_addr.s_addr);
        if (mb_count_ip(s, ip) >= s->cfg.max_conn_per_ip) {
            LOG_WARN("modbus-stack", "per-IP limit %d from %u.%u.%u.%u",
                     s->cfg.max_conn_per_ip, (ip >> 24) & 0xff,
                     (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
            close(fd);
            continue;
        }
        int slot = -1;
        for (int i = 0; i < s->max_clients; i++) {
            if (s->clients[i].fd < 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            close(fd);
            continue;
        }
        s->clients[slot].fd = fd;
        s->clients[slot].rx_len = 0;
        s->clients[slot].peer_ip = ip;
        s->clients[slot].last_rx_ns = mb_now_ns();
        LOG_INFO("modbus-stack", "master connected (slot %d)", slot);
    }
}

static void serve_client(mb_stack_t *s, struct mb_client *c)
{
    for (;;) {
        if (c->rx_len >= MB_RX_CAP) {
            close_client(c);
            return;
        }
        ssize_t n = recv(c->fd, c->rx + c->rx_len, MB_RX_CAP - c->rx_len, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            close_client(c);
            return;
        }
        if (n == 0) {
            close_client(c);
            return;
        }
        c->rx_len += (size_t)n;
        c->last_rx_ns = mb_now_ns();

        while (c->rx_len >= MB_MBAP_LEN) {
            uint16_t len = rd_be16(c->rx + 4);
            size_t need = (size_t)(MB_MBAP_LEN - 1) + (size_t)len;
            if (len < 2 || need > MB_ADU_MAX) {
                close_client(c);
                return;
            }
            if (c->rx_len < need) {
                break;
            }
            uint8_t resp[MB_ADU_MAX];
            size_t resp_len = 0;
            if (mb_stack_handle_adu(s, c->rx, need, resp, sizeof(resp),
                                    &resp_len) == 0 &&
                resp_len > 0) {
                if (send_all(c->fd, resp, resp_len) != 0) {
                    close_client(c);
                    return;
                }
            }
            memmove(c->rx, c->rx + need, c->rx_len - need);
            c->rx_len -= need;
        }
    }
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

static int client_recv_adu(mb_stack_t *s, uint16_t expect_tid, uint8_t *resp,
                           size_t resp_cap, size_t *resp_len)
{
    size_t got = 0;
    int to_ms = s->cfg.client_timeout_ms > 0 ? s->cfg.client_timeout_ms : 200;
    while (got < MB_MBAP_LEN) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s->client_fd, &rfds);
        struct timeval tv = {.tv_sec = to_ms / 1000,
                             .tv_usec = (to_ms % 1000) * 1000};
        if (select(s->client_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            snprintf(s->last_error, sizeof(s->last_error), "client read timeout");
            return -ETIMEDOUT;
        }
        ssize_t n = recv(s->client_fd, resp + got, resp_cap - got, 0);
        if (n <= 0) {
            s->connected = 0;
            return -EIO;
        }
        got += (size_t)n;
    }
    uint16_t tid = rd_be16(resp);
    uint16_t proto = rd_be16(resp + 2);
    uint16_t len = rd_be16(resp + 4);
    if (proto != 0 || len < 2) {
        return -EIO;
    }
    size_t need = (size_t)(MB_MBAP_LEN - 1) + (size_t)len;
    if (need > resp_cap) {
        return -ENOSPC;
    }
    while (got < need) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s->client_fd, &rfds);
        struct timeval tv = {.tv_sec = to_ms / 1000,
                             .tv_usec = (to_ms % 1000) * 1000};
        if (select(s->client_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            snprintf(s->last_error, sizeof(s->last_error), "client read timeout");
            return -ETIMEDOUT;
        }
        ssize_t n = recv(s->client_fd, resp + got, need - got, 0);
        if (n <= 0) {
            s->connected = 0;
            return -EIO;
        }
        got += (size_t)n;
    }
    if (tid != expect_tid) {
        snprintf(s->last_error, sizeof(s->last_error), "tid mismatch");
        return -EIO;
    }
    *resp_len = need;
    return 0;
}

/* Client-role: issue one FC03/04/01/02 into local cache. Used by adapter. */
static int client_txn(mb_stack_t *s, uint8_t fc, uint16_t addr, uint16_t qty,
                      uint8_t *data_out, size_t *data_len)
{
    if (s->client_fd < 0) {
        return -ENOTCONN;
    }
    if ((fc == MB_FC_READ_HOLDING || fc == MB_FC_READ_INPUT) &&
        (qty < 1 || qty > 125)) {
        return -EINVAL;
    }
    if ((fc == MB_FC_READ_COILS || fc == MB_FC_READ_DISCRETE) &&
        (qty < 1 || qty > 2000)) {
        return -EINVAL;
    }
    static uint16_t tid_seq;
    uint16_t tid = ++tid_seq;
    if (tid == 0) {
        tid = ++tid_seq;
    }
    uint8_t req[12];
    wr_be16(req, tid);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = (uint8_t)s->cfg.unit_id;
    req[7] = fc;
    wr_be16(req + 8, addr);
    wr_be16(req + 10, qty);
    if (send_all(s->client_fd, req, sizeof(req)) != 0) {
        s->connected = 0;
        return -EIO;
    }

    uint8_t resp[MB_ADU_MAX];
    size_t resp_len = 0;
    int rc = client_recv_adu(s, tid, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        return rc;
    }
    uint8_t rfc = resp[7];
    if (rfc & 0x80) {
        snprintf(s->last_error, sizeof(s->last_error), "exception 0x%02x",
                 resp[8]);
        return -EIO;
    }
    if (rfc != fc || resp_len < 9) {
        return -EIO;
    }
    uint8_t nbytes = resp[8];
    if ((size_t)nbytes + 9 > resp_len) {
        return -EIO;
    }
    if (data_out && data_len) {
        if (*data_len < nbytes) {
            return -ENOSPC;
        }
        memcpy(data_out, resp + 9, nbytes);
        *data_len = nbytes;
    }

    /* Mirror into local map for read_point cache. */
    if (fc == MB_FC_READ_HOLDING || fc == MB_FC_READ_INPUT) {
        uint16_t *map =
            (fc == MB_FC_READ_HOLDING) ? s->holding : s->input;
        uint16_t nreg = (uint16_t)(nbytes / 2);
        if (!map_ok_regs(s,
                         fc == MB_FC_READ_HOLDING ? MB_REG_HOLDING
                                                   : MB_REG_INPUT,
                         addr, nreg)) {
            return -EINVAL;
        }
        for (uint16_t i = 0; i < nreg; i++) {
            map[addr + i] = rd_be16(resp + 9 + i * 2);
        }
    } else if (fc == MB_FC_READ_COILS || fc == MB_FC_READ_DISCRETE) {
        uint8_t *map = (fc == MB_FC_READ_COILS) ? s->coils : s->discrete;
        mb_reg_type_t t =
            (fc == MB_FC_READ_COILS) ? MB_REG_COIL : MB_REG_DISCRETE;
        if (!map_ok_bits(s, t, addr, qty)) {
            return -EINVAL;
        }
        for (uint16_t i = 0; i < qty; i++) {
            int bit = (resp[9 + i / 8] >> (i % 8)) & 1;
            set_bit(map, (uint16_t)(addr + i), bit);
        }
    }
    return 0;
}

int mb_stack_client_read(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                         uint16_t quantity)
{
    if (!s || s->cfg.role != MB_ROLE_CLIENT) {
        return -EINVAL;
    }
    uint8_t fc;
    switch (type) {
    case MB_REG_HOLDING:
        fc = MB_FC_READ_HOLDING;
        break;
    case MB_REG_INPUT:
        fc = MB_FC_READ_INPUT;
        break;
    case MB_REG_COIL:
        fc = MB_FC_READ_COILS;
        break;
    case MB_REG_DISCRETE:
        fc = MB_FC_READ_DISCRETE;
        break;
    default:
        return -EINVAL;
    }
    uint8_t tmp[250];
    size_t tlen = sizeof(tmp);
    return client_txn(s, fc, addr, quantity, tmp, &tlen);
}

int mb_stack_client_write_regs(mb_stack_t *s, uint16_t addr,
                               const uint16_t *src, uint16_t quantity)
{
    if (!s || s->cfg.role != MB_ROLE_CLIENT || !src || quantity == 0 ||
        quantity > 123) {
        return -EINVAL;
    }
    if (s->client_fd < 0) {
        return -ENOTCONN;
    }
    static uint16_t tid_seq;
    uint16_t tid = ++tid_seq;
    if (tid == 0) {
        tid = ++tid_seq;
    }
    uint8_t req[MB_ADU_MAX];
    size_t total;
    if (quantity == 1) {
        wr_be16(req, tid);
        wr_be16(req + 2, 0);
        wr_be16(req + 4, 6);
        req[6] = (uint8_t)s->cfg.unit_id;
        req[7] = MB_FC_WRITE_SINGLE_REG;
        wr_be16(req + 8, addr);
        wr_be16(req + 10, src[0]);
        total = 12;
    } else {
        size_t pdu_len = 6u + (size_t)quantity * 2u;
        total = 7 + pdu_len;
        if (total > MB_ADU_MAX) {
            return -EINVAL;
        }
        wr_be16(req, tid);
        wr_be16(req + 2, 0);
        wr_be16(req + 4, (uint16_t)(1 + pdu_len));
        req[6] = (uint8_t)s->cfg.unit_id;
        req[7] = MB_FC_WRITE_MULTI_REGS;
        wr_be16(req + 8, addr);
        wr_be16(req + 10, quantity);
        req[12] = (uint8_t)(quantity * 2);
        for (uint16_t i = 0; i < quantity; i++) {
            wr_be16(req + 13 + i * 2, src[i]);
        }
    }
    if (send_all(s->client_fd, req, total) != 0) {
        s->connected = 0;
        return -EIO;
    }
    uint8_t resp[MB_ADU_MAX];
    size_t resp_len = 0;
    int rc = client_recv_adu(s, tid, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        return rc;
    }
    uint8_t rfc = resp[7];
    if (rfc & 0x80) {
        snprintf(s->last_error, sizeof(s->last_error), "exception 0x%02x",
                 resp[8]);
        return -EIO;
    }
    if (rfc != (quantity == 1 ? MB_FC_WRITE_SINGLE_REG
                              : MB_FC_WRITE_MULTI_REGS)) {
        return -EIO;
    }
    if (map_ok_regs(s, MB_REG_HOLDING, addr, quantity)) {
        memcpy(&s->holding[addr], src, quantity * sizeof(uint16_t));
    }
    return 0;
}

int mb_stack_client_write_bits(mb_stack_t *s, uint16_t addr, const uint8_t *src,
                               uint16_t quantity)
{
    if (!s || s->cfg.role != MB_ROLE_CLIENT || !src || quantity == 0 ||
        quantity > 1968) {
        return -EINVAL;
    }
    if (s->client_fd < 0) {
        return -ENOTCONN;
    }
    static uint16_t tid_seq;
    uint16_t tid = ++tid_seq;
    if (tid == 0) {
        tid = ++tid_seq;
    }
    uint8_t req[MB_ADU_MAX];
    size_t total;
    if (quantity == 1) {
        wr_be16(req, tid);
        wr_be16(req + 2, 0);
        wr_be16(req + 4, 6);
        req[6] = (uint8_t)s->cfg.unit_id;
        req[7] = MB_FC_WRITE_SINGLE_COIL;
        wr_be16(req + 8, addr);
        wr_be16(req + 10, src[0] ? 0xFF00 : 0x0000);
        total = 12;
    } else {
        uint8_t nbytes = (uint8_t)((quantity + 7) / 8);
        size_t pdu_len = 6u + nbytes;
        total = 7 + pdu_len;
        if (total > MB_ADU_MAX) {
            return -EINVAL;
        }
        wr_be16(req, tid);
        wr_be16(req + 2, 0);
        wr_be16(req + 4, (uint16_t)(1 + pdu_len));
        req[6] = (uint8_t)s->cfg.unit_id;
        req[7] = MB_FC_WRITE_MULTI_COILS;
        wr_be16(req + 8, addr);
        wr_be16(req + 10, quantity);
        req[12] = nbytes;
        memset(req + 13, 0, nbytes);
        for (uint16_t i = 0; i < quantity; i++) {
            if (src[i]) {
                req[13 + i / 8] |= (uint8_t)(1u << (i % 8));
            }
        }
    }
    if (send_all(s->client_fd, req, total) != 0) {
        s->connected = 0;
        return -EIO;
    }
    uint8_t resp[MB_ADU_MAX];
    size_t resp_len = 0;
    int rc = client_recv_adu(s, tid, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        return rc;
    }
    uint8_t rfc = resp[7];
    if (rfc & 0x80) {
        snprintf(s->last_error, sizeof(s->last_error), "exception 0x%02x",
                 resp[8]);
        return -EIO;
    }
    if (rfc != (quantity == 1 ? MB_FC_WRITE_SINGLE_COIL
                              : MB_FC_WRITE_MULTI_COILS)) {
        return -EIO;
    }
    for (uint16_t i = 0; i < quantity; i++) {
        if (map_ok_bits(s, MB_REG_COIL, (uint16_t)(addr + i), 1)) {
            set_bit(s->coils, (uint16_t)(addr + i), src[i] ? 1 : 0);
        }
    }
    return 0;
}

void mb_stack_poll(mb_stack_t *s)
{
    if (!s) {
        return;
    }
    if (s->cfg.role == MB_ROLE_SERVER) {
        if (s->listen_fd < 0) {
            return;
        }
        accept_clients(s);
        for (int i = 0; i < MB_CLIENTS_MAX; i++) {
            if (s->clients[i].fd >= 0) {
                serve_client(s, &s->clients[i]);
            }
        }
        uint64_t now = mb_now_ns();
        uint64_t idle_ns =
            (uint64_t)s->cfg.idle_timeout_ms * 1000000ull;
        for (int i = 0; i < MB_CLIENTS_MAX; i++) {
            uint64_t last = s->clients[i].last_rx_ns;
            if (s->clients[i].fd >= 0 && idle_ns > 0 && last != 0 &&
                now > last && now - last > idle_ns) {
                LOG_INFO("modbus-stack", "idle timeout slot %d", i);
                close_client(&s->clients[i]);
            }
        }
        return;
    }

    /* Client: reconnect if needed. Point refresh is driven by adapter. */
    if (s->client_fd < 0 || !s->connected) {
        if (s->client_fd >= 0) {
            close(s->client_fd);
            s->client_fd = -1;
        }
        (void)client_connect(s);
    }
}

int mb_stack_connected(const mb_stack_t *s)
{
    return s ? s->connected : 0;
}

const mb_cfg_t *mb_stack_cfg(const mb_stack_t *s)
{
    return s ? &s->cfg : NULL;
}

int mb_stack_read_regs(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint16_t *dst, uint16_t quantity)
{
    if (!s || !dst || !map_ok_regs(s, type, addr, quantity)) {
        return -EINVAL;
    }
    const uint16_t *map =
        (type == MB_REG_HOLDING) ? s->holding : s->input;
    if (type != MB_REG_HOLDING && type != MB_REG_INPUT) {
        return -EINVAL;
    }
    memcpy(dst, &map[addr], quantity * sizeof(uint16_t));
    return 0;
}

int mb_stack_write_regs(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        const uint16_t *src, uint16_t quantity)
{
    if (!s || !src || (type != MB_REG_HOLDING && type != MB_REG_INPUT)) {
        return -EINVAL;
    }
    if (!map_ok_regs(s, type, addr, quantity)) {
        return -EINVAL;
    }
    uint16_t *map = (type == MB_REG_HOLDING) ? s->holding : s->input;
    memcpy(&map[addr], src, quantity * sizeof(uint16_t));
    return 0;
}

int mb_stack_read_bits(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint8_t *dst, uint16_t quantity)
{
    if (!s || !dst || !map_ok_bits(s, type, addr, quantity)) {
        return -EINVAL;
    }
    const uint8_t *map =
        (type == MB_REG_COIL) ? s->coils : s->discrete;
    if (type != MB_REG_COIL && type != MB_REG_DISCRETE) {
        return -EINVAL;
    }
    for (uint16_t i = 0; i < quantity; i++) {
        dst[i] = (uint8_t)get_bit(map, (uint16_t)(addr + i));
    }
    return 0;
}

int mb_stack_write_bits(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        const uint8_t *src, uint16_t quantity)
{
    if (!s || !src) {
        return -EINVAL;
    }
    if (type != MB_REG_COIL && type != MB_REG_DISCRETE) {
        return -EINVAL;
    }
    if (!map_ok_bits(s, type, addr, quantity)) {
        return -EINVAL;
    }
    uint8_t *map = (type == MB_REG_COIL) ? s->coils : s->discrete;
    for (uint16_t i = 0; i < quantity; i++) {
        set_bit(map, (uint16_t)(addr + i), src[i] ? 1 : 0);
    }
    return 0;
}

int mb_stack_read_bytes(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        uint8_t *dst, size_t len)
{
    if (!s || !dst || len == 0) {
        return -EINVAL;
    }
    if (type == MB_REG_COIL || type == MB_REG_DISCRETE) {
        if (len > 0xFFFF || !map_ok_bits(s, type, addr, (uint16_t)len)) {
            return -EINVAL;
        }
        return mb_stack_read_bits(s, type, addr, dst, (uint16_t)len);
    }
    uint16_t qty = (uint16_t)((len + 1) / 2);
    if (!map_ok_regs(s, type, addr, qty)) {
        return -EINVAL;
    }
    const uint16_t *map =
        (type == MB_REG_HOLDING) ? s->holding : s->input;
    for (size_t i = 0; i < len; i++) {
        uint16_t reg = map[addr + i / 2];
        dst[i] = (i % 2 == 0) ? (uint8_t)(reg >> 8) : (uint8_t)(reg & 0xff);
    }
    return 0;
}

int mb_stack_write_bytes(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                         const uint8_t *src, size_t len)
{
    if (!s || !src || len == 0) {
        return -EINVAL;
    }
    if (type == MB_REG_COIL || type == MB_REG_DISCRETE) {
        if (len > 0xFFFF || !map_ok_bits(s, type, addr, (uint16_t)len)) {
            return -EINVAL;
        }
        return mb_stack_write_bits(s, type, addr, src, (uint16_t)len);
    }
    uint16_t qty = (uint16_t)((len + 1) / 2);
    if (!map_ok_regs(s, type, addr, qty)) {
        return -EINVAL;
    }
    uint16_t *map = (type == MB_REG_HOLDING) ? s->holding : s->input;
    for (uint16_t i = 0; i < qty; i++) {
        size_t off = (size_t)i * 2u;
        uint8_t hi = (off < len) ? src[off] : 0;
        uint8_t lo = (off + 1 < len) ? src[off + 1] : 0;
        map[addr + i] = (uint16_t)((hi << 8) | lo);
    }
    return 0;
}
