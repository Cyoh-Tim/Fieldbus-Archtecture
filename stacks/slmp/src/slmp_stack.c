#include "slmp_stack.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "logger.h"

typedef struct {
    uint8_t code;
    int is_bit;
    uint16_t *words; /* bit devices: packed LSB-first within each word */
    uint32_t capacity; /* words, or bit-count rounded up into words storage */
    uint32_t bit_capacity;
} slmp_dev_slot_t;

struct slmp_stack {
    slmp_cfg_t cfg;
    int sockfd; /* client: connected fd; server: listen fd */
    int client_fds[8];
    int n_clients;
    int connected;
    slmp_dev_slot_t maps[SLMP_DEV_MAP_MAX];
    int map_count;
    char last_error[128];
};

typedef struct {
    const char *name;
    uint8_t code;
    int is_bit;
    int hex_addr; /* X/Y/B/W/SB/SW style hex head numbers in manuals */
} slmp_dev_info_t;

static const slmp_dev_info_t g_devices[] = {
    {"X", SLMP_DEV_X, 1, 1},     {"Y", SLMP_DEV_Y, 1, 1},
    {"M", SLMP_DEV_M, 1, 0},     {"L", SLMP_DEV_L, 1, 0},
    {"F", SLMP_DEV_F, 1, 0},     {"V", SLMP_DEV_V, 1, 0},
    {"B", SLMP_DEV_B, 1, 1},     {"D", SLMP_DEV_D, 0, 0},
    {"W", SLMP_DEV_W, 0, 1},     {"TS", SLMP_DEV_TS, 1, 0},
    {"TC", SLMP_DEV_TC, 1, 0},   {"TN", SLMP_DEV_TN, 0, 0},
    {"SS", SLMP_DEV_SS, 1, 0},   {"SC", SLMP_DEV_SC, 1, 0},
    {"SN", SLMP_DEV_SN, 0, 0},   {"CS", SLMP_DEV_CS, 1, 0},
    {"CC", SLMP_DEV_CC, 1, 0},   {"CN", SLMP_DEV_CN, 0, 0},
    {"SB", SLMP_DEV_SB, 1, 1},   {"SW", SLMP_DEV_SW, 0, 1},
    {"S", SLMP_DEV_S, 1, 0},     {"DX", SLMP_DEV_DX, 1, 1},
    {"DY", SLMP_DEV_DY, 1, 1},   {"Z", SLMP_DEV_Z, 0, 0},
    {"R", SLMP_DEV_R, 0, 0},     {"ZR", SLMP_DEV_ZR, 0, 0},
    {"SM", SLMP_DEV_SM, 1, 0},   {"SD", SLMP_DEV_SD, 0, 0},
};

static int eqi_ch(char a, char b)
{
    if (a >= 'A' && a <= 'Z') {
        a = (char)(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
        b = (char)(b - 'A' + 'a');
    }
    return a == b;
}

static int eqi(const char *a, const char *b)
{
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        if (!eqi_ch(*a, *b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void wr_le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
}

static uint32_t rd_le24(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

int slmp_device_code_from_name(const char *name, uint8_t *code_out, int *is_bit)
{
    if (!name || !name[0] || !code_out) {
        return -EINVAL;
    }
    /* Raw numeric / 0xNN */
    if ((name[0] >= '0' && name[0] <= '9') ||
        (name[0] == '0' && (name[1] == 'x' || name[1] == 'X'))) {
        char *end = NULL;
        unsigned long v = strtoul(name, &end, 0);
        if (end == name || v > 0xFF) {
            return -EINVAL;
        }
        *code_out = (uint8_t)v;
        if (is_bit) {
            *is_bit = 0;
            for (size_t i = 0; i < sizeof(g_devices) / sizeof(g_devices[0]);
                 i++) {
                if (g_devices[i].code == (uint8_t)v) {
                    *is_bit = g_devices[i].is_bit;
                    break;
                }
            }
        }
        return 0;
    }
    for (size_t i = 0; i < sizeof(g_devices) / sizeof(g_devices[0]); i++) {
        if (eqi(name, g_devices[i].name)) {
            *code_out = g_devices[i].code;
            if (is_bit) {
                *is_bit = g_devices[i].is_bit;
            }
            return 0;
        }
    }
    return -ENOENT;
}

const char *slmp_device_name_from_code(uint8_t code)
{
    for (size_t i = 0; i < sizeof(g_devices) / sizeof(g_devices[0]); i++) {
        if (g_devices[i].code == code) {
            return g_devices[i].name;
        }
    }
    return NULL;
}

int slmp_device_is_hex_addr(uint8_t code)
{
    for (size_t i = 0; i < sizeof(g_devices) / sizeof(g_devices[0]); i++) {
        if (g_devices[i].code == code) {
            return g_devices[i].hex_addr;
        }
    }
    return 0;
}

static slmp_dev_slot_t *find_slot(slmp_stack_t *s, uint8_t code)
{
    for (int i = 0; i < s->map_count; i++) {
        if (s->maps[i].code == code) {
            return &s->maps[i];
        }
    }
    return NULL;
}

int slmp_stack_map_ensure(slmp_stack_t *s, uint8_t device_code, int is_bit)
{
    if (!s) {
        return -EINVAL;
    }
    slmp_dev_slot_t *slot = find_slot(s, device_code);
    if (slot) {
        return 0;
    }
    if (s->map_count >= SLMP_DEV_MAP_MAX) {
        return -ENOSPC;
    }
    slot = &s->maps[s->map_count];
    memset(slot, 0, sizeof(*slot));
    slot->code = device_code;
    slot->is_bit = is_bit ? 1 : 0;
    if (slot->is_bit) {
        slot->bit_capacity =
            s->cfg.map_bits ? s->cfg.map_bits : SLMP_DEV_BITS_DEFAULT;
        slot->capacity = (slot->bit_capacity + 15u) / 16u;
    } else {
        slot->capacity =
            s->cfg.map_words ? s->cfg.map_words : SLMP_DEV_WORDS_DEFAULT;
        slot->bit_capacity = 0;
    }
    slot->words = calloc(slot->capacity, sizeof(uint16_t));
    if (!slot->words) {
        return -ENOMEM;
    }
    s->map_count++;
    return 0;
}

static int default_is_bit(uint8_t code)
{
    for (size_t i = 0; i < sizeof(g_devices) / sizeof(g_devices[0]); i++) {
        if (g_devices[i].code == code) {
            return g_devices[i].is_bit;
        }
    }
    return 0;
}

slmp_stack_t *slmp_stack_create(const slmp_cfg_t *cfg)
{
    if (!cfg) {
        return NULL;
    }
    if (cfg->frame != SLMP_FRAME_3E_BINARY) {
        LOG_ERROR("slmp", "현재 Binary 3E 만 지원 (frame=%d)", (int)cfg->frame);
        return NULL;
    }
    slmp_stack_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->cfg = *cfg;
    s->sockfd = -1;
    for (int i = 0; i < 8; i++) {
        s->client_fds[i] = -1;
    }
    if (s->cfg.port <= 0) {
        s->cfg.port = SLMP_TCP_DEFAULT_PORT;
    }
    if (s->cfg.pc_no == 0 && cfg->pc_no == 0) {
        /* Keep 0 if explicitly set; default own-station is 0xFF when unset.
         * Callers should set pc_no; adapter defaults to 0xFF. */
    }
    if (s->cfg.dest_module_io == 0) {
        s->cfg.dest_module_io = SLMP_DEST_MODULE_CPU;
    }
    if (s->cfg.timeout_ms <= 0) {
        s->cfg.timeout_ms = 1000;
    }
    if (s->cfg.max_clients <= 0 || s->cfg.max_clients > 8) {
        s->cfg.max_clients = 4;
    }
    if (s->cfg.monitoring_timer == 0) {
        s->cfg.monitoring_timer = 0x0010; /* 4s */
    }
    /* Pre-seed common maps for server/sim convenience */
    slmp_stack_map_ensure(s, SLMP_DEV_D, 0);
    slmp_stack_map_ensure(s, SLMP_DEV_W, 0);
    slmp_stack_map_ensure(s, SLMP_DEV_R, 0);
    slmp_stack_map_ensure(s, SLMP_DEV_M, 1);
    slmp_stack_map_ensure(s, SLMP_DEV_X, 1);
    slmp_stack_map_ensure(s, SLMP_DEV_Y, 1);
    slmp_stack_map_ensure(s, SLMP_DEV_B, 1);
    return s;
}

void slmp_stack_destroy(slmp_stack_t *s)
{
    if (!s) {
        return;
    }
    slmp_stack_stop(s);
    for (int i = 0; i < s->map_count; i++) {
        free(s->maps[i].words);
    }
    free(s);
}

const slmp_cfg_t *slmp_stack_cfg(const slmp_stack_t *s)
{
    return s ? &s->cfg : NULL;
}

int slmp_stack_connected(const slmp_stack_t *s)
{
    return s ? s->connected : 0;
}

int slmp_stack_read_words(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                          uint16_t *dst, uint16_t quantity)
{
    if (!s || !dst || quantity == 0) {
        return -EINVAL;
    }
    if (slmp_stack_map_ensure(s, device_code, default_is_bit(device_code)) !=
        0) {
        return -ENOMEM;
    }
    slmp_dev_slot_t *slot = find_slot(s, device_code);
    if (!slot || slot->is_bit) {
        /* Allow reading bit device in word units from packed storage */
        if (!slot) {
            return -ENOENT;
        }
    }
    if (head + quantity > slot->capacity) {
        return -ERANGE;
    }
    memcpy(dst, slot->words + head, quantity * sizeof(uint16_t));
    return 0;
}

int slmp_stack_write_words(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                           const uint16_t *src, uint16_t quantity)
{
    if (!s || !src || quantity == 0) {
        return -EINVAL;
    }
    if (slmp_stack_map_ensure(s, device_code, default_is_bit(device_code)) !=
        0) {
        return -ENOMEM;
    }
    slmp_dev_slot_t *slot = find_slot(s, device_code);
    if (!slot) {
        return -ENOENT;
    }
    if (head + quantity > slot->capacity) {
        return -ERANGE;
    }
    memcpy(slot->words + head, src, quantity * sizeof(uint16_t));
    return 0;
}

int slmp_stack_read_bits(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                         uint8_t *dst, uint16_t quantity)
{
    if (!s || !dst || quantity == 0) {
        return -EINVAL;
    }
    if (slmp_stack_map_ensure(s, device_code, 1) != 0) {
        return -ENOMEM;
    }
    slmp_dev_slot_t *slot = find_slot(s, device_code);
    if (!slot) {
        return -ENOENT;
    }
    uint32_t lim = slot->is_bit ? slot->bit_capacity : slot->capacity * 16u;
    if (head + quantity > lim) {
        return -ERANGE;
    }
    for (uint16_t i = 0; i < quantity; i++) {
        uint32_t bit = head + i;
        uint16_t w = slot->words[bit / 16u];
        dst[i] = (uint8_t)((w >> (bit % 16u)) & 1u);
    }
    return 0;
}

int slmp_stack_write_bits(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                          const uint8_t *src, uint16_t quantity)
{
    if (!s || !src || quantity == 0) {
        return -EINVAL;
    }
    if (slmp_stack_map_ensure(s, device_code, 1) != 0) {
        return -ENOMEM;
    }
    slmp_dev_slot_t *slot = find_slot(s, device_code);
    if (!slot) {
        return -ENOENT;
    }
    uint32_t lim = slot->is_bit ? slot->bit_capacity : slot->capacity * 16u;
    if (head + quantity > lim) {
        return -ERANGE;
    }
    for (uint16_t i = 0; i < quantity; i++) {
        uint32_t bit = head + i;
        uint32_t wi = bit / 16u;
        uint16_t mask = (uint16_t)(1u << (bit % 16u));
        if (src[i]) {
            slot->words[wi] = (uint16_t)(slot->words[wi] | mask);
        } else {
            slot->words[wi] = (uint16_t)(slot->words[wi] & (uint16_t)~mask);
        }
    }
    return 0;
}

int slmp_stack_read_bytes(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                          uint8_t *dst, size_t len)
{
    if (!dst || len == 0) {
        return -EINVAL;
    }
    uint16_t nwords = (uint16_t)((len + 1) / 2);
    uint16_t *tmp = calloc(nwords, sizeof(uint16_t));
    if (!tmp) {
        return -ENOMEM;
    }
    int rc = slmp_stack_read_words(s, device_code, head, tmp, nwords);
    if (rc == 0) {
        for (uint16_t i = 0; i < nwords; i++) {
            size_t o = (size_t)i * 2u;
            if (o < len) {
                dst[o] = (uint8_t)(tmp[i] >> 8); /* canonical BE window */
            }
            if (o + 1 < len) {
                dst[o + 1] = (uint8_t)(tmp[i] & 0xff);
            }
        }
    }
    free(tmp);
    return rc;
}

int slmp_stack_write_bytes(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                           const uint8_t *src, size_t len)
{
    if (!src || len == 0) {
        return -EINVAL;
    }
    uint16_t nwords = (uint16_t)((len + 1) / 2);
    uint16_t *tmp = calloc(nwords, sizeof(uint16_t));
    if (!tmp) {
        return -ENOMEM;
    }
    for (uint16_t i = 0; i < nwords; i++) {
        size_t o = (size_t)i * 2u;
        uint8_t hi = o < len ? src[o] : 0;
        uint8_t lo = (o + 1 < len) ? src[o + 1] : 0;
        tmp[i] = (uint16_t)(((uint16_t)hi << 8) | lo);
    }
    int rc = slmp_stack_write_words(s, device_code, head, tmp, nwords);
    free(tmp);
    return rc;
}

static int encode_subheader(const slmp_cfg_t *cfg, uint16_t data_len,
                            uint8_t *out, size_t out_cap)
{
    if (out_cap < 11) {
        return -ENOSPC;
    }
    wr_le16(out, SLMP_SUBHEADER_REQ_3E);
    out[2] = cfg->network_no;
    out[3] = cfg->pc_no;
    wr_le16(out + 4, cfg->dest_module_io);
    out[6] = cfg->dest_multidrop;
    wr_le16(out + 7, data_len);
    return 11;
}

int slmp_encode_batch_read(const slmp_cfg_t *cfg, const slmp_range_t *range,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!cfg || !range || !out || !out_len) {
        return -EINVAL;
    }
    /* monitoring(2)+cmd(2)+sub(2)+dev(4)+qty(2) = 12 */
    const uint16_t data_len = 12;
    if (out_cap < 9 + data_len) {
        return -ENOSPC;
    }
    encode_subheader(cfg, data_len, out, out_cap);
    wr_le16(out + 9, cfg->monitoring_timer);
    wr_le16(out + 11, SLMP_CMD_BATCH_READ);
    wr_le16(out + 13, range->addr.unit == SLMP_ACCESS_BIT ? SLMP_SUB_BIT
                                                          : SLMP_SUB_WORD);
    wr_le24(out + 15, range->addr.head);
    out[18] = range->addr.device_code;
    wr_le16(out + 19, range->quantity);
    *out_len = 21;
    return 0;
}

int slmp_encode_batch_write(const slmp_cfg_t *cfg, const slmp_range_t *range,
                            const uint8_t *raw, size_t raw_len, uint8_t *out,
                            size_t out_cap, size_t *out_len)
{
    if (!cfg || !range || !out || !out_len) {
        return -EINVAL;
    }
    size_t need_data;
    if (range->addr.unit == SLMP_ACCESS_BIT) {
        need_data = (size_t)range->quantity; /* 1 byte/bit */
    } else {
        need_data = (size_t)range->quantity * 2u; /* LE words on wire */
    }
    if (raw_len < need_data) {
        return -EINVAL;
    }
    uint16_t data_len = (uint16_t)(12 + need_data);
    if (out_cap < (size_t)9 + data_len) {
        return -ENOSPC;
    }
    encode_subheader(cfg, data_len, out, out_cap);
    wr_le16(out + 9, cfg->monitoring_timer);
    wr_le16(out + 11, SLMP_CMD_BATCH_WRITE);
    wr_le16(out + 13, range->addr.unit == SLMP_ACCESS_BIT ? SLMP_SUB_BIT
                                                          : SLMP_SUB_WORD);
    wr_le24(out + 15, range->addr.head);
    out[18] = range->addr.device_code;
    wr_le16(out + 19, range->quantity);
    if (range->addr.unit == SLMP_ACCESS_BIT) {
        memcpy(out + 21, raw, need_data);
    } else {
        /* raw is canonical BE bytes from adapter; convert to SLMP LE words */
        for (uint16_t i = 0; i < range->quantity; i++) {
            uint8_t hi = raw[i * 2u];
            uint8_t lo = raw[i * 2u + 1u];
            out[21 + i * 2u] = lo;
            out[21 + i * 2u + 1u] = hi;
        }
    }
    *out_len = 21 + need_data;
    return 0;
}

int slmp_decode_response(const uint8_t *frame, size_t frame_len,
                         uint16_t *end_code, const uint8_t **data,
                         size_t *data_len)
{
    if (!frame || frame_len < 11 || !end_code) {
        return -EINVAL;
    }
    if (rd_le16(frame) != SLMP_SUBHEADER_RES_3E) {
        return -EBADMSG;
    }
    uint16_t resp_len = rd_le16(frame + 7);
    if (frame_len < (size_t)9 + resp_len) {
        return -EBADMSG;
    }
    if (resp_len < 2) {
        return -EBADMSG;
    }
    *end_code = rd_le16(frame + 9);
    if (data && data_len) {
        if (resp_len > 2) {
            *data = frame + 11;
            *data_len = (size_t)resp_len - 2u;
        } else {
            *data = NULL;
            *data_len = 0;
        }
    }
    return 0;
}

static int set_nonblock(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (on) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
}

static int wait_fd(int fd, int write, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = write ? POLLOUT : POLLIN};
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        return rc == 0 ? -ETIMEDOUT : -errno;
    }
    return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t len, int timeout_ms)
{
    size_t off = 0;
    while (off < len) {
        int w = wait_fd(fd, 1, timeout_ms);
        if (w != 0) {
            return w;
        }
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return -errno;
        }
        off += (size_t)n;
    }
    return 0;
}

static int recv_exact(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
    size_t off = 0;
    while (off < len) {
        int w = wait_fd(fd, 0, timeout_ms);
        if (w != 0) {
            return w;
        }
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n == 0) {
            return -ECONNRESET;
        }
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return -errno;
        }
        off += (size_t)n;
    }
    return 0;
}

static int client_transact(slmp_stack_t *s, const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    if (!s || s->sockfd < 0) {
        return -ENOTCONN;
    }
    int rc = send_all(s->sockfd, req, req_len, s->cfg.timeout_ms);
    if (rc != 0) {
        s->connected = 0;
        return rc;
    }
    uint8_t hdr[9];
    rc = recv_exact(s->sockfd, hdr, sizeof(hdr), s->cfg.timeout_ms);
    if (rc != 0) {
        s->connected = 0;
        return rc;
    }
    if (rd_le16(hdr) != SLMP_SUBHEADER_RES_3E) {
        s->connected = 0;
        return -EBADMSG;
    }
    uint16_t data_len = rd_le16(hdr + 7);
    size_t total = 9u + data_len;
    if (total > resp_cap) {
        return -ENOSPC;
    }
    memcpy(resp, hdr, 9);
    if (data_len > 0) {
        rc = recv_exact(s->sockfd, resp + 9, data_len, s->cfg.timeout_ms);
        if (rc != 0) {
            s->connected = 0;
            return rc;
        }
    }
    *resp_len = total;
    return 0;
}

static void wire_words_to_be(const uint8_t *le_words, uint16_t quantity,
                             uint8_t *be_out)
{
    for (uint16_t i = 0; i < quantity; i++) {
        uint16_t w = rd_le16(le_words + i * 2u);
        be_out[i * 2u] = (uint8_t)(w >> 8);
        be_out[i * 2u + 1u] = (uint8_t)(w & 0xff);
    }
}

int slmp_stack_client_batch_read(slmp_stack_t *s, const slmp_range_t *range,
                                 uint8_t *raw_out, size_t raw_cap,
                                 size_t *raw_len)
{
    if (!s || !range || !raw_out || !raw_len) {
        return -EINVAL;
    }
    if (s->cfg.role != SLMP_ROLE_CLIENT) {
        /* Local-only read from map */
        if (range->addr.unit == SLMP_ACCESS_BIT) {
            if (raw_cap < range->quantity) {
                return -ENOSPC;
            }
            int rc = slmp_stack_read_bits(s, range->addr.device_code,
                                          range->addr.head, raw_out,
                                          range->quantity);
            if (rc == 0) {
                *raw_len = range->quantity;
            }
            return rc;
        }
        size_t need = (size_t)range->quantity * 2u;
        if (raw_cap < need) {
            return -ENOSPC;
        }
        int rc = slmp_stack_read_bytes(s, range->addr.device_code,
                                       range->addr.head, raw_out, need);
        if (rc == 0) {
            *raw_len = need;
        }
        return rc;
    }

    uint8_t req[64];
    size_t req_len = 0;
    int rc = slmp_encode_batch_read(&s->cfg, range, req, sizeof(req), &req_len);
    if (rc != 0) {
        return rc;
    }
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    rc = client_transact(s, req, req_len, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        snprintf(s->last_error, sizeof(s->last_error), "batch_read io %d", rc);
        return rc;
    }
    uint16_t end = 0;
    const uint8_t *data = NULL;
    size_t dlen = 0;
    rc = slmp_decode_response(resp, resp_len, &end, &data, &dlen);
    if (rc != 0) {
        return rc;
    }
    if (end != SLMP_END_OK) {
        snprintf(s->last_error, sizeof(s->last_error), "end_code=0x%04X", end);
        LOG_WARN("slmp", "batch_read end_code=0x%04X", end);
        return -EIO;
    }
    if (range->addr.unit == SLMP_ACCESS_BIT) {
        if (dlen < range->quantity || raw_cap < range->quantity) {
            return -ENOSPC;
        }
        memcpy(raw_out, data, range->quantity);
        *raw_len = range->quantity;
        slmp_stack_write_bits(s, range->addr.device_code, range->addr.head,
                              raw_out, range->quantity);
        return 0;
    }
    size_t need = (size_t)range->quantity * 2u;
    if (dlen < need || raw_cap < need) {
        return -ENOSPC;
    }
    wire_words_to_be(data, range->quantity, raw_out);
    *raw_len = need;
    slmp_stack_write_bytes(s, range->addr.device_code, range->addr.head, raw_out,
                           need);
    return 0;
}

int slmp_stack_client_batch_write(slmp_stack_t *s, const slmp_range_t *range,
                                  const uint8_t *raw, size_t raw_len)
{
    if (!s || !range || !raw) {
        return -EINVAL;
    }
    /* Always update local cache */
    if (range->addr.unit == SLMP_ACCESS_BIT) {
        int rc = slmp_stack_write_bits(s, range->addr.device_code,
                                       range->addr.head, raw, range->quantity);
        if (rc != 0) {
            return rc;
        }
    } else {
        size_t need = (size_t)range->quantity * 2u;
        if (raw_len < need) {
            return -EINVAL;
        }
        int rc = slmp_stack_write_bytes(s, range->addr.device_code,
                                        range->addr.head, raw, need);
        if (rc != 0) {
            return rc;
        }
    }
    if (s->cfg.role != SLMP_ROLE_CLIENT) {
        return 0;
    }

    uint8_t req[SLMP_FRAME_MAX];
    size_t req_len = 0;
    int rc = slmp_encode_batch_write(&s->cfg, range, raw, raw_len, req,
                                     sizeof(req), &req_len);
    if (rc != 0) {
        return rc;
    }
    uint8_t resp[64];
    size_t resp_len = 0;
    rc = client_transact(s, req, req_len, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        snprintf(s->last_error, sizeof(s->last_error), "batch_write io %d", rc);
        return rc;
    }
    uint16_t end = 0;
    rc = slmp_decode_response(resp, resp_len, &end, NULL, NULL);
    if (rc != 0) {
        return rc;
    }
    if (end != SLMP_END_OK) {
        snprintf(s->last_error, sizeof(s->last_error), "end_code=0x%04X", end);
        LOG_WARN("slmp", "batch_write end_code=0x%04X", end);
        return -EIO;
    }
    return 0;
}

static int build_response(const uint8_t *req, uint16_t end_code,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    uint16_t data_len = (uint16_t)(2 + payload_len);
    size_t total = 9u + data_len;
    if (total > resp_cap) {
        return -ENOSPC;
    }
    wr_le16(resp, SLMP_SUBHEADER_RES_3E);
    resp[2] = req[2];
    resp[3] = req[3];
    resp[4] = req[4];
    resp[5] = req[5];
    resp[6] = req[6];
    wr_le16(resp + 7, data_len);
    wr_le16(resp + 9, end_code);
    if (payload_len && payload) {
        memcpy(resp + 11, payload, payload_len);
    }
    *resp_len = total;
    return 0;
}

int slmp_stack_handle_request(slmp_stack_t *s, const uint8_t *req,
                              size_t req_len, uint8_t *resp, size_t resp_cap,
                              size_t *resp_len)
{
    if (!s || !req || !resp || !resp_len || req_len < 21) {
        return -EINVAL;
    }
    if (rd_le16(req) != SLMP_SUBHEADER_REQ_3E) {
        return -EBADMSG;
    }
    uint16_t cmd = rd_le16(req + 11);
    uint16_t sub = rd_le16(req + 13);
    uint32_t head = rd_le24(req + 15);
    uint8_t code = req[18];
    uint16_t qty = rd_le16(req + 19);
    int bit_unit = (sub == SLMP_SUB_BIT);

    if (cmd == SLMP_CMD_BATCH_READ) {
        uint8_t payload[SLMP_PAYLOAD_MAX];
        size_t plen = 0;
        int rc;
        if (bit_unit) {
            if (qty > sizeof(payload)) {
                return build_response(req, 0xC051, NULL, 0, resp, resp_cap,
                                      resp_len);
            }
            rc = slmp_stack_read_bits(s, code, head, payload, qty);
            plen = qty;
        } else {
            if ((size_t)qty * 2u > sizeof(payload)) {
                return build_response(req, 0xC051, NULL, 0, resp, resp_cap,
                                      resp_len);
            }
            uint16_t words[SLMP_PAYLOAD_MAX / 2u];
            rc = slmp_stack_read_words(s, code, head, words, qty);
            if (rc == 0) {
                for (uint16_t i = 0; i < qty; i++) {
                    wr_le16(payload + i * 2u, words[i]);
                }
                plen = (size_t)qty * 2u;
            }
        }
        if (rc != 0) {
            return build_response(req, 0xC056, NULL, 0, resp, resp_cap,
                                  resp_len);
        }
        return build_response(req, SLMP_END_OK, payload, plen, resp, resp_cap,
                              resp_len);
    }

    if (cmd == SLMP_CMD_BATCH_WRITE) {
        const uint8_t *data = req + 21;
        size_t need = bit_unit ? (size_t)qty : (size_t)qty * 2u;
        if (req_len < 21 + need) {
            return -EBADMSG;
        }
        int rc;
        if (bit_unit) {
            rc = slmp_stack_write_bits(s, code, head, data, qty);
        } else {
            uint16_t words[SLMP_PAYLOAD_MAX / 2u];
            for (uint16_t i = 0; i < qty; i++) {
                words[i] = rd_le16(data + i * 2u);
            }
            rc = slmp_stack_write_words(s, code, head, words, qty);
        }
        if (rc != 0) {
            return build_response(req, 0xC056, NULL, 0, resp, resp_cap,
                                  resp_len);
        }
        return build_response(req, SLMP_END_OK, NULL, 0, resp, resp_cap,
                              resp_len);
    }

    return build_response(req, 0xC050, NULL, 0, resp, resp_cap, resp_len);
}

static int tcp_connect_client(slmp_stack_t *s)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.port);
    if (inet_pton(AF_INET, s->cfg.plc_ip, &addr.sin_addr) != 1) {
        close(fd);
        return -EINVAL;
    }
    set_nonblock(fd, 1);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        int e = errno;
        close(fd);
        return -e;
    }
    rc = wait_fd(fd, 1, s->cfg.timeout_ms);
    if (rc != 0) {
        close(fd);
        return rc;
    }
    int soerr = 0;
    socklen_t sl = sizeof(soerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr != 0) {
        close(fd);
        return -soerr;
    }
    s->sockfd = fd;
    s->connected = 1;
    return 0;
}

static int tcp_listen_server(slmp_stack_t *s)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->cfg.port);
    const char *ip =
        s->cfg.bind_ip[0] ? s->cfg.bind_ip : "0.0.0.0";
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -EINVAL;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    if (listen(fd, s->cfg.max_clients) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    set_nonblock(fd, 1);
    s->sockfd = fd;
    s->connected = 1;
    return 0;
}

int slmp_stack_start(slmp_stack_t *s)
{
    if (!s) {
        return -EINVAL;
    }
    if (s->cfg.role == SLMP_ROLE_CLIENT) {
        if (!s->cfg.plc_ip[0]) {
            return -EINVAL;
        }
        int rc = tcp_connect_client(s);
        if (rc != 0) {
            LOG_ERROR("slmp", "connect %s:%d failed (%d)", s->cfg.plc_ip,
                      s->cfg.port, rc);
            snprintf(s->last_error, sizeof(s->last_error), "connect failed %d",
                     rc);
        } else {
            LOG_INFO("slmp", "connected to %s:%d", s->cfg.plc_ip, s->cfg.port);
        }
        return rc;
    }
    int rc = tcp_listen_server(s);
    if (rc != 0) {
        LOG_ERROR("slmp", "listen failed (%d)", rc);
    } else {
        LOG_INFO("slmp", "listening on %s:%d",
                 s->cfg.bind_ip[0] ? s->cfg.bind_ip : "0.0.0.0", s->cfg.port);
    }
    return rc;
}

void slmp_stack_stop(slmp_stack_t *s)
{
    if (!s) {
        return;
    }
    for (int i = 0; i < s->n_clients; i++) {
        if (s->client_fds[i] >= 0) {
            close(s->client_fds[i]);
            s->client_fds[i] = -1;
        }
    }
    s->n_clients = 0;
    if (s->sockfd >= 0) {
        close(s->sockfd);
        s->sockfd = -1;
    }
    s->connected = 0;
}

static void server_accept(slmp_stack_t *s)
{
    while (s->n_clients < s->cfg.max_clients) {
        struct sockaddr_in peer;
        socklen_t pl = sizeof(peer);
        int cfd = accept(s->sockfd, (struct sockaddr *)&peer, &pl);
        if (cfd < 0) {
            break;
        }
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        set_nonblock(cfd, 1);
        s->client_fds[s->n_clients++] = cfd;
        LOG_INFO("slmp", "server accept client fd=%d", cfd);
    }
}

void slmp_stack_poll(slmp_stack_t *s)
{
    if (!s || s->cfg.role != SLMP_ROLE_SERVER || s->sockfd < 0) {
        return;
    }
    server_accept(s);

    struct pollfd pfds[9];
    int n = 0;
    for (int i = 0; i < s->n_clients; i++) {
        pfds[n].fd = s->client_fds[i];
        pfds[n].events = POLLIN;
        pfds[n].revents = 0;
        n++;
    }
    if (n == 0) {
        return;
    }
    if (poll(pfds, (nfds_t)n, 0) <= 0) {
        return;
    }
    for (int i = n - 1; i >= 0; i--) {
        if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
            /* map poll index back — client_fds may shrink */
            int fd = pfds[i].fd;
            int idx = -1;
            for (int j = 0; j < s->n_clients; j++) {
                if (s->client_fds[j] == fd) {
                    idx = j;
                    break;
                }
            }
            if (idx >= 0) {
                if (pfds[i].revents & POLLIN) {
                    /* Peek header with blocking wait since poll said ready */
                    uint8_t hdr[9];
                    int rc = recv_exact(fd, hdr, sizeof(hdr), s->cfg.timeout_ms);
                    if (rc != 0) {
                        close(fd);
                        s->client_fds[idx] = s->client_fds[s->n_clients - 1];
                        s->client_fds[s->n_clients - 1] = -1;
                        s->n_clients--;
                        continue;
                    }
                    uint16_t data_len = rd_le16(hdr + 7);
                    size_t total = 9u + data_len;
                    uint8_t req[SLMP_FRAME_MAX];
                    if (total > sizeof(req)) {
                        close(fd);
                        s->client_fds[idx] = s->client_fds[s->n_clients - 1];
                        s->client_fds[s->n_clients - 1] = -1;
                        s->n_clients--;
                        continue;
                    }
                    memcpy(req, hdr, 9);
                    if (data_len &&
                        recv_exact(fd, req + 9, data_len, s->cfg.timeout_ms) !=
                            0) {
                        close(fd);
                        s->client_fds[idx] = s->client_fds[s->n_clients - 1];
                        s->client_fds[s->n_clients - 1] = -1;
                        s->n_clients--;
                        continue;
                    }
                    uint8_t resp[SLMP_FRAME_MAX];
                    size_t resp_len = 0;
                    if (slmp_stack_handle_request(s, req, total, resp,
                                                  sizeof(resp),
                                                  &resp_len) == 0) {
                        send_all(fd, resp, resp_len, s->cfg.timeout_ms);
                    }
                } else {
                    close(fd);
                    s->client_fds[idx] = s->client_fds[s->n_clients - 1];
                    s->client_fds[s->n_clients - 1] = -1;
                    s->n_clients--;
                }
            }
        }
    }
}
