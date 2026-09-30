#include "slmp_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int g_fail;
static volatile int g_serve;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static void test_device_table(void)
{
    uint8_t code = 0;
    int is_bit = 0;
    expect(slmp_device_code_from_name("D", &code, &is_bit) == 0 && code == 0xA8 &&
               !is_bit,
           "D");
    expect(slmp_device_code_from_name("m", &code, &is_bit) == 0 && code == 0x90 &&
               is_bit,
           "M");
    expect(slmp_device_code_from_name("ZR", &code, &is_bit) == 0 &&
               code == 0xB0,
           "ZR");
    expect(slmp_device_code_from_name("0xA8", &code, &is_bit) == 0 &&
               code == 0xA8,
           "raw");
    expect(slmp_device_is_hex_addr(SLMP_DEV_X) == 1, "X hex");
    expect(slmp_device_is_hex_addr(SLMP_DEV_D) == 0, "D dec");
}

static void test_encode_batch_read(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.network_no = 0;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.dest_multidrop = 0;
    cfg.monitoring_timer = 0x0010;

    slmp_range_t range;
    memset(&range, 0, sizeof(range));
    range.addr.device_code = SLMP_DEV_D;
    range.addr.head = 100;
    range.addr.unit = SLMP_ACCESS_WORD;
    range.quantity = 2;

    uint8_t frame[64];
    size_t len = 0;
    expect(slmp_encode_batch_read(&cfg, &range, frame, sizeof(frame), &len) ==
               0,
           "encode read");
    expect(len == 21, "read len");
    expect(rd_le16(frame) == SLMP_SUBHEADER_REQ_3E, "subheader");
    expect(frame[2] == 0 && frame[3] == 0xFF, "net/pc");
    expect(rd_le16(frame + 4) == 0x03FF, "io");
    expect(rd_le16(frame + 7) == 12, "data len");
    expect(rd_le16(frame + 11) == SLMP_CMD_BATCH_READ, "cmd");
    expect(rd_le16(frame + 13) == SLMP_SUB_WORD, "sub");
    expect(frame[15] == 100 && frame[16] == 0 && frame[17] == 0, "head");
    expect(frame[18] == SLMP_DEV_D, "dev");
    expect(rd_le16(frame + 19) == 2, "qty");
}

static void test_decode_empty_ok_payload(void)
{
    /* Binary 3E response: subheader + net/pc/io/multi + length=2 + end=OK */
    uint8_t frame[11];
    memset(frame, 0, sizeof(frame));
    wr_le16(frame, SLMP_SUBHEADER_RES_3E);
    wr_le16(frame + 7, 2);
    wr_le16(frame + 9, SLMP_END_OK);

    uint16_t end = 0xFFFFu;
    const uint8_t *data = (const uint8_t *)(uintptr_t)1;
    size_t dlen = 99;
    expect(slmp_decode_response(frame, sizeof(frame), &end, &data, &dlen) == 0,
           "decode empty OK");
    expect(end == SLMP_END_OK, "end OK");
    expect(data == NULL && dlen == 0, "empty payload is NULL/0 not a crash");
}

static void test_handle_read_write(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    cfg.port = 5000;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.monitoring_timer = 0x10;

    slmp_stack_t *s = slmp_stack_create(&cfg);
    expect(s != NULL, "create");

    uint16_t seed[2] = {0x1234, 0xABCD};
    expect(slmp_stack_write_words(s, SLMP_DEV_D, 100, seed, 2) == 0, "seed");

    slmp_range_t range = {.addr = {.device_code = SLMP_DEV_D,
                                   .head = 100,
                                   .unit = SLMP_ACCESS_WORD},
                          .quantity = 2};
    uint8_t req[64];
    size_t req_len = 0;
    expect(slmp_encode_batch_read(&cfg, &range, req, sizeof(req), &req_len) ==
               0,
           "enc");

    uint8_t resp[128];
    size_t resp_len = 0;
    expect(slmp_stack_handle_request(s, req, req_len, resp, sizeof(resp),
                                     &resp_len) == 0,
           "handle read");
    uint16_t end = 0xFFFF;
    const uint8_t *data = NULL;
    size_t dlen = 0;
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "decode");
    expect(end == 0 && dlen == 4, "ok payload");
    expect(data[0] == 0x34 && data[1] == 0x12, "LE word0");
    expect(data[2] == 0xCD && data[3] == 0xAB, "LE word1");

    uint8_t bits[4] = {1, 0, 1, 1};
    slmp_range_t br = {.addr = {.device_code = SLMP_DEV_M,
                                .head = 0,
                                .unit = SLMP_ACCESS_BIT},
                       .quantity = 4};
    uint8_t wreq[64];
    size_t wlen = 0;
    expect(slmp_encode_batch_write(&cfg, &br, bits, 4, wreq, sizeof(wreq),
                                   &wlen) == 0,
           "enc write bits");
    expect(slmp_stack_handle_request(s, wreq, wlen, resp, sizeof(resp),
                                     &resp_len) == 0,
           "handle write bits");
    uint8_t outb[4] = {0};
    expect(slmp_stack_read_bits(s, SLMP_DEV_M, 0, outb, 4) == 0, "read bits");
    expect(outb[0] == 1 && outb[1] == 0 && outb[2] == 1 && outb[3] == 1,
           "bits");

    const char *bc = "ABC123";
    expect(slmp_stack_write_bytes(s, SLMP_DEV_D, 200, (const uint8_t *)bc, 6) ==
               0,
           "write bytes");
    uint8_t bout[8];
    memset(bout, 0, sizeof(bout));
    expect(slmp_stack_read_bytes(s, SLMP_DEV_D, 200, bout, 6) == 0,
           "read bytes");
    expect(memcmp(bout, bc, 6) == 0, "barcode");
    uint16_t r0 = 0, r1 = 0, r2 = 0;
    slmp_stack_read_words(s, SLMP_DEV_D, 200, &r0, 1);
    slmp_stack_read_words(s, SLMP_DEV_D, 201, &r1, 1);
    slmp_stack_read_words(s, SLMP_DEV_D, 202, &r2, 1);
    expect(r0 == 0x4142 && r1 == 0x4331 && r2 == 0x3233, "packed words");

    slmp_stack_destroy(s);
}

static void *serve_thread(void *arg)
{
    slmp_stack_t *server = arg;
    while (g_serve) {
        slmp_stack_poll(server);
        usleep(1000);
    }
    return NULL;
}

static void test_client_server_loopback(void)
{
    slmp_cfg_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = SLMP_ROLE_SERVER;
    scfg.frame = SLMP_FRAME_3E_BINARY;
    scfg.port = 15557;
    snprintf(scfg.bind_ip, sizeof(scfg.bind_ip), "127.0.0.1");
    scfg.pc_no = 0xFF;
    scfg.dest_module_io = 0x03FF;
    scfg.monitoring_timer = 0x10;
    scfg.timeout_ms = 1000;
    scfg.max_clients = 2;

    slmp_stack_t *server = slmp_stack_create(&scfg);
    expect(server != NULL, "server create");
    expect(slmp_stack_start(server) == 0, "server start");

    g_serve = 1;
    pthread_t th;
    expect(pthread_create(&th, NULL, serve_thread, server) == 0, "thread");

    slmp_cfg_t ccfg = scfg;
    ccfg.role = SLMP_ROLE_CLIENT;
    snprintf(ccfg.plc_ip, sizeof(ccfg.plc_ip), "127.0.0.1");
    slmp_stack_t *client = slmp_stack_create(&ccfg);
    expect(client != NULL, "client create");
    expect(slmp_stack_start(client) == 0, "client start");
    usleep(50000);

    uint8_t be[4] = {0x12, 0x34, 0x56, 0x78};
    slmp_range_t wr = {.addr = {.device_code = SLMP_DEV_D,
                                .head = 10,
                                .unit = SLMP_ACCESS_WORD},
                       .quantity = 2};
    expect(slmp_stack_client_batch_write(client, &wr, be, 4) == 0,
           "client write");

    uint16_t words[2] = {0};
    expect(slmp_stack_read_words(server, SLMP_DEV_D, 10, words, 2) == 0,
           "server map");
    expect(words[0] == 0x1234 && words[1] == 0x5678, "written values");

    uint8_t out[4];
    size_t out_len = 0;
    expect(slmp_stack_client_batch_read(client, &wr, out, sizeof(out),
                                        &out_len) == 0,
           "client read");
    expect(out_len == 4 && memcmp(out, be, 4) == 0, "readback");

    wr.quantity = 0;
    expect(slmp_stack_client_batch_read(client, &wr, out, sizeof(out),
                                        &out_len) != 0,
           "client read qty 0 rejected");

    g_serve = 0;
    pthread_join(th, NULL);
    slmp_stack_destroy(client);
    slmp_stack_destroy(server);
}

static void wr_le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
}

static slmp_stack_t *make_server(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    cfg.port = 5000;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.monitoring_timer = 0x10;
    return slmp_stack_create(&cfg);
}

static size_t build_batch_req(uint8_t *out, uint16_t cmd, uint16_t sub,
                              uint8_t code, uint32_t head, uint16_t qty,
                              const uint8_t *payload, size_t plen)
{
    wr_le16(out, SLMP_SUBHEADER_REQ_3E);
    out[2] = 0;
    out[3] = 0xFF;
    wr_le16(out + 4, 0x03FF);
    out[6] = 0;
    wr_le16(out + 7, (uint16_t)(12 + plen));
    wr_le16(out + 9, 0x0010);
    wr_le16(out + 11, cmd);
    wr_le16(out + 13, sub);
    wr_le24(out + 15, head);
    out[18] = code;
    wr_le16(out + 19, qty);
    if (plen && payload) {
        memcpy(out + 21, payload, plen);
    }
    return 21 + plen;
}

static void test_handle_qty_and_unknown(void)
{
    slmp_stack_t *s = make_server();
    expect(s != NULL, "sec create");
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    uint16_t end = 0xFFFF;
    const uint8_t *data = NULL;
    size_t dlen = 0;

    /* qty == 0 word write */
    uint8_t req0[64];
    size_t n0 = build_batch_req(req0, SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD,
                                SLMP_DEV_D, 0, 0, NULL, 0);
    expect(slmp_stack_handle_request(s, req0, n0, resp, sizeof(resp),
                                     &resp_len) == 0,
           "qty0 handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "qty0 decode");
    expect(end == SLMP_END_POINTS, "qty0 end 0xC051");

    /* qty == 0 bit read */
    n0 = build_batch_req(req0, SLMP_CMD_BATCH_READ, SLMP_SUB_BIT, SLMP_DEV_M, 0,
                         0, NULL, 0);
    expect(slmp_stack_handle_request(s, req0, n0, resp, sizeof(resp),
                                     &resp_len) == 0,
           "bit qty0 handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "bit qty0 decode");
    expect(end == SLMP_END_POINTS, "bit qty0 end 0xC051");

    /* Word write qty=1013 would overflow uint16_t words[960] if unbounded. */
    uint8_t req_big[SLMP_FRAME_MAX];
    uint8_t payload[2026];
    memset(payload, 0x5A, sizeof(payload));
    uint16_t qty_over = 1013;
    size_t nbig = build_batch_req(req_big, SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD,
                                  SLMP_DEV_D, 0, qty_over, payload,
                                  (size_t)qty_over * 2u);
    expect(nbig > 21, "overflow req built");
    expect(slmp_stack_handle_request(s, req_big, nbig, resp, sizeof(resp),
                                     &resp_len) == 0,
           "overflow handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "overflow decode");
    expect(end == SLMP_END_POINTS, "word qty 1013 -> 0xC051");

    /* Word read qty=961 (spec max 960) */
    n0 = build_batch_req(req0, SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, SLMP_DEV_D, 0,
                         961, NULL, 0);
    expect(slmp_stack_handle_request(s, req0, n0, resp, sizeof(resp),
                                     &resp_len) == 0,
           "read 961 handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "read 961 decode");
    expect(end == SLMP_END_POINTS, "word read qty 961 -> 0xC051");

    /* Bit write qty above spec (7168+1) — request may not carry payload;
     * still reject on qty before copy. */
    n0 = build_batch_req(req0, SLMP_CMD_BATCH_WRITE, SLMP_SUB_BIT, SLMP_DEV_M, 0,
                         7169, NULL, 0);
    expect(slmp_stack_handle_request(s, req0, n0, resp, sizeof(resp),
                                     &resp_len) == 0,
           "bit 7169 handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "bit 7169 decode");
    expect(end == SLMP_END_POINTS, "bit qty 7169 -> 0xC051");

    /* Unknown subcommand treated as word before: now 0xC050 */
    n0 = build_batch_req(req0, SLMP_CMD_BATCH_READ, 0x0002, SLMP_DEV_D, 0, 1,
                         NULL, 0);
    expect(slmp_stack_handle_request(s, req0, n0, resp, sizeof(resp),
                                     &resp_len) == 0,
           "bad sub handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "bad sub decode");
    expect(end == SLMP_END_CMD, "unknown sub -> 0xC050");

    /* Unknown device code: do not allocate a new map */
    int maps_before = slmp_device_known(0xEE) ? 1 : 0;
    expect(maps_before == 0, "0xEE not a known device");
    n0 = build_batch_req(req0, SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, 0xEE, 0, 1,
                         NULL, 0);
    expect(slmp_stack_handle_request(s, req0, n0, resp, sizeof(resp),
                                     &resp_len) == 0,
           "unk dev handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "unk dev decode");
    expect(end == SLMP_END_DEVICE, "unknown device -> 0xC056");

    /* Spec-max word write (960) still accepted and bounded. */
    uint8_t okpay[960 * 2];
    memset(okpay, 0, sizeof(okpay));
    okpay[0] = 0x34;
    okpay[1] = 0x12;
    size_t nok = build_batch_req(req_big, SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD,
                                 SLMP_DEV_D, 0, 960, okpay, sizeof(okpay));
    expect(slmp_stack_handle_request(s, req_big, nok, resp, sizeof(resp),
                                     &resp_len) == 0,
           "qty 960 handle");
    expect(slmp_decode_response(resp, resp_len, &end, &data, &dlen) == 0,
           "qty 960 decode");
    expect(end == SLMP_END_OK, "qty 960 word write OK");
    uint16_t w0 = 0;
    expect(slmp_stack_read_words(s, SLMP_DEV_D, 0, &w0, 1) == 0, "read D0");
    expect(w0 == 0x1234, "D0 written");

    slmp_stack_destroy(s);
}

static int slmp_connect(int port)
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

static void test_g7_slmp_idle_per_ip_and_slow(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.port = 16153;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.timeout_ms = 1000;
    cfg.max_clients = 4;
    cfg.idle_timeout_ms = 200;
    cfg.max_conn_per_ip = 1;
    slmp_stack_t *s = slmp_stack_create(&cfg);
    expect(s != NULL, "g7 slmp create");
    if (!s) {
        return;
    }
    if (slmp_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: g7 slmp start\n");
        g_fail = 1;
        slmp_stack_destroy(s);
        return;
    }
    int a = slmp_connect(16153);
    expect(a >= 0, "g7 slmp connect a");
    for (int i = 0; i < 20; i++) {
        slmp_stack_poll(s);
        usleep(1000);
    }
    int b = slmp_connect(16153);
    expect(b >= 0, "g7 slmp connect b");
    for (int i = 0; i < 20; i++) {
        slmp_stack_poll(s);
        usleep(1000);
    }
    uint8_t tmp[8];
    ssize_t n = recv(b, tmp, sizeof(tmp), MSG_DONTWAIT);
    expect(n == 0 || n < 0, "g7 slmp per-ip dropped");
    if (b >= 0) {
        close(b);
    }
    usleep(250000);
    for (int i = 0; i < 20; i++) {
        slmp_stack_poll(s);
        usleep(1000);
    }
    n = recv(a, tmp, sizeof(tmp), MSG_DONTWAIT);
    expect(n == 0 || n < 0, "g7 slmp idle dropped");
    if (a >= 0) {
        close(a);
    }
    slmp_stack_destroy(s);

    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.port = 16154;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.timeout_ms = 1000;
    cfg.max_clients = 4;
    cfg.idle_timeout_ms = 60000;
    cfg.max_conn_per_ip = 8;
    s = slmp_stack_create(&cfg);
    expect(s != NULL, "g7 slmp slow create");
    if (!s || slmp_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: g7 slmp slow start\n");
        g_fail = 1;
        if (s) {
            slmp_stack_destroy(s);
        }
        return;
    }
    int slow = slmp_connect(16154);
    int fast = slmp_connect(16154);
    expect(slow >= 0 && fast >= 0, "g7 slmp slow/fast connect");
    for (int i = 0; i < 20; i++) {
        slmp_stack_poll(s);
        usleep(1000);
    }
    uint8_t partial[4] = {0x50, 0x00, 0x00, 0xFF};
    expect(send(slow, partial, sizeof(partial), MSG_NOSIGNAL) == 4,
           "g7 slmp partial send");
    slmp_range_t range;
    memset(&range, 0, sizeof(range));
    range.addr.device_code = SLMP_DEV_D;
    range.addr.head = 0;
    range.addr.unit = SLMP_ACCESS_WORD;
    range.quantity = 1;
    uint8_t req[64];
    size_t req_len = 0;
    expect(slmp_encode_batch_read(&cfg, &range, req, sizeof(req), &req_len) == 0,
           "g7 encode");
    expect(send(fast, req, req_len, MSG_NOSIGNAL) == (ssize_t)req_len,
           "g7 fast send");

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    slmp_stack_poll(s);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 +
                     (t1.tv_nsec - t0.tv_nsec) / 1000000);
    expect(ms < 200, "g7 slmp poll not blocked by slow client");

    uint8_t rbuf[64];
    ssize_t rn = recv(fast, rbuf, sizeof(rbuf), MSG_DONTWAIT);
    expect(rn > 0, "g7 fast client got response while slow partial");
    if (slow >= 0) {
        close(slow);
    }
    if (fast >= 0) {
        close(fast);
    }
    slmp_stack_destroy(s);
}

/* T10-2: a late reply to the first request must not become the next result.
 * Binary 3E has no request id, so the only safe reaction to a timeout is to
 * drop the TCP connection. This server answers D0 later than the client
 * timeout and answers any later head immediately. */
typedef struct {
    int lfd;
    int port;
    int late_ms;
    uint16_t d0_value;
    uint16_t d1_value;
    atomic_int stop;
    atomic_int late_sent;
    atomic_int accepts;
    atomic_int inflight;
} late_srv_t;

typedef struct {
    int fd;
    late_srv_t *srv;
} late_conn_t;

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
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

static void write_word_response(int fd, const uint8_t *req, uint16_t value)
{
    uint8_t resp[13];
    memset(resp, 0, sizeof(resp));
    wr_le16(resp, SLMP_SUBHEADER_RES_3E);
    memcpy(resp + 2, req + 2, 5);
    wr_le16(resp + 7, 4);
    wr_le16(resp + 9, SLMP_END_OK);
    wr_le16(resp + 11, value);
    size_t off = 0;
    while (off < sizeof(resp)) {
        ssize_t n = send(fd, resp + off, sizeof(resp) - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }
        off += (size_t)n;
    }
}

static void *late_conn_main(void *arg)
{
    late_conn_t *c = arg;
    late_srv_t *srv = c->srv;
    uint8_t req[21];
    if (read_full(c->fd, req, sizeof(req)) == 0) {
        uint32_t head = (uint32_t)req[15] | ((uint32_t)req[16] << 8) |
                        ((uint32_t)req[17] << 16);
        if (head == 0) {
            usleep((useconds_t)srv->late_ms * 1000u);
            write_word_response(c->fd, req, srv->d0_value);
            atomic_store(&srv->late_sent, 1);
        } else {
            write_word_response(c->fd, req, srv->d1_value);
        }
    }
    close(c->fd);
    free(c);
    atomic_fetch_sub(&srv->inflight, 1);
    return NULL;
}

static void *late_accept_main(void *arg)
{
    late_srv_t *srv = arg;
    while (!atomic_load(&srv->stop)) {
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = srv->lfd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 50);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            continue;
        }
        int fd = accept(srv->lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        atomic_fetch_add(&srv->accepts, 1);
        late_conn_t *c = calloc(1, sizeof(*c));
        if (!c) {
            close(fd);
            continue;
        }
        c->fd = fd;
        c->srv = srv;
        atomic_fetch_add(&srv->inflight, 1);
        pthread_t th;
        if (pthread_create(&th, NULL, late_conn_main, c) != 0) {
            atomic_fetch_sub(&srv->inflight, 1);
            close(fd);
            free(c);
            continue;
        }
        pthread_detach(th);
    }
    return NULL;
}

static int late_srv_listen(late_srv_t *srv)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(fd);
        return -1;
    }
    srv->lfd = fd;
    srv->port = ntohs(addr.sin_port);
    return 0;
}

static void late_srv_stop(late_srv_t *srv, pthread_t acc, int acc_started)
{
    atomic_store(&srv->stop, 1);
    if (acc_started) {
        pthread_join(acc, NULL);
    }
    if (srv->lfd >= 0) {
        close(srv->lfd);
        srv->lfd = -1;
    }
    for (int i = 0; i < 150 && atomic_load(&srv->inflight) != 0; i++) {
        usleep(20000);
    }
}

static void test_t10_2_stale_response_after_timeout(void)
{
    late_srv_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.lfd = -1;
    srv.late_ms = 800;
    srv.d0_value = 0x1111;
    srv.d1_value = 0x2222;
    atomic_init(&srv.stop, 0);
    atomic_init(&srv.late_sent, 0);
    atomic_init(&srv.accepts, 0);
    atomic_init(&srv.inflight, 0);
    if (late_srv_listen(&srv) != 0) {
        fprintf(stderr, "FAIL: T10-2 listen\n");
        g_fail = 1;
        return;
    }
    pthread_t acc;
    memset(&acc, 0, sizeof(acc));
    int acc_started = pthread_create(&acc, NULL, late_accept_main, &srv) == 0;
    if (!acc_started) {
        fprintf(stderr, "FAIL: T10-2 accept thread\n");
        g_fail = 1;
        late_srv_stop(&srv, acc, 0);
        return;
    }

    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_CLIENT;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    cfg.port = srv.port;
    snprintf(cfg.plc_ip, sizeof(cfg.plc_ip), "127.0.0.1");
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    /* 1 tick = 250 ms, equal to timeout_ms so the socket wait is not raised. */
    cfg.monitoring_timer = 1;
    cfg.timeout_ms = 250;

    slmp_stack_t *client = slmp_stack_create(&cfg);
    if (!client || slmp_stack_start(client) != 0) {
        fprintf(stderr, "FAIL: T10-2 client start\n");
        g_fail = 1;
        slmp_stack_destroy(client);
        late_srv_stop(&srv, acc, acc_started);
        return;
    }

    slmp_range_t d0 = {.addr = {.device_code = SLMP_DEV_D,
                                .head = 0,
                                .unit = SLMP_ACCESS_WORD},
                       .quantity = 1};
    uint8_t out[8];
    size_t out_len = 0;
    memset(out, 0, sizeof(out));
    int rc = slmp_stack_client_batch_read(client, &d0, out, sizeof(out),
                                          &out_len);
    if (rc != -ETIMEDOUT) {
        fprintf(stderr, "FAIL: D0 read rc=%d, want -ETIMEDOUT (%d)\n", rc,
                -ETIMEDOUT);
        g_fail = 1;
    }

    /* Backoff starts at 100 ms and must not reuse the socket that still
     * has the late D0 reply in flight. */
    slmp_range_t d1 = d0;
    d1.addr.head = 1;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    memset(out, 0, sizeof(out));
    out_len = 0;
    rc = slmp_stack_client_batch_read(client, &d1, out, sizeof(out), &out_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long backoff_ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 +
                             (t1.tv_nsec - t0.tv_nsec) / 1000000);
    if (rc != -EAGAIN || backoff_ms > 200 ||
        (out[0] == 0x11 && out[1] == 0x11)) {
        fprintf(stderr,
                "FAIL: retry during backoff rc=%d elapsed=%ld ms value=%02x%02x "
                "(want -EAGAIN, not D0)\n",
                rc, backoff_ms, out[0], out[1]);
        g_fail = 1;
    }

    int saw_late = 0;
    for (int i = 0; i < 100; i++) {
        if (atomic_load(&srv.late_sent)) {
            saw_late = 1;
            break;
        }
        usleep(20000);
    }
    if (!saw_late) {
        fprintf(stderr, "FAIL: late D0 response was not attempted\n");
        g_fail = 1;
    }
    /* Reconnect backoff starts at 100 ms. This wait lets the next read
     * open a new connection instead of being deferred. */
    usleep(150000);

    memset(out, 0, sizeof(out));
    out_len = 0;
    rc = slmp_stack_client_batch_read(client, &d1, out, sizeof(out), &out_len);
    int accepts = atomic_load(&srv.accepts);
    if (rc != 0 || out_len != 2 || out[0] != 0x22 || out[1] != 0x22) {
        fprintf(stderr,
                "FAIL: D1 read rc=%d len=%zu value=%02x%02x accepts=%d "
                "(stale D0 is 1111 on the old socket)\n",
                rc, out_len, out[0], out[1], accepts);
        g_fail = 1;
    }

    slmp_stack_destroy(client);
    late_srv_stop(&srv, acc, acc_started);
}

static void test_t10_2_timeout_not_shorter_than_monitor(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_CLIENT;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    snprintf(cfg.plc_ip, sizeof(cfg.plc_ip), "127.0.0.1");
    cfg.monitoring_timer = 0x0010; /* 16 * 250 ms = 4000 ms */
    cfg.timeout_ms = 1000;
    slmp_stack_t *s = slmp_stack_create(&cfg);
    const slmp_cfg_t *got = slmp_stack_cfg(s);
    if (!s || !got || got->timeout_ms < 16 * 250) {
        fprintf(stderr,
                "FAIL: timeout_ms %d is shorter than monitoring timer %d ms\n",
                got ? got->timeout_ms : -1, 16 * 250);
        g_fail = 1;
    }
    slmp_stack_destroy(s);

    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_CLIENT;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    snprintf(cfg.plc_ip, sizeof(cfg.plc_ip), "127.0.0.1");
    cfg.monitoring_timer = 1;
    cfg.timeout_ms = 250;
    s = slmp_stack_create(&cfg);
    got = slmp_stack_cfg(s);
    if (!s || !got || got->timeout_ms != 250) {
        fprintf(stderr,
                "FAIL: timeout_ms %d changed when it already matched the "
                "monitoring timer\n",
                got ? got->timeout_ms : -1);
        g_fail = 1;
    }
    slmp_stack_destroy(s);
}

int main(void)
{
    test_device_table();
    test_encode_batch_read();
    test_decode_empty_ok_payload();
    test_handle_read_write();
    test_handle_qty_and_unknown();
    test_client_server_loopback();
    test_g7_slmp_idle_per_ip_and_slow();
    test_t10_2_stale_response_after_timeout();
    test_t10_2_timeout_not_shorter_than_monitor();
    if (g_fail) {
        fprintf(stderr, "test_slmp_stack: FAILED\n");
        return 1;
    }
    printf("test_slmp_stack: OK\n");
    return 0;
}
