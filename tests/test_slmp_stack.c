#include "slmp_stack.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

int main(void)
{
    test_device_table();
    test_encode_batch_read();
    test_decode_empty_ok_payload();
    test_handle_read_write();
    test_handle_qty_and_unknown();
    test_client_server_loopback();
    if (g_fail) {
        fprintf(stderr, "test_slmp_stack: FAILED\n");
        return 1;
    }
    printf("test_slmp_stack: OK\n");
    return 0;
}
