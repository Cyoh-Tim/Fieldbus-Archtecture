#include "slmp_stack.h"

#include <pthread.h>
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

    g_serve = 0;
    pthread_join(th, NULL);
    slmp_stack_destroy(client);
    slmp_stack_destroy(server);
}

int main(void)
{
    test_device_table();
    test_encode_batch_read();
    test_handle_read_write();
    test_client_server_loopback();
    if (g_fail) {
        fprintf(stderr, "test_slmp_stack: FAILED\n");
        return 1;
    }
    printf("test_slmp_stack: OK\n");
    return 0;
}
