#include "eip_stack.h"
#include "ethernetip_adapter.h"
#include "fb_api.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static int write_file(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        return -1;
    }
    if (fputs(body, f) == EOF) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* eip_ctx_t in ethernetip_adapter.c keeps the stack pointer first. */
typedef struct {
    eip_stack_t *stack;
} eip_ctx_peek_t;

static int open_cfg(const char *json, fb_runtime_t **rt)
{
    char path[] = "/tmp/eip-t1-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    if (write_file(path, json) != 0) {
        unlink(path);
        return -1;
    }
    int rc = fb_open(path, rt);
    unlink(path);
    return rc;
}

static void expect_bytes(const uint8_t *got, size_t n, const uint8_t *exp,
                         size_t en, const char *msg)
{
    if (n != en || memcmp(got, exp, en) != 0) {
        fprintf(stderr, "FAIL: %s got", msg);
        for (size_t i = 0; i < n && i < 8; i++) {
            fprintf(stderr, " %02X", got[i]);
        }
        fprintf(stderr, " (n=%zu)\n", n);
        g_fail = 1;
    }
}

/*
 * Issue harness: config/example.ethernetip.json status_word = 300.
 * fb_read_bytes returns the raw assembly image (no numeric conversion).
 */
static const char *example_cfg(void)
{
    static const char *cands[] = {
        "config/example.ethernetip.json",
        "../config/example.ethernetip.json",
        "../../config/example.ethernetip.json",
    };
    for (size_t i = 0; i < sizeof cands / sizeof cands[0]; i++) {
        if (access(cands[i], R_OK) == 0) {
            return cands[i];
        }
    }
    return cands[0];
}

static void test_repro_status_word(void)
{
    fb_runtime_t *rt = NULL;
    const char *cfg = example_cfg();
    int rc = fb_open(cfg, &rt);
    expect(rc == FB_OK, "fb_open example.ethernetip.json");
    if (rc != FB_OK) {
        fprintf(stderr, "fb_open: %s\n", fb_strerror(rc));
        return;
    }
    expect(fb_write_u32(rt, "status_word", 300) == FB_OK, "write status_word");
    unsigned char b[8] = {0};
    size_t n = 0;
    expect(fb_read_bytes(rt, "status_word", b, sizeof b, &n) == FB_OK,
           "read status_word bytes");
    printf("%02X %02X -> CIP UINT %u\n", b[0], b[1],
           (unsigned)(b[0] | (b[1] << 8)));
    fflush(stdout);
    expect(n >= 2 && b[0] == 0x2C && b[1] == 0x01, "status_word wire 2C 01");
    expect((b[0] | (b[1] << 8)) == 300, "CIP UINT 300");

    uint32_t back = 0;
    expect(fb_read_u32(rt, "status_word", &back) == FB_OK, "read status_word u32");
    expect(back == 300, "status_word numeric roundtrip");
    fb_close(rt);
}

static const char *k_roundtrip =
    "{\n"
    "  \"protocol\": \"ethernetip\",\n"
    "  \"device\": {\"name\": \"eip_t1\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"role\": \"server\", \"mock\": true, \"security_class\": 0,\n"
    "    \"input_assembly\": 150, \"output_assembly\": 101,\n"
    "    \"input_size\": 64, \"output_size\": 16\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"u16\", \"access\": \"read\", \"data_type\": \"uint16\",\n"
    "     \"length\": 2, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 0, \"length\": 2}}},\n"
    "    {\"name\": \"i16\", \"access\": \"read\", \"data_type\": \"int16\",\n"
    "     \"length\": 2, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 2, \"length\": 2}}},\n"
    "    {\"name\": \"u32\", \"access\": \"read\", \"data_type\": \"uint32\",\n"
    "     \"length\": 4, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 4, \"length\": 4}}},\n"
    "    {\"name\": \"i32\", \"access\": \"read\", \"data_type\": \"int32\",\n"
    "     \"length\": 4, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 8, \"length\": 4}}},\n"
    "    {\"name\": \"f32\", \"access\": \"read\", \"data_type\": \"float\",\n"
    "     \"length\": 4, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 12, \"length\": 4}}},\n"
    "    {\"name\": \"f64\", \"access\": \"read\", \"data_type\": \"double\",\n"
    "     \"length\": 8, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 16, \"length\": 8}}},\n"
    "    {\"name\": \"flag\", \"access\": \"read\", \"data_type\": \"bool\",\n"
    "     \"length\": 1, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 24, \"length\": 1}}},\n"
    "    {\"name\": \"text\", \"access\": \"read\", \"data_type\": \"string\",\n"
    "     \"length\": 8, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 32, \"length\": 8}}},\n"
    "    {\"name\": \"blob\", \"access\": \"read\", \"data_type\": \"bytes\",\n"
    "     \"length\": 4, \"address\": {\"ethernetip\": {\"assembly\": 150,\n"
    "     \"byte_offset\": 40, \"length\": 4}}}\n"
    "  ]\n"
    "}\n";

static void test_numeric_roundtrip(void)
{
    fb_runtime_t *rt = NULL;
    expect(open_cfg(k_roundtrip, &rt) == FB_OK, "open roundtrip cfg");
    if (!rt) {
        return;
    }

    expect(fb_write_u32(rt, "u16", 0x1234) == FB_OK, "write u16");
    unsigned char b[8] = {0};
    size_t n = 0;
    expect(fb_read_bytes(rt, "u16", b, sizeof b, &n) == FB_OK, "read u16 bytes");
    {
        const uint8_t exp[] = {0x34, 0x12};
        expect_bytes(b, n, exp, 2, "u16 LE");
    }
    uint32_t u = 0;
    expect(fb_read_u32(rt, "u16", &u) == FB_OK && u == 0x1234, "u16 value");

    expect(fb_write_i32(rt, "i16", -2) == FB_OK, "write i16");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "i16", b, sizeof b, &n) == FB_OK, "read i16 bytes");
    {
        const uint8_t exp[] = {0xFE, 0xFF};
        expect_bytes(b, n, exp, 2, "i16 LE");
    }
    int32_t s = 0;
    expect(fb_read_i32(rt, "i16", &s) == FB_OK && s == -2, "i16 value");

    expect(fb_write_u32(rt, "u32", 0x01020304u) == FB_OK, "write u32");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "u32", b, sizeof b, &n) == FB_OK, "read u32 bytes");
    {
        const uint8_t exp[] = {0x04, 0x03, 0x02, 0x01};
        expect_bytes(b, n, exp, 4, "u32 LE");
    }
    u = 0;
    expect(fb_read_u32(rt, "u32", &u) == FB_OK && u == 0x01020304u, "u32 value");

    expect(fb_write_i32(rt, "i32", -123456) == FB_OK, "write i32");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "i32", b, sizeof b, &n) == FB_OK, "read i32 bytes");
    {
        const uint8_t exp[] = {0xC0, 0x1D, 0xFE, 0xFF};
        expect_bytes(b, n, exp, 4, "i32 LE");
    }
    s = 0;
    expect(fb_read_i32(rt, "i32", &s) == FB_OK && s == -123456, "i32 value");

    expect(fb_write_f32(rt, "f32", 12.5f) == FB_OK, "write f32");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "f32", b, sizeof b, &n) == FB_OK, "read f32 bytes");
    {
        const uint8_t exp[] = {0x00, 0x00, 0x48, 0x41};
        expect_bytes(b, n, exp, 4, "f32 LE");
    }
    float f = 0;
    expect(fb_read_f32(rt, "f32", &f) == FB_OK && f == 12.5f, "f32 value");

    fb_value_t dv;
    memset(&dv, 0, sizeof dv);
    dv.type = FB_TYPE_F64;
    dv.v.f64 = 1.5;
    expect(fb_write_point(rt, "f64", &dv) == FB_OK, "write f64");
    unsigned char d[8] = {0};
    n = 0;
    expect(fb_read_bytes(rt, "f64", d, sizeof d, &n) == FB_OK, "read f64 bytes");
    {
        const uint8_t exp[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x3F};
        expect_bytes(d, n, exp, 8, "f64 LE");
    }
    fb_value_t dr;
    memset(&dr, 0, sizeof dr);
    dr.type = FB_TYPE_F64;
    expect(fb_read_point(rt, "f64", &dr) == FB_OK && dr.v.f64 == 1.5, "f64 value");

    fb_close(rt);
}

static void test_string_bool_bytes_unchanged(void)
{
    fb_runtime_t *rt = NULL;
    expect(open_cfg(k_roundtrip, &rt) == FB_OK, "open passthrough cfg");
    if (!rt) {
        return;
    }
    expect(fb_write_bool(rt, "flag", 1) == FB_OK, "write bool");
    unsigned char b[8] = {0};
    size_t n = 0;
    expect(fb_read_bytes(rt, "flag", b, sizeof b, &n) == FB_OK, "read bool bytes");
    expect(n == 1 && b[0] == 0x01, "bool not swapped");
    int flag = 0;
    expect(fb_read_bool(rt, "flag", &flag) == FB_OK && flag == 1, "bool value");

    expect(fb_write_string(rt, "text", "ABC") == FB_OK, "write string");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "text", b, sizeof b, &n) == FB_OK, "read string bytes");
    expect(n >= 3 && b[0] == 'A' && b[1] == 'B' && b[2] == 'C',
           "string not reversed");
    char sbuf[16];
    expect(fb_read_string(rt, "text", sbuf, sizeof sbuf) == FB_OK, "read string");
    expect(strcmp(sbuf, "ABC") == 0, "string value");

    const uint8_t blob[] = {0x11, 0x22, 0x33, 0x44};
    expect(fb_write_bytes(rt, "blob", blob, sizeof blob) == FB_OK, "write bytes");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "blob", b, sizeof b, &n) == FB_OK, "read bytes");
    expect_bytes(b, n, blob, 4, "bytes not swapped");
    fb_close(rt);
}

static const char *k_originator =
    "{\n"
    "  \"protocol\": \"ethernetip\",\n"
    "  \"device\": {\"name\": \"eip_t1_orig\", \"role\": \"client\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"role\": \"client\", \"mock\": true, \"security_class\": 0,\n"
    "    \"ip\": \"127.0.0.1\", \"port\": 44818,\n"
    "    \"input_assembly\": 150, \"output_assembly\": 101,\n"
    "    \"input_size\": 32, \"output_size\": 8\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"tag_u16\", \"access\": \"read\", \"data_type\": \"uint16\",\n"
    "     \"length\": 2, \"address\": {\"ethernetip\": {\"tag\": \"N16\"}}},\n"
    "    {\"name\": \"tag_raw\", \"access\": \"read\", \"data_type\": \"bytes\",\n"
    "     \"length\": 2, \"address\": {\"ethernetip\": {\"tag\": \"N16\"}}},\n"
    "    {\"name\": \"cip_i32\", \"access\": \"read\", \"data_type\": \"int32\",\n"
    "     \"length\": 4, \"address\": {\"ethernetip\": {\"class_id\": 4,\n"
    "     \"instance\": 150, \"attribute\": 3, \"length\": 4}}},\n"
    "    {\"name\": \"cip_raw\", \"access\": \"read\", \"data_type\": \"bytes\",\n"
    "     \"length\": 4, \"address\": {\"ethernetip\": {\"class_id\": 4,\n"
    "     \"instance\": 150, \"attribute\": 3, \"length\": 4}}}\n"
    "  ]\n"
    "}\n";

static void test_originator_paths(void)
{
    fb_runtime_t *rt = NULL;
    int rc = open_cfg(k_originator, &rt);
    expect(rc == FB_OK, "open originator cfg");
    if (rc != FB_OK) {
        fprintf(stderr, "originator open: %s\n", fb_strerror(rc));
        return;
    }

    expect(fb_write_u32(rt, "tag_u16", 300) == FB_OK, "tag write");
    unsigned char b[8] = {0};
    size_t n = 0;
    expect(fb_read_bytes(rt, "tag_raw", b, sizeof b, &n) == FB_OK, "tag raw read");
    {
        const uint8_t exp[] = {0x2C, 0x01};
        expect_bytes(b, n >= 2 ? 2 : n, exp, 2, "tag wire LE");
    }
    uint32_t u = 0;
    expect(fb_read_u32(rt, "tag_u16", &u) == FB_OK && u == 300, "tag numeric");

    expect(fb_write_i32(rt, "cip_i32", -2) == FB_OK, "cip write");
    memset(b, 0, sizeof b);
    n = 0;
    expect(fb_read_bytes(rt, "cip_raw", b, sizeof b, &n) == FB_OK, "cip raw read");
    {
        /* int32 -2 = 0xFFFFFFFE, CIP little-endian */
        const uint8_t exp[] = {0xFE, 0xFF, 0xFF, 0xFF};
        expect_bytes(b, n >= 4 ? 4 : n, exp, 4, "cip wire LE");
    }
    int32_t s = 0;
    expect(fb_read_i32(rt, "cip_i32", &s) == FB_OK && s == -2, "cip numeric");
    fb_close(rt);
}

static void test_assembly_directions(void)
{
    const char *params =
        "{\"role\":\"server\",\"mock\":true,\"security_class\":0,"
        "\"input_assembly\":150,\"output_assembly\":101,"
        "\"input_size\":16,\"output_size\":8}";
    const char *points =
        "["
        "{\"name\":\"to_plc\",\"access\":\"read\",\"data_type\":\"uint16\","
        "\"length\":2,\"address\":{\"ethernetip\":{\"assembly\":150,"
        "\"byte_offset\":4,\"length\":2}}},"
        "{\"name\":\"from_plc\",\"access\":\"write\",\"data_type\":\"uint16\","
        "\"length\":2,\"address\":{\"ethernetip\":{\"assembly\":101,"
        "\"byte_offset\":0,\"length\":2}}}"
        "]";
    protocol_adapter_t *a = ethernetip_adapter_create();
    expect(a != NULL, "adapter create");
    if (!a) {
        return;
    }
    expect(a->init(a, params, points) == 0, "adapter init");
    expect(a->connect(a) == 0, "adapter connect");
    eip_ctx_peek_t *ctx = a->ctx;
    expect(ctx && ctx->stack, "stack");
    if (!ctx || !ctx->stack) {
        a->destroy(a);
        return;
    }

    uint8_t be[2] = {0x01, 0x2C};
    point_value_t w = {.data = be, .len = 2};
    expect(a->write_point(a, "to_plc", &w) == 0, "write input");
    uint8_t raw[2] = {0};
    expect(eip_stack_read_input(ctx->stack, 4, raw, 2) == 2, "read assembly");
    expect(raw[0] == 0x2C && raw[1] == 0x01, "input assembly LE");

    uint8_t canon[2] = {0};
    point_value_t r = {.data = canon, .len = sizeof canon};
    expect(a->read_point(a, "to_plc", &r) == 0, "read input canonical");
    expect(canon[0] == 0x01 && canon[1] == 0x2C, "input read LE->BE");

    uint8_t ple[2] = {0x34, 0x12}; /* scanner UINT 0x1234 */
    expect(eip_stack_write_output(ctx->stack, 0, ple, 2) == 2, "seed output");
    uint8_t got[2] = {0};
    point_value_t pr = {.data = got, .len = sizeof got};
    expect(a->read_point(a, "from_plc", &pr) == 0, "read output");
    expect(got[0] == 0x12 && got[1] == 0x34, "output read LE->BE");

    a->disconnect(a);
    a->destroy(a);
}

int main(void)
{
    test_repro_status_word();
    test_numeric_roundtrip();
    test_string_bool_bytes_unchanged();
    test_originator_paths();
    test_assembly_directions();
    if (g_fail) {
        fprintf(stderr, "test_eip_adapter: FAILED\n");
        return 1;
    }
    printf("test_eip_adapter: OK\n");
    return 0;
}
