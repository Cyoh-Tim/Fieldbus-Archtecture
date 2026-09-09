#include "modbus_adapter.h"
#include "modbus_codec.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static uint32_t be_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void test_offset_scale_endian_aliases(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15556,"
        "\"unit_id\":1,\"max_clients\":2,\"client_timeout_ms\":100}";
    const char *points =
        "["
        "{\"name\":\"temperature\",\"access\":\"read\",\"data_type\":\"u16\","
        "\"scale\":0.1,\"offset\":0.0,"
        "\"address\":{\"modbus\":{\"type\":\"4x\",\"address\":\"40001\","
        "\"offset\":16,\"count\":1}}},"
        "{\"name\":\"flow\",\"access\":\"read\",\"data_type\":\"float\","
        "\"endian\":\"CDAB\","
        "\"address\":{\"modbus\":{\"register_type\":\"holding\","
        "\"start\":40100,\"quantity\":2}}},"
        "{\"name\":\"tag\",\"access\":\"read\",\"data_type\":\"ascii\","
        "\"length\":4,\"chars_per_register\":1,"
        "\"address\":{\"modbus\":{\"type\":\"hr\",\"start\":40200}}},"
        "{\"name\":\"flag\",\"access\":\"write\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40300,"
        "\"bit\":5,\"bit_count\":1}}}"
        "]";

    protocol_adapter_t *a = modbus_adapter_create();
    expect(a->init(a, params, points) == 0, "init");
    expect(a->connect(a) == 0, "connect");

    float eng = 25.5f;
    uint32_t u;
    memcpy(&u, &eng, sizeof(u));
    uint8_t eng_be[4] = {(uint8_t)(u >> 24), (uint8_t)(u >> 16),
                         (uint8_t)(u >> 8), (uint8_t)u};
    point_value_t wv = {.data = eng_be, .len = 4};
    expect(a->write_point(a, "temperature", &wv) == 0, "write temp");
    point_value_t rv = {0};
    expect(a->read_point(a, "temperature", &rv) == 0, "read temp");
    float rf;
    u = be_u32(rv.data);
    memcpy(&rf, &u, sizeof(rf));
    expect(fabsf(rf - 25.5f) < 0.05f, "temp eng");
    free(rv.data);

    /* float CDAB: write canonical IEEE then verify roundtrip */
    float f = 1.5f;
    memcpy(&u, &f, sizeof(u));
    uint8_t fb[4] = {(uint8_t)(u >> 24), (uint8_t)(u >> 16), (uint8_t)(u >> 8),
                     (uint8_t)u};
    point_value_t fw = {.data = fb, .len = 4};
    expect(a->write_point(a, "flow", &fw) == 0, "write flow");
    point_value_t fr = {0};
    expect(a->read_point(a, "flow", &fr) == 0, "read flow");
    u = be_u32(fr.data);
    float f2;
    memcpy(&f2, &u, sizeof(f2));
    expect(fabsf(f2 - 1.5f) < 0.01f, "flow roundtrip");
    free(fr.data);

    uint8_t tag[4] = {'A', 'B', 'C', 'D'};
    point_value_t tw = {.data = tag, .len = 4};
    expect(a->write_point(a, "tag", &tw) == 0, "write tag");
    point_value_t tr = {0};
    expect(a->read_point(a, "tag", &tr) == 0, "read tag");
    expect(tr.len == 4 && memcmp(tr.data, "ABCD", 4) == 0, "tag chars/reg=1");
    free(tr.data);

    uint8_t one = 1;
    point_value_t bw = {.data = &one, .len = 1};
    expect(a->write_point(a, "flag", &bw) == 0, "write bit");
    point_value_t br = {0};
    expect(a->read_point(a, "flag", &br) == 0, "read bit");
    expect(br.len >= 1 && br.data[0] == 1, "bit set");
    free(br.data);

    a->disconnect(a);
    a->destroy(a);
}

static void test_endian_helpers(void)
{
    uint8_t b[4] = {0x12, 0x34, 0x56, 0x78};
    mb_wire_to_canonical(b, 4, MB_END_CDAB);
    expect(b[0] == 0x56 && b[1] == 0x78 && b[2] == 0x12 && b[3] == 0x34,
           "CDAB");
    expect(mb_parse_data_type("REAL") == MB_DT_FLOAT32, "alias REAL");
    expect(mb_parse_data_type("qword") == MB_DT_UINT64, "alias qword");
    expect(mb_bcd_to_u32(0x1234) == 1234, "bcd");
}

int main(void)
{
    test_endian_helpers();
    test_offset_scale_endian_aliases();
    if (g_fail) {
        fprintf(stderr, "test_mb_adapter: FAILED\n");
        return 1;
    }
    printf("test_mb_adapter: OK\n");
    return 0;
}
