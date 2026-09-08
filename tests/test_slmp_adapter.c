#include "slmp_adapter.h"
#include "slmp_codec.h"

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

static void test_codec_helpers(void)
{
    uint8_t b[4] = {0x12, 0x34, 0x56, 0x78};
    slmp_wire_to_canonical(b, 4, SLMP_END_CDAB);
    expect(b[0] == 0x56 && b[1] == 0x78 && b[2] == 0x12 && b[3] == 0x34,
           "CDAB");
    expect(slmp_parse_data_type("REAL") == SLMP_DT_FLOAT32, "alias REAL");
    expect(slmp_parse_data_type("ascii") == SLMP_DT_STRING, "alias ascii");
    expect(slmp_bcd_to_u32(0x1234) == 1234, "bcd");
}

static void test_adapter_mapping(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15558,"
        "\"network_no\":0,\"pc_no\":255,\"frame\":\"3E\","
        "\"timeout_ms\":200,\"max_clients\":2}";
    const char *points =
        "["
        "{\"name\":\"barcode_value\",\"access\":\"read\",\"data_type\":"
        "\"string\",\"length\":6,"
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":100}}},"
        "{\"name\":\"temperature\",\"access\":\"read\",\"data_type\":\"u16\","
        "\"scale\":0.1,"
        "\"address\":{\"slmp\":{\"device\":\"D\",\"address\":\"110\","
        "\"offset\":0,\"count\":1}}},"
        "{\"name\":\"pressure\",\"access\":\"read\",\"data_type\":\"float\","
        "\"endian\":\"CDAB\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":200,"
        "\"quantity\":2}}},"
        "{\"name\":\"trigger\",\"access\":\"write\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"M\",\"start\":0,"
        "\"unit\":\"bit\"}}},"
        "{\"name\":\"alarm_bit\",\"access\":\"write\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device\":\"D\",\"start\":300,\"bit\":3}}},"
        "{\"name\":\"hex_in\",\"access\":\"write\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"X\",\"start\":\"1A\","
        "\"unit\":\"bit\"}}}"
        "]";

    protocol_adapter_t *a = slmp_adapter_create();
    expect(a->init(a, params, points) == 0, "init");
    expect(a->connect(a) == 0, "connect");

    uint8_t tag[6] = {'A', 'B', 'C', '1', '2', '3'};
    point_value_t tw = {.data = tag, .len = 6};
    expect(a->write_point(a, "barcode_value", &tw) == 0, "write barcode");
    point_value_t tr = {0};
    expect(a->read_point(a, "barcode_value", &tr) == 0, "read barcode");
    expect(tr.len == 6 && memcmp(tr.data, "ABC123", 6) == 0, "barcode match");
    free(tr.data);

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

    float f = 1.5f;
    memcpy(&u, &f, sizeof(u));
    uint8_t fb[4] = {(uint8_t)(u >> 24), (uint8_t)(u >> 16), (uint8_t)(u >> 8),
                     (uint8_t)u};
    point_value_t fw = {.data = fb, .len = 4};
    expect(a->write_point(a, "pressure", &fw) == 0, "write pressure");
    point_value_t fr = {0};
    expect(a->read_point(a, "pressure", &fr) == 0, "read pressure");
    u = be_u32(fr.data);
    float f2;
    memcpy(&f2, &u, sizeof(f2));
    expect(fabsf(f2 - 1.5f) < 0.01f, "pressure roundtrip");
    free(fr.data);

    uint8_t one = 1;
    point_value_t bw = {.data = &one, .len = 1};
    expect(a->write_point(a, "alarm_bit", &bw) == 0, "write bit-in-word");
    point_value_t br = {0};
    expect(a->read_point(a, "alarm_bit", &br) == 0, "read bit-in-word");
    expect(br.len >= 1 && br.data[0] == 1, "bit set");
    free(br.data);

    expect(a->write_point(a, "hex_in", &bw) == 0, "write X1A");
    point_value_t xr = {0};
    expect(a->read_point(a, "hex_in", &xr) == 0, "read X1A");
    expect(xr.len >= 1 && xr.data[0] == 1, "X1A set");
    free(xr.data);

    a->disconnect(a);
    a->destroy(a);
}

int main(void)
{
    test_codec_helpers();
    test_adapter_mapping();
    if (g_fail) {
        fprintf(stderr, "test_slmp_adapter: FAILED\n");
        return 1;
    }
    printf("test_slmp_adapter: OK\n");
    return 0;
}
