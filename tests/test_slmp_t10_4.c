/*
 * T10-4 repro: omitted SLMP string and 32-bit layout must follow MELSEC.
 *
 * MELSEC $MOV: first character is the low byte of D(n).
 *   "ABCD" -> D(n)=0x4241, D(n+1)=0x4443
 * MELSEC DMOV/DINT/REAL: low word is D(n) (this adapter's CDAB).
 *   int32 0x12345678 -> D(n)=0x5678, D(n+1)=0x1234
 *   float32 1.5      -> D(n)=0x0000, D(n+1)=0x3FC0
 *
 * Points below set neither endian nor string_swap.
 */
#include "slmp_adapter.h"
#include "slmp_codec.h"

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

static uint16_t read_word(protocol_adapter_t *a, const char *name)
{
    point_value_t r = {0};
    int rc = a->read_point(a, name, &r);
    expect(rc == 0, name);
    uint16_t w = 0;
    if (rc == 0 && r.data && r.len >= 2) {
        w = (uint16_t)(((uint16_t)r.data[0] << 8) | r.data[1]);
    } else {
        fprintf(stderr, "FAIL: %s word bytes missing (rc=%d len=%zu)\n", name,
                rc, r.len);
        g_fail = 1;
    }
    free(r.data);
    return w;
}

static void test_parse_endian_default_is_cdab(void)
{
    expect(slmp_parse_endian(NULL, NULL, NULL) == SLMP_END_CDAB,
           "omitted endian is MELSEC CDAB");
    expect(slmp_parse_endian("", "", "") == SLMP_END_CDAB,
           "empty endian is MELSEC CDAB");
    expect(slmp_parse_endian("big", "ab", NULL) == SLMP_END_ABCD,
           "explicit big/ab stays ABCD");
    expect(slmp_parse_endian(NULL, NULL, "ABCD") == SLMP_END_ABCD,
           "explicit ABCD");
    expect(slmp_parse_endian(NULL, NULL, "CDAB") == SLMP_END_CDAB,
           "explicit CDAB");
}

static protocol_adapter_t *open_server(const char *params, const char *points)
{
    protocol_adapter_t *a = slmp_adapter_create();
    expect(a != NULL, "create");
    if (!a) {
        return NULL;
    }
    int rc = a->init(a, params, points);
    expect(rc == 0, "init");
    if (rc != 0) {
        a->destroy(a);
        return NULL;
    }
    return a;
}

static void test_omitted_layout_is_melsec(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15590,"
        "\"frame\":\"3E\"}";
    const char *points =
        "["
        "{\"name\":\"s\",\"access\":\"readwrite\",\"data_type\":\"string\","
        "\"length\":4,\"address\":{\"slmp\":{\"device_code\":\"D\","
        "\"start\":300}}},"
        "{\"name\":\"s0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":300}}},"
        "{\"name\":\"s1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":301}}},"
        "{\"name\":\"v\",\"access\":\"readwrite\",\"data_type\":\"int32\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":310}}},"
        "{\"name\":\"v0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":310}}},"
        "{\"name\":\"v1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":311}}},"
        "{\"name\":\"f\",\"access\":\"readwrite\",\"data_type\":\"float32\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":320}}},"
        "{\"name\":\"f0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":320}}},"
        "{\"name\":\"f1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":321}}},"
        "{\"name\":\"u\",\"access\":\"readwrite\",\"data_type\":\"uint64\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":330}}},"
        "{\"name\":\"u0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":330}}},"
        "{\"name\":\"u1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":331}}},"
        "{\"name\":\"u2\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":332}}},"
        "{\"name\":\"u3\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":333}}}"
        "]";

    protocol_adapter_t *a = open_server(params, points);
    if (!a) {
        return;
    }

    uint8_t str[4] = {'A', 'B', 'C', 'D'};
    point_value_t sw = {.data = str, .len = 4};
    expect(a->write_point(a, "s", &sw) == 0, "write string");
    uint16_t s0 = read_word(a, "s0");
    uint16_t s1 = read_word(a, "s1");
    expect(s0 == 0x4241 && s1 == 0x4443, "string MELSEC low-byte first");
    if (!(s0 == 0x4241 && s1 == 0x4443)) {
        fprintf(stderr, "  string words D300=%04x D301=%04x (want 4241 4443)\n",
                s0, s1);
    }

    uint8_t i32[4] = {0x12, 0x34, 0x56, 0x78};
    point_value_t iw = {.data = i32, .len = 4};
    expect(a->write_point(a, "v", &iw) == 0, "write int32");
    uint16_t v0 = read_word(a, "v0");
    uint16_t v1 = read_word(a, "v1");
    expect(v0 == 0x5678 && v1 == 0x1234, "int32 MELSEC low word first");
    if (!(v0 == 0x5678 && v1 == 0x1234)) {
        fprintf(stderr, "  int32 words D310=%04x D311=%04x (want 5678 1234)\n",
                v0, v1);
    }

    /* float32 1.5 canonical BE is 3F C0 00 00. */
    uint8_t f32[4] = {0x3F, 0xC0, 0x00, 0x00};
    point_value_t fw = {.data = f32, .len = 4};
    expect(a->write_point(a, "f", &fw) == 0, "write float32");
    uint16_t f0 = read_word(a, "f0");
    uint16_t f1 = read_word(a, "f1");
    expect(f0 == 0x0000 && f1 == 0x3FC0, "float32 MELSEC low word first");
    if (!(f0 == 0x0000 && f1 == 0x3FC0)) {
        fprintf(stderr, "  float words D320=%04x D321=%04x (want 0000 3fc0)\n",
                f0, f1);
    }

    /* 0x1122334455667788, low word at D(n). */
    uint8_t u64[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    point_value_t uw = {.data = u64, .len = 8};
    expect(a->write_point(a, "u", &uw) == 0, "write uint64");
    uint16_t u0 = read_word(a, "u0");
    uint16_t u1 = read_word(a, "u1");
    uint16_t u2 = read_word(a, "u2");
    uint16_t u3 = read_word(a, "u3");
    expect(u0 == 0x7788 && u1 == 0x5566 && u2 == 0x3344 && u3 == 0x1122,
           "uint64 MELSEC low word first");
    if (!(u0 == 0x7788 && u1 == 0x5566 && u2 == 0x3344 && u3 == 0x1122)) {
        fprintf(stderr, "  uint64 words %04x %04x %04x %04x\n", u0, u1, u2, u3);
    }

    point_value_t ir = {0};
    expect(a->read_point(a, "v", &ir) == 0, "read int32 back");
    expect(ir.len == 4 && ir.data && ir.data[0] == 0x12 && ir.data[1] == 0x34 &&
               ir.data[2] == 0x56 && ir.data[3] == 0x78,
           "int32 canonical roundtrip");
    free(ir.data);

    uint8_t seed0[2] = {0x42, 0x41};
    uint8_t seed1[2] = {0x44, 0x43};
    point_value_t p0 = {.data = seed0, .len = 2};
    point_value_t p1 = {.data = seed1, .len = 2};
    expect(a->write_point(a, "s0", &p0) == 0, "seed D300");
    expect(a->write_point(a, "s1", &p1) == 0, "seed D301");
    point_value_t sr = {0};
    expect(a->read_point(a, "s", &sr) == 0, "read string");
    expect(sr.len == 4 && sr.data && memcmp(sr.data, "ABCD", 4) == 0,
           "string unpack MELSEC");
    free(sr.data);

    a->destroy(a);
}

static void test_layout_legacy_keeps_old_words(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15591,"
        "\"frame\":\"3E\",\"layout\":\"legacy\"}";
    const char *points =
        "["
        "{\"name\":\"s\",\"access\":\"readwrite\",\"data_type\":\"string\","
        "\"length\":4,\"address\":{\"slmp\":{\"device_code\":\"D\","
        "\"start\":300}}},"
        "{\"name\":\"s0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":300}}},"
        "{\"name\":\"s1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":301}}},"
        "{\"name\":\"v\",\"access\":\"readwrite\",\"data_type\":\"int32\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":310}}},"
        "{\"name\":\"v0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":310}}},"
        "{\"name\":\"v1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":311}}},"
        "{\"name\":\"f\",\"access\":\"readwrite\",\"data_type\":\"float32\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":320}}},"
        "{\"name\":\"f0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":320}}},"
        "{\"name\":\"f1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":321}}}"
        "]";
    protocol_adapter_t *a = open_server(params, points);
    if (!a) {
        return;
    }
    uint8_t str[4] = {'A', 'B', 'C', 'D'};
    point_value_t sw = {.data = str, .len = 4};
    expect(a->write_point(a, "s", &sw) == 0, "legacy write string");
    expect(read_word(a, "s0") == 0x4142 && read_word(a, "s1") == 0x4344,
           "legacy string high-byte first");
    uint8_t i32[4] = {0x12, 0x34, 0x56, 0x78};
    point_value_t iw = {.data = i32, .len = 4};
    expect(a->write_point(a, "v", &iw) == 0, "legacy write int32");
    expect(read_word(a, "v0") == 0x1234 && read_word(a, "v1") == 0x5678,
           "legacy int32 high word first");
    uint8_t f32[4] = {0x3F, 0xC0, 0x00, 0x00};
    point_value_t fw = {.data = f32, .len = 4};
    expect(a->write_point(a, "f", &fw) == 0, "legacy write float32");
    expect(read_word(a, "f0") == 0x3FC0 && read_word(a, "f1") == 0x0000,
           "legacy float32 high word first");
    a->destroy(a);
}

static void test_explicit_fields_override_layout(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15592,"
        "\"frame\":\"3E\",\"layout\":\"legacy\"}";
    const char *points =
        "["
        "{\"name\":\"s\",\"access\":\"readwrite\",\"data_type\":\"string\","
        "\"length\":4,\"string_swap\":true,"
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":100}}},"
        "{\"name\":\"s0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":100}}},"
        "{\"name\":\"s1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":101}}},"
        "{\"name\":\"v\",\"access\":\"readwrite\",\"data_type\":\"int32\","
        "\"endian\":\"CDAB\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":110}}},"
        "{\"name\":\"v0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":110}}},"
        "{\"name\":\"v1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":111}}},"
        "{\"name\":\"old\",\"access\":\"readwrite\",\"data_type\":\"int32\","
        "\"layout\":\"melsec\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":120}}},"
        "{\"name\":\"o0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":120}}},"
        "{\"name\":\"o1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":121}}},"
        "{\"name\":\"hi\",\"access\":\"readwrite\",\"data_type\":\"string\","
        "\"length\":4,\"string_swap\":false,\"layout\":\"melsec\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":130}}},"
        "{\"name\":\"h0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":130}}},"
        "{\"name\":\"h1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":131}}}"
        "]";
    protocol_adapter_t *a = open_server(params, points);
    if (!a) {
        return;
    }
    uint8_t str[4] = {'A', 'B', 'C', 'D'};
    point_value_t sw = {.data = str, .len = 4};
    expect(a->write_point(a, "s", &sw) == 0, "override string");
    expect(read_word(a, "s0") == 0x4241 && read_word(a, "s1") == 0x4443,
           "explicit string_swap beats legacy");
    uint8_t i32[4] = {0x12, 0x34, 0x56, 0x78};
    point_value_t iw = {.data = i32, .len = 4};
    expect(a->write_point(a, "v", &iw) == 0, "override int32");
    expect(read_word(a, "v0") == 0x5678 && read_word(a, "v1") == 0x1234,
           "explicit CDAB beats legacy");
    expect(a->write_point(a, "old", &iw) == 0, "point layout melsec");
    expect(read_word(a, "o0") == 0x5678 && read_word(a, "o1") == 0x1234,
           "point layout melsec beats protocol legacy");
    expect(a->write_point(a, "hi", &sw) == 0, "string_swap false");
    expect(read_word(a, "h0") == 0x4142 && read_word(a, "h1") == 0x4344,
           "explicit string_swap false beats melsec layout");
    a->destroy(a);
}

static void test_address_layout_and_bad_token(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15593,"
        "\"frame\":\"3E\"}";
    const char *points =
        "["
        "{\"name\":\"v\",\"access\":\"readwrite\",\"data_type\":\"int32\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":10,"
        "\"layout\":\"legacy\"}}},"
        "{\"name\":\"v0\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":10}}},"
        "{\"name\":\"v1\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"D\",\"start\":11}}}"
        "]";
    protocol_adapter_t *a = open_server(params, points);
    if (!a) {
        return;
    }
    uint8_t i32[4] = {0x12, 0x34, 0x56, 0x78};
    point_value_t iw = {.data = i32, .len = 4};
    expect(a->write_point(a, "v", &iw) == 0, "address layout write");
    expect(read_word(a, "v0") == 0x1234 && read_word(a, "v1") == 0x5678,
           "address.slmp.layout legacy");
    a->destroy(a);

    protocol_adapter_t *bad = slmp_adapter_create();
    expect(bad != NULL, "bad create");
    if (!bad) {
        return;
    }
    const char *bad_params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15594,"
        "\"frame\":\"3E\",\"layout\":\"abcd\"}";
    expect(bad->init(bad, bad_params, "[]") != 0, "unknown layout rejected");
    bad->destroy(bad);
}

int main(void)
{
    test_parse_endian_default_is_cdab();
    test_omitted_layout_is_melsec();
    test_layout_legacy_keeps_old_words();
    test_explicit_fields_override_layout();
    test_address_layout_and_bad_token();
    if (g_fail) {
        fprintf(stderr, "test_slmp_t10_4: FAILED\n");
        return 1;
    }
    printf("test_slmp_t10_4: OK\n");
    return 0;
}
