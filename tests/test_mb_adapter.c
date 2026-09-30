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

/* T9-2: bit_count <= 8 inside a 2-byte type. The app boundary is canonical
 * big-endian of the data type (T0 A), so uint16 0x000A is the bytes 00 0A.
 * Before the fix, a write kept only the high byte (recorded 0) and a read
 * returned the extracted nibble in byte 0 plus an uninitialized byte 1. */
static void expect_mem(const uint8_t *got, size_t glen, const uint8_t *exp,
                       size_t elen, const char *msg)
{
    int ok = got && glen == elen && (elen == 0 || memcmp(got, exp, elen) == 0);
    if (!ok) {
        fprintf(stderr, "FAIL: %s (len %zu, bytes", msg, glen);
        for (size_t i = 0; i < glen && i < 8; i++) {
            fprintf(stderr, " %02X", got ? got[i] : 0);
        }
        fprintf(stderr, ", expected");
        for (size_t i = 0; i < elen && i < 8; i++) {
            fprintf(stderr, " %02X", exp[i]);
        }
        fprintf(stderr, ")\n");
        g_fail = 1;
    }
}

static void test_u16_bitfield_roundtrip(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15564,"
        "\"unit_id\":1,\"max_clients\":2,\"client_timeout_ms\":100}";
    const char *points =
        "["
        "{\"name\":\"status_nibble\",\"access\":\"write\",\"data_type\":\"uint16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40101,"
        "\"bit\":0,\"bit_count\":4}}},"
        "{\"name\":\"status_word\",\"access\":\"write\",\"data_type\":\"uint16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40101,"
        "\"quantity\":1}}},"
        "{\"name\":\"high_nibble\",\"access\":\"write\",\"data_type\":\"int16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40200,"
        "\"bit\":4,\"bit_count\":4}}},"
        "{\"name\":\"high_word\",\"access\":\"write\",\"data_type\":\"int16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40200,"
        "\"quantity\":1}}},"
        "{\"name\":\"scaled_nibble\",\"access\":\"write\",\"data_type\":\"uint16\","
        "\"scale\":0.1,"
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40300,"
        "\"bit\":0,\"bit_count\":4}}},"
        "{\"name\":\"scaled_word\",\"access\":\"write\",\"data_type\":\"uint16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40300,"
        "\"quantity\":1}}}"
        "]";

    protocol_adapter_t *a = modbus_adapter_create();
    expect(a->init(a, params, points) == 0, "bitfield init");
    expect(a->connect(a) == 0, "bitfield connect");

    /* Read: seed the register with 0x000A via the full word, then the nibble
     * point must come back as canonical uint16 00 0A (not 0A plus garbage). */
    uint8_t seed[2] = {0x00, 0x0A};
    point_value_t sw = {.data = seed, .len = 2};
    expect(a->write_point(a, "status_word", &sw) == 0, "seed status word");
    point_value_t nr = {0};
    expect(a->read_point(a, "status_nibble", &nr) == 0, "read seeded nibble");
    expect_mem(nr.data, nr.len, seed, 2, "seeded nibble is uint16 0x000A");
    free(nr.data);

    /* Write: 0x00F0 already in the word, store nibble 0xA, keep the upper bits. */
    uint8_t base[2] = {0x00, 0xF0};
    point_value_t bw = {.data = base, .len = 2};
    expect(a->write_point(a, "status_word", &bw) == 0, "seed neighbor bits");
    uint8_t nib[2] = {0x00, 0x0A};
    point_value_t nw = {.data = nib, .len = 2};
    expect(a->write_point(a, "status_nibble", &nw) == 0, "write nibble 0x000A");
    point_value_t wr = {0};
    expect(a->read_point(a, "status_word", &wr) == 0, "read word after nibble");
    uint8_t expect_word[2] = {0x00, 0xFA};
    expect_mem(wr.data, wr.len, expect_word, 2, "word keeps 0xF0 and stores 0xA");
    free(wr.data);
    point_value_t nr2 = {0};
    expect(a->read_point(a, "status_nibble", &nr2) == 0, "read nibble back");
    expect_mem(nr2.data, nr2.len, nib, 2, "nibble readback is uint16 0x000A");
    free(nr2.data);

    /* int16, bit_count 4 starting at bit 4: value 0xA lands in bits 7..4. */
    uint8_t in16[2] = {0x00, 0x0A};
    point_value_t hw = {.data = in16, .len = 2};
    expect(a->write_point(a, "high_nibble", &hw) == 0, "write int16 high nibble");
    point_value_t hr = {0};
    expect(a->read_point(a, "high_word", &hr) == 0, "read int16 word");
    uint8_t expect_hi[2] = {0x00, 0xA0};
    expect_mem(hr.data, hr.len, expect_hi, 2, "int16 bits 7..4 are 0xA");
    free(hr.data);
    point_value_t hnr = {0};
    expect(a->read_point(a, "high_nibble", &hnr) == 0, "read int16 nibble");
    expect_mem(hnr.data, hnr.len, in16, 2, "int16 nibble readback is 0x000A");
    free(hnr.data);

    /* Scale path: engineering 1.0 / scale 0.1 = raw 10 in the same nibble. */
    float eng = 1.0f;
    uint32_t u;
    memcpy(&u, &eng, sizeof(u));
    uint8_t eng_be[4] = {(uint8_t)(u >> 24), (uint8_t)(u >> 16),
                         (uint8_t)(u >> 8), (uint8_t)u};
    point_value_t scw = {.data = eng_be, .len = 4};
    expect(a->write_point(a, "scaled_nibble", &scw) == 0, "write scaled nibble");
    point_value_t scr = {0};
    expect(a->read_point(a, "scaled_word", &scr) == 0, "read scaled word");
    uint8_t expect_sc[2] = {0x00, 0x0A};
    expect_mem(scr.data, scr.len, expect_sc, 2, "scaled raw nibble is 10");
    free(scr.data);
    point_value_t scn = {0};
    expect(a->read_point(a, "scaled_nibble", &scn) == 0, "read scaled nibble");
    expect(scn.len == 4, "scaled nibble returns float32");
    if (scn.data && scn.len == 4) {
        uint32_t ru = be_u32(scn.data);
        float rf;
        memcpy(&rf, &ru, sizeof(rf));
        expect(fabsf(rf - 1.0f) < 0.05f, "scaled nibble eng 1.0");
    }
    free(scn.data);

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
    test_u16_bitfield_roundtrip();
    if (g_fail) {
        fprintf(stderr, "test_mb_adapter: FAILED\n");
        return 1;
    }
    printf("test_mb_adapter: OK\n");
    return 0;
}
