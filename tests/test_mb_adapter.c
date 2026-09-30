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

/* T9-3: a leading zero is decimal padding (Modicon "00010", "040001"),
 * not an octal prefix. "0x" remains hexadecimal. */
static int read_bytes(protocol_adapter_t *a, const char *name, uint8_t *dst,
                      size_t n)
{
    point_value_t rv = {0};
    int rc = a->read_point(a, name, &rv);
    if (rc != 0 || !rv.data || rv.len < n) {
        free(rv.data);
        return -1;
    }
    memcpy(dst, rv.data, n);
    free(rv.data);
    return 0;
}

static void test_leading_zero_address_is_decimal(void)
{
    const char *params =
        "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":15753,"
        "\"unit_id\":1,\"max_clients\":2}";
    /* Probes are numeric addresses, which are unaffected by strtol base.
     * coil N (1-based) is PDU N-1. holding 40001 is PDU 0; holding 16 is PDU 16. */
    const char *points =
        "["
        "{\"name\":\"coil_00010\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"coil\",\"start\":\"00010\"}}},"
        "{\"name\":\"coil_pdu7\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"coil\",\"start\":8}}},"
        "{\"name\":\"coil_pdu9\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"coil\",\"start\":10}}},"
        "{\"name\":\"coil_00009\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"coil\",\"start\":\"00009\"}}},"
        "{\"name\":\"coil_pdu0\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"coil\",\"start\":1}}},"
        "{\"name\":\"coil_pdu8\",\"data_type\":\"bool\","
        "\"address\":{\"modbus\":{\"type\":\"coil\",\"start\":9}}},"
        "{\"name\":\"hr_040001\",\"data_type\":\"u16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":\"040001\"}}},"
        "{\"name\":\"hr_pdu0\",\"data_type\":\"u16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":40001}}},"
        "{\"name\":\"hr_0x10\",\"data_type\":\"u16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":\"0x10\"}}},"
        "{\"name\":\"hr_pdu16\",\"data_type\":\"u16\","
        "\"address\":{\"modbus\":{\"type\":\"holding\",\"start\":16}}}"
        "]";

    protocol_adapter_t *a = modbus_adapter_create();
    if (!a) {
        expect(0, "T9-3 create");
        return;
    }
    int irc = a->init(a, params, points);
    expect(irc == 0, "T9-3 init");
    if (irc != 0) {
        a->destroy(a);
        return;
    }
    expect(a->connect(a) == 0, "T9-3 connect");

    uint8_t one = 1;
    point_value_t on = {.data = &one, .len = 1};
    expect(a->write_point(a, "coil_00010", &on) == 0, "write coil \"00010\"");
    uint8_t b9 = 0xFF, b7 = 0xFF;
    int rc9 = read_bytes(a, "coil_pdu9", &b9, 1);
    int rc7 = read_bytes(a, "coil_pdu7", &b7, 1);
    if (rc9 != 0 || b9 != 1 || rc7 != 0 || b7 != 0) {
        fprintf(stderr,
                "FAIL: coil \"00010\" PDU (decimal 10 → 9, not octal 8 → 7): "
                "pdu9 rc=%d val=%u, pdu7 rc=%d val=%u\n",
                rc9, b9, rc7, b7);
        g_fail = 1;
    }

    expect(a->write_point(a, "coil_00009", &on) == 0, "write coil \"00009\"");
    uint8_t b8 = 0xFF, b0 = 0xFF;
    int rc8 = read_bytes(a, "coil_pdu8", &b8, 1);
    int rc0 = read_bytes(a, "coil_pdu0", &b0, 1);
    if (rc8 != 0 || b8 != 1 || rc0 != 0 || b0 != 0) {
        fprintf(stderr,
                "FAIL: coil \"00009\" PDU (decimal 9 → 8, not truncated octal 0): "
                "pdu8 rc=%d val=%u, pdu0 rc=%d val=%u\n",
                rc8, b8, rc0, b0);
        g_fail = 1;
    }

    /* Sentinel at PDU 0, then "0x10" must land on PDU 16 and leave it alone.
     * strtol base 0 already accepts 0x; base 10 without an explicit prefix
     * would parse "0x10" as 0 and overwrite this register. */
    uint8_t sentinel[2] = {0x11, 0x11};
    point_value_t sv = {.data = sentinel, .len = 2};
    expect(a->write_point(a, "hr_pdu0", &sv) == 0, "seed holding PDU 0");
    uint8_t hexv[2] = {0x00, 0x10};
    point_value_t hv = {.data = hexv, .len = 2};
    expect(a->write_point(a, "hr_0x10", &hv) == 0, "write holding \"0x10\"");
    uint8_t hr16[2] = {0xFF, 0xFF};
    uint8_t hr0[2] = {0xFF, 0xFF};
    int r16 = read_bytes(a, "hr_pdu16", hr16, 2);
    int rhr = read_bytes(a, "hr_pdu0", hr0, 2);
    if (r16 != 0 || hr16[0] != 0x00 || hr16[1] != 0x10 || rhr != 0 ||
        hr0[0] != 0x11 || hr0[1] != 0x11) {
        fprintf(stderr,
                "FAIL: holding \"0x10\" must be hex PDU 16 (pdu16 rc=%d "
                "val=%02x%02x, pdu0 rc=%d val=%02x%02x)\n",
                r16, hr16[0], hr16[1], rhr, hr0[0], hr0[1]);
        g_fail = 1;
    }

    uint8_t beef[2] = {0xBE, 0xEF};
    point_value_t wv = {.data = beef, .len = 2};
    int wrc = a->write_point(a, "hr_040001", &wv);
    rhr = read_bytes(a, "hr_pdu0", hr0, 2);
    if (wrc != 0 || rhr != 0 || hr0[0] != 0xBE || hr0[1] != 0xEF) {
        fprintf(stderr,
                "FAIL: holding \"040001\" PDU (decimal 40001 → 0, not octal "
                "16385): write rc=%d, pdu0 rc=%d val=%02x%02x\n",
                wrc, rhr, hr0[0], hr0[1]);
        g_fail = 1;
    }

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
    test_leading_zero_address_is_decimal();
    if (g_fail) {
        fprintf(stderr, "test_mb_adapter: FAILED\n");
        return 1;
    }
    printf("test_mb_adapter: OK\n");
    return 0;
}
