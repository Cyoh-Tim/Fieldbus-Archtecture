#include "slmp_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * T10-3: hex device numbers that start with A-F ("XA", device_code X +
 * start "A") must parse as hex. A bad number must fail init (LOG_ERROR),
 * not drop the point and return success.
 *
 * X/Y/B/W/SB/SW/DX/DY are the hex devices. A letter-leading form must
 * alias the same head as the 0-padded form (XA == X0A == 10).
 */

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static const char *PARAMS =
    "{\"role\":\"server\",\"ip\":\"127.0.0.1\",\"port\":0}";

static protocol_adapter_t *open_adapter(const char *points, int *rc_out)
{
    protocol_adapter_t *a = slmp_adapter_create();
    expect(a != NULL, "slmp_adapter_create");
    if (!a) {
        return NULL;
    }
    int rc = a->init(a, PARAMS, points);
    if (rc_out) {
        *rc_out = rc;
    }
    return a;
}

static void write_u8(protocol_adapter_t *a, const char *name, uint8_t v,
                     const char *msg)
{
    point_value_t pv = {.data = &v, .len = 1};
    int rc = a->write_point(a, name, &pv);
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s write rc=%d\n", msg, rc);
        g_fail = 1;
    }
}

static void expect_u8(protocol_adapter_t *a, const char *name, uint8_t want,
                      const char *msg)
{
    point_value_t pv = {0};
    int rc = a->read_point(a, name, &pv);
    if (rc != 0 || !pv.data || pv.len < 1 || pv.data[0] != want) {
        fprintf(stderr, "FAIL: %s (rc=%d len=%zu val=%u want=%u)\n", msg, rc,
                pv.data ? pv.len : 0, (pv.data && pv.len) ? pv.data[0] : 0,
                want);
        g_fail = 1;
    }
    free(pv.data);
}

static void write_u16(protocol_adapter_t *a, const char *name, uint16_t v,
                      const char *msg)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    point_value_t pv = {.data = b, .len = 2};
    int rc = a->write_point(a, name, &pv);
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s write rc=%d\n", msg, rc);
        g_fail = 1;
    }
}

static void expect_u16(protocol_adapter_t *a, const char *name, uint16_t want,
                       const char *msg)
{
    point_value_t pv = {0};
    int rc = a->read_point(a, name, &pv);
    uint16_t got = 0;
    if (pv.data && pv.len >= 2) {
        got = (uint16_t)(((uint16_t)pv.data[0] << 8) | pv.data[1]);
    }
    if (rc != 0 || !pv.data || pv.len < 2 || got != want) {
        fprintf(stderr, "FAIL: %s (rc=%d len=%zu got=0x%04x want=0x%04x)\n",
                msg, rc, pv.data ? pv.len : 0, got, want);
        g_fail = 1;
    }
    free(pv.data);
}

/* Letter-leading hex numbers share the head with the 0-padded form. */
static void test_hex_letter_aliases(void)
{
    const char *points =
        "["
        "{\"name\":\"x0a\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"X0A\",\"unit\":\"bit\"}}},"
        "{\"name\":\"xa\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"XA\",\"unit\":\"bit\"}}},"
        "{\"name\":\"xa_low\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"xa\",\"unit\":\"bit\"}}},"
        "{\"name\":\"x_a\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"X\",\"start\":\"A\","
        "\"unit\":\"bit\"}}},"
        "{\"name\":\"x_num\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"X\",\"start\":10,"
        "\"unit\":\"bit\"}}},"
        "{\"name\":\"x0\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"X0\",\"unit\":\"bit\"}}},"
        "{\"name\":\"x1a\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"X\",\"start\":\"1A\","
        "\"unit\":\"bit\"}}},"
        "{\"name\":\"x_26\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"X\",\"start\":26,"
        "\"unit\":\"bit\"}}},"

        "{\"name\":\"y0a\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"Y0A\",\"unit\":\"bit\"}}},"
        "{\"name\":\"ya\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"YA\",\"unit\":\"bit\"}}},"

        "{\"name\":\"b_a0\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"B\",\"start\":\"A0\","
        "\"unit\":\"bit\"}}},"
        "{\"name\":\"ba0\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"BA0\",\"unit\":\"bit\"}}},"

        "{\"name\":\"sb0a\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"SB0A\",\"unit\":\"bit\"}}},"
        "{\"name\":\"sba\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"SBA\",\"unit\":\"bit\"}}},"

        "{\"name\":\"dx0a\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"DX0A\",\"unit\":\"bit\"}}},"
        "{\"name\":\"dxa\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"DXA\",\"unit\":\"bit\"}}},"

        "{\"name\":\"dy0f\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"DY\",\"start\":\"0F\","
        "\"unit\":\"bit\"}}},"
        "{\"name\":\"dy_f\",\"access\":\"readwrite\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"DY\",\"start\":\"F\","
        "\"unit\":\"bit\"}}},"

        "{\"name\":\"w0a\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"W0A\"}}},"
        "{\"name\":\"wa\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"WA\"}}},"
        "{\"name\":\"w_a\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"W\",\"start\":\"A\"}}},"

        "{\"name\":\"sw0a\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"SW0A\"}}},"
        "{\"name\":\"swa\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"SWA\"}}},"
        "{\"name\":\"swff\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"SWFF\"}}},"
        "{\"name\":\"sw_ff\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"SW\",\"start\":\"FF\"}}},"
        "{\"name\":\"sw_255\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"device_code\":\"SW\",\"start\":255}}},"

        "{\"name\":\"d100\",\"access\":\"readwrite\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"D100\"}}}"
        "]";

    int rc = 0;
    protocol_adapter_t *a = open_adapter(points, &rc);
    expect(a && rc == 0, "init letter-leading hex points");
    if (!a || rc != 0) {
        if (a) {
            a->destroy(a);
        }
        return;
    }

    write_u8(a, "xa", 1, "write XA");
    expect_u8(a, "x0a", 1, "XA aliases X0A");
    expect_u8(a, "xa_low", 1, "xa aliases X0A");
    expect_u8(a, "x_a", 1, "device X start A aliases X0A");
    expect_u8(a, "x_num", 1, "XA aliases numeric 10");
    expect_u8(a, "x0", 0, "X0 stays clear");

    write_u8(a, "x1a", 1, "write X1A");
    expect_u8(a, "x_26", 1, "X1A aliases numeric 26");

    write_u8(a, "ya", 1, "write YA");
    expect_u8(a, "y0a", 1, "YA aliases Y0A");

    write_u8(a, "ba0", 1, "write BA0");
    expect_u8(a, "b_a0", 1, "BA0 aliases B A0");

    write_u8(a, "sba", 1, "write SBA");
    expect_u8(a, "sb0a", 1, "SBA aliases SB0A");

    write_u8(a, "dxa", 1, "write DXA");
    expect_u8(a, "dx0a", 1, "DXA aliases DX0A");

    write_u8(a, "dy_f", 1, "write DY F");
    expect_u8(a, "dy0f", 1, "DY F aliases DY 0F");

    write_u16(a, "wa", 0x1234, "write WA");
    expect_u16(a, "w0a", 0x1234, "WA aliases W0A");
    expect_u16(a, "w_a", 0x1234, "device W start A aliases W0A");

    write_u16(a, "swa", 0x00AB, "write SWA");
    expect_u16(a, "sw0a", 0x00AB, "SWA aliases SW0A");

    write_u16(a, "swff", 0x00FF, "write SWFF");
    expect_u16(a, "sw_ff", 0x00FF, "SWFF aliases SW FF");
    expect_u16(a, "sw_255", 0x00FF, "SWFF aliases numeric 255");

    write_u16(a, "d100", 0x0042, "write D100");
    expect_u16(a, "d100", 0x0042, "decimal D100 still parses");

    a->destroy(a);
}

/* A number that is not valid for the device fails init instead of
 * dropping the point. */
static void test_bad_number_fails_init(void)
{
    const char *cases[] = {
        "[{\"name\":\"p\",\"access\":\"read\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"XG\",\"unit\":\"bit\"}}}]",
        "[{\"name\":\"p\",\"access\":\"read\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"device_code\":\"X\",\"start\":\"G\","
        "\"unit\":\"bit\"}}}]",
        "[{\"name\":\"p\",\"access\":\"read\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"D1A\"}}}]",
        "[{\"name\":\"p\",\"access\":\"read\",\"data_type\":\"uint16\","
        "\"address\":{\"slmp\":{\"start\":\"Q10\"}}}]",
        "[{\"name\":\"p\",\"access\":\"read\",\"data_type\":\"bool\","
        "\"address\":{\"slmp\":{\"start\":\"X1AG\",\"unit\":\"bit\"}}}]",
    };
    const char *names[] = {"XG", "X start G", "D1A", "Q10", "X1AG"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = 0;
        protocol_adapter_t *a = open_adapter(cases[i], &rc);
        if (!a) {
            continue;
        }
        if (rc == 0) {
            fprintf(stderr, "FAIL: init succeeded for bad address %s\n",
                    names[i]);
            g_fail = 1;
        }
        a->destroy(a);
    }
}

int main(void)
{
    test_hex_letter_aliases();
    test_bad_number_fails_init();
    if (g_fail) {
        fprintf(stderr, "test_slmp_t10_3: FAILED\n");
        return 1;
    }
    printf("test_slmp_t10_3: OK\n");
    return 0;
}
