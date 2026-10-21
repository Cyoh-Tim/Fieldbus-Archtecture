/*
 * T9-6: a server with the default unit filter must answer Unit ID 0xFF.
 *
 * The Modbus Messaging on TCP/IP Implementation Guide recommends 0xFF for a
 * device attached directly to TCP. Before the fix, unit_id=1 and
 * unit_id_any=0 ignore 0xFF (no response) while still answering unit 0 and
 * the configured id. A different id (9) stays ignored.
 *
 * The response echoes the request Unit ID and returns the seeded register
 * (holding[0] = 0xA000), matching the oracle PDU.
 */
#include "mb_stack.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static mb_stack_t *make_server(int unit_id, int unit_id_any)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = unit_id;
    cfg.unit_id_any = unit_id_any;
    cfg.n_holding = 16;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;

    mb_stack_t *s = mb_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    uint16_t hv = 0xA000;
    if (mb_stack_write_regs(s, MB_REG_HOLDING, 0, &hv, 1) != 0) {
        mb_stack_destroy(s);
        return NULL;
    }
    return s;
}

/* FC03 read holding address 0 quantity 1. */
static void fill_fc03(uint8_t req[12], uint8_t unit)
{
    wr_be16(req, 0x001C);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = unit;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 0);
    wr_be16(req + 10, 1);
}

static void expect_answered(mb_stack_t *s, uint8_t unit, const char *what)
{
    uint8_t req[12];
    uint8_t resp[32];
    size_t resp_len = 99;
    char msg[96];

    fill_fc03(req, unit);
    memset(resp, 0x5A, sizeof(resp));
    int rc = mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                                 &resp_len);
    snprintf(msg, sizeof(msg), "%s rc", what);
    expect(rc == 0, msg);
    snprintf(msg, sizeof(msg), "%s len (got %zu)", what, resp_len);
    expect(resp_len == 11, msg);
    if (resp_len < 11) {
        return;
    }
    snprintf(msg, sizeof(msg), "%s tid", what);
    expect(rd_be16(resp) == 0x001C, msg);
    snprintf(msg, sizeof(msg), "%s unit echo (got 0x%02x)", what, resp[6]);
    expect(resp[6] == unit, msg);
    snprintf(msg, sizeof(msg), "%s fc", what);
    expect(resp[7] == MB_FC_READ_HOLDING, msg);
    snprintf(msg, sizeof(msg), "%s byte count", what);
    expect(resp[8] == 2, msg);
    snprintf(msg, sizeof(msg), "%s value (got 0x%04x)", what, rd_be16(resp + 9));
    expect(rd_be16(resp + 9) == 0xA000, msg);
}

static void expect_ignored(mb_stack_t *s, uint8_t unit, const char *what)
{
    uint8_t req[12];
    uint8_t resp[32];
    size_t resp_len = 99;
    char msg[96];

    fill_fc03(req, unit);
    int rc = mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                                 &resp_len);
    snprintf(msg, sizeof(msg), "%s rc", what);
    expect(rc == 0, msg);
    snprintf(msg, sizeof(msg), "%s ignored (len %zu)", what, resp_len);
    expect(resp_len == 0, msg);
}

static void test_default_accepts_unit_ff(void)
{
    mb_stack_t *s = make_server(1, 0);
    expect(s != NULL, "create default server");
    if (!s) {
        return;
    }
    expect_answered(s, 0xFF, "default unit 0xFF");
    expect_answered(s, 1, "default unit 1");
    expect_answered(s, 0, "default unit 0");
    expect_ignored(s, 9, "default unit 9");
    mb_stack_destroy(s);
}

int main(void)
{
    test_default_accepts_unit_ff();
    if (g_fail) {
        fprintf(stderr, "test_mb_t9_6: FAILED\n");
        return 1;
    }
    printf("test_mb_t9_6: OK\n");
    return 0;
}
