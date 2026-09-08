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

static void test_read_holding(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.port = 1502;
    cfg.unit_id = 1;
    cfg.n_holding = 64;
    cfg.n_input = 64;
    cfg.n_coil = 64;
    cfg.n_discrete = 64;

    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "create stack");

    uint16_t vals[2] = {0x1234, 0xABCD};
    expect(mb_stack_write_regs(s, MB_REG_HOLDING, 0, vals, 2) == 0,
           "seed holding");

    uint8_t req[12];
    wr_be16(req, 0x0001);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 0);
    wr_be16(req + 10, 2);

    uint8_t resp[64];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "handle read holding");
    expect(resp_len == 13, "read holding resp len");
    expect(resp[7] == MB_FC_READ_HOLDING, "fc echo");
    expect(resp[8] == 4, "byte count");
    expect(rd_be16(resp + 9) == 0x1234, "reg0");
    expect(rd_be16(resp + 11) == 0xABCD, "reg1");

    mb_stack_destroy(s);
}

static void test_write_single_coil(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 16;
    cfg.n_input = 16;
    cfg.n_coil = 16;
    cfg.n_discrete = 16;

    mb_stack_t *s = mb_stack_create(&cfg);
    expect(s != NULL, "create stack coil");

    uint8_t req[12];
    wr_be16(req, 0x0002);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_WRITE_SINGLE_COIL;
    wr_be16(req + 8, 0); /* coil 0 */
    wr_be16(req + 10, 0xFF00);

    uint8_t resp[32];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "handle write coil");
    expect(resp_len == 12, "write coil resp len");

    uint8_t bit = 0;
    expect(mb_stack_read_bits(s, MB_REG_COIL, 0, &bit, 1) == 0, "read coil");
    expect(bit == 1, "coil set");

    mb_stack_destroy(s);
}

static void test_string_bytes(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 32;
    cfg.n_input = 8;
    cfg.n_coil = 8;
    cfg.n_discrete = 8;

    mb_stack_t *s = mb_stack_create(&cfg);
    const char *barcode = "ABC123";
    expect(mb_stack_write_bytes(s, MB_REG_HOLDING, 0, (const uint8_t *)barcode,
                                6) == 0,
           "write barcode bytes");

    uint8_t out[8];
    memset(out, 0, sizeof(out));
    expect(mb_stack_read_bytes(s, MB_REG_HOLDING, 0, out, 6) == 0,
           "read barcode bytes");
    expect(memcmp(out, barcode, 6) == 0, "barcode match");

    /* Holding map packs 2 chars per register, big-endian. */
    uint16_t r0 = 0, r1 = 0, r2 = 0;
    mb_stack_read_regs(s, MB_REG_HOLDING, 0, &r0, 1);
    mb_stack_read_regs(s, MB_REG_HOLDING, 1, &r1, 1);
    mb_stack_read_regs(s, MB_REG_HOLDING, 2, &r2, 1);
    expect(r0 == 0x4142, "AB");
    expect(r1 == 0x4331, "C1");
    expect(r2 == 0x3233, "23");

    mb_stack_destroy(s);
}

static void test_exception_illegal_address(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = 10;
    cfg.n_input = 10;
    cfg.n_coil = 10;
    cfg.n_discrete = 10;

    mb_stack_t *s = mb_stack_create(&cfg);
    uint8_t req[12];
    wr_be16(req, 1);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, 6);
    req[6] = 1;
    req[7] = MB_FC_READ_HOLDING;
    wr_be16(req + 8, 9);
    wr_be16(req + 10, 2); /* overflows map */

    uint8_t resp[32];
    size_t resp_len = 0;
    expect(mb_stack_handle_adu(s, req, sizeof(req), resp, sizeof(resp),
                               &resp_len) == 0,
           "handle OOB");
    expect(resp_len == 9, "exception len");
    expect(resp[7] == (MB_FC_READ_HOLDING | 0x80), "exception fc");
    expect(resp[8] == MB_EX_ILLEGAL_ADDRESS, "exception code");

    mb_stack_destroy(s);
}

int main(void)
{
    test_read_holding();
    test_write_single_coil();
    test_string_bytes();
    test_exception_illegal_address();
    if (g_fail) {
        fprintf(stderr, "test_mb_stack: FAILED\n");
        return 1;
    }
    printf("test_mb_stack: OK\n");
    return 0;
}
