/*
 * T9-4: FC01–04 quantity violations (0 or over the protocol limit) must be
 * exception 03 (ILLEGAL DATA VALUE). Address violations stay exception 02.
 * Quantity is checked before address, so a request that breaks both is 03.
 * FC15/16/23 already split those checks; this file keeps that contract.
 */
#include "mb_stack.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static int transact(mb_stack_t *s, const uint8_t *pdu, size_t pdu_len,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    uint8_t req[520];
    if (pdu_len < 1 || 7u + pdu_len > sizeof(req)) {
        return -1;
    }
    wr_be16(req, 1);
    wr_be16(req + 2, 0);
    wr_be16(req + 4, (uint16_t)(1u + pdu_len));
    req[6] = 1;
    memcpy(req + 7, pdu, pdu_len);
    return mb_stack_handle_adu(s, req, 7u + pdu_len, resp, resp_cap, resp_len);
}

/* want_ex == 0: normal response. Otherwise exception PDU with that code. */
static void expect_pdu(mb_stack_t *s, const char *what, const uint8_t *pdu,
                       size_t pdu_len, uint8_t fc, uint8_t want_ex)
{
    uint8_t resp[520];
    size_t resp_len = 0;
    int rc = transact(s, pdu, pdu_len, resp, sizeof(resp), &resp_len);
    if (rc != 0 || resp_len < 9) {
        fprintf(stderr, "FAIL: %s: rc=%d resp_len=%zu\n", what, rc, resp_len);
        g_fail = 1;
        return;
    }
    if (want_ex == 0) {
        if (resp[7] != fc || (resp[7] & 0x80) != 0) {
            fprintf(stderr, "FAIL: %s: expected normal fc 0x%02x, got 0x%02x code 0x%02x\n",
                    what, fc, resp[7], resp[8]);
            g_fail = 1;
        }
        return;
    }
    if (resp[7] != (uint8_t)(fc | 0x80) || resp[8] != want_ex || resp_len != 9) {
        fprintf(stderr,
                "FAIL: %s: expected ex fc 0x%02x code 0x%02x len 9, got fc 0x%02x code 0x%02x len %zu\n",
                what, (unsigned)(fc | 0x80), want_ex, resp[7], resp[8], resp_len);
        g_fail = 1;
    }
}

static void read_pdu(uint8_t pdu[5], uint8_t fc, uint16_t addr, uint16_t qty)
{
    pdu[0] = fc;
    wr_be16(pdu + 1, addr);
    wr_be16(pdu + 3, qty);
}

static void expect_read(mb_stack_t *s, const char *what, uint8_t fc,
                        uint16_t addr, uint16_t qty, uint8_t want_ex)
{
    uint8_t pdu[5];
    read_pdu(pdu, fc, addr, qty);
    expect_pdu(s, what, pdu, sizeof(pdu), fc, want_ex);
}

/* FC15/16: fc addr qty bc data[bc]. data bytes are zero. */
static void expect_write_multi(mb_stack_t *s, const char *what, uint8_t fc,
                               uint16_t addr, uint16_t qty, uint8_t nbytes,
                               uint8_t want_ex)
{
    uint8_t pdu[520];
    if (6u + nbytes > sizeof(pdu)) {
        fprintf(stderr, "FAIL: %s: pdu too big\n", what);
        g_fail = 1;
        return;
    }
    pdu[0] = fc;
    wr_be16(pdu + 1, addr);
    wr_be16(pdu + 3, qty);
    pdu[5] = nbytes;
    memset(pdu + 6, 0, nbytes);
    expect_pdu(s, what, pdu, 6u + nbytes, fc, want_ex);
}

/* FC23: raddr rqty waddr wqty bc data[bc]. */
static void expect_fc23(mb_stack_t *s, const char *what, uint16_t raddr,
                        uint16_t rqty, uint16_t waddr, uint16_t wqty,
                        uint8_t nbytes, uint8_t want_ex)
{
    uint8_t pdu[520];
    if (10u + nbytes > sizeof(pdu)) {
        fprintf(stderr, "FAIL: %s: pdu too big\n", what);
        g_fail = 1;
        return;
    }
    pdu[0] = MB_FC_READ_WRITE_REGS;
    wr_be16(pdu + 1, raddr);
    wr_be16(pdu + 3, rqty);
    wr_be16(pdu + 5, waddr);
    wr_be16(pdu + 7, wqty);
    pdu[9] = nbytes;
    memset(pdu + 10, 0, nbytes);
    expect_pdu(s, what, pdu, 10u + nbytes, MB_FC_READ_WRITE_REGS, want_ex);
}

static mb_stack_t *make_server(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    /* Larger than each FC's quantity cap so an over-limit qty is not also
     * an address miss. Address cases use an explicit end past the map. */
    cfg.n_holding = 200;
    cfg.n_input = 200;
    cfg.n_coil = 4000;
    cfg.n_discrete = 4000;
    return mb_stack_create(&cfg);
}

static void test_fc01_04_quantity_vs_address(void)
{
    mb_stack_t *s = make_server();
    if (!s) {
        fprintf(stderr, "FAIL: create stack\n");
        g_fail = 1;
        return;
    }

    /* FC01 coils: 1..2000. */
    expect_read(s, "FC01 qty 0", MB_FC_READ_COILS, 0, 0, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC01 qty 2001", MB_FC_READ_COILS, 0, 2001, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC01 qty 0 and addr OOB", MB_FC_READ_COILS, 0xFFFF, 0,
                MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC01 addr OOB", MB_FC_READ_COILS, 3999, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_read(s, "FC01 addr wrap", MB_FC_READ_COILS, 0xFFFF, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_read(s, "FC01 qty 1", MB_FC_READ_COILS, 0, 1, 0);
    expect_read(s, "FC01 qty 2000", MB_FC_READ_COILS, 0, 2000, 0);

    /* FC02 discrete inputs: same limits, other map. */
    expect_read(s, "FC02 qty 0", MB_FC_READ_DISCRETE, 0, 0, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC02 qty 2001", MB_FC_READ_DISCRETE, 0, 2001, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC02 addr OOB", MB_FC_READ_DISCRETE, 3999, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_read(s, "FC02 qty 1", MB_FC_READ_DISCRETE, 0, 1, 0);

    /* FC03 holding: 1..125. */
    expect_read(s, "FC03 qty 0", MB_FC_READ_HOLDING, 0, 0, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC03 qty 126", MB_FC_READ_HOLDING, 0, 126, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC03 qty 126 and addr OOB", MB_FC_READ_HOLDING, 0xFFFF, 126,
                MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC03 addr OOB", MB_FC_READ_HOLDING, 199, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_read(s, "FC03 addr wrap", MB_FC_READ_HOLDING, 0xFFFF, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_read(s, "FC03 qty 1", MB_FC_READ_HOLDING, 0, 1, 0);
    expect_read(s, "FC03 qty 125", MB_FC_READ_HOLDING, 0, 125, 0);

    /* FC04 input registers. */
    expect_read(s, "FC04 qty 0", MB_FC_READ_INPUT, 0, 0, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC04 qty 126", MB_FC_READ_INPUT, 0, 126, MB_EX_ILLEGAL_VALUE);
    expect_read(s, "FC04 addr OOB", MB_FC_READ_INPUT, 199, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_read(s, "FC04 qty 125", MB_FC_READ_INPUT, 0, 125, 0);

    mb_stack_destroy(s);
}

static void test_fc15_16_23_quantity(void)
{
    mb_stack_t *s = make_server();
    if (!s) {
        fprintf(stderr, "FAIL: create stack fc15\n");
        g_fail = 1;
        return;
    }

    /* FC15: quantity 1..1968, byte count = ceil(qty/8), then address. */
    expect_write_multi(s, "FC15 qty 0", MB_FC_WRITE_MULTI_COILS, 0, 0, 0,
                       MB_EX_ILLEGAL_VALUE);
    expect_write_multi(s, "FC15 qty 1969", MB_FC_WRITE_MULTI_COILS, 0, 1969,
                       (uint8_t)((1969 + 7) / 8), MB_EX_ILLEGAL_VALUE);
    expect_write_multi(s, "FC15 bad byte count", MB_FC_WRITE_MULTI_COILS, 0, 8, 2,
                       MB_EX_ILLEGAL_VALUE);
    expect_write_multi(s, "FC15 addr OOB", MB_FC_WRITE_MULTI_COILS, 3999, 2, 1,
                       MB_EX_ILLEGAL_ADDRESS);
    expect_write_multi(s, "FC15 qty 1968", MB_FC_WRITE_MULTI_COILS, 0, 1968,
                       (uint8_t)((1968 + 7) / 8), 0);

    /* FC16: quantity 1..123, byte count = 2*qty, then address. */
    expect_write_multi(s, "FC16 qty 0", MB_FC_WRITE_MULTI_REGS, 0, 0, 0,
                       MB_EX_ILLEGAL_VALUE);
    expect_write_multi(s, "FC16 qty 124", MB_FC_WRITE_MULTI_REGS, 0, 124,
                       (uint8_t)(124 * 2), MB_EX_ILLEGAL_VALUE);
    expect_write_multi(s, "FC16 bad byte count", MB_FC_WRITE_MULTI_REGS, 0, 1, 1,
                       MB_EX_ILLEGAL_VALUE);
    expect_write_multi(s, "FC16 addr OOB", MB_FC_WRITE_MULTI_REGS, 199, 2, 4,
                       MB_EX_ILLEGAL_ADDRESS);
    expect_write_multi(s, "FC16 qty 123", MB_FC_WRITE_MULTI_REGS, 0, 123,
                       (uint8_t)(123 * 2), 0);

    /* FC23: read 1..125, write 1..121, byte count = 2*wqty, then addresses. */
    expect_fc23(s, "FC23 rqty 0", 0, 0, 0, 1, 2, MB_EX_ILLEGAL_VALUE);
    expect_fc23(s, "FC23 rqty 126", 0, 126, 0, 1, 2, MB_EX_ILLEGAL_VALUE);
    expect_fc23(s, "FC23 wqty 0", 0, 1, 0, 0, 0, MB_EX_ILLEGAL_VALUE);
    expect_fc23(s, "FC23 wqty 122", 0, 1, 0, 122, (uint8_t)(122 * 2),
                MB_EX_ILLEGAL_VALUE);
    expect_fc23(s, "FC23 bad byte count", 0, 1, 0, 1, 1, MB_EX_ILLEGAL_VALUE);
    expect_fc23(s, "FC23 read addr OOB", 199, 2, 0, 1, 2, MB_EX_ILLEGAL_ADDRESS);
    expect_fc23(s, "FC23 write addr OOB", 0, 1, 199, 2, 4, MB_EX_ILLEGAL_ADDRESS);
    expect_fc23(s, "FC23 rqty 125 wqty 121", 0, 125, 0, 121, (uint8_t)(121 * 2), 0);

    mb_stack_destroy(s);
}

int main(void)
{
    test_fc01_04_quantity_vs_address();
    test_fc15_16_23_quantity();
    if (g_fail) {
        fprintf(stderr, "test_mb_t9_4: FAILED\n");
        return 1;
    }
    printf("test_mb_t9_4: OK\n");
    return 0;
}
