/*
 * SLMP Binary 3E request fuzzer.
 *
 * The original harness dumped raw bytes into slmp_stack_handle_request().
 * Valid 3E headers (0x0050 + cmd 0x0401/0x1401 + known device code) are rare,
 * so the 1h campaign plateaued around cov=268 / ft=545. handle_request only
 * implements batch read/write (word + bit). Random 0x0403/0x1402 and monitor
 * registration are parsed then rejected with SLMP_END_CMD — still worth
 * wrapping so that path stays covered.
 *
 * ASCII / 4E are not created (stack_create refuses them).
 */
#include "slmp_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static slmp_stack_t *g_stack;

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static uint8_t u8_at(const uint8_t *p, size_t plen, size_t i, uint8_t def)
{
    return i < plen ? p[i] : def;
}

static uint16_t u16_at(const uint8_t *p, size_t plen, size_t i, uint16_t def)
{
    if (i + 1 < plen) {
        return (uint16_t)(p[i] | ((uint16_t)p[i + 1] << 8));
    }
    return i < plen ? p[i] : def;
}

static const uint8_t k_word_dev[] = {
    SLMP_DEV_D, SLMP_DEV_W, SLMP_DEV_R,  SLMP_DEV_ZR, SLMP_DEV_SD,
    SLMP_DEV_TN, SLMP_DEV_SW, SLMP_DEV_Z, SLMP_DEV_SN, SLMP_DEV_CN};
static const uint8_t k_bit_dev[] = {
    SLMP_DEV_M, SLMP_DEV_X, SLMP_DEV_Y, SLMP_DEV_B, SLMP_DEV_L,
    SLMP_DEV_F, SLMP_DEV_SM, SLMP_DEV_SB, SLMP_DEV_S, SLMP_DEV_V};

static void feed_one(const uint8_t *req, size_t n)
{
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    (void)slmp_stack_handle_request(g_stack, req, n, resp, sizeof(resp),
                                    &resp_len);
}

static size_t build_3e(uint8_t *out, size_t cap, uint16_t cmd, uint16_t sub,
                       uint32_t head, uint8_t code, uint16_t qty,
                       const uint8_t *data, size_t dlen)
{
    uint16_t data_len = (uint16_t)(2u + 2u + 2u + 3u + 1u + 2u + dlen);
    size_t n = 9u + data_len;
    if (n > cap || n < 21u) {
        return 0;
    }
    wr_le16(out, SLMP_SUBHEADER_REQ_3E);
    out[2] = 0;
    out[3] = SLMP_PC_OWN_STATION;
    wr_le16(out + 4, SLMP_DEST_MODULE_CPU);
    out[6] = 0;
    wr_le16(out + 7, data_len);
    wr_le16(out + 9, 0x0010);
    wr_le16(out + 11, cmd);
    wr_le16(out + 13, sub);
    out[15] = (uint8_t)head;
    out[16] = (uint8_t)(head >> 8);
    out[17] = (uint8_t)(head >> 16);
    out[18] = code;
    wr_le16(out + 19, qty);
    if (dlen) {
        memcpy(out + 21, data, dlen);
    }
    return n;
}

static void feed_3e(uint16_t cmd, uint16_t sub, uint32_t head, uint8_t code,
                    uint16_t qty, const uint8_t *data, size_t dlen)
{
    uint8_t buf[SLMP_FRAME_MAX];
    size_t n = build_3e(buf, sizeof(buf), cmd, sub, head, code, qty, data, dlen);
    if (n) {
        feed_one(buf, n);
    }
}

static uint8_t pick_word_dev(const uint8_t *p, size_t plen)
{
    return k_word_dev[u8_at(p, plen, 0, 0) % (uint8_t)sizeof(k_word_dev)];
}

static uint8_t pick_bit_dev(const uint8_t *p, size_t plen)
{
    return k_bit_dev[u8_at(p, plen, 0, 0) % (uint8_t)sizeof(k_bit_dev)];
}

static int fuzz_init(void)
{
    slmp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLMP_ROLE_SERVER;
    cfg.frame = SLMP_FRAME_3E_BINARY;
    cfg.pc_no = 0xFF;
    cfg.dest_module_io = 0x03FF;
    cfg.map_words = 1024;
    cfg.map_bits = 4096;
    g_stack = slmp_stack_create(&cfg);
    if (!g_stack) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(k_word_dev); i++) {
        (void)slmp_stack_map_ensure(g_stack, k_word_dev[i], 0);
    }
    for (size_t i = 0; i < sizeof(k_bit_dev); i++) {
        (void)slmp_stack_map_ensure(g_stack, k_bit_dev[i], 1);
    }
    /* Remaining built-in codes (timers/counters) so device_known + map hit. */
    (void)slmp_stack_map_ensure(g_stack, SLMP_DEV_TS, 1);
    (void)slmp_stack_map_ensure(g_stack, SLMP_DEV_TC, 1);
    (void)slmp_stack_map_ensure(g_stack, SLMP_DEV_CS, 1);
    (void)slmp_stack_map_ensure(g_stack, SLMP_DEV_CC, 1);
    (void)slmp_stack_map_ensure(g_stack, SLMP_DEV_DX, 1);
    (void)slmp_stack_map_ensure(g_stack, SLMP_DEV_DY, 1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_stack && fuzz_init() != 0) {
        return 0;
    }
    if (size == 0) {
        return 0;
    }

    uint8_t mode = (uint8_t)(data[0] & 7u);
    const uint8_t *p = data + 1;
    size_t plen = size - 1;
    uint32_t head = (uint32_t)(u16_at(p, plen, 1, 0) % 256u);
    uint16_t qty = (uint16_t)(1u + (u16_at(p, plen, 3, 2) % 16u));

    switch (mode) {
    case 0: /* raw (legacy corpus, short, wrong subheader) */
        feed_one(p, plen);
        break;
    case 1: /* batch word read, all known word devices */
        feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, head, pick_word_dev(p, plen),
                qty, NULL, 0);
        break;
    case 2: { /* batch word write */
        uint8_t payload[64];
        size_t need = (size_t)qty * 2u;
        if (need > sizeof(payload)) {
            need = sizeof(payload);
            qty = (uint16_t)(need / 2u);
        }
        memset(payload, 0x5A, need);
        if (plen) {
            memcpy(payload, p, plen < need ? plen : need);
        }
        feed_3e(SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD, head, pick_word_dev(p, plen),
                qty, payload, need);
        break;
    }
    case 3: { /* batch bit read / write */
        uint8_t code = pick_bit_dev(p, plen);
        uint16_t bqty = (uint16_t)(1u + (u8_at(p, plen, 2, 8) % 32u));
        if (u8_at(p, plen, 1, 0) & 1) {
            /* Wire data is nibble-packed: ceil(points / 2) bytes. */
            size_t wire = ((size_t)bqty + 1u) / 2u;
            uint8_t bits[16];
            memset(bits, 0xA5, sizeof(bits));
            if (plen > 2) {
                size_t copy = plen - 2;
                if (copy > wire) {
                    copy = wire;
                }
                memcpy(bits, p + 2, copy);
            }
            feed_3e(SLMP_CMD_BATCH_WRITE, SLMP_SUB_BIT, head, code, bqty, bits,
                    wire);
        } else {
            feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_BIT, head, code, bqty, NULL,
                    0);
        }
        break;
    }
    case 4: { /* unimplemented commands → SLMP_END_CMD */
        uint16_t cmd = SLMP_CMD_RANDOM_READ;
        uint8_t k = u8_at(p, plen, 0, 0) & 3u;
        if (k == 1) {
            cmd = SLMP_CMD_RANDOM_WRITE;
        } else if (k == 2) {
            cmd = 0x0801; /* monitor register (not implemented) */
        } else if (k == 3) {
            cmd = 0x0402; /* array? reserved */
        }
        feed_3e(cmd, SLMP_SUB_WORD, head, pick_word_dev(p, plen), qty, NULL, 0);
        break;
    }
    case 5: { /* unknown device / bad subcommand */
        if (u8_at(p, plen, 0, 0) & 1) {
            feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, head, 0x00, qty, NULL,
                    0);
        } else {
            feed_3e(SLMP_CMD_BATCH_READ, 0x0002, head, SLMP_DEV_D, qty, NULL, 0);
        }
        break;
    }
    case 6: { /* qty overflow / truncated write */
        uint8_t k = u8_at(p, plen, 0, 0) & 3u;
        if (k == 0) {
            feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, head, SLMP_DEV_D, 0,
                    NULL, 0);
        } else if (k == 1) {
            feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, head, SLMP_DEV_D, 961,
                    NULL, 0);
        } else if (k == 2) {
            feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_BIT, head, SLMP_DEV_M, 7169,
                    NULL, 0);
        } else {
            uint8_t one = 0x12;
            feed_3e(SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD, head, SLMP_DEV_D, 4,
                    &one, 1); /* short data → -EBADMSG */
        }
        break;
    }
    default: { /* write then read (stateful) + word access on bit device */
        uint8_t payload[8] = {0x34, 0x12, 0xCD, 0xAB, 0x01, 0x00, 0x02, 0x00};
        uint8_t code = pick_word_dev(p, plen);
        feed_3e(SLMP_CMD_BATCH_WRITE, SLMP_SUB_WORD, head, code, 4, payload, 8);
        feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, head, code, 4, NULL, 0);
        feed_3e(SLMP_CMD_BATCH_READ, SLMP_SUB_WORD, head, pick_bit_dev(p, plen),
                1, NULL, 0);
        /* concatenated leftover as raw (parser / short) */
        if (plen) {
            feed_one(p, plen);
        }
        break;
    }
    }
    return 0;
}
