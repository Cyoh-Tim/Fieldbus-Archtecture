/*
 * Modbus TCP ADU fuzzer.
 *
 * The original harness fed raw bytes into mb_stack_handle_adu() on a 64-register
 * map. libFuzzer rarely emitted valid MBAP + FC 0x16/0x17 / multi-coil PDU
 * layouts, so the 1h campaign plateaued around cov=186 / ft=399. handle_adu
 * also consumes a single ADU (TCP reassembly lives in poll() and needs sockets).
 *
 * Byte 0 selects a mode; remaining bytes are payload. Implemented FCs only
 * (01–06, 0F, 10, 16, 17). Diagnostics 0x08 and MEI 0x2B are wrapped as
 * illegal-function seeds — the stack has no handlers for them.
 */
#include "mb_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUZZ_NREG 128
#define FUZZ_NBIT 256

static mb_stack_t *g_stack;

static void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static size_t wrap_mbap(uint8_t *out, size_t cap, uint16_t tid, uint16_t proto,
                        uint8_t unit, const uint8_t *pdu, size_t plen)
{
    if (plen < 1 || 7u + plen > cap) {
        return 0;
    }
    wr_be16(out, tid);
    wr_be16(out + 2, proto);
    wr_be16(out + 4, (uint16_t)(1u + plen));
    out[6] = unit;
    memcpy(out + 7, pdu, plen);
    return 7u + plen;
}

static void feed_one(const uint8_t *req, size_t n)
{
    uint8_t resp[MB_ADU_MAX];
    size_t resp_len = 0;
    (void)mb_stack_handle_adu(g_stack, req, n, resp, sizeof(resp), &resp_len);
}

/* Walk concatenated MBAPs (multi-ADU stream). Truncated tail still fed once. */
static void feed_stream(const uint8_t *data, size_t size)
{
    size_t off = 0;
    int n = 0;
    while (off < size && n < 8) {
        if (size - off < (size_t)MB_MBAP_LEN + 1u) {
            feed_one(data + off, size - off);
            break;
        }
        uint16_t len = rd_be16(data + off + 4);
        size_t need = (size_t)(MB_MBAP_LEN - 1 + len);
        if (len < 2 || need < (size_t)MB_MBAP_LEN + 1u || off + need > size) {
            feed_one(data + off, size - off);
            break;
        }
        feed_one(data + off, need);
        off += need;
        n++;
    }
}

static uint16_t u16_at(const uint8_t *p, size_t plen, size_t i, uint16_t def)
{
    if (i + 1 < plen) {
        return rd_be16(p + i);
    }
    if (i < plen) {
        return p[i];
    }
    return def;
}

static uint8_t u8_at(const uint8_t *p, size_t plen, size_t i, uint8_t def)
{
    return i < plen ? p[i] : def;
}

/* Structurally valid PDU for an implemented FC; addr/qty taken from payload. */
static size_t build_fc_pdu(uint8_t fc, const uint8_t *p, size_t plen, uint8_t *pdu,
                           size_t cap)
{
    uint16_t addr = (uint16_t)(u16_at(p, plen, 0, 0) % FUZZ_NREG);
    uint16_t baddr = (uint16_t)(u16_at(p, plen, 0, 0) % FUZZ_NBIT);
    switch (fc) {
    case MB_FC_READ_COILS:
    case MB_FC_READ_DISCRETE: {
        uint16_t qty = (uint16_t)(1u + (u16_at(p, plen, 2, 8) % 64u));
        if (cap < 5) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, baddr);
        wr_be16(pdu + 3, qty);
        return 5;
    }
    case MB_FC_READ_HOLDING:
    case MB_FC_READ_INPUT: {
        uint16_t qty = (uint16_t)(1u + (u16_at(p, plen, 2, 2) % 32u));
        if (cap < 5) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, qty);
        return 5;
    }
    case MB_FC_WRITE_SINGLE_COIL: {
        if (cap < 5) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, baddr);
        wr_be16(pdu + 3, (p && plen && (p[plen - 1] & 1)) ? 0xFF00 : 0x0000);
        return 5;
    }
    case MB_FC_WRITE_SINGLE_REG: {
        if (cap < 5) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, u16_at(p, plen, 2, 0x1234));
        return 5;
    }
    case MB_FC_WRITE_MULTI_COILS: {
        uint16_t qty = (uint16_t)(1u + (u16_at(p, plen, 2, 8) % 32u));
        uint8_t nbytes = (uint8_t)((qty + 7) / 8);
        if (cap < 6u + nbytes) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, baddr);
        wr_be16(pdu + 3, qty);
        pdu[5] = nbytes;
        memset(pdu + 6, 0xA5, nbytes);
        if (plen) {
            memcpy(pdu + 6, p, plen < nbytes ? plen : nbytes);
        }
        return 6u + nbytes;
    }
    case MB_FC_WRITE_MULTI_REGS: {
        uint16_t qty = (uint16_t)(1u + (u16_at(p, plen, 2, 2) % 8u));
        uint8_t nbytes = (uint8_t)(qty * 2);
        if (cap < 6u + nbytes) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, qty);
        pdu[5] = nbytes;
        memset(pdu + 6, 0, nbytes);
        if (plen) {
            memcpy(pdu + 6, p, plen < nbytes ? plen : nbytes);
        }
        return 6u + nbytes;
    }
    case MB_FC_MASK_WRITE_REG: {
        if (cap < 7) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, addr);
        wr_be16(pdu + 3, u16_at(p, plen, 2, 0xFFFF));
        wr_be16(pdu + 5, u16_at(p, plen, 4, 0x0000));
        return 7;
    }
    case MB_FC_READ_WRITE_REGS: {
        uint16_t rqty = (uint16_t)(1u + (u8_at(p, plen, 0, 2) % 8u));
        uint16_t wqty = (uint16_t)(1u + (u8_at(p, plen, 1, 1) % 4u));
        uint8_t nbytes = (uint8_t)(wqty * 2);
        if (cap < 10u + nbytes) {
            return 0;
        }
        pdu[0] = fc;
        wr_be16(pdu + 1, (uint16_t)(addr % (FUZZ_NREG / 2)));
        wr_be16(pdu + 3, rqty);
        wr_be16(pdu + 5, (uint16_t)((addr + 8) % FUZZ_NREG));
        wr_be16(pdu + 7, wqty);
        pdu[9] = nbytes;
        memset(pdu + 10, 0x11, nbytes);
        if (plen > 2) {
            size_t n = plen - 2;
            memcpy(pdu + 10, p + 2, n < nbytes ? n : nbytes);
        }
        return 10u + nbytes;
    }
    default: {
        size_t n = plen < 8 ? plen : 8;
        if (cap < 1 + n) {
            return 0;
        }
        pdu[0] = fc;
        if (n) {
            memcpy(pdu + 1, p, n);
        }
        return 1 + n;
    }
    }
}

static void feed_wrapped(uint8_t fc, uint8_t unit, uint16_t proto,
                         const uint8_t *p, size_t plen)
{
    uint8_t pdu[MB_PDU_MAX];
    uint8_t adu[MB_ADU_MAX];
    size_t pn = build_fc_pdu(fc, p, plen, pdu, sizeof(pdu));
    if (!pn) {
        return;
    }
    size_t n = wrap_mbap(adu, sizeof(adu), 1, proto, unit, pdu, pn);
    if (n) {
        feed_one(adu, n);
    }
}

static int fuzz_init(void)
{
    mb_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = MB_ROLE_SERVER;
    cfg.unit_id = 1;
    cfg.n_holding = FUZZ_NREG;
    cfg.n_input = FUZZ_NREG;
    cfg.n_coil = FUZZ_NBIT;
    cfg.n_discrete = FUZZ_NBIT;
    g_stack = mb_stack_create(&cfg);
    return g_stack ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t k_fcs[] = {
        MB_FC_READ_COILS,        MB_FC_READ_DISCRETE, MB_FC_READ_HOLDING,
        MB_FC_READ_INPUT,        MB_FC_WRITE_SINGLE_COIL, MB_FC_WRITE_SINGLE_REG,
        MB_FC_WRITE_MULTI_COILS, MB_FC_WRITE_MULTI_REGS, MB_FC_MASK_WRITE_REG,
        MB_FC_READ_WRITE_REGS};
    static const uint8_t k_bad_fc[] = {0x00, 0x08, 0x0B, 0x11, 0x2B, 0x43,
                                       0x7F, 0x80};

    if (!g_stack && fuzz_init() != 0) {
        return 0;
    }
    if (size == 0) {
        return 0;
    }

    uint8_t mode = (uint8_t)(data[0] & 7u);
    const uint8_t *p = data + 1;
    size_t plen = size - 1;
    uint8_t pdu[MB_PDU_MAX];
    uint8_t adu[MB_ADU_MAX];
    uint8_t buf[1024];

    switch (mode) {
    case 0: /* raw / multi-ADU stream (legacy corpus) */
        feed_stream(p, plen);
        break;
    case 1: { /* wrap an implemented FC */
        uint8_t fc = k_fcs[u8_at(p, plen, 0, 3) % (uint8_t)sizeof(k_fcs)];
        feed_wrapped(fc, 1, 0, p + (plen ? 1 : 0), plen > 1 ? plen - 1 : 0);
        break;
    }
    case 2: /* FC 0x16 / 0x17 specifically */
        feed_wrapped((p && plen && (p[0] & 1)) ? MB_FC_READ_WRITE_REGS
                                               : MB_FC_MASK_WRITE_REG,
                     1, 0, p, plen);
        break;
    case 3: /* illegal function (diagnostics 0x08, MEI 0x2B, …) */
        feed_wrapped(k_bad_fc[u8_at(p, plen, 0, 1) % (uint8_t)sizeof(k_bad_fc)],
                     1, 0, p, plen);
        break;
    case 4: { /* exception: OOB addr/qty, bad coil value, nbytes mismatch */
        uint8_t kind = u8_at(p, plen, 0, 0) & 7u;
        size_t pn = 0;
        if (kind == 0) { /* qty=0 */
            pdu[0] = MB_FC_READ_HOLDING;
            wr_be16(pdu + 1, 0);
            wr_be16(pdu + 3, 0);
            pn = 5;
        } else if (kind == 1) { /* qty too large */
            pdu[0] = MB_FC_READ_COILS;
            wr_be16(pdu + 1, 0);
            wr_be16(pdu + 3, 2001);
            pn = 5;
        } else if (kind == 2) { /* addr OOB */
            pdu[0] = MB_FC_READ_HOLDING;
            wr_be16(pdu + 1, FUZZ_NREG);
            wr_be16(pdu + 3, 1);
            pn = 5;
        } else if (kind == 3) { /* bad coil value */
            pdu[0] = MB_FC_WRITE_SINGLE_COIL;
            wr_be16(pdu + 1, 0);
            wr_be16(pdu + 3, 0x0001);
            pn = 5;
        } else if (kind == 4) { /* nbytes mismatch */
            pdu[0] = MB_FC_WRITE_MULTI_REGS;
            wr_be16(pdu + 1, 0);
            wr_be16(pdu + 3, 2);
            pdu[5] = 1;
            pdu[6] = 0x11;
            pn = 7;
        } else if (kind == 5) { /* short PDU */
            pdu[0] = MB_FC_READ_WRITE_REGS;
            wr_be16(pdu + 1, 0);
            pn = 3;
        } else if (kind == 6) { /* multi-coil qty vs nbytes */
            pdu[0] = MB_FC_WRITE_MULTI_COILS;
            wr_be16(pdu + 1, 0);
            wr_be16(pdu + 3, 16);
            pdu[5] = 1;
            pdu[6] = 0xFF;
            pn = 7;
        } else { /* holding qty 126 */
            pdu[0] = MB_FC_READ_HOLDING;
            wr_be16(pdu + 1, 0);
            wr_be16(pdu + 3, 126);
            pn = 5;
        }
        {
            size_t n = wrap_mbap(adu, sizeof(adu), 2, 0, 1, pdu, pn);
            if (n) {
                feed_one(adu, n);
            }
        }
        break;
    }
    case 5: { /* unit mismatch, broadcast unit 0, proto != 0, short MBAP */
        uint8_t kind = u8_at(p, plen, 0, 0) & 3u;
        if (kind == 0) {
            feed_wrapped(MB_FC_READ_HOLDING, 2, 0, p, plen); /* ignored */
        } else if (kind == 1) {
            feed_wrapped(MB_FC_READ_HOLDING, 0, 0, p, plen); /* unit 0 ok */
        } else if (kind == 2) {
            feed_wrapped(MB_FC_READ_HOLDING, 1, 1, p, plen); /* proto != 0 */
        } else {
            feed_one(p, plen); /* truncated */
        }
        break;
    }
    case 6: { /* write then read (stateful pair) */
        feed_wrapped(MB_FC_WRITE_SINGLE_REG, 1, 0, p, plen);
        feed_wrapped(MB_FC_READ_HOLDING, 1, 0, p, plen);
        feed_wrapped(MB_FC_MASK_WRITE_REG, 1, 0, p, plen);
        feed_wrapped(MB_FC_READ_WRITE_REGS, 1, 0, p, plen);
        break;
    }
    default: { /* packed multi-ADU of mixed implemented FCs */
        size_t off = 0;
        for (int i = 0; i < 4 && off < sizeof(buf); i++) {
            uint8_t fc = k_fcs[(u8_at(p, plen, (size_t)i, (uint8_t)i)) %
                               (uint8_t)sizeof(k_fcs)];
            size_t pn = build_fc_pdu(fc, p, plen, pdu, sizeof(pdu));
            size_t n = wrap_mbap(buf + off, sizeof(buf) - off, (uint16_t)(i + 1),
                                 0, 1, pdu, pn);
            if (!n) {
                break;
            }
            off += n;
        }
        if (off) {
            feed_stream(buf, off);
        }
        break;
    }
    }
    return 0;
}
