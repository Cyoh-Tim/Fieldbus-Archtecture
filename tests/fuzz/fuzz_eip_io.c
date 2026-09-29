/*
 * Class 1 UDP I/O fuzzer.
 *
 * The original harness only called eip_stack_handle_io() on a stack with no
 * Forward Open. Every frame failed the O->T conn-id lookup (-ENOENT), so
 * coverage plateaued around cov=38 / ft=154 (CPF parse + miss).
 *
 * This harness keeps an Adapter session + exclusive-owner Class 1 connection
 * alive (RegisterSession → Forward Open) and drives:
 *   - CPF I/O with the live O->T conn id stitched in
 *   - valid wrapped I/O (seq count + 8-byte image)
 *   - raw frames (parser / miss path)
 *   - SendRR (FO / FC / other CIP)
 *   - Forward Close then re-open
 *   - poll (produce + watchdog)
 */
#include "eip_endian.h"
#include "eip_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define FUZZ_IO_IN  8
#define FUZZ_IO_OUT 8
#define FUZZ_ASM_CFG 100
#define FUZZ_ASM_OUT 101
#define FUZZ_ASM_IN  150

static eip_stack_t *g_stack;
static uint32_t g_session;
static uint32_t g_o2t;
static uint16_t g_conn_serial = 0x1234;
static uint16_t g_orig_vendor = 1;
static uint32_t g_orig_serial = 0x99;
static uint32_t g_seq = 1;

static int send_encap(const uint8_t *req, size_t req_len, uint8_t *resp,
                      size_t resp_cap, size_t *resp_len)
{
    *resp_len = 0;
    return eip_stack_handle_encap(g_stack, req, req_len, resp, resp_cap,
                                  resp_len);
}

static int send_cip(const uint8_t *cip, size_t cip_len, uint8_t *resp,
                    size_t resp_cap, size_t *resp_len)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 32 + 256];
    if (cip_len > 256) {
        cip_len = 256;
    }
    uint8_t *body = req + EIP_ENCAP_HDR_SIZE;
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;
    memset(req, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, g_session);
    return send_encap(req, EIP_ENCAP_HDR_SIZE + boff, resp, resp_cap, resp_len);
}

static int register_session(void)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t n = 0;
    if (send_encap(req, sizeof(req), resp, sizeof(resp), &n) == 0 && n >= 8) {
        uint32_t h = eip_rd_le32(resp + 4);
        if (h != 0) {
            g_session = h;
            return 0;
        }
    }
    return -1;
}

static uint32_t parse_fo_o2t(const uint8_t *resp, size_t n)
{
    size_t start = n > EIP_ENCAP_HDR_SIZE ? EIP_ENCAP_HDR_SIZE : 0;
    for (size_t i = start; i + 12 < n; i++) {
        uint8_t svc = resp[i];
        if (resp[i + 2] != 0) {
            continue;
        }
        if (svc == (uint8_t)(CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) ||
            svc == (uint8_t)(CIP_SVC_LARGE_FORWARD_OPEN | CIP_SVC_REPLY)) {
            return eip_rd_le32(resp + i + 4);
        }
    }
    return 0;
}

static int forward_open(int large, uint16_t serial)
{
    uint8_t fo[80];
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, g_orig_vendor);
    off += 2;
    eip_wr_le32(fo + off, g_orig_serial);
    off += 4;
    fo[off++] = 7; /* timeout multiplier → long watchdog while fuzzing */
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 8000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, FUZZ_IO_OUT);
        off += 4;
    } else {
        eip_wr_le16(fo + off, FUZZ_IO_OUT);
        off += 2;
    }
    eip_wr_le32(fo + off, 8000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, FUZZ_IO_IN);
        off += 4;
    } else {
        eip_wr_le16(fo + off, FUZZ_IO_IN);
        off += 2;
    }
    fo[off++] = 0x01; /* Class 1 */
    fo[off++] = 4;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = (uint8_t)FUZZ_ASM_CFG;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)FUZZ_ASM_OUT;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)FUZZ_ASM_IN;

    uint8_t cip[2 + 4 + 80];
    cip[0] = large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);

    uint8_t resp[512];
    size_t n = 0;
    if (send_cip(cip, 6 + off, resp, sizeof(resp), &n) != 0) {
        return -1;
    }
    uint32_t o2t = parse_fo_o2t(resp, n);
    if (o2t == 0) {
        return -1;
    }
    g_o2t = o2t;
    g_conn_serial = serial;
    return 0;
}

static void forward_close(void)
{
    uint8_t fc[12];
    memset(fc, 0, sizeof(fc));
    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, g_conn_serial);
    eip_wr_le16(fc + 4, g_orig_vendor);
    eip_wr_le32(fc + 6, g_orig_serial);
    uint8_t cip[2 + 4 + 12];
    cip[0] = CIP_SVC_FORWARD_CLOSE;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fc, 12);
    uint8_t resp[128];
    size_t n = 0;
    (void)send_cip(cip, 6 + 12, resp, sizeof(resp), &n);
    g_o2t = 0;
}

static void ensure_session(void)
{
    if (g_session == 0) {
        (void)register_session();
    }
}

static void ensure_open(void)
{
    ensure_session();
    if (g_session == 0) {
        return;
    }
    if (eip_stack_class1_up(g_stack) && g_o2t != 0) {
        return;
    }
    g_conn_serial++;
    if (g_conn_serial == 0) {
        g_conn_serial = 1;
    }
    (void)forward_open(0, g_conn_serial);
}

static void stitch_o2t(uint8_t *frame, size_t len, uint32_t conn_id)
{
    if (len < 2 || conn_id == 0) {
        return;
    }
    uint16_t items = eip_rd_le16(frame);
    size_t off = 2;
    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > len) {
            return;
        }
        uint16_t type = eip_rd_le16(frame + off);
        uint16_t length = eip_rd_le16(frame + off + 2);
        off += 4;
        if (off + length > len) {
            return;
        }
        if (type == EIP_ITEM_SEQ_ADDR && length >= 8) {
            eip_wr_le32(frame + off, conn_id);
            return;
        }
        off += length;
    }
}

static size_t wrap_class1_io(uint8_t *io, size_t cap, uint32_t o2t, uint32_t seq,
                             const uint8_t *payload, size_t plen)
{
    if (plen > FUZZ_IO_OUT) {
        plen = FUZZ_IO_OUT;
    }
    size_t need = 22u + plen;
    if (need > cap) {
        return 0;
    }
    size_t off = 0;
    eip_wr_le16(io + off, 2);
    off += 2;
    eip_wr_le16(io + off, EIP_ITEM_SEQ_ADDR);
    off += 2;
    eip_wr_le16(io + off, 8);
    off += 2;
    eip_wr_le32(io + off, o2t);
    off += 4;
    eip_wr_le32(io + off, seq);
    off += 4;
    eip_wr_le16(io + off, EIP_ITEM_CONNECTED_DATA);
    off += 2;
    eip_wr_le16(io + off, (uint16_t)(2 + plen));
    off += 2;
    eip_wr_le16(io + off, (uint16_t)(seq & 0xffff));
    off += 2;
    if (plen) {
        memcpy(io + off, payload, plen);
        off += plen;
    }
    return off;
}

static int looks_like_cpf(const uint8_t *data, size_t n)
{
    if (n < 6) {
        return 0;
    }
    uint16_t items = eip_rd_le16(data);
    return items >= 1 && items <= 8;
}

static int fuzz_init(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = FUZZ_IO_IN;
    cfg.output_size = FUZZ_IO_OUT;
    cfg.input_assembly = FUZZ_ASM_IN;
    cfg.output_assembly = FUZZ_ASM_OUT;
    cfg.config_assembly = FUZZ_ASM_CFG;
    cfg.rpi_us = 8000;
    g_stack = eip_stack_create(&cfg);
    if (!g_stack) {
        return -1;
    }
    if (eip_stack_start(g_stack) != 0) {
        return -1;
    }
    ensure_open();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_stack) {
        if (fuzz_init() != 0) {
            return 0;
        }
    }

    if (size == 0) {
        ensure_open();
        return 0;
    }

    uint8_t mode = (uint8_t)(data[0] & 7u);
    const uint8_t *payload = data + 1;
    size_t plen = size - 1;
    uint8_t buf[4096];
    uint8_t resp[EIP_TCP_BUF_MAX];
    size_t resp_len = 0;

    switch (mode) {
    case 0: /* stitch live O->T id into a CPF, else wrap */
        ensure_open();
        if (looks_like_cpf(payload, plen)) {
            size_t n = plen > sizeof(buf) ? sizeof(buf) : plen;
            memcpy(buf, payload, n);
            stitch_o2t(buf, n, g_o2t);
            (void)eip_stack_handle_io(g_stack, buf, n);
        } else {
            size_t n = wrap_class1_io(buf, sizeof(buf), g_o2t, g_seq++, payload,
                                      plen);
            if (n) {
                (void)eip_stack_handle_io(g_stack, buf, n);
            }
        }
        eip_stack_poll(g_stack);
        break;
    case 1: /* always a well-formed Class 1 frame */
        ensure_open();
        {
            size_t n = wrap_class1_io(buf, sizeof(buf), g_o2t, g_seq++, payload,
                                      plen);
            if (n) {
                (void)eip_stack_handle_io(g_stack, buf, n);
            }
            eip_stack_poll(g_stack);
        }
        break;
    case 2: /* raw UDP CPF (legacy corpus / miss path) */
        (void)eip_stack_handle_io(g_stack, payload, plen);
        break;
    case 3: /* SendRR with this connection's session handle */
        ensure_session();
        if (plen >= EIP_ENCAP_HDR_SIZE) {
            size_t n = plen > sizeof(buf) ? sizeof(buf) : plen;
            memcpy(buf, payload, n);
            if (g_session != 0 &&
                eip_rd_le16(buf) == EIP_CMD_SENDRRDATA) {
                eip_wr_le32(buf + 4, g_session);
            }
            (void)send_encap(buf, n, resp, sizeof(resp), &resp_len);
        } else if (plen > 0) {
            (void)send_cip(payload, plen, resp, sizeof(resp), &resp_len);
        }
        break;
    case 4: /* Forward Close then re-open */
        ensure_open();
        forward_close();
        eip_stack_poll(g_stack);
        ensure_open();
        break;
    case 5: /* produce / watchdog */
        ensure_open();
        eip_stack_poll(g_stack);
        if (plen >= 1 && payload[0] == 0xff) {
            /* Rare: tiny-RPI FO so the next poll can reclaim the slot. */
            forward_close();
            uint8_t fo_tm0[80];
            size_t off = 0;
            fo_tm0[off++] = 0x0A;
            fo_tm0[off++] = 0x05;
            eip_wr_le32(fo_tm0 + off, 0);
            off += 4;
            eip_wr_le32(fo_tm0 + off, 0);
            off += 4;
            g_conn_serial++;
            eip_wr_le16(fo_tm0 + off, g_conn_serial);
            off += 2;
            eip_wr_le16(fo_tm0 + off, g_orig_vendor);
            off += 2;
            eip_wr_le32(fo_tm0 + off, g_orig_serial);
            off += 4;
            fo_tm0[off++] = 0;
            fo_tm0[off++] = 0;
            fo_tm0[off++] = 0;
            fo_tm0[off++] = 0;
            eip_wr_le32(fo_tm0 + off, 1); /* 1 µs RPI → 4 µs watchdog */
            off += 4;
            eip_wr_le16(fo_tm0 + off, FUZZ_IO_OUT);
            off += 2;
            eip_wr_le32(fo_tm0 + off, 1);
            off += 4;
            eip_wr_le16(fo_tm0 + off, FUZZ_IO_IN);
            off += 2;
            fo_tm0[off++] = 0x01;
            fo_tm0[off++] = 4;
            fo_tm0[off++] = 0x20;
            fo_tm0[off++] = CIP_CLASS_ASSEMBLY;
            fo_tm0[off++] = 0x24;
            fo_tm0[off++] = (uint8_t)FUZZ_ASM_CFG;
            fo_tm0[off++] = 0x2C;
            fo_tm0[off++] = (uint8_t)FUZZ_ASM_OUT;
            fo_tm0[off++] = 0x2C;
            fo_tm0[off++] = (uint8_t)FUZZ_ASM_IN;
            uint8_t cip[2 + 4 + 80];
            cip[0] = CIP_SVC_FORWARD_OPEN;
            cip[1] = 2;
            cip[2] = 0x20;
            cip[3] = CIP_CLASS_CONN_MANAGER;
            cip[4] = 0x24;
            cip[5] = 1;
            memcpy(cip + 6, fo_tm0, off);
            (void)send_cip(cip, 6 + off, resp, sizeof(resp), &resp_len);
            struct timespec ts = {0, 20000};
            (void)nanosleep(&ts, NULL);
            eip_stack_poll(g_stack);
            ensure_open();
        }
        break;
    case 6: /* other Encaps commands */
        ensure_session();
        if (plen >= 2) {
            size_t n = plen > sizeof(buf) ? sizeof(buf) : plen;
            memcpy(buf, payload, n);
            if (n >= 8 && g_session != 0) {
                uint16_t cmd = eip_rd_le16(buf);
                if (cmd == EIP_CMD_UNREGISTERSESSION ||
                    cmd == EIP_CMD_SENDRRDATA ||
                    cmd == EIP_CMD_SENDUNITDATA) {
                    eip_wr_le32(buf + 4, g_session);
                }
            }
            (void)send_encap(buf, n, resp, sizeof(resp), &resp_len);
            if (n >= EIP_ENCAP_HDR_SIZE &&
                eip_rd_le16(buf) == EIP_CMD_REGISTERSESSION &&
                resp_len >= 8) {
                uint32_t h = eip_rd_le32(resp + 4);
                if (h != 0) {
                    g_session = h;
                }
            }
            if (eip_rd_le16(buf) == EIP_CMD_UNREGISTERSESSION) {
                g_session = 0;
                g_o2t = 0;
            }
        }
        break;
    default: /* Large Forward Open + I/O */
        ensure_session();
        g_conn_serial++;
        (void)forward_open(1, g_conn_serial);
        {
            size_t n = wrap_class1_io(buf, sizeof(buf), g_o2t, g_seq++, payload,
                                      plen);
            if (n) {
                (void)eip_stack_handle_io(g_stack, buf, n);
            }
            eip_stack_poll(g_stack);
        }
        break;
    }
    return 0;
}
