/*
 * T12-12: Connect.res AlarmCRBlockRes body is 6 bytes (BlockLength 8):
 * AlarmCRType, LocalAlarmReference (this device), MaxAlarmDataLength.
 * The extra 2 bytes (0x00A0) make BlockLength 10.
 * ARBlockRes CMResponderUDPRTPort for RT_CLASS_1 is 0x8892 (L2 RT
 * marker, PN_ETHTYPE_PN). 0x8894 is the CM RPC port, not this field.
 * Oracle: test_connect_alarm_cr_block_res_length,
 * test_connect_ar_block_res_udp_rt_port.
 */
#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

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

static void fill_aruuid(uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = (uint8_t)(0xA0 + i);
    }
}

static size_t wr_block(uint8_t *p, uint16_t type, const uint8_t *body,
                       uint16_t body_len)
{
    uint16_t blen = (uint16_t)(2 + body_len);
    pn_wr_be16(p, type);
    pn_wr_be16(p + 2, blen);
    p[4] = 1;
    p[5] = 0;
    memcpy(p + 6, body, body_len);
    size_t n = 4u + blen;
    if (n & 1u) {
        p[n++] = 0;
    }
    return n;
}

static size_t ndr_wrap(uint8_t *out, const uint8_t *blocks, size_t n)
{
    pn_wr_le32(out, (uint32_t)n);
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

static size_t wrap_rpc(uint8_t *out, const uint8_t *stub, size_t slen)
{
    memset(out, 0, 80);
    out[0] = 4;
    out[1] = 0;
    out[4] = 0x10;
    static const uint8_t obj[16] = {
        0x00, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xab, 0xcd};
    static const uint8_t iface[16] = {
        0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d};
    memcpy(out + 8, obj, 16);
    memcpy(out + 24, iface, 16);
    pn_wr_le16(out + 68, 0); /* Connect */
    pn_wr_le16(out + 74, (uint16_t)slen);
    memcpy(out + 80, stub, slen);
    return 80 + slen;
}

static pn_stack_t *make_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "t12-12");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.cycle_us = 8000;
    return pn_stack_create(&cfg);
}

/* ARBlockReq only. Legacy startup, so the response has no ARServerBlock. */
static size_t build_connect(uint8_t *pdu, uint16_t session)
{
    uint8_t ar[2 + 16 + 2 + 6];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_aruuid(ar + 2);
    pn_wr_be16(ar + 18, session);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    return wrap_rpc(pdu, stub, sn);
}

/* Walk BlockHeader. Returns the block (type through body) or NULL. */
static const uint8_t *find_block(const uint8_t *blocks, size_t n, uint16_t type,
                                 size_t *block_len)
{
    size_t off = 0;
    const uint8_t *found = NULL;
    int count = 0;
    while (off + 4 <= n) {
        uint16_t btype = pn_rd_be16(blocks + off);
        uint16_t blen = pn_rd_be16(blocks + off + 2);
        if (blen < 2 || off + 4u + blen > n) {
            break;
        }
        if (btype == type) {
            found = blocks + off;
            *block_len = 4u + blen;
            count++;
        }
        off += 4u + blen;
        if (off < n && (off & 1u)) {
            off++;
        }
    }
    if (count != 1) {
        fprintf(stderr, "FAIL: block 0x%04x count %d (want 1)\n", type, count);
        g_fail = 1;
        return NULL;
    }
    return found;
}

static void test_connect_res_alarmcr_and_port(void)
{
    pn_stack_t *s = make_stack();
    expect(s != NULL, "create");
    if (!s) {
        return;
    }

    const uint16_t session = 0x1234;
    uint8_t pdu[512];
    uint8_t resp[1024];
    size_t rlen = 0;
    size_t plen = build_connect(pdu, session);
    expect(pn_rpc_handle(s, pdu, plen, resp, sizeof(resp), &rlen, 0x0a000001) ==
               0,
           "connect");
    expect(pn_stack_ar_up(s) == 1, "ar up");
    expect(rlen >= 100, "response has NDR");
    if (rlen < 100) {
        pn_stack_destroy(s);
        return;
    }

    const uint8_t *stub = resp + 80;
    uint32_t args_len = pn_rd_le32(stub + 4);
    expect(20u + args_len <= rlen - 80, "ArgsLength fits");
    const uint8_t *blocks = stub + 20;
    size_t blen = args_len;
    if (20u + blen > rlen - 80) {
        blen = rlen - 100;
    }

    size_t ar_len = 0;
    const uint8_t *ar = find_block(blocks, blen, PN_BLOCK_AR_RES, &ar_len);
    if (ar) {
        /* Body: ARType(2) ARUUID(16) SessionKey(2) CMResponderMacAdd(6)
         * CMResponderUDPRTPort(2). BlockLength counts from BlockVersion. */
        uint16_t block_length = pn_rd_be16(ar + 2);
        expect(block_length == 30, "ARBlockRes BlockLength 30");
        expect(pn_rd_be16(ar + 6) == 0x0001, "ARType IOCARSingle");
        expect(memcmp(ar + 8, s->ar.uuid, 16) == 0, "ARUUID echoed");
        uint16_t got_session = pn_rd_be16(ar + 24);
        if (got_session != session) {
            fprintf(stderr, "FAIL: SessionKey got 0x%04x want 0x%04x\n",
                    got_session, session);
            g_fail = 1;
        }
        expect(memcmp(ar + 26, s->cfg.mac, 6) == 0, "CMResponderMacAdd");
        uint16_t port = pn_rd_be16(ar + 32);
        if (port != 0x8892) {
            fprintf(stderr,
                    "FAIL: CMResponderUDPRTPort got 0x%04x want 0x8892 "
                    "(RT_CLASS_1 L2 RT marker; 0x8894 is the RPC port)\n",
                    port);
            g_fail = 1;
        }
    }

    size_t al_len = 0;
    const uint8_t *al = find_block(blocks, blen, PN_BLOCK_ALARMCR_RES, &al_len);
    if (al) {
        uint16_t block_length = pn_rd_be16(al + 2);
        /* BlockLength 8 = BlockVersion(2) + AlarmCRType + LocalAlarmReference
         * + MaxAlarmDataLength. Body after the version is 6 bytes. */
        if (block_length != 8) {
            fprintf(stderr,
                    "FAIL: AlarmCRBlockRes BlockLength got %u want 8 "
                    "(body 6; BlockLength 10 is the extra 2 bytes)\n",
                    block_length);
            g_fail = 1;
        }
        expect(al[4] == 1 && al[5] == 0, "AlarmCRBlockRes version 1.0");
        uint16_t cr_type = pn_rd_be16(al + 6);
        uint16_t local_ref = pn_rd_be16(al + 8);
        uint16_t max_len = pn_rd_be16(al + 10);
        if (cr_type != 1) {
            fprintf(stderr, "FAIL: AlarmCRType got 0x%04x want 0x0001\n",
                    cr_type);
            g_fail = 1;
        }
        if (local_ref != s->ar.alarm_src_ref) {
            fprintf(stderr,
                    "FAIL: LocalAlarmReference got 0x%04x want 0x%04x "
                    "(device reference)\n",
                    local_ref, s->ar.alarm_src_ref);
            g_fail = 1;
        }
        if (max_len != 200) {
            fprintf(stderr, "FAIL: MaxAlarmDataLength got %u want 200\n",
                    max_len);
            g_fail = 1;
        }
        if (al_len != 12) {
            fprintf(stderr,
                    "FAIL: AlarmCRBlockRes wire size got %zu want 12 "
                    "(header 4 + BlockLength 8, no extra 0x00A0)\n",
                    al_len);
            g_fail = 1;
        }
    }

    pn_stack_destroy(s);
}

int main(void)
{
    test_connect_res_alarmcr_and_port();
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_12: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_12: OK\n");
    return 0;
}
