#include "pn_crypto.h"
#include "pn_endian.h"
#include "pn_stack.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int g_fail;

static int contains(const uint8_t *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    if (m == 0 || m > n) {
        return 0;
    }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return 1;
        }
    }
    return 0;
}

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

/* RFC 4231 HMAC-SHA256 test case 1 */
static void test_hmac(void)
{
    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    const uint8_t *data = (const uint8_t *)"Hi There";
    uint8_t mac[32];
    pn_hmac_sha256(key, sizeof(key), data, 8, mac);
    static const uint8_t exp[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
        0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
        0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    expect(memcmp(mac, exp, 32) == 0, "HMAC-SHA256 RFC4231 case 1");
}

typedef struct {
    uint8_t frames[8][PN_FRAME_MAX];
    size_t lens[8];
    int n;
} tx_cap_t;

static int cap_send(void *ctx, const uint8_t *frame, size_t len)
{
    tx_cap_t *c = ctx;
    if (c->n < 8 && len <= PN_FRAME_MAX) {
        memcpy(c->frames[c->n], frame, len);
        c->lens[c->n] = len;
        c->n++;
    }
    return 0;
}

static void build_dcp_identify(uint8_t *out, size_t *len)
{
    static const uint8_t mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x11223344);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);
    *len = pn_eth_build(out, PN_FRAME_MAX, mc, src, PN_ETHTYPE_PN, pay, 16);
}

static size_t append_dcp_block(uint8_t *p, uint8_t opt, uint8_t sub,
                               const uint8_t *data, uint16_t dlen)
{
    p[0] = opt;
    p[1] = sub;
    pn_wr_be16(p + 2, dlen);
    memcpy(p + 4, data, dlen);
    size_t n = 4u + dlen;
    if (dlen & 1u) {
        p[n++] = 0;
    }
    return n;
}

static void test_dcp_identify(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "sensor-line1");
    cfg.security_class = 0;
    pn_stack_t *s = pn_stack_create(&cfg);
    tx_cap_t cap;
    memset(&cap, 0, sizeof(cap));
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = &cap};
    pn_stack_set_eth_ops(s, ops);
    pn_stack_start(s);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = 0;
    build_dcp_identify(frame, &flen);
    pn_stack_handle_eth(s, frame, flen);

    int found = 0;
    int valid_res = 0;
    for (int i = 0; i < cap.n; i++) {
        const uint8_t *f = cap.frames[i];
        size_t n = cap.lens[i];
        if (n < 16) {
            continue;
        }
        uint16_t et = pn_rd_be16(f + 12);
        uint16_t fid = pn_rd_be16(f + 14);
        uint8_t sid = f[16];
        uint8_t st = f[17];
        if (et == PN_ETHTYPE_PN && fid == PN_FRAMEID_DCP_ID_RES &&
            sid == PN_DCP_IDENTIFY && st == PN_DCP_RESP_SUCCESS &&
            contains(f, n, "sensor-line1")) {
            valid_res = 1;
        }
        if (contains(f, n, "sensor-line1")) {
            found = 1;
        }
    }
    expect(found, "DCP Identify response contains NameOfStation");
    expect(valid_res,
           "DCP Identify.Res FrameID=0xFEFF service=Identify success");
    pn_stack_destroy(s);
}

static void test_dcp_set_sec(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "old-name");
    cfg.security_class = 1;
    memset(cfg.psk, 0x11, PN_PSK_LEN);
    cfg.psk_set = 1;
    pn_stack_t *s = pn_stack_create(&cfg);
    tx_cap_t cap;
    memset(&cap, 0, sizeof(cap));
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = &cap};
    pn_stack_set_eth_ops(s, ops);
    pn_stack_start(s);

    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    uint8_t blocks[128];
    size_t bn = 0;
    uint8_t nameblk[2 + 8];
    pn_wr_be16(nameblk, 1); /* qualifier */
    memcpy(nameblk + 2, "new-name", 8);
    bn += append_dcp_block(blocks + bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                           nameblk, 10);

    uint8_t pay[256];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xAABBCCDD);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    size_t plen = 12 + bn;

    uint8_t frame[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(frame, sizeof(frame), dst, src, PN_ETHTYPE_PN, pay, plen);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    expect(strcmp(pn_stack_cfg(s)->station_name, "old-name") == 0,
           "unsigned DCP Set rejected under Security Class 1");

    /* signed: HMAC over payload without sec block (the unsigned body) */
    uint8_t mac[PN_HMAC_LEN];
    pn_hmac_sha256(cfg.psk, PN_PSK_LEN, pay, plen, mac);
    size_t bn2 = bn;
    bn2 += append_dcp_block(blocks + bn2, PN_DCP_OPT_SEC, PN_DCP_SUB_SEC_HMAC,
                            mac, PN_HMAC_LEN);
    pn_wr_be16(pay + 10, (uint16_t)bn2);
    memcpy(pay + 12, blocks, bn2);
    plen = 12 + bn2;
    flen =
        pn_eth_build(frame, sizeof(frame), dst, src, PN_ETHTYPE_PN, pay, plen);
    pn_stack_handle_eth(s, frame, flen);
    expect(strcmp(pn_stack_cfg(s)->station_name, "new-name") == 0,
           "signed DCP Set accepted and NameOfStation updated");

    pn_stack_destroy(s);
}

static void test_connect_sec(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    cfg.security_class = 1;
    memset(cfg.psk, 0x22, PN_PSK_LEN);
    cfg.psk_set = 1;
    pn_stack_t *s = pn_stack_create(&cfg);
    tx_cap_t cap;
    memset(&cap, 0, sizeof(cap));
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = &cap};
    pn_stack_set_eth_ops(s, ops);
    pn_stack_start(s);

    uint8_t pdu[256];
    memset(pdu, 0, sizeof(pdu));
    pdu[0] = 1; /* rpcvers */
    pdu[1] = 0; /* request */
    pn_wr_le16(pdu + 68, 0); /* Connect */
    /* empty NDR + AR-less blocks */
    pn_wr_le16(pdu + 74, 20);
    pn_wr_le32(pdu + 80 + 4, 0);
    pn_wr_le32(pdu + 80 + 16, 0);
    uint8_t resp[512];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc(s, pdu, 100, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 0, "Connect without integrity returns RPC resp");
    expect(!pn_stack_ar_up(s), "AR not established without Security block");

    pn_stack_destroy(s);
}

static size_t wr_pn_block(uint8_t *p, uint16_t type, const uint8_t *body,
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

static size_t ndr_wrap_le(uint8_t *out, const uint8_t *blocks, size_t n)
{
    pn_wr_le32(out, (uint32_t)n);
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

static size_t rpc_req(uint8_t *pdu, uint16_t op, const uint8_t *stub,
                      size_t slen)
{
    memset(pdu, 0, 80 + slen);
    pdu[0] = 4;
    pdu[1] = 0;
    pdu[4] = 0x10; /* little-endian drep */
    pn_wr_le16(pdu + 68, op);
    pn_wr_le16(pdu + 74, (uint16_t)slen);
    memcpy(pdu + 80, stub, slen);
    return 80 + slen;
}

static size_t build_iocr_body(uint8_t *b, uint16_t type, uint16_t ref,
                              uint16_t data_len, uint16_t frame_id,
                              uint16_t sc, uint16_t rr, uint16_t wd,
                              uint16_t slot, uint16_t sub, uint16_t data_off,
                              uint16_t iocs_off)
{
    memset(b, 0, 64);
    pn_wr_be16(b + 0, type);
    pn_wr_be16(b + 2, ref);
    pn_wr_be16(b + 4, 0x8892);
    pn_wr_be32(b + 6, 0x00000001); /* RT_CLASS_1 */
    pn_wr_be16(b + 10, data_len);
    pn_wr_be16(b + 12, frame_id);
    pn_wr_be16(b + 14, sc);
    pn_wr_be16(b + 16, rr);
    pn_wr_be16(b + 18, 1); /* phase */
    pn_wr_be16(b + 20, 0);
    pn_wr_be32(b + 22, 0xffffffffu);
    pn_wr_be16(b + 26, wd);
    pn_wr_be16(b + 28, wd);
    pn_wr_be16(b + 30, 0xC000); /* PCP 6, VLAN 0 */
    pn_wr_be16(b + 38, 1);      /* NumberOfAPIs */
    pn_wr_be32(b + 40, 0);
    pn_wr_be16(b + 44, 1); /* IODataObjects */
    pn_wr_be16(b + 46, slot);
    pn_wr_be16(b + 48, sub);
    pn_wr_be16(b + 50, data_off);
    pn_wr_be16(b + 52, 1); /* IOCS */
    pn_wr_be16(b + 54, slot);
    pn_wr_be16(b + 56, sub);
    pn_wr_be16(b + 58, iocs_off);
    return 60;
}

static size_t build_expsub_body(uint8_t *b, uint16_t in_len, uint16_t out_len)
{
    memset(b, 0, 48);
    pn_wr_be16(b + 0, 1); /* APIs */
    pn_wr_be32(b + 2, 0);
    pn_wr_be16(b + 6, 1); /* slot */
    pn_wr_be32(b + 8, 0x10);
    pn_wr_be16(b + 12, 0);
    pn_wr_be16(b + 14, 1); /* submodules */
    pn_wr_be16(b + 16, 1); /* subslot */
    pn_wr_be32(b + 18, 0x11);
    pn_wr_be16(b + 22, 0x0003); /* INPUT_OUTPUT */
    pn_wr_be16(b + 24, 1);      /* Input */
    pn_wr_be16(b + 26, in_len);
    b[28] = 1;
    b[29] = 1;
    pn_wr_be16(b + 30, 2); /* Output */
    pn_wr_be16(b + 32, out_len);
    b[34] = 1;
    b[35] = 1;
    return 36;
}

static size_t build_ar_body(uint8_t *b, const uint8_t uuid[16],
                            const uint8_t mac[6])
{
    memset(b, 0, 64);
    pn_wr_be16(b, 0x0001);
    memcpy(b + 2, uuid, 16);
    pn_wr_be16(b + 18, 1);
    memcpy(b + 20, mac, 6);
    /* initiator object UUID */
    b[26] = 0xDE;
    b[27] = 0xA0;
    b[28] = 0x00;
    b[29] = 0x02;
    pn_wr_be32(b + 42, 0x00000001); /* ARProperties State=Active */
    pn_wr_be16(b + 46, 1000);
    pn_wr_be16(b + 48, 0x8892);
    pn_wr_be16(b + 50, 4);
    memcpy(b + 52, "plc1", 4);
    return 56;
}

static size_t build_connect_stub(uint8_t *blocks, size_t cap)
{
    static const uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                                     9, 10, 11, 12, 13, 14, 15, 16};
    static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t ar[64], iin[64], iout[64], exp[48];
    size_t an = build_ar_body(ar, uuid, mac);
    size_t nin = build_iocr_body(iin, PN_IOCR_INPUT, 1, 40, 0x8123, 32, 8, 3, 1,
                                 1, 0, 33);
    size_t nout = build_iocr_body(iout, PN_IOCR_OUTPUT, 2, 40, 0xFFFF, 32, 8, 3,
                                  1, 1, 0, 9);
    size_t ne = build_expsub_body(exp, 32, 8);
    size_t n = 0;
    n += wr_pn_block(blocks + n, PN_BLOCK_AR_REQ, ar, (uint16_t)an);
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iin, (uint16_t)nin);
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iout, (uint16_t)nout);
    n += wr_pn_block(blocks + n, PN_BLOCK_EXPSUB_REQ, exp, (uint16_t)ne);
    (void)cap;
    return n;
}

static pn_stack_t *mock_stack(tx_cap_t *cap)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "sensor-line1");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.cycle_us = 8000;
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 1;
    pn_stack_t *s = pn_stack_create(&cfg);
    memset(cap, 0, sizeof(*cap));
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = cap};
    pn_stack_set_eth_ops(s, ops);
    pn_stack_start(s);
    return s;
}

static int do_connect(pn_stack_t *s)
{
    uint8_t blocks[512];
    size_t bn = build_connect_stub(blocks, sizeof(blocks));
    uint8_t stub[600];
    size_t sn = ndr_wrap_le(stub, blocks, bn);
    uint8_t pdu[800];
    size_t plen = rpc_req(pdu, 0, stub, sn);
    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc_from(s, pdu, plen, 0xC0A80001u, 34964, resp,
                                      sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Connect.res returned");
    expect(pn_stack_cm_state(s) == PN_CM_CONNECTED,
           "CM state CONNECTED after Connect");
    expect(!pn_stack_ar_up(s), "cyclic not up before PrmEnd");
    expect(contains(resp, rlen, "sensor-line1"),
           "Connect.res ARServerBlock has CMResponderStationName");
    int saw_arsrv = 0, saw_moddiff = 0;
    if (rlen > 100) {
        const uint8_t *p = resp + 100;
        size_t left = rlen - 100;
        size_t off = 0;
        while (off + 6 <= left) {
            uint16_t type = pn_rd_be16(p + off);
            uint16_t blen = pn_rd_be16(p + off + 2);
            if (type == PN_BLOCK_ARSERVER_RES) {
                saw_arsrv = 1;
            }
            if (type == PN_BLOCK_MODDIFF) {
                saw_moddiff = 1;
            }
            if (blen < 2 || off + 4u + blen > left) {
                break;
            }
            off += 4u + blen;
            if (off & 1u) {
                off++;
            }
        }
    }
    expect(saw_arsrv, "Connect.res contains ARServerBlockRes 0x8106");
    expect(!saw_moddiff, "Connect.res omits ModuleDiff when ExpectedSubmodule matches");
    return rc;
}

static int do_prmend(pn_stack_t *s)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body + 22, PN_CTRL_PRM_END);
    uint8_t blk[64];
    size_t bn = wr_pn_block(blk, PN_BLOCK_PRMEND_REQ, body, 26);
    uint8_t stub[128];
    size_t sn = ndr_wrap_le(stub, blk, bn);
    uint8_t pdu[256];
    size_t plen = rpc_req(pdu, 4, stub, sn);
    uint8_t resp[512];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "PrmEnd.res returned");
    return rc;
}

static void test_dcp_identify_filter(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);

    static const uint8_t mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t pay[32];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x1);
    pn_wr_be16(pay + 8, 0);
    /* NameOfStation = other-name */
    pay[12] = PN_DCP_OPT_DEV;
    pay[13] = PN_DCP_SUB_DEV_NAME;
    pn_wr_be16(pay + 14, 10);
    memcpy(pay + 16, "other-name", 10);
    pn_wr_be16(pay + 10, 18);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(frame, PN_FRAME_MAX, mc, src, PN_ETHTYPE_PN, pay, 30);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    int found = 0;
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found = 1;
        }
    }
    expect(!found, "Identify with other NameOfStation is ignored");

    memcpy(pay + 16, "sensor-line1", 12);
    pn_wr_be16(pay + 14, 12);
    pn_wr_be16(pay + 10, 16);
    flen = pn_eth_build(frame, PN_FRAME_MAX, mc, src, PN_ETHTYPE_PN, pay, 28);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    found = 0;
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found = 1;
        }
    }
    expect(found, "Identify with matching NameOfStation is answered");
    pn_stack_destroy(s);
}

static void test_dcp_get(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t pay[20];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_GET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x2);
    pn_wr_be16(pay + 8, 0);
    pay[12] = PN_DCP_OPT_DEV;
    pay[13] = PN_DCP_SUB_DEV_NAME;
    pn_wr_be16(pay + 14, 0);
    pn_wr_be16(pay + 10, 4);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(frame, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay, 16);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    int found_name = 0, found_ip_mac = 0;
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found_name = 1;
        }
        /* Get asked only NameOfStation; MAC block 02 FB should still be src */
    }
    expect(found_name, "DCP Get NameOfStation returns station name");
    (void)found_ip_mac;
    pn_stack_destroy(s);
}

static void test_cm_connect_prmend(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    do_connect(s);
    /* FrameID 0x8123 must be used, not SendClock 32 */
    uint8_t in[4];
    uint8_t pattern[4] = {0x11, 0x22, 0x33, 0x44};
    pn_stack_write_input(s, 0, pattern, 4);

    do_prmend(s);
    expect(pn_stack_ar_up(s), "AR up after PrmEnd / ApplicationReady");
    expect(pn_stack_cm_state(s) == PN_CM_DATAEX, "CM DATAEX");

    uint8_t tx[PN_FRAME_MAX];
    size_t tlen = 0;
    uint32_t dip = 0;
    uint16_t dport = 0;
    int trc = pn_stack_take_rpc_tx(s, tx, sizeof(tx), &tlen, &dip, &dport);
    expect(trc == 0 && tlen > 80, "ApplicationReady RPC queued");
    int saw_apprdy = 0;
    for (size_t i = 0; i + 2 < tlen; i++) {
        if (pn_rd_be16(tx + i) == PN_BLOCK_APPRDY_REQ) {
            saw_apprdy = 1;
            break;
        }
    }
    expect(saw_apprdy, "queued RPC contains IOXBlock ApplicationReady");
    expect(dport == PN_RPC_PORT, "ApplicationReady dest port 34964");

    cap.n = 0;
    pn_stack_poll(s);
    int saw_fid = 0;
    for (int i = 0; i < cap.n; i++) {
        if (cap.lens[i] < 16) {
            continue;
        }
        uint16_t et = pn_rd_be16(cap.frames[i] + 12);
        if (et != PN_ETHTYPE_PN) {
            continue;
        }
        uint16_t fid = pn_rd_be16(cap.frames[i] + 14);
        if (fid == 0x8123 && cap.frames[i][16] == 0x11 &&
            cap.frames[i][17] == 0x22) {
            saw_fid = 1;
            expect(cap.frames[i][16 + 32] == PN_IOPS_GOOD,
                   "IOPS GOOD after input data");
        }
    }
    expect(saw_fid, "RTC1 input uses Connect FrameID 0x8123 and process data");

    /* controller output CR uses device-assigned 0x8000 */
    uint8_t opay[48];
    memset(opay, 0, sizeof(opay));
    pn_wr_be16(opay, 0x8000);
    memset(opay + 2, 0xAB, 8);
    opay[10] = PN_IOPS_GOOD;
    uint8_t oframe[PN_FRAME_MAX];
    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    size_t oflen =
        pn_eth_build(oframe, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, opay, 46);
    pn_stack_handle_eth(s, oframe, oflen);
    uint8_t outb[8];
    expect(pn_stack_read_output(s, 0, outb, 8) == 0, "read output image");
    expect(outb[0] == 0xAB && outb[7] == 0xAB, "output C_SDU copied to image");

    pn_stack_destroy(s);
    (void)in;
}

static size_t put_iod_write_hdr(uint8_t *p, uint16_t seq, uint32_t api,
                                uint16_t slot, uint16_t sub, uint16_t index,
                                uint32_t dlen)
{
    pn_wr_be16(p, PN_BLOCK_WRITE_REQ);
    pn_wr_be16(p + 2, 60);
    p[4] = 1;
    p[5] = 0;
    memset(p + 6, 0, 58);
    pn_wr_be16(p + 6, seq);
    pn_wr_be32(p + 6 + 18, api);
    pn_wr_be16(p + 6 + 22, slot);
    pn_wr_be16(p + 6 + 24, sub);
    pn_wr_be16(p + 6 + 28, index);
    pn_wr_be32(p + 6 + 30, dlen);
    return 64;
}

static size_t build_read_pdu(uint8_t *pdu, uint16_t slot, uint16_t sub,
                             uint16_t index)
{
    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body + 22, slot);
    pn_wr_be16(body + 24, sub);
    pn_wr_be16(body + 28, index);
    uint8_t blk[80];
    size_t bn = wr_pn_block(blk, PN_BLOCK_READ_REQ, body, 58);
    uint8_t stub[160];
    size_t sn = ndr_wrap_le(stub, blk, bn);
    return rpc_req(pdu, 2, stub, sn);
}

static int count_block(const uint8_t *resp, size_t n, uint16_t want)
{
    if (n < 100) {
        return 0;
    }
    const uint8_t *p = resp + 100;
    size_t left = n - 100;
    size_t off = 0;
    int c = 0;
    while (off + 6 <= left) {
        uint16_t type = pn_rd_be16(p + off);
        uint16_t blen = pn_rd_be16(p + off + 2);
        if (type == want) {
            c++;
        }
        if (blen < 2 || off + 4u + blen > left) {
            break;
        }
        off += 4u + blen;
        if (off & 1u) {
            off++;
        }
    }
    return c;
}

static size_t build_expsub_pdev_body(uint8_t *b)
{
    memset(b, 0, 48);
    pn_wr_be16(b + 0, 1);
    pn_wr_be32(b + 2, 0);
    pn_wr_be16(b + 6, 0);
    pn_wr_be32(b + 8, 1);
    pn_wr_be16(b + 12, 0);
    pn_wr_be16(b + 14, 3);
    pn_wr_be16(b + 16, 1);
    pn_wr_be32(b + 18, 1);
    pn_wr_be16(b + 22, 0);
    pn_wr_be16(b + 24, 0x8000);
    pn_wr_be32(b + 26, 2);
    pn_wr_be16(b + 30, 0);
    pn_wr_be16(b + 32, 0x8001);
    pn_wr_be32(b + 34, 3);
    pn_wr_be16(b + 38, 0);
    return 40;
}

static void test_cm_write_read(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    do_connect(s);

    uint8_t data[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t blocks[128];
    size_t bn = put_iod_write_hdr(blocks, 1, 0, 1, 1, 1, 4);
    memcpy(blocks + bn, data, 4);
    bn += 4;
    uint8_t stub[200];
    size_t sn = ndr_wrap_le(stub, blocks, bn);
    uint8_t pdu[400];
    size_t plen = rpc_req(pdu, 3, stub, sn);
    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Write.res returned");
    expect(count_block(resp, rlen, PN_BLOCK_WRITE_RES) == 1,
           "single Write returns one IODWriteRes");

    uint8_t inner[160];
    size_t in = 0;
    in += put_iod_write_hdr(inner + in, 2, 0, 0, 0x8000, 0x8071, 4);
    memcpy(inner + in, data, 4);
    in += 4;
    in += put_iod_write_hdr(inner + in, 3, 0, 0, 0x8001, 0x802F, 4);
    memcpy(inner + in, data, 4);
    in += 4;
    uint8_t multi[256];
    size_t mn = put_iod_write_hdr(multi, 1, 0xffffffffu, 0xffff, 0xffff,
                                  PN_INDEX_WRITE_MULTI, (uint32_t)in);
    memcpy(multi + mn, inner, in);
    mn += in;
    sn = ndr_wrap_le(stub, multi, mn);
    plen = rpc_req(pdu, 3, stub, sn);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "WriteMultiple.res returned");
    expect(count_block(resp, rlen, PN_BLOCK_WRITE_RES) == 3,
           "WriteMultiple returns outer + two inner IODWriteRes");
    if (rlen > 136) {
        expect(pn_rd_be32(resp + 100 + 36) == 128,
               "WriteMultiple outer recordDataLength is 2×64");
    }

    plen = build_read_pdu(pdu, 0, 1, PN_INDEX_IM0);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Read I&M0 returned");
    expect(contains(resp, rlen, "FB-ARCH-PN-DEV"), "I&M0 OrderID");
    expect(count_block(resp, rlen, PN_BLOCK_IM0) == 1, "I&M0 wrapped as 0x0020");

    plen = build_read_pdu(pdu, 0, 1, PN_INDEX_REALIDENT_API);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Read RealIdent returned");
    expect(count_block(resp, rlen, PN_BLOCK_REALIDENT) == 1,
           "RealIdent block type 0x0013");
    int saw_slot1 = 0;
    if (rlen > 100) {
        for (size_t i = 100; i + 6 <= rlen; i++) {
            if (pn_rd_be16(resp + i) == 1 && pn_rd_be32(resp + i + 2) == 0x10u) {
                saw_slot1 = 1;
                break;
            }
        }
    }
    expect(saw_slot1, "RealIdent contains slot 1 module ident 0x10");

    plen = build_read_pdu(pdu, 0, 0x8001, PN_INDEX_PDPORT_REAL);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Read PDPortDataReal returned");
    expect(contains(resp, rlen, "port-001"), "PDPortDataReal OwnPortID");

    do_prmend(s);
    expect(pn_stack_ar_up(s), "AR up after Write/Read then PrmEnd");
    pn_stack_destroy(s);
}

static void test_cm_pdev_expected(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    static const uint8_t uuid[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                                     9, 10, 11, 12, 13, 14, 15, 16};
    static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t ar[64], iin[64], iout[64], exp[48], pdev[48];
    size_t an = build_ar_body(ar, uuid, mac);
    size_t nin = build_iocr_body(iin, PN_IOCR_INPUT, 1, 40, 0x8123, 32, 8, 3, 1,
                                 1, 0, 33);
    size_t nout = build_iocr_body(iout, PN_IOCR_OUTPUT, 2, 40, 0xFFFF, 32, 8, 3,
                                  1, 1, 0, 9);
    size_t ne = build_expsub_body(exp, 32, 8);
    size_t np = build_expsub_pdev_body(pdev);
    uint8_t blocks[512];
    size_t n = 0;
    n += wr_pn_block(blocks + n, PN_BLOCK_AR_REQ, ar, (uint16_t)an);
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iin, (uint16_t)nin);
    n += wr_pn_block(blocks + n, PN_BLOCK_IOCR_REQ, iout, (uint16_t)nout);
    n += wr_pn_block(blocks + n, PN_BLOCK_EXPSUB_REQ, pdev, (uint16_t)np);
    n += wr_pn_block(blocks + n, PN_BLOCK_EXPSUB_REQ, exp, (uint16_t)ne);
    uint8_t stub[600];
    size_t sn = ndr_wrap_le(stub, blocks, n);
    uint8_t pdu[800];
    size_t plen = rpc_req(pdu, 0, stub, sn);
    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc_from(s, pdu, plen, 0xC0A80001u, 34964, resp,
                                      sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Connect with PDev ExpectedSubmodule");
    expect(!pn_stack_ar_up(s), "still not cyclic before PrmEnd");

    plen = build_read_pdu(pdu, 0, 1, PN_INDEX_REALIDENT_API);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0, "RealIdent after PDev Connect");
    int saw_if = 0, saw_port = 0, saw_io = 0;
    if (rlen > 100) {
        for (size_t i = 100; i + 6 <= rlen; i++) {
            uint16_t v = pn_rd_be16(resp + i);
            if (v == 0x8000) {
                saw_if = 1;
            }
            if (v == 0x8001) {
                saw_port = 1;
            }
            if (v == 1 && pn_rd_be32(resp + i + 2) == 0x11u) {
                saw_io = 1;
            }
        }
    }
    expect(saw_if && saw_port, "RealIdent lists PDev subslots 0x8000/0x8001");
    expect(saw_io, "RealIdent still lists IO submodule ident 0x11");

    uint8_t pattern[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    pn_stack_write_input(s, 0, pattern, 4);
    do_prmend(s);
    cap.n = 0;
    pn_stack_poll(s);
    int saw_fid = 0;
    for (int i = 0; i < cap.n; i++) {
        if (cap.lens[i] < 18) {
            continue;
        }
        if (pn_rd_be16(cap.frames[i] + 12) != PN_ETHTYPE_PN) {
            continue;
        }
        if (pn_rd_be16(cap.frames[i] + 14) == 0x8123 &&
            cap.frames[i][16] == 0xAA) {
            saw_fid = 1;
        }
    }
    expect(saw_fid, "PDev ExpectedSubmodule does not steal IO process image");
    pn_stack_destroy(s);
}

static void test_watchdog(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    do_connect(s);
    do_prmend(s);
    expect(pn_stack_ar_up(s), "AR up before watchdog");
    usleep(40000); /* 40ms > 8ms * watchdog 3 */
    pn_stack_poll(s);
    expect(!pn_stack_ar_up(s), "AR down after output watchdog");
    pn_stack_destroy(s);
}

int main(void)
{
    test_hmac();
    test_dcp_identify();
    test_dcp_identify_filter();
    test_dcp_get();
    test_dcp_set_sec();
    test_connect_sec();
    test_cm_connect_prmend();
    test_cm_write_read();
    test_cm_pdev_expected();
    test_watchdog();
    if (g_fail) {
        fprintf(stderr, "pn stack tests FAILED\n");
        return 1;
    }
    fprintf(stderr, "pn stack tests OK\n");
    return 0;
}
