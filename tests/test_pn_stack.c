#include "pn_crypto.h"
#include "pn_endian.h"
#include "pn_stack.h"

#include <errno.h>
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

static int contains_bytes(const uint8_t *hay, size_t n, const void *needle,
                          size_t nlen)
{
    const uint8_t *nd = needle;
    if (!hay || nlen == 0 || n < nlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= n; i++) {
        if (memcmp(hay + i, nd, nlen) == 0) {
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

static void test_dcp_set_unsigned(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "old-name");
    cfg.security_class = 0;
    pn_stack_t *s = pn_stack_create(&cfg);
    tx_cap_t cap;
    memset(&cap, 0, sizeof(cap));
    pn_eth_ops_t ops = {.send = cap_send, .recv = NULL, .ctx = &cap};
    pn_stack_set_eth_ops(s, ops);
    pn_stack_start(s);

    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t nameblk[2 + 8];
    pn_wr_be16(nameblk, 1);
    memcpy(nameblk + 2, "new-name", 8);
    uint8_t blocks[32];
    size_t bn = append_dcp_block(blocks, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                                 nameblk, 10);
    uint8_t pay[64];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xAABB0001);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(frame, sizeof(frame), dst, src, PN_ETHTYPE_PN, pay,
                     12 + bn);
    pn_stack_handle_eth(s, frame, flen);
    expect(strcmp(pn_stack_cfg(s)->station_name, "new-name") == 0,
           "unsigned DCP Set accepted when security_class is 0");

    uint8_t ipb[14];
    pn_wr_be16(ipb, 1);
    pn_wr_be32(ipb + 2, 0xC0A80A32u);
    pn_wr_be32(ipb + 6, 0xFFFFFF00u);
    pn_wr_be32(ipb + 10, 0xC0A80A01u);
    bn = append_dcp_block(blocks, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb, 14);
    pn_wr_be32(pay + 4, 0xAABB0002);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    flen = pn_eth_build(frame, sizeof(frame), dst, src, PN_ETHTYPE_PN, pay,
                        12 + bn);
    pn_stack_handle_eth(s, frame, flen);
    expect(pn_stack_cfg(s)->ip == 0xC0A80A32u,
           "DCP Set IPParameter updates cfg.ip");
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
    uint8_t alarmcr[20];
    memset(alarmcr, 0, sizeof(alarmcr));
    pn_wr_be16(alarmcr + 0, 1);
    pn_wr_be16(alarmcr + 2, 0x8892);
    pn_wr_be32(alarmcr + 4, 0);
    pn_wr_be16(alarmcr + 8, 1);
    pn_wr_be16(alarmcr + 10, 3);
    pn_wr_be16(alarmcr + 12, 3);
    pn_wr_be16(alarmcr + 14, 200);
    pn_wr_be16(alarmcr + 16, 0xC000);
    pn_wr_be16(alarmcr + 18, 0xA000);
    n += wr_pn_block(blocks + n, PN_BLOCK_ALARMCR_REQ, alarmcr, sizeof(alarmcr));
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

static void inject_lldp_neighbor(pn_stack_t *s, const char *name)
{
    static const uint8_t dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t pdu[64];
    size_t n = 0;
    pdu[n++] = 0x02;
    pdu[n++] = 0x07;
    pdu[n++] = 4;
    memcpy(pdu + n, src, 6);
    n += 6;
    pdu[n++] = 0x04;
    pdu[n++] = 0x07;
    pdu[n++] = 3;
    memcpy(pdu + n, src, 6);
    n += 6;
    pdu[n++] = 0x06;
    pdu[n++] = 0x02;
    pdu[n++] = 0x00;
    pdu[n++] = 0x14;
    size_t nl = strlen(name);
    pdu[n++] = 0x0A;
    pdu[n++] = (uint8_t)nl;
    memcpy(pdu + n, name, nl);
    n += nl;
    pdu[n++] = 0x00;
    pdu[n++] = 0x00;
    uint8_t frame[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(frame, sizeof(frame), dst, src, PN_ETHTYPE_LLDP, pdu, n);
    pn_stack_handle_eth(s, frame, flen);
}

static void pump_output_cr(pn_stack_t *s)
{
    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t opay[48];
    memset(opay, 0, sizeof(opay));
    pn_wr_be16(opay, 0x8000);
    opay[10] = PN_IOPS_GOOD;
    opay[44] = PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID | PN_DATASTATUS_RUN;
    uint8_t oframe[PN_FRAME_MAX];
    size_t flen =
        pn_eth_build(oframe, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, opay, 46);
    pn_stack_handle_eth(s, oframe, flen);
}

static int find_rta_data(tx_cap_t *cap, int *idx)
{
    for (int i = 0; i < cap->n; i++) {
        if (cap->lens[i] < 28) {
            continue;
        }
        if (pn_rd_be16(cap->frames[i] + 12) != PN_ETHTYPE_PN) {
            continue;
        }
        uint16_t fid = pn_rd_be16(cap->frames[i] + 14);
        if (fid == PN_FRAMEID_ALARM_HIGH || fid == PN_FRAMEID_ALARM_LOW) {
            uint8_t kind = (uint8_t)(cap->frames[i][20] & 0x0Fu);
            if (kind == 1) {
                *idx = i;
                return 1;
            }
        }
    }
    return 0;
}

static void ack_rta_frame(pn_stack_t *s, const uint8_t *f)
{
    uint16_t fid = pn_rd_be16(f + 14);
    uint16_t dst_ref = pn_rd_be16(f + 16);
    uint16_t src_ref = pn_rd_be16(f + 18);
    uint16_t send_seq = pn_rd_be16(f + 22);
    uint8_t ack[64];
    memset(ack, 0, sizeof(ack));
    memcpy(ack, f + 6, 6);
    memcpy(ack + 6, f, 6);
    pn_wr_be16(ack + 12, PN_ETHTYPE_PN);
    pn_wr_be16(ack + 14, fid);
    pn_wr_be16(ack + 16, src_ref);
    pn_wr_be16(ack + 18, dst_ref);
    ack[20] = 0x13;
    ack[21] = 0x21;
    pn_wr_be16(ack + 22, 0xFFFF);
    pn_wr_be16(ack + 24, send_seq);
    pn_stack_handle_eth(s, ack, 60);
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
    int saw_arsrv = 0, saw_moddiff = 0, saw_alarm = 0;
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
            if (type == PN_BLOCK_ALARMCR_RES) {
                saw_alarm = 1;
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
    expect(saw_alarm, "Connect.res contains AlarmCRBlockRes 0x8103");
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

static int do_apprdy_ack(pn_stack_t *s)
{
    uint8_t tx[PN_FRAME_MAX];
    size_t tlen = 0;
    uint32_t dip = 0;
    uint16_t dport = 0;
    int trc = pn_stack_take_rpc_tx(s, tx, sizeof(tx), &tlen, &dip, &dport);
    expect(trc == 0 && tlen > 80, "ApplicationReady RPC queued");
    if (trc != 0 || tlen < 2) {
        return -1;
    }
    tx[1] = 2;
    uint8_t resp[512];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc(s, tx, tlen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && pn_stack_ar_up(s), "DATAEX after ApplicationReady ACK");
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

    /* DeviceID match / mismatch */
    memset(pay, 0, sizeof(pay));
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x3);
    pn_wr_be16(pay + 8, 0);
    pay[12] = PN_DCP_OPT_DEV;
    pay[13] = PN_DCP_SUB_DEV_ID;
    pn_wr_be16(pay + 14, 4);
    pn_wr_be16(pay + 16, 0x0001);
    pn_wr_be16(pay + 18, 0x0001);
    pn_wr_be16(pay + 10, 8);
    flen = pn_eth_build(frame, PN_FRAME_MAX, mc, src, PN_ETHTYPE_PN, pay, 20);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    found = 0;
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found = 1;
        }
    }
    expect(!found, "Identify with other DeviceID is ignored");

    pn_wr_be16(pay + 16, 0xABCD);
    pn_wr_be16(pay + 18, 0x0001);
    flen = pn_eth_build(frame, PN_FRAME_MAX, mc, src, PN_ETHTYPE_PN, pay, 20);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    found = 0;
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found = 1;
        }
    }
    expect(found, "Identify with matching DeviceID is answered");

    /* IP-only filter is not AllSelector and not Name/DeviceID. */
    memset(pay, 0, sizeof(pay));
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x4);
    pn_wr_be16(pay + 8, 0);
    pay[12] = PN_DCP_OPT_IP;
    pay[13] = PN_DCP_SUB_IP_PARAM;
    pn_wr_be16(pay + 14, 0);
    pn_wr_be16(pay + 10, 4);
    flen = pn_eth_build(frame, PN_FRAME_MAX, mc, src, PN_ETHTYPE_PN, pay, 16);
    cap.n = 0;
    pn_stack_handle_eth(s, frame, flen);
    found = 0;
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found = 1;
        }
    }
    expect(!found, "Identify with IP-only filter is ignored");
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

    pay[13] = PN_DCP_SUB_DEV_ID;
    pn_wr_be32(pay + 4, 0x3);
    cap.n = 0;
    flen = pn_eth_build(frame, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay, 16);
    pn_stack_handle_eth(s, frame, flen);
    int found_id = 0;
    for (int i = 0; i < cap.n; i++) {
        for (size_t j = 0; j + 4 <= cap.lens[i]; j++) {
            if (pn_rd_be16(cap.frames[i] + j) == 0xABCD &&
                pn_rd_be16(cap.frames[i] + j + 2) == 0x0001) {
                found_id = 1;
            }
        }
    }
    expect(found_id, "DCP Get DeviceID returns vendor/device");
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
    expect(!pn_stack_ar_up(s), "cyclic not up before ApplicationReady ACK");
    expect(pn_stack_cm_state(s) == PN_CM_W_APPRDY, "CM W_APPRDY after PrmEnd");

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
    tx[1] = 2;
    {
        uint8_t rbuf[512];
        size_t rlen = 0;
        expect(pn_stack_handle_rpc(s, tx, tlen, rbuf, sizeof(rbuf), &rlen) == 0,
               "ApplicationReady ACK accepted");
    }
    expect(pn_stack_ar_up(s), "AR up after ApplicationReady ACK");
    expect(pn_stack_cm_state(s) == PN_CM_DATAEX, "CM DATAEX");

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

    inject_lldp_neighbor(s, "ctl-lab1");
    static const uint8_t peer_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    plen = build_read_pdu(pdu, 0, 0x8001, PN_INDEX_PDPORT_REAL);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Read PDPortDataReal returned");
    expect(contains(resp, rlen, "port-001"), "PDPortDataReal OwnPortID");
    expect(contains_bytes(resp, rlen, peer_mac, 6),
           "PDPortDataReal NumberOfPeers includes LLDP chassis");

    plen = build_read_pdu(pdu, 0, 0x8001, PN_INDEX_PDPORT_CHECK);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80 &&
               count_block(resp, rlen, PN_BLOCK_PDPORT_CHECK) >= 1,
           "PDPortDataCheck default CheckPeers after LLDP");

    plen = build_read_pdu(pdu, 0, 0x8000, PN_INDEX_PDIF_FSU);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "PDIF FSU empty success");

    {
        uint8_t fsu[16];
        memset(fsu, 0, sizeof(fsu));
        pn_wr_be16(fsu, PN_BLOCK_PDIF_FSU);
        pn_wr_be16(fsu + 2, 12);
        fsu[4] = 1;
        fsu[6] = 0x11;
        bn = put_iod_write_hdr(blocks, 6, 0, 0, 0x8000, PN_INDEX_PDIF_FSU,
                               sizeof(fsu));
        memcpy(blocks + bn, fsu, sizeof(fsu));
        bn += sizeof(fsu);
        sn = ndr_wrap_le(stub, blocks, bn);
        plen = rpc_req(pdu, 3, stub, sn);
        rlen = 0;
        rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
        expect(rc == 0 && count_block(resp, rlen, PN_BLOCK_WRITE_RES) == 1,
               "PDIF FSU Write.res");
        plen = build_read_pdu(pdu, 0, 0x8000, PN_INDEX_PDIF_FSU);
        rlen = 0;
        rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
        expect(rc == 0 && rlen > 80 &&
                   count_block(resp, rlen, PN_BLOCK_PDIF_FSU) >= 1,
               "PDIF FSU stored after Write");
    }

    plen = build_read_pdu(pdu, 0, 0x8000, PN_INDEX_PDIF_REAL);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "Read PDInterfaceDataReal returned");
    expect(contains(resp, rlen, "sensor-line1"),
           "PDInterfaceDataReal station name");
    expect(count_block(resp, rlen, PN_BLOCK_PDIF_REAL) == 1,
           "PDInterfaceDataReal block type 0x0240");

    uint8_t im1[60];
    memset(im1, ' ', sizeof(im1));
    pn_wr_be16(im1, PN_BLOCK_IM1);
    pn_wr_be16(im1 + 2, 56);
    im1[4] = 1;
    im1[5] = 0;
    memcpy(im1 + 6, "LINE-A", 6);
    memcpy(im1 + 38, "CAB-1", 5);
    bn = put_iod_write_hdr(blocks, 4, 0, 0, 1, PN_INDEX_IM1, sizeof(im1));
    memcpy(blocks + bn, im1, sizeof(im1));
    bn += sizeof(im1);
    sn = ndr_wrap_le(stub, blocks, bn);
    plen = rpc_req(pdu, 3, stub, sn);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && count_block(resp, rlen, PN_BLOCK_WRITE_RES) == 1,
           "I&M1 Write.res");
    plen = build_read_pdu(pdu, 0, 1, PN_INDEX_IM1);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && contains(resp, rlen, "LINE-A") &&
               contains(resp, rlen, "CAB-1") &&
               count_block(resp, rlen, PN_BLOCK_IM1) == 1,
           "I&M1 TagFunction/Location after Write");

    plen = build_read_pdu(pdu, 0, 1, PN_INDEX_IM2);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && contains(resp, rlen, "2020-01-01") &&
               count_block(resp, rlen, PN_BLOCK_IM2) == 1,
           "I&M2 default date");

    plen = build_read_pdu(pdu, 0, 0x8001, PN_INDEX_PDPORT_STAT);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80 &&
               count_block(resp, rlen, PN_BLOCK_PDPORT_STAT) == 1,
           "PDPortStatistic 0x802F");

    plen = build_read_pdu(pdu, 0, 1, 0x1234);
    rlen = 0;
    rc = pn_stack_handle_rpc(s, pdu, plen, resp, sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 80, "unknown record index still succeeds");
    expect(count_block(resp, rlen, PN_BLOCK_READ_RES) >= 1,
           "unknown index wrapped as IODReadRes");

    do_prmend(s);
    do_apprdy_ack(s);
    expect(pn_stack_ar_up(s), "AR up after Write/Read then AppReady");
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
    do_apprdy_ack(s);
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

static void test_lldp_start(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    int saw = 0;
    for (int i = 0; i < cap.n; i++) {
        if (cap.lens[i] < 14) {
            continue;
        }
        if (pn_rd_be16(cap.frames[i] + 12) == PN_ETHTYPE_LLDP &&
            contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            saw = 1;
        }
    }
    expect(saw, "LLDP sent on start with station name");
    pn_stack_destroy(s);
}

static void test_lldp_remote(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    inject_lldp_neighbor(s, "ctl-lab1");
    char rem[64];
    expect(pn_stack_lldp_remote_name(s, rem, sizeof(rem)) == 0 &&
               strcmp(rem, "ctl-lab1") == 0,
           "LLDP RX stores remote sysName");
    pn_stack_destroy(s);
}

static size_t snmp_pdu(uint8_t *out, uint8_t rid, uint8_t pdu_tag,
                       const uint8_t *oid, size_t olen)
{
    uint8_t vb[80];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x05;
    vb[i++] = 0x00;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);
    uint8_t vbl[96];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;
    uint8_t pdu[160];
    size_t p = 0;
    pdu[p++] = pdu_tag;
    size_t pdu_len_at = p++;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = rid;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);
    size_t m = 0;
    out[m++] = 0x30;
    size_t msg_len_at = m++;
    out[m++] = 0x02;
    out[m++] = 0x01;
    out[m++] = 0x00;
    out[m++] = 0x04;
    out[m++] = 0x06;
    memcpy(out + m, "public", 6);
    m += 6;
    memcpy(out + m, pdu, p);
    m += p;
    out[msg_len_at] = (uint8_t)(m - msg_len_at - 1);
    return m;
}

/* Same Get as snmp_pdu but PDU length is BER long-form 0x81. */
static size_t snmp_pdu_long_len(uint8_t *out, uint8_t rid, const uint8_t *oid,
                                size_t olen)
{
    uint8_t vb[80];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x05;
    vb[i++] = 0x00;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);
    uint8_t vbl[96];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;
    uint8_t pdu[160];
    size_t p = 0;
    pdu[p++] = 0xa0;
    pdu[p++] = 0x81;
    size_t pdu_len_at = p++;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = rid;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);
    size_t m = 0;
    out[m++] = 0x30;
    size_t msg_len_at = m++;
    out[m++] = 0x02;
    out[m++] = 0x01;
    out[m++] = 0x00;
    out[m++] = 0x04;
    out[m++] = 0x06;
    memcpy(out + m, "public", 6);
    m += 6;
    memcpy(out + m, pdu, p);
    m += p;
    out[msg_len_at] = (uint8_t)(m - msg_len_at - 1);
    return m;
}

static size_t snmp_pdu_set(uint8_t *out, uint8_t rid, const uint8_t *oid,
                           size_t olen, const char *str)
{
    size_t sl = strlen(str);
    uint8_t vb[120];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x04;
    vb[i++] = (uint8_t)sl;
    memcpy(vb + i, str, sl);
    i += sl;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);
    uint8_t vbl[136];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;
    uint8_t pdu[180];
    size_t p = 0;
    pdu[p++] = 0xA3;
    size_t pdu_len_at = p++;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = rid;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00;
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);
    size_t m = 0;
    out[m++] = 0x30;
    size_t msg_len_at = m++;
    out[m++] = 0x02;
    out[m++] = 0x01;
    out[m++] = 0x00;
    out[m++] = 0x04;
    out[m++] = 0x06;
    memcpy(out + m, "public", 6);
    m += 6;
    memcpy(out + m, pdu, p);
    m += p;
    out[msg_len_at] = (uint8_t)(m - msg_len_at - 1);
    return m;
}

static size_t snmp_pdu_bulk(uint8_t *out, uint8_t rid, uint8_t max_rep,
                            const uint8_t *oid, size_t olen)
{
    uint8_t vb[80];
    size_t i = 0;
    vb[i++] = 0x30;
    size_t vb_len_at = i++;
    vb[i++] = 0x06;
    vb[i++] = (uint8_t)olen;
    memcpy(vb + i, oid, olen);
    i += olen;
    vb[i++] = 0x05;
    vb[i++] = 0x00;
    vb[vb_len_at] = (uint8_t)(i - vb_len_at - 1);
    uint8_t vbl[96];
    size_t v = 0;
    vbl[v++] = 0x30;
    vbl[v++] = (uint8_t)i;
    memcpy(vbl + v, vb, i);
    v += i;
    uint8_t pdu[160];
    size_t p = 0;
    pdu[p++] = 0xA5;
    size_t pdu_len_at = p++;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = rid;
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = 0x00; /* non-repeaters */
    pdu[p++] = 0x02;
    pdu[p++] = 0x01;
    pdu[p++] = max_rep;
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);
    size_t m = 0;
    out[m++] = 0x30;
    size_t msg_len_at = m++;
    out[m++] = 0x02;
    out[m++] = 0x01;
    out[m++] = 0x00;
    out[m++] = 0x04;
    out[m++] = 0x06;
    memcpy(out + m, "public", 6);
    m += 6;
    memcpy(out + m, pdu, p);
    m += p;
    out[msg_len_at] = (uint8_t)(m - msg_len_at - 1);
    return m;
}

static int snmp_has(const uint8_t *resp, size_t n, const void *needle,
                    size_t nlen)
{
    if (!resp || nlen == 0 || n < nlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= n; i++) {
        if (memcmp(resp + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_snmp_mib(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    static const uint8_t oid_sys[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01};
    static const uint8_t oid_sysname[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                          0x05, 0x00};
    static const uint8_t oid_ifnumber[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                           0x01, 0x00};
    static const uint8_t oid_ifphys[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                         0x02, 0x01, 0x06, 0x01};
    static const uint8_t oid_lldp_loc[] = {0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
                                           0x01, 0x03, 0x03, 0x00};
    static const uint8_t oid_lldp_rem[] = {0x28, 0xc4, 0x62, 0x01, 0x01, 0x02,
                                           0x01, 0x04, 0x01, 0x01, 0x09, 0x00,
                                           0x01, 0x01};
    uint8_t req[256], resp[1024];
    size_t rlen = 0;
    size_t qn = snmp_pdu(req, 1, 0xa0, oid_sysname, sizeof(oid_sysname));
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "sensor-line1"),
           "SNMP Get sysName");
    qn = snmp_pdu_long_len(req, 20, oid_sysname, sizeof(oid_sysname));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "sensor-line1"),
           "SNMP Get sysName with long-form BER PDU length");
    qn = snmp_pdu(req, 2, 0xa1, oid_sys, sizeof(oid_sys));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "Fieldbus PN Device"),
           "SNMP GetNext system → sysDescr");
    qn = snmp_pdu(req, 3, 0xa0, oid_ifnumber, sizeof(oid_ifnumber));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x02\x01\x01", 3),
           "SNMP Get ifNumber=1");
    static const uint8_t mac[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    qn = snmp_pdu(req, 4, 0xa0, oid_ifphys, sizeof(oid_ifphys));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, mac, 6),
           "SNMP Get ifPhysAddress");
    qn = snmp_pdu(req, 5, 0xa0, oid_lldp_loc, sizeof(oid_lldp_loc));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "sensor-line1"),
           "SNMP Get lldpLocSysName");

    static const uint8_t oid_ipaddr[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x04,
                                         0x14, 0x01, 0x01, 0x00, 0x00, 0x00,
                                         0x00};
    qn = snmp_pdu(req, 10, 0xa0, oid_ipaddr, sizeof(oid_ipaddr));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x00\x00\x00\x00", 4),
           "SNMP Get ipAdEntAddr 0.0.0.0");
    static const uint8_t oid_icmp[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x01,
                                       0x00};
    qn = snmp_pdu(req, 11, 0xa0, oid_icmp, sizeof(oid_icmp));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x41", 1),
           "SNMP Get icmpInMsgs Counter32");
    qn = snmp_pdu_bulk(req, 12, 3, oid_sys, sizeof(oid_sys));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0,
           "SNMP GetBulk system");
    {
        int n_oid = 0;
        for (size_t i = 0; i + 1 < rlen; i++) {
            if (resp[i] == 0x06) {
                n_oid++;
            }
        }
        expect(n_oid >= 3, "SNMP GetBulk max-repetitions returns 3 varbinds");
        expect(contains(resp, rlen, "Fieldbus PN Device"),
               "SNMP GetBulk includes sysDescr");
    }
    static const uint8_t oid_tcp[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x06, 0x01,
                                      0x00};
    qn = snmp_pdu(req, 30, 0xa0, oid_tcp, sizeof(oid_tcp));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x02\x01\x04", 3),
           "SNMP Get tcpRtoAlgorithm");
    static const uint8_t oid_at[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x03, 0x01,
                                     0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00};
    qn = snmp_pdu(req, 31, 0xa0, oid_at, sizeof(oid_at));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x02\x01\x01", 3),
           "SNMP Get atIfIndex");

    inject_lldp_neighbor(s, "ctl-lab1");
    qn = snmp_pdu(req, 6, 0xa0, oid_lldp_rem, sizeof(oid_lldp_rem));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "ctl-lab1"),
           "SNMP Get lldpRemSysName after LLDP RX");
    static const uint8_t oid_lldp_rem_cap[] = {
        0x28, 0xc4, 0x62, 0x01, 0x01, 0x02, 0x01, 0x04, 0x01, 0x01, 0x0b, 0x00,
        0x01, 0x01};
    qn = snmp_pdu(req, 13, 0xa0, oid_lldp_rem_cap, sizeof(oid_lldp_rem_cap));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x00\x80", 2),
           "SNMP Get lldpRemSysCapSupported after LLDP RX");
    static const uint8_t oid_ifinoct[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02,
                                          0x02, 0x01, 0x0a, 0x01};
    qn = snmp_pdu(req, 7, 0xa0, oid_ifinoct, sizeof(oid_ifinoct));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               snmp_has(resp, rlen, "\x41", 1),
           "SNMP Get ifInOctets Counter32 after RX");
    static const uint8_t oid_sysloc[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                         0x06, 0x00};
    qn = snmp_pdu_set(req, 8, oid_sysloc, sizeof(oid_sysloc), "lab-rack");
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "lab-rack"),
           "SNMP Set sysLocation");
    qn = snmp_pdu(req, 9, 0xa0, oid_sysloc, sizeof(oid_sysloc));
    rlen = 0;
    expect(pn_stack_handle_snmp(s, req, qn, resp, sizeof(resp), &rlen) == 0 &&
               contains(resp, rlen, "lab-rack"),
           "SNMP Get sysLocation after Set");
    pn_stack_destroy(s);
}

static void test_rta_alarm(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    do_connect(s);
    do_prmend(s);
    do_apprdy_ack(s);
    cap.n = 0;
    pn_stack_poll(s);
    int saw_idle = 0;
    for (int i = 0; i < cap.n; i++) {
        if (cap.lens[i] >= 16 &&
            pn_rd_be16(cap.frames[i] + 14) == PN_FRAMEID_ALARM_HIGH) {
            saw_idle = 1;
        }
    }
    expect(!saw_idle, "no diagnosis RTA until appear is requested");
    pn_stack_diag_appear(s);
    cap.n = 0;
    pn_stack_poll(s);
    int saw = 0;
    int idx = -1;
    for (int i = 0; i < cap.n; i++) {
        if (cap.lens[i] < 28) {
            continue;
        }
        if (pn_rd_be16(cap.frames[i] + 12) != PN_ETHTYPE_PN) {
            continue;
        }
        uint16_t fid = pn_rd_be16(cap.frames[i] + 14);
        if (fid == PN_FRAMEID_ALARM_HIGH || fid == PN_FRAMEID_ALARM_LOW) {
            uint8_t kind = (uint8_t)(cap.frames[i][20] & 0x0Fu);
            uint16_t dst_ref = pn_rd_be16(cap.frames[i] + 16);
            if (kind == 1 && dst_ref == 3) {
                saw = 1;
                idx = i;
            }
        }
    }
    expect(saw, "RTA Data 0xFC01 after DATAEX with controller alarm ref");
    if (saw && idx >= 0) {
        const uint8_t *f = cap.frames[idx];
        uint16_t fid = pn_rd_be16(f + 14);
        uint16_t dst_ref = pn_rd_be16(f + 16);
        uint16_t src_ref = pn_rd_be16(f + 18);
        uint16_t send_seq = pn_rd_be16(f + 22);
        uint8_t ack[64];
        memset(ack, 0, sizeof(ack));
        memcpy(ack, f + 6, 6);
        memcpy(ack + 6, f, 6);
        pn_wr_be16(ack + 12, PN_ETHTYPE_PN);
        pn_wr_be16(ack + 14, fid);
        pn_wr_be16(ack + 16, src_ref);
        pn_wr_be16(ack + 18, dst_ref);
        ack[20] = 0x13;
        ack[21] = 0x21;
        pn_wr_be16(ack + 22, 0xFFFF);
        pn_wr_be16(ack + 24, send_seq);
        pn_stack_handle_eth(s, ack, 60);
        cap.n = 0;
        pn_stack_poll(s);
        int again = 0;
        for (int i = 0; i < cap.n; i++) {
            if (cap.lens[i] >= 16 &&
                pn_rd_be16(cap.frames[i] + 14) == PN_FRAMEID_ALARM_HIGH) {
                again = 1;
            }
        }
        expect(!again, "RTA Data not retransmitted immediately after ACK");
        uint8_t rpdu[256];
        size_t rlen = 0;
        size_t plen = build_read_pdu(rpdu, 0, 0x8001, PN_INDEX_CHAN_DIAG);
        uint8_t rresp[512];
        expect(pn_stack_handle_rpc(s, rpdu, plen, rresp, sizeof(rresp), &rlen) ==
                       0 &&
                   rlen > 80 &&
                   count_block(rresp, rlen, PN_BLOCK_DIAGNOSIS) >= 1,
               "ChannelDiagnosis 0x800A after RTA");
        plen = build_read_pdu(rpdu, 0, 0x8001, PN_INDEX_QUAL_CHAN_DIAG);
        rlen = 0;
        expect(pn_stack_handle_rpc(s, rpdu, plen, rresp, sizeof(rresp), &rlen) ==
                       0 &&
                   rlen > 80 &&
                   count_block(rresp, rlen, PN_BLOCK_DIAGNOSIS) >= 1,
               "QualifiedChannelDiagnosis 0x8011");
        pump_output_cr(s);
        pn_stack_diag_clear(s);
        cap.n = 0;
        pn_stack_poll(s);
        int didx = -1;
        expect(find_rta_data(&cap, &didx), "RTA disappear after diag_clear");
        if (didx >= 0) {
            const uint8_t *df = cap.frames[didx];
            uint16_t spec = pn_rd_be16(df + 14 + 14 + 30);
            expect(spec == PN_CHAN_DISAPPEARS_REM || spec == PN_CHAN_DISAPPEARS,
                   "disappear ChannelProperties 0x1800/0x1000");
            ack_rta_frame(s, df);
            plen = build_read_pdu(rpdu, 0, 0x8001, PN_INDEX_CHAN_DIAG);
            rlen = 0;
            expect(pn_stack_handle_rpc(s, rpdu, plen, rresp, sizeof(rresp),
                                       &rlen) == 0 &&
                       count_block(rresp, rlen, PN_BLOCK_DIAGNOSIS) == 0,
                   "ChannelDiagnosis cleared after disappear ACK");
            pn_stack_alarm_process(s);
            cap.n = 0;
            pn_stack_poll(s);
            int pidx = -1;
            expect(find_rta_data(&cap, &pidx), "RTA process alarm on request");
            if (pidx >= 0) {
                uint16_t altype = pn_rd_be16(cap.frames[pidx] + 14 + 14 + 6);
                expect(altype == PN_ALARM_TYPE_PROCESS,
                       "process AlarmType 0x0002");
                ack_rta_frame(s, cap.frames[pidx]);
            }
        }
        /* Controller → device RTA Data must be ACKed. */
        static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
        static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint8_t pay[32];
        memset(pay, 0, sizeof(pay));
        pn_wr_be16(pay, PN_FRAMEID_ALARM_HIGH);
        pn_wr_be16(pay + 2, 1);
        pn_wr_be16(pay + 4, 3);
        pay[6] = 0x11;
        pay[7] = 0x21;
        pn_wr_be16(pay + 8, 7);
        pn_wr_be16(pay + 10, 0xFFFF);
        pn_wr_be16(pay + 12, 0);
        uint8_t cfr[PN_FRAME_MAX];
        size_t clen =
            pn_eth_build(cfr, sizeof(cfr), dst, src, PN_ETHTYPE_PN, pay, 14);
        cap.n = 0;
        pn_stack_handle_eth(s, cfr, clen);
        int saw_ack = 0;
        for (int i = 0; i < cap.n; i++) {
            if (cap.lens[i] >= 22 &&
                pn_rd_be16(cap.frames[i] + 14) == PN_FRAMEID_ALARM_HIGH &&
                (cap.frames[i][20] & 0x0Fu) == 3) {
                saw_ack = 1;
            }
        }
        expect(saw_ack, "device ACKs controller RTA Data");
    }
    pn_stack_destroy(s);
}

static void test_irt_reject(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    uint8_t blocks[512];
    size_t bn = build_connect_stub(blocks, sizeof(blocks));
    size_t off = 0;
    while (off + 12 < bn) {
        uint16_t type = pn_rd_be16(blocks + off);
        uint16_t blen = pn_rd_be16(blocks + off + 2);
        if (type == PN_BLOCK_IOCR_REQ) {
            pn_wr_be32(blocks + off + 12, PN_RT_CLASS_3);
        }
        if (blen < 2) {
            break;
        }
        off += 4u + blen;
        if (off & 1u) {
            off++;
        }
    }
    uint8_t stub[600];
    size_t sn = ndr_wrap_le(stub, blocks, bn);
    uint8_t pdu[800];
    size_t plen = rpc_req(pdu, 0, stub, sn);
    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc_from(s, pdu, plen, 0xC0A80001u, 34964, resp,
                                      sizeof(resp), &rlen);
    expect(rc == 0 && rlen > 0, "IRT Connect returns RPC");
    expect(pn_stack_cm_state(s) == PN_CM_OFFLINE,
           "CC-C RT_CLASS_3 Connect is rejected");
    expect(count_block(resp, rlen, PN_BLOCK_ARSERVER_RES) == 0,
           "no ARServerBlock on CC-C/IRT Connect");
    pn_stack_destroy(s);
}

static void test_dcp_hello(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    int saw = 0;
    for (int i = 0; i < cap.n; i++) {
        if (cap.lens[i] < 16) {
            continue;
        }
        if (pn_rd_be16(cap.frames[i] + 12) == PN_ETHTYPE_PN &&
            pn_rd_be16(cap.frames[i] + 14) == PN_FRAMEID_DCP_HELLO &&
            contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            saw = 1;
        }
    }
    expect(saw, "DCP Hello sent on start with station name");
    pn_stack_destroy(s);
}

static void test_dcp_set_ip_resets_ar(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    do_connect(s);
    expect(pn_stack_cm_state(s) == PN_CM_CONNECTED,
           "AR connected before DCP Set IP");
    uint8_t b;
    expect(pn_stack_read_input(s, 32, &b, 1) == -EINVAL,
           "input read past end rejected");
    expect(pn_stack_read_output(s, 8, &b, 1) == -EINVAL,
           "output read past end rejected");

    static const uint8_t dst[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t ipb[14];
    pn_wr_be16(ipb, 1);
    pn_wr_be32(ipb + 2, 0xC0A80A32u);
    pn_wr_be32(ipb + 6, 0xFFFFFF00u);
    pn_wr_be32(ipb + 10, 0xC0A80A01u);
    uint8_t blocks[32];
    size_t bn =
        append_dcp_block(blocks, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb, 14);
    uint8_t pay[64];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xAABB0003);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), dst, src, PN_ETHTYPE_PN,
                               pay, 12 + bn);
    pn_stack_handle_eth(s, frame, flen);
    expect(pn_stack_cfg(s)->ip == 0xC0A80A32u, "DCP Set IP after Connect");
    expect(pn_stack_cm_state(s) == PN_CM_OFFLINE,
           "DCP Set IP resets a live AR");
    pn_stack_destroy(s);
}

static void test_watchdog(void)
{
    tx_cap_t cap;
    pn_stack_t *s = mock_stack(&cap);
    do_connect(s);
    do_prmend(s);
    do_apprdy_ack(s);
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
    test_dcp_set_unsigned();
    test_connect_sec();
    test_cm_connect_prmend();
    test_cm_write_read();
    test_cm_pdev_expected();
    test_lldp_start();
    test_lldp_remote();
    test_snmp_mib();
    test_rta_alarm();
    test_irt_reject();
    test_dcp_hello();
    test_dcp_set_ip_resets_ar();
    test_watchdog();
    if (g_fail) {
        fprintf(stderr, "pn stack tests FAILED\n");
        return 1;
    }
    fprintf(stderr, "pn stack tests OK\n");
    return 0;
}
