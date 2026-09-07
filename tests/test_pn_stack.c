#include "pn_crypto.h"
#include "pn_endian.h"
#include "pn_stack.h"

#include <stdio.h>
#include <string.h>

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
    for (int i = 0; i < cap.n; i++) {
        if (contains(cap.frames[i], cap.lens[i], "sensor-line1")) {
            found = 1;
        }
    }
    expect(found, "DCP Identify response contains NameOfStation");
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

int main(void)
{
    test_hmac();
    test_dcp_identify();
    test_dcp_set_sec();
    test_connect_sec();
    if (g_fail) {
        fprintf(stderr, "pn stack tests FAILED\n");
        return 1;
    }
    fprintf(stderr, "pn stack tests OK\n");
    return 0;
}
