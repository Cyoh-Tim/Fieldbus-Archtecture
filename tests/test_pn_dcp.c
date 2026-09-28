#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static uint8_t g_tx[8][PN_FRAME_MAX];
static size_t g_txlen[8];
static int g_ntx;

static int capture_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (g_ntx < 8 && len <= PN_FRAME_MAX) {
        memcpy(g_tx[g_ntx], frame, len);
        g_txlen[g_ntx] = len;
        g_ntx++;
    }
    return (int)len;
}

static void tx_reset(void)
{
    g_ntx = 0;
    memset(g_txlen, 0, sizeof(g_txlen));
}

static int tx_has_fid(uint16_t fid)
{
    for (int i = 0; i < g_ntx; i++) {
        if (g_txlen[i] >= 16 && pn_rd_be16(g_tx[i] + 14) == fid) {
            return 1;
        }
    }
    return 0;
}

static pn_stack_t *make_dcp_stack(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "sensor-line1");
    cfg.security_class = 0;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 0x0001;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    if (pn_stack_start(s) != 0) {
        pn_stack_destroy(s);
        return NULL;
    }
    return s;
}

static size_t dcp_ident_frame(uint8_t *out, const uint8_t *dst,
                              const uint8_t *src, uint16_t delay,
                              const uint8_t *blocks, size_t blen)
{
    uint8_t pay[64];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x11223344);
    pn_wr_be16(pay + 8, delay);
    pn_wr_be16(pay + 10, (uint16_t)blen);
    memcpy(pay + 12, blocks, blen);
    return pn_eth_build(out, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay,
                        12 + blen);
}

static size_t dcp_set_name_frame(uint8_t *out, const uint8_t *dst,
                                 const uint8_t *src, const char *name)
{
    size_t nlen = strlen(name);
    uint8_t blk[2 + 256];
    pn_wr_be16(blk, 1);
    memcpy(blk + 2, name, nlen);
    uint8_t blocks[512];
    size_t bn = 0;
    blocks[bn++] = PN_DCP_OPT_DEV;
    blocks[bn++] = PN_DCP_SUB_DEV_NAME;
    pn_wr_be16(blocks + bn, (uint16_t)(2 + nlen));
    bn += 2;
    memcpy(blocks + bn, blk, 2 + nlen);
    bn += 2 + nlen;
    if ((2 + nlen) & 1u) {
        blocks[bn++] = 0;
    }
    uint8_t pay[PN_FRAME_MAX];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xAABBCCDD);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    return pn_eth_build(out, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay,
                        12 + bn);
}

static void test_name_ok(void)
{
    expect(pn_dcp_name_ok((const uint8_t *)"sensor-line1", 12) == 1,
           "valid name");
    expect(pn_dcp_name_ok((const uint8_t *)"a", 1) == 1, "single label");
    expect(pn_dcp_name_ok((const uint8_t *)"-bad", 4) == 0, "leading hyphen");
    expect(pn_dcp_name_ok((const uint8_t *)"bad-", 4) == 0, "trailing hyphen");
    expect(pn_dcp_name_ok((const uint8_t *)"Bad", 3) == 0, "uppercase");
    expect(pn_dcp_name_ok((const uint8_t *)"192.168.0.1", 11) == 0, "ip-like");
    expect(pn_dcp_name_ok((const uint8_t *)"port-abc", 8) == 0, "port-xyz");
    expect(pn_dcp_name_ok((const uint8_t *)"port-abc-x", 10) == 0,
           "port-xyz-rest");
    char lab64[65];
    memset(lab64, 'a', 64);
    expect(pn_dcp_name_ok((const uint8_t *)lab64, 64) == 0, "label 64");
    char lab63[64];
    memset(lab63, 'a', 63);
    lab63[63] = '\0';
    expect(pn_dcp_name_ok((const uint8_t *)lab63, 63) == 1, "label 63");
    expect(pn_dcp_name_ok((const uint8_t *)"portal", 6) == 1, "portal ok");
    expect(pn_dcp_name_ok((const uint8_t *)"", 0) == 0, "empty");
    char n240[241];
    int pos = 0;
    for (int lab = 0; lab < 3; lab++) {
        if (lab) {
            n240[pos++] = '.';
        }
        memset(n240 + pos, 'a', 63);
        pos += 63;
    }
    n240[pos++] = '.';
    memset(n240 + pos, 'a', 48);
    pos += 48;
    n240[pos] = '\0';
    expect(pos == 240 && pn_dcp_name_ok((const uint8_t *)n240, 240) == 1,
           "240 DNS labels");
    expect(pn_dcp_name_ok((const uint8_t *)n240, 241) == 0, "241 rejected");
}

static void test_ident_filter_and_delay(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "dcp stack");
    if (!s) {
        return;
    }
    uint8_t dst[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t frame[PN_FRAME_MAX];

    uint8_t all[4] = {PN_DCP_OPT_ALL, 0xFF, 0x00, 0x00};
    tx_reset();
    size_t flen = dcp_ident_frame(frame, dst, src, 0, all, sizeof(all));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident all");
    expect(tx_has_fid(PN_FRAMEID_DCP_ID_RES), "ident all -> res");

    uint8_t nam[4 + 12];
    nam[0] = PN_DCP_OPT_DEV;
    nam[1] = PN_DCP_SUB_DEV_NAME;
    pn_wr_be16(nam + 2, 12);
    memcpy(nam + 4, "sensor-line1", 12);
    tx_reset();
    flen = dcp_ident_frame(frame, dst, src, 0, nam, 16);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident name match");
    expect(tx_has_fid(PN_FRAMEID_DCP_ID_RES), "matching name filter");

    memcpy(nam + 4, "other-station", 12);
    pn_wr_be16(nam + 2, 12);
    tx_reset();
    flen = dcp_ident_frame(frame, dst, src, 0, nam, 16);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident name miss");
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES), "mismatch name no res");

    uint8_t devid[8];
    devid[0] = PN_DCP_OPT_DEV;
    devid[1] = PN_DCP_SUB_DEV_ID;
    pn_wr_be16(devid + 2, 4);
    pn_wr_be16(devid + 4, 0xABCD);
    pn_wr_be16(devid + 6, 0x0001);
    tx_reset();
    flen = dcp_ident_frame(frame, dst, src, 0, devid, sizeof(devid));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident device id");
    expect(tx_has_fid(PN_FRAMEID_DCP_ID_RES), "matching device id");
    pn_wr_be16(devid + 6, 0x0002);
    tx_reset();
    flen = dcp_ident_frame(frame, dst, src, 0, devid, sizeof(devid));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident device id miss");
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES), "mismatch device id no res");

    /* MAC 02:FB:00:00:00:01, delay factor 2 -> 1*10ms. */
    tx_reset();
    flen = dcp_ident_frame(frame, dst, src, 2, all, sizeof(all));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident delay");
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES), "delay not immediate");
    usleep(40000);
    pn_stack_poll(s);
    expect(tx_has_fid(PN_FRAMEID_DCP_ID_RES), "delay then res");

    pn_stack_destroy(s);
}

static void test_set_name_and_enforce(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "set stack");
    if (!s) {
        return;
    }
    uint8_t dst[6];
    memcpy(dst, s->cfg.mac, 6);
    uint8_t src[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t frame[PN_FRAME_MAX];

    tx_reset();
    size_t flen = dcp_set_name_frame(frame, dst, src, "ok-name");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set ok");
    expect(strcmp(s->cfg.station_name, "ok-name") == 0, "name applied");

    flen = dcp_set_name_frame(frame, dst, src, "192.168.1.1");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set ip-like");
    expect(strcmp(s->cfg.station_name, "ok-name") == 0, "ip-like rejected");

    flen = dcp_set_name_frame(frame, dst, src, "port-abc");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set port-xyz");
    expect(strcmp(s->cfg.station_name, "ok-name") == 0, "port-xyz rejected");

    char lab64[65];
    memset(lab64, 'q', 64);
    lab64[64] = '\0';
    flen = dcp_set_name_frame(frame, dst, src, lab64);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set label64");
    expect(strcmp(s->cfg.station_name, "ok-name") == 0, "label64 rejected");

    pn_stack_destroy(s);

    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "lab");
    cfg.enforce_security_class = 1;
    cfg.security_class = 0;
    expect(pn_stack_create(&cfg) == NULL, "enforce + class0 fails");

    cfg.security_class = PN_SECURITY_CLASS_1;
    cfg.psk_set = 1;
    memset(cfg.psk, 0x33, PN_PSK_LEN);
    s = pn_stack_create(&cfg);
    expect(s != NULL, "enforce class1 create");
    if (s) {
        pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
        pn_stack_set_eth_ops(s, ops);
        pn_stack_start(s);
        memcpy(dst, s->cfg.mac, 6);
        tx_reset();
        flen = dcp_set_name_frame(frame, dst, src, "prod-name");
        pn_stack_handle_eth(s, frame, flen);
        expect(strcmp(s->cfg.station_name, "lab") == 0,
               "unsigned set rejected when enforce");
        pn_stack_destroy(s);
    }
}

int main(void)
{
    test_name_ok();
    test_ident_filter_and_delay();
    test_set_name_and_enforce();
    if (g_fail) {
        fprintf(stderr, "test_pn_dcp: FAILED\n");
        return 1;
    }
    printf("test_pn_dcp: OK\n");
    return 0;
}
