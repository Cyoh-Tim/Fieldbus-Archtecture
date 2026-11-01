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

static const uint8_t *tx_frame_fid(uint16_t fid, size_t *len)
{
    for (int i = 0; i < g_ntx; i++) {
        if (g_txlen[i] >= 16 && pn_rd_be16(g_tx[i] + 14) == fid) {
            *len = g_txlen[i];
            return g_tx[i];
        }
    }
    return NULL;
}

/* DCP payload starts at Ethernet offset 14. Blocks follow the 12-byte header. */
static const uint8_t *dcp_blocks_of(const uint8_t *frame, size_t len,
                                    uint16_t *dlen)
{
    if (len < 26) {
        return NULL;
    }
    *dlen = pn_rd_be16(frame + 24);
    if (26u + *dlen > len) {
        return NULL;
    }
    return frame + 26;
}

static const uint8_t *find_dcp_block(const uint8_t *blocks, uint16_t dlen,
                                     uint8_t opt, uint8_t sub, uint16_t *blen)
{
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            return NULL;
        }
        if (blocks[off] == opt && blocks[off + 1] == sub) {
            *blen = bl;
            return blocks + off;
        }
        off += total;
    }
    return NULL;
}

static void dump_prefix(const uint8_t *p, size_t n)
{
    if (n > 40) {
        n = 40;
    }
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, " %02x", p[i]);
    }
    fprintf(stderr, "\n");
}

/* Identify.res / Get.res / Hello.req: value is BlockInfo(2) then the payload. */
static void expect_blockinfo(const uint8_t *blocks, uint16_t dlen, uint8_t opt,
                             uint8_t sub, uint16_t info, const void *val,
                             size_t vlen, const char *what)
{
    uint16_t bl = 0;
    const uint8_t *b = find_dcp_block(blocks, dlen, opt, sub, &bl);
    if (!b) {
        fprintf(stderr, "FAIL: %s block missing\n", what);
        g_fail = 1;
        return;
    }
    uint16_t want_len = (uint16_t)(2u + vlen);
    int ok = bl == want_len && pn_rd_be16(b + 4) == info &&
             (vlen == 0 || memcmp(b + 6, val, vlen) == 0);
    if (!ok) {
        fprintf(stderr,
                "FAIL: %s BlockInfo len=%u want %u info=0x%04x want 0x%04x\n",
                what, bl, want_len, pn_rd_be16(b + 4), info);
        fprintf(stderr, "  bytes:");
        dump_prefix(b, 4u + bl);
        g_fail = 1;
    }
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

static size_t dcp_get_frame(uint8_t *out, const uint8_t *dst, const uint8_t *src)
{
    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_GET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x55667788);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);
    return pn_eth_build(out, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay, 16);
}

static size_t dcp_set_ip_frame(uint8_t *out, const uint8_t *dst,
                               const uint8_t *src, uint32_t ip, uint32_t nm,
                               uint32_t gw)
{
    uint8_t val[14];
    pn_wr_be16(val, 1); /* BlockQualifier: permanent */
    pn_wr_be32(val + 2, ip);
    pn_wr_be32(val + 6, nm);
    pn_wr_be32(val + 10, gw);
    uint8_t blocks[32];
    blocks[0] = PN_DCP_OPT_IP;
    blocks[1] = PN_DCP_SUB_IP_PARAM;
    pn_wr_be16(blocks + 2, 14);
    memcpy(blocks + 4, val, 14);
    uint8_t pay[64];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0x01020304);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 18);
    memcpy(pay + 12, blocks, 18);
    return pn_eth_build(out, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay, 30);
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

    cfg.security_class = PN_VENDOR_INTEGRITY;
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

static int blocks_of_tx(uint16_t fid, const uint8_t **blocks, uint16_t *dlen,
                          const char *what)
{
    size_t flen = 0;
    const uint8_t *frame = tx_frame_fid(fid, &flen);
    if (!frame) {
        fprintf(stderr, "FAIL: %s frame missing\n", what);
        g_fail = 1;
        return 0;
    }
    *blocks = dcp_blocks_of(frame, flen, dlen);
    if (!*blocks) {
        fprintf(stderr, "FAIL: %s DCP blocks truncated\n", what);
        g_fail = 1;
        return 0;
    }
    return 1;
}

/* T12-2: Identify/Get/Hello blocks carry BlockInfo. A spec parser reads the
 * first two value bytes as BlockInfo, so the station name must follow them
 * intact ("sensor-line1", not "nsor-line1") and the IP must not shift.
 * Set.res Control/Response stays BlockError without BlockInfo.
 * DeviceRole details stay 0x02 (T12-22). */
static void test_response_blockinfo(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "blockinfo stack");
    if (!s) {
        return;
    }
    uint8_t mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[PN_FRAME_MAX];
    const char *name = "sensor-line1";
    const char *dtype = "Fieldbus PN Device";
    uint8_t devid[4];
    pn_wr_be16(devid, 0xABCD);
    pn_wr_be16(devid + 2, 0x0001);
    uint8_t role[2] = {0x02, 0x00};
    uint8_t ip_zero[12];
    memset(ip_zero, 0, sizeof(ip_zero));
    uint8_t mac[6] = {0x02, 0xFB, 0x00, 0x00, 0x00, 0x01};
    uint8_t opts[4] = {PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, PN_DCP_OPT_DEV,
                       PN_DCP_SUB_DEV_NAME};

    uint8_t all[4] = {PN_DCP_OPT_ALL, 0xFF, 0x00, 0x00};
    tx_reset();
    size_t flen = dcp_ident_frame(frame, mc, src, 0, all, sizeof(all));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident for blockinfo");
    const uint8_t *blocks = NULL;
    uint16_t dlen = 0;
    if (blocks_of_tx(PN_FRAMEID_DCP_ID_RES, &blocks, &dlen, "Identify.Res")) {
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_TYPE, 0,
                         dtype, strlen(dtype), "Identify TypeOfStation");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, 0,
                         name, strlen(name), "Identify NameOfStation");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ID, 0,
                         devid, sizeof(devid), "Identify DeviceID");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ROLE, 0,
                         role, sizeof(role), "Identify DeviceRole");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, 0,
                         ip_zero, sizeof(ip_zero), "Identify IP not set");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_IP, PN_DCP_SUB_IP_MAC, 0, mac,
                         sizeof(mac), "Identify MAC");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_OPTS, 0,
                         opts, sizeof(opts), "Identify DeviceOptions");
    }

    tx_reset();
    flen = dcp_get_frame(frame, s->cfg.mac, src);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "get for blockinfo");
    if (blocks_of_tx(PN_FRAMEID_DCP_GETSET, &blocks, &dlen, "Get.Res")) {
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, 0,
                         name, strlen(name), "Get NameOfStation");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, 0,
                         ip_zero, sizeof(ip_zero), "Get IP not set");
    }

    tx_reset();
    pn_stack_send_hello(s);
    if (blocks_of_tx(PN_FRAMEID_DCP_HELLO, &blocks, &dlen, "Hello.Req")) {
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, 0,
                         name, strlen(name), "Hello NameOfStation");
    }

    /* Set.res Control/Response has no BlockInfo: Option, Suboption, BlockError. */
    tx_reset();
    flen = dcp_set_name_frame(frame, s->cfg.mac, src, "ok-name");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set name for res shape");
    if (blocks_of_tx(PN_FRAMEID_DCP_GETSET, &blocks, &dlen, "Set.Res")) {
        uint16_t bl = 0;
        const uint8_t *b =
            find_dcp_block(blocks, dlen, PN_DCP_OPT_CTRL, PN_DCP_SUB_CTRL_RESPONSE,
                           &bl);
        uint8_t want[3] = {PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, 0x00};
        int ok = b && bl == 3 && memcmp(b + 4, want, 3) == 0;
        if (!ok) {
            fprintf(stderr, "FAIL: Set.Res Control/Response must stay "
                            "without BlockInfo\n");
            if (b) {
                fprintf(stderr, "  bytes:");
                dump_prefix(b, 4u + bl + (bl & 1u));
            }
            g_fail = 1;
        }
    }

    uint8_t ipb[12];
    pn_wr_be32(ipb, 0xC0A8000Au);
    pn_wr_be32(ipb + 4, 0xFFFFFF00u);
    pn_wr_be32(ipb + 8, 0xC0A80001u);
    tx_reset();
    flen = dcp_set_ip_frame(frame, s->cfg.mac, src, 0xC0A8000Au, 0xFFFFFF00u,
                            0xC0A80001u);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set ip");
    tx_reset();
    flen = dcp_ident_frame(frame, mc, src, 0, all, sizeof(all));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "ident after set ip");
    if (blocks_of_tx(PN_FRAMEID_DCP_ID_RES, &blocks, &dlen, "Identify after IP")) {
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, 0x0001,
                         ipb, sizeof(ipb), "Identify IP set");
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, 0,
                         "ok-name", 7, "Identify name after Set");
    }

    pn_stack_destroy(s);
}

/* One Set.res Control/Response entry: the request block it answers. */
typedef struct {
    uint8_t opt;
    uint8_t sub;
    uint8_t err;
} set_res_t;

/* qual is BlockQualifier. ResetToFactory mode is qual >> 1. */
static size_t append_set_block_qual(uint8_t *blocks, size_t bn, uint8_t opt,
                                    uint8_t sub, uint16_t qual, const void *val,
                                    size_t vlen)
{
    uint16_t blen = (uint16_t)(2u + vlen);
    blocks[bn++] = opt;
    blocks[bn++] = sub;
    pn_wr_be16(blocks + bn, blen);
    bn += 2;
    pn_wr_be16(blocks + bn, qual);
    bn += 2;
    if (vlen && val) {
        memcpy(blocks + bn, val, vlen);
        bn += vlen;
    }
    if (blen & 1u) {
        blocks[bn++] = 0;
    }
    return bn;
}

static size_t append_set_block(uint8_t *blocks, size_t bn, uint8_t opt,
                               uint8_t sub, const void *val, size_t vlen)
{
    return append_set_block_qual(blocks, bn, opt, sub, 1, val, vlen);
}

/* ERR-RTA-PDU tail: Vendor 0xCF, PNIO 0x81, protocol class 0xFD, ErrorCode2. */
static int tx_rta_code2(uint8_t code2)
{
    static const uint8_t mark[3] = {0xCF, 0x81, 0xFD};
    for (int i = 0; i < g_ntx; i++) {
        if (g_txlen[i] < 4) {
            continue;
        }
        for (size_t o = 0; o + 4 <= g_txlen[i]; o++) {
            if (memcmp(g_tx[i] + o, mark, 3) == 0 &&
                g_tx[i][o + 3] == code2) {
                return 1;
            }
        }
    }
    return 0;
}

static int im_is(pn_stack_t *s, uint16_t index, uint8_t fill, size_t n)
{
    uint8_t got[128];
    size_t got_n = 0;
    if (pn_record_read(s, 0, 1, index, got, sizeof(got), &got_n) != 0 ||
        got_n < 6 + n) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (got[6 + i] != fill) {
            return 0;
        }
    }
    return 1;
}

static size_t dcp_set_blocks_frame(uint8_t *out, const uint8_t *dst,
                                   const uint8_t *src, uint32_t xid,
                                   const uint8_t *blocks, size_t bn)
{
    uint8_t pay[PN_FRAME_MAX];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    return pn_eth_build(out, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay,
                        12 + bn);
}

/* Set.res Control/Response blocks. Returns the count, or -1 if the frame
 * is not a Set response. */
static int parse_set_responses(const uint8_t *frame, size_t len, uint8_t *stype,
                               set_res_t *out, int cap)
{
    if (!frame || len < 26 || pn_rd_be16(frame + 14) != PN_FRAMEID_DCP_GETSET ||
        frame[16] != PN_DCP_SET) {
        return -1;
    }
    *stype = frame[17];
    uint16_t dlen = pn_rd_be16(frame + 24);
    if (26u + dlen > len) {
        return -1;
    }
    const uint8_t *blocks = frame + 26;
    int n = 0;
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            return -1;
        }
        if (blocks[off] == PN_DCP_OPT_CTRL &&
            blocks[off + 1] == PN_DCP_SUB_CTRL_RESPONSE && bl >= 3 && n < cap) {
            out[n].opt = blocks[off + 4];
            out[n].sub = blocks[off + 5];
            out[n].err = blocks[off + 6];
            n++;
        }
        off += total;
    }
    return n;
}

static int set_res_err(const set_res_t *r, int n, uint8_t opt, uint8_t sub,
                       uint8_t *err)
{
    for (int i = 0; i < n; i++) {
        if (r[i].opt == opt && r[i].sub == sub) {
            *err = r[i].err;
            return 1;
        }
    }
    return 0;
}

/* T12-16: one Control/Response per Set block. ServiceType stays success.
 * Name during AR is accepted and aborts the AR unless RejectDCPsetRequests
 * is set. A different IP during AR is rejected. ResetToFactory follows
 * BlockQualifier mode and the factory value is an empty name and 0.0.0.0. */
static void test_t12_16_set_rules(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "t12-16 stack");
    if (!s) {
        return;
    }
    uint8_t dst[6];
    memcpy(dst, s->cfg.mac, 6);
    uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[PN_FRAME_MAX];
    uint8_t blocks[256];
    uint8_t ipb[12];
    pn_wr_be32(ipb, 0xC0A80014u);
    pn_wr_be32(ipb + 4, 0xFFFFFF00u);
    pn_wr_be32(ipb + 8, 0xC0A80001u);

    /* Name + IP: a response block for each, ServiceType success, both OK. */
    size_t bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                          "press-7", 7);
    bn = append_set_block(blocks, bn, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb,
                          sizeof(ipb));
    tx_reset();
    size_t flen = dcp_set_blocks_frame(frame, dst, src, 0x5101, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set name+ip");
    size_t rlen = 0;
    const uint8_t *rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    uint8_t stype = 0xFF;
    set_res_t res[8];
    int nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(nres == 2, "name+ip yields two Control/Response blocks");
    expect(stype == PN_DCP_RESP_SUCCESS, "name+ip ServiceType success");
    uint8_t err = 0xFF;
    expect(set_res_err(res, nres, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, &err) &&
               err == 0x00,
           "NameOfStation BlockError 0");
    expect(set_res_err(res, nres, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, &err) &&
               err == 0x00,
           "IP parameter BlockError 0");
    expect(strcmp(s->cfg.station_name, "press-7") == 0, "name applied");
    expect(s->cfg.ip == 0xC0A80014u, "ip applied");

    /* Read-only TypeOfStation (2/1): BlockError is not OK. Name stays. */
    bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_TYPE,
                          "OtherVendor", 11);
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5102, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set type of station");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(stype == PN_DCP_RESP_SUCCESS, "read-only ServiceType success");
    expect(set_res_err(res, nres, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_TYPE, &err) &&
               err != 0x00,
           "TypeOfStation BlockError is not OK");
    expect(strcmp(s->cfg.station_name, "press-7") == 0,
           "read-only set leaves name");

    /* Bad NameOfStation: ServiceType stays success; the block is not OK. */
    tx_reset();
    flen = dcp_set_name_frame(frame, dst, src, "port-abc");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set reserved port name");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(stype == PN_DCP_RESP_SUCCESS && stype != PN_DCP_RESP_UNSUP,
           "invalid name ServiceType is success, not unsupported");
    expect(set_res_err(res, nres, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, &err) &&
               err == PN_DCP_BLOCK_ERR_SUB_NOT_SET,
           "invalid name BlockError 0x03");
    expect(strcmp(s->cfg.station_name, "press-7") == 0, "invalid name not applied");

    /* AR, RejectDCPsetRequests=0: a different name is accepted and the AR
     * is released (RTC1 would stop). ErrorCode2 on the ERR-RTA is 0x1F. */
    s->ar.established = 1;
    s->ar.reject_dcp_set = 0;
    tx_reset();
    flen = dcp_set_name_frame(frame, dst, src, "during-ar");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set name during ar");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(stype == PN_DCP_RESP_SUCCESS, "in-ar name ServiceType success");
    expect(set_res_err(res, nres, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, &err) &&
               err == 0x00,
           "in-ar name BlockError 0");
    expect(strcmp(s->cfg.station_name, "during-ar") == 0, "in-ar name applied");
    expect(!s->ar.established, "in-ar name releases AR");
    expect(tx_rta_code2(0x1F), "in-ar name abort ErrorCode2 0x1F");

    /* Same name: success, AR stays. */
    s->ar.established = 1;
    s->ar.reject_dcp_set = 0;
    tx_reset();
    flen = dcp_set_name_frame(frame, dst, src, "during-ar");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set same name during ar");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(set_res_err(res, nres, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, &err) &&
               err == 0x00,
           "same name BlockError 0");
    expect(s->ar.established, "same name keeps AR");
    expect(!tx_rta_code2(0x1F), "same name does not abort");

    /* RejectDCPsetRequests=1: different name is BlockError 0x06, AR stays. */
    s->ar.reject_dcp_set = 1;
    tx_reset();
    flen = dcp_set_name_frame(frame, dst, src, "other-nm");
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set name when reject bit");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(stype == PN_DCP_RESP_SUCCESS, "reject-bit ServiceType success");
    expect(set_res_err(res, nres, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, &err) &&
               err == PN_DCP_BLOCK_ERR_IN_OPERATION,
           "reject-bit name BlockError 0x06");
    expect(strcmp(s->cfg.station_name, "during-ar") == 0,
           "reject-bit name not applied");
    expect(s->ar.established, "reject-bit name keeps AR");

    /* Different IP during AR: reject, keep IP and AR. */
    uint32_t ip_before = s->cfg.ip;
    pn_wr_be32(ipb, 0x0A000001u);
    pn_wr_be32(ipb + 4, 0xFFFFFF00u);
    pn_wr_be32(ipb + 8, 0x0A0000FEu);
    bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb,
                          sizeof(ipb));
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5104, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set ip during ar");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(set_res_err(res, nres, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, &err) &&
               err == PN_DCP_BLOCK_ERR_IN_OPERATION,
           "in-ar ip BlockError 0x06");
    expect(s->cfg.ip == ip_before, "in-ar ip not applied");
    expect(s->ar.established, "in-ar ip keeps AR");

    /* Same IP suite: success, AR stays. */
    pn_wr_be32(ipb, ip_before);
    pn_wr_be32(ipb + 4, s->cfg.netmask);
    pn_wr_be32(ipb + 8, s->cfg.gateway);
    bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb,
                          sizeof(ipb));
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5105, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "set same ip during ar");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(set_res_err(res, nres, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, &err) &&
               err == 0x00,
           "same ip BlockError 0");
    expect(s->cfg.ip == ip_before, "same ip unchanged");
    expect(s->ar.established, "same ip keeps AR");
    s->ar.established = 0;

    /* Plant I&M so mode 1 can clear it without touching name or IP. */
    uint8_t im[PN_IM1_FUNC_LEN + PN_IM1_LOC_LEN];
    memset(im, 'X', sizeof(im));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM1, im, sizeof(im)) == 0,
           "write im1");
    uint8_t im2[PN_IM2_DATE_LEN];
    memset(im2, 'Y', sizeof(im2));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM2, im2, sizeof(im2)) == 0,
           "write im2");
    uint8_t im3[PN_IM3_DESC_LEN];
    memset(im3, 'Z', sizeof(im3));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM3, im3, sizeof(im3)) == 0,
           "write im3");
    uint8_t im4[PN_IM4_SIG_LEN];
    memset(im4, 0x5A, sizeof(im4));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM4, im4, sizeof(im4)) == 0,
           "write im4");

    /* Reserved ResetToFactory modes change nothing, BlockError 0x03.
     * qual 1 is mode 0 (bit 0 is the permanent flag). */
    static const uint16_t reserved_qual[] = {0, 1, 5u << 1, 6u << 1, 7u << 1,
                                              10u << 1};
    for (size_t i = 0; i < sizeof(reserved_qual) / sizeof(reserved_qual[0]);
         i++) {
        bn = 0;
        bn = append_set_block_qual(blocks, bn, PN_DCP_OPT_CTRL, 0x06,
                                   reserved_qual[i], NULL, 0);
        tx_reset();
        flen = dcp_set_blocks_frame(frame, dst, src, 0x5200u + (uint32_t)i,
                                    blocks, bn);
        expect(pn_stack_handle_eth(s, frame, flen) == 0, "reserved reset");
        rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
        nres = parse_set_responses(rsp, rlen, &stype, res, 8);
        expect(stype == PN_DCP_RESP_SUCCESS, "reserved reset ServiceType");
        expect(set_res_err(res, nres, PN_DCP_OPT_CTRL, 0x06, &err) &&
                   err == PN_DCP_BLOCK_ERR_SUB_NOT_SET,
               "reserved reset BlockError 0x03");
    }
    expect(strcmp(s->cfg.station_name, "during-ar") == 0,
           "reserved reset leaves name");
    expect(s->cfg.ip == ip_before && s->cfg.netmask != 0, "reserved reset leaves ip");
    expect(im_is(s, PN_INDEX_IM1, 'X', sizeof(im)), "reserved reset leaves I&M1");
    expect(im_is(s, PN_INDEX_IM4, 0x5A, PN_IM4_SIG_LEN),
           "reserved reset leaves I&M4");

    /* Mode 1: I&M1–4 only. */
    bn = 0;
    bn = append_set_block_qual(blocks, bn, PN_DCP_OPT_CTRL, 0x06, 1u << 1, NULL,
                               0);
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5210, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "reset mode 1");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(set_res_err(res, nres, PN_DCP_OPT_CTRL, 0x06, &err) && err == 0x00,
           "mode 1 BlockError 0");
    expect(strcmp(s->cfg.station_name, "during-ar") == 0, "mode 1 keeps name");
    expect(s->cfg.ip == ip_before, "mode 1 keeps ip");
    expect(im_is(s, PN_INDEX_IM1, ' ', sizeof(im)), "mode 1 clears I&M1");
    expect(im_is(s, PN_INDEX_IM2, ' ', PN_IM2_DATE_LEN), "mode 1 clears I&M2");
    expect(im_is(s, PN_INDEX_IM3, ' ', PN_IM3_DESC_LEN), "mode 1 clears I&M3");
    expect(im_is(s, PN_INDEX_IM4, 0, PN_IM4_SIG_LEN), "mode 1 clears I&M4");

    /* Mode 2: empty NameOfStation and IP 0.0.0.0. I&M stays. */
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM3, im3, sizeof(im3)) == 0,
           "rewrite im3");
    bn = 0;
    bn = append_set_block_qual(blocks, bn, PN_DCP_OPT_CTRL, 0x06, 2u << 1, NULL,
                               0);
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5211, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "reset mode 2");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(set_res_err(res, nres, PN_DCP_OPT_CTRL, 0x06, &err) && err == 0x00,
           "mode 2 BlockError 0");
    expect(s->cfg.station_name[0] == '\0', "mode 2 clears name");
    expect(s->cfg.ip == 0 && s->cfg.netmask == 0 && s->cfg.gateway == 0,
           "mode 2 clears ip suite");
    expect(im_is(s, PN_INDEX_IM3, 'Z', PN_IM3_DESC_LEN), "mode 2 keeps I&M3");

    /* Modes 3, 4, 8, 9 and Reset Factory Settings (5/5): all supported. */
    static const uint16_t all_qual[] = {3u << 1, 4u << 1, 8u << 1, 9u << 1};
    for (size_t i = 0; i < sizeof(all_qual) / sizeof(all_qual[0]); i++) {
        bn = 0;
        bn = append_set_block(blocks, bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                              "again-1", 7);
        flen = dcp_set_blocks_frame(frame, dst, src, 0x5220u + (uint32_t)i,
                                    blocks, bn);
        pn_stack_handle_eth(s, frame, flen);
        pn_wr_be32(ipb, 0xC0A80030u + (uint32_t)i);
        bn = 0;
        bn = append_set_block(blocks, bn, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb,
                              sizeof(ipb));
        flen = dcp_set_blocks_frame(frame, dst, src, 0x5230u + (uint32_t)i,
                                    blocks, bn);
        pn_stack_handle_eth(s, frame, flen);
        expect(pn_record_write(s, 0, 1, PN_INDEX_IM4, im4, sizeof(im4)) == 0,
               "rewrite im4 before all-reset");
        bn = 0;
        bn = append_set_block_qual(blocks, bn, PN_DCP_OPT_CTRL, 0x06, all_qual[i],
                                   NULL, 0);
        tx_reset();
        flen = dcp_set_blocks_frame(frame, dst, src, 0x5240u + (uint32_t)i,
                                    blocks, bn);
        expect(pn_stack_handle_eth(s, frame, flen) == 0, "reset all mode");
        rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
        nres = parse_set_responses(rsp, rlen, &stype, res, 8);
        expect(set_res_err(res, nres, PN_DCP_OPT_CTRL, 0x06, &err) && err == 0x00,
               "all-mode BlockError 0");
        expect(s->cfg.station_name[0] == '\0', "all-mode clears name");
        expect(s->cfg.ip == 0 && s->cfg.netmask == 0 && s->cfg.gateway == 0,
               "all-mode clears ip");
        expect(im_is(s, PN_INDEX_IM4, 0, PN_IM4_SIG_LEN), "all-mode clears I&M4");
    }

    bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                          "again-1", 7);
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5250, blocks, bn);
    pn_stack_handle_eth(s, frame, flen);
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM3, im3, sizeof(im3)) == 0,
           "rewrite im3 before factory settings");
    /* 5/5 ignores BlockQualifier. qual 1 would be reserved on 5/6. */
    bn = 0;
    bn = append_set_block_qual(blocks, bn, PN_DCP_OPT_CTRL, 0x05, 1, NULL, 0);
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5251, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "reset factory settings");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(set_res_err(res, nres, PN_DCP_OPT_CTRL, 0x05, &err) && err == 0x00,
           "Reset Factory Settings BlockError 0");
    expect(s->cfg.station_name[0] == '\0', "factory settings clears name");
    expect(im_is(s, PN_INDEX_IM3, ' ', PN_IM3_DESC_LEN),
           "factory settings clears I&M3");

    /* ResetToFactory during AR is accepted and releases the AR (0x20). */
    bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                          "keep-ar", 7);
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5252, blocks, bn);
    pn_stack_handle_eth(s, frame, flen);
    pn_wr_be32(ipb, 0xC0A80014u);
    pn_wr_be32(ipb + 4, 0xFFFFFF00u);
    pn_wr_be32(ipb + 8, 0xC0A80001u);
    bn = 0;
    bn = append_set_block(blocks, bn, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ipb,
                          sizeof(ipb));
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5253, blocks, bn);
    pn_stack_handle_eth(s, frame, flen);
    s->ar.established = 1;
    s->ar.reject_dcp_set = 1; /* reset is still accepted */
    bn = 0;
    bn = append_set_block_qual(blocks, bn, PN_DCP_OPT_CTRL, 0x06, 2u << 1, NULL,
                               0);
    tx_reset();
    flen = dcp_set_blocks_frame(frame, dst, src, 0x5254, blocks, bn);
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "reset during ar");
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(stype == PN_DCP_RESP_SUCCESS, "in-ar reset ServiceType success");
    expect(set_res_err(res, nres, PN_DCP_OPT_CTRL, 0x06, &err) && err == 0x00,
           "in-ar ResetToFactory BlockError 0");
    expect(s->cfg.station_name[0] == '\0', "in-ar reset clears name");
    expect(s->cfg.ip == 0, "in-ar reset clears ip");
    expect(!s->ar.established, "in-ar reset releases AR");
    expect(tx_rta_code2(0x20), "in-ar reset abort ErrorCode2 0x20");

    pn_stack_destroy(s);

    /* Unsigned Set while the vendor integrity extension is required:
     * ServiceType success + a non-zero BlockError, name unchanged. */
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "lab");
    cfg.security_class = PN_VENDOR_INTEGRITY;
    cfg.enforce_security_class = 1;
    cfg.psk_set = 1;
    memset(cfg.psk, 0x33, PN_PSK_LEN);
    s = pn_stack_create(&cfg);
    expect(s != NULL, "enforce stack for service type");
    if (!s) {
        return;
    }
    pn_eth_ops_t ops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, ops);
    pn_stack_start(s);
    memcpy(dst, s->cfg.mac, 6);
    tx_reset();
    flen = dcp_set_name_frame(frame, dst, src, "prod-name");
    pn_stack_handle_eth(s, frame, flen);
    rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    expect(stype == PN_DCP_RESP_SUCCESS && stype != PN_DCP_RESP_UNSUP,
           "integrity failure ServiceType is success, not unsupported");
    expect(nres >= 1 && res[0].err == PN_DCP_BLOCK_ERR_SUB_NOT_SET,
           "integrity failure BlockError 0x03");
    expect(strcmp(s->cfg.station_name, "lab") == 0, "unsigned name not applied");
    pn_stack_destroy(s);
}

int main(void)
{
    test_name_ok();
    test_ident_filter_and_delay();
    test_set_name_and_enforce();
    test_response_blockinfo();
    test_t12_16_set_rules();
    if (g_fail) {
        fprintf(stderr, "test_pn_dcp: FAILED\n");
        return 1;
    }
    printf("test_pn_dcp: OK\n");
    return 0;
}
