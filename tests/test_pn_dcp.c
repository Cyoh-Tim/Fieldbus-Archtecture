#include "logger.h"
#include "pn_endian.h"
#include "pn_internal.h"
#include "pn_stack.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/route.h>
#include <sys/ioctl.h>

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

static size_t dcp_ident_frame_xid(uint8_t *out, const uint8_t *dst,
                                  const uint8_t *src, uint16_t delay,
                                  uint32_t xid, const uint8_t *blocks,
                                  size_t blen)
{
    uint8_t pay[64];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, delay);
    pn_wr_be16(pay + 10, (uint16_t)blen);
    memcpy(pay + 12, blocks, blen);
    return pn_eth_build(out, PN_FRAME_MAX, dst, src, PN_ETHTYPE_PN, pay,
                        12 + blen);
}

static size_t dcp_ident_frame(uint8_t *out, const uint8_t *dst,
                              const uint8_t *src, uint16_t delay,
                              const uint8_t *blocks, size_t blen)
{
    return dcp_ident_frame_xid(out, dst, src, delay, 0x11223344u, blocks, blen);
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
 * DeviceRole details are 0x01 (IO-Device, T12-22). */
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
    uint8_t role[2] = {0x01, 0x00};
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

typedef struct {
    int calls;
    struct {
        char iface[16];
        uint32_t ip;
        uint32_t netmask;
        uint32_t gateway;
    } ev[4];
} os_hook_t;

static int os_hook_fn(void *ctx, const char *iface, uint32_t ip, uint32_t mask,
                      uint32_t gw)
{
    os_hook_t *h = ctx;
    if (h->calls < 4) {
        snprintf(h->ev[h->calls].iface, sizeof(h->ev[h->calls].iface), "%s",
                 iface ? iface : "");
        h->ev[h->calls].ip = ip;
        h->ev[h->calls].netmask = mask;
        h->ev[h->calls].gateway = gw;
    }
    h->calls++;
    return 0;
}

typedef struct {
    int have;
    int saves;
    int erases;
    pn_nvm_image_t img;
} mem_nvm_t;

static int mem_load(void *ctx, pn_nvm_image_t *out)
{
    mem_nvm_t *m = ctx;
    if (!m->have) {
        return 1;
    }
    *out = m->img;
    return 0;
}

static int mem_save(void *ctx, const pn_nvm_image_t *image)
{
    mem_nvm_t *m = ctx;
    m->img = *image;
    m->have = 1;
    m->saves++;
    return 0;
}

static int mem_erase(void *ctx)
{
    mem_nvm_t *m = ctx;
    int erases = m->erases + 1;
    memset(m, 0, sizeof(*m));
    m->erases = erases;
    return 0;
}

static pn_stack_t *open_nvm_stack(const char *name, uint32_t ip, uint32_t mask,
                                  uint32_t gw, int apply_os, mem_nvm_t *mem,
                                  os_hook_t *hook)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "%s", name ? name : "");
    cfg.ip = ip;
    cfg.netmask = mask;
    cfg.gateway = gw;
    cfg.apply_os_ip = apply_os;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 0x0001;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "FAIL: nvm stack create\n");
        g_fail = 1;
        return NULL;
    }
    pn_eth_ops_t eops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, eops);
    if (hook) {
        pn_stack_set_os_ip_fn(s, os_hook_fn, hook);
    }
    if (mem) {
        pn_nvm_ops_t nops = {
            .load = mem_load,
            .save = mem_save,
            .erase = mem_erase,
            .ctx = mem,
        };
        pn_stack_set_nvm_ops(s, &nops);
    }
    if (pn_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: nvm stack start\n");
        g_fail = 1;
        pn_stack_destroy(s);
        return NULL;
    }
    return s;
}

static int dcp_set_ok(pn_stack_t *s, const uint8_t *blocks, size_t bn,
                      uint32_t xid, uint8_t opt, uint8_t sub)
{
    uint8_t dst[6];
    memcpy(dst, s->cfg.mac, 6);
    uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[PN_FRAME_MAX];
    tx_reset();
    size_t flen = dcp_set_blocks_frame(frame, dst, src, xid, blocks, bn);
    if (pn_stack_handle_eth(s, frame, flen) != 0) {
        fprintf(stderr, "FAIL: handle set xid=0x%x\n", xid);
        g_fail = 1;
        return 0;
    }
    size_t rlen = 0;
    const uint8_t *rsp = tx_frame_fid(PN_FRAMEID_DCP_GETSET, &rlen);
    uint8_t stype = 0;
    set_res_t res[8];
    int nres = parse_set_responses(rsp, rlen, &stype, res, 8);
    uint8_t err = 0xFF;
    if (stype != PN_DCP_RESP_SUCCESS ||
        !set_res_err(res, nres, opt, sub, &err) || err != 0) {
        fprintf(stderr,
                "FAIL: set xid=0x%x opt=%u sub=%u stype=%u err=%u nres=%d\n",
                xid, opt, sub, stype, err, nres);
        g_fail = 1;
        return 0;
    }
    return 1;
}

static void set_name_qual(pn_stack_t *s, const char *name, uint16_t qual,
                          uint32_t xid)
{
    uint8_t blocks[320];
    size_t bn = append_set_block_qual(blocks, 0, PN_DCP_OPT_DEV,
                                      PN_DCP_SUB_DEV_NAME, qual, name,
                                      strlen(name));
    dcp_set_ok(s, blocks, bn, xid, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME);
}

static void set_ip_qual(pn_stack_t *s, uint32_t ip, uint32_t mask, uint32_t gw,
                        uint16_t qual, uint32_t xid)
{
    uint8_t ipb[12];
    pn_wr_be32(ipb, ip);
    pn_wr_be32(ipb + 4, mask);
    pn_wr_be32(ipb + 8, gw);
    uint8_t blocks[64];
    size_t bn = append_set_block_qual(blocks, 0, PN_DCP_OPT_IP,
                                      PN_DCP_SUB_IP_PARAM, qual, ipb,
                                      sizeof(ipb));
    dcp_set_ok(s, blocks, bn, xid, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM);
}

static void set_reset_qual(pn_stack_t *s, uint8_t sub, uint16_t qual,
                           uint32_t xid)
{
    uint8_t blocks[16];
    size_t bn =
        append_set_block_qual(blocks, 0, PN_DCP_OPT_CTRL, sub, qual, NULL, 0);
    dcp_set_ok(s, blocks, bn, xid, PN_DCP_OPT_CTRL, sub);
}

static void write_im_pattern(pn_stack_t *s)
{
    uint8_t im1[PN_IM1_FUNC_LEN + PN_IM1_LOC_LEN];
    memset(im1, 'A', PN_IM1_FUNC_LEN);
    memset(im1 + PN_IM1_FUNC_LEN, 'B', PN_IM1_LOC_LEN);
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM1, im1, sizeof(im1)) == 0,
           "write im1 pattern");
    uint8_t im2[PN_IM2_DATE_LEN];
    memset(im2, 'C', sizeof(im2));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM2, im2, sizeof(im2)) == 0,
           "write im2 pattern");
    uint8_t im3[PN_IM3_DESC_LEN];
    memset(im3, 'D', sizeof(im3));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM3, im3, sizeof(im3)) == 0,
           "write im3 pattern");
    uint8_t im4[PN_IM4_SIG_LEN];
    memset(im4, 0x11, sizeof(im4));
    expect(pn_record_write(s, 0, 1, PN_INDEX_IM4, im4, sizeof(im4)) == 0,
           "write im4 pattern");
}

/* I&M1 is function then location. im_is() fills one byte, so check both. */
static int im1_pattern_ok(pn_stack_t *s)
{
    uint8_t got[128];
    size_t n = 0;
    if (pn_record_read(s, 0, 1, PN_INDEX_IM1, got, sizeof(got), &n) != 0 ||
        n < 6 + PN_IM1_FUNC_LEN + PN_IM1_LOC_LEN) {
        return 0;
    }
    for (size_t i = 0; i < PN_IM1_FUNC_LEN; i++) {
        if (got[6 + i] != 'A') {
            return 0;
        }
    }
    for (size_t i = 0; i < PN_IM1_LOC_LEN; i++) {
        if (got[6 + PN_IM1_FUNC_LEN + i] != 'B') {
            return 0;
        }
    }
    return 1;
}

static int im_factory_ok(pn_stack_t *s)
{
    return im_is(s, PN_INDEX_IM1, ' ', PN_IM1_FUNC_LEN + PN_IM1_LOC_LEN) &&
           im_is(s, PN_INDEX_IM2, ' ', PN_IM2_DATE_LEN) &&
           im_is(s, PN_INDEX_IM3, ' ', PN_IM3_DESC_LEN) &&
           im_is(s, PN_INDEX_IM4, 0, PN_IM4_SIG_LEN);
}

static void expect_suite(pn_stack_t *s, uint32_t ip, uint32_t mask, uint32_t gw,
                         const char *what)
{
    if (s->cfg.ip != ip || s->cfg.netmask != mask || s->cfg.gateway != gw) {
        fprintf(stderr,
                "FAIL: %s ip=%08x/%08x gw=%08x want %08x/%08x gw=%08x\n", what,
                s->cfg.ip, s->cfg.netmask, s->cfg.gateway, ip, mask, gw);
        g_fail = 1;
    }
}

/* T12-20: DCP Set IP calls the OS apply hook when apply_os_ip is set.
 * The flag at 0 does not. Reset that clears the suite calls it with 0. */
static void test_t12_20_os_ip_hook(void)
{
    os_hook_t hook;
    memset(&hook, 0, sizeof(hook));
    pn_stack_t *s = open_nvm_stack("sensor-line1", 0, 0, 0, 1, NULL, &hook);
    if (!s) {
        return;
    }
    expect(hook.calls == 0, "start does not apply a zero suite");
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7120);
    if (hook.calls != 1 || hook.ev[0].ip != 0xC0A80014u ||
        hook.ev[0].netmask != 0xFFFFFF00u || hook.ev[0].gateway != 0xC0A80001u ||
        strcmp(hook.ev[0].iface, "mock") != 0) {
        fprintf(stderr,
                "FAIL: Set IP did not call OS hook calls=%d ip=%08x iface=%s\n",
                hook.calls, hook.calls ? hook.ev[0].ip : 0,
                hook.calls ? hook.ev[0].iface : "");
        g_fail = 1;
    }
    set_reset_qual(s, PN_DCP_SUB_CTRL_RESET, 2u << 1, 0x7121);
    if (hook.calls != 2 || hook.ev[1].ip != 0 || hook.ev[1].netmask != 0 ||
        hook.ev[1].gateway != 0) {
        fprintf(stderr, "FAIL: reset did not apply 0.0.0.0 calls=%d ip=%08x\n",
                hook.calls, hook.calls > 1 ? hook.ev[1].ip : 0);
        g_fail = 1;
    }
    pn_stack_destroy(s);

    memset(&hook, 0, sizeof(hook));
    s = open_nvm_stack("sensor-line1", 0, 0, 0, 0, NULL, &hook);
    if (!s) {
        return;
    }
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7122);
    expect(hook.calls == 0, "apply_os_ip 0 does not call the hook");
    expect(s->cfg.ip == 0xC0A80014u, "IP still stored in the stack");
    pn_stack_destroy(s);
}

/* BlockQualifier 1 name, IP, and I&M1–4 survive a new stack on the same store.
 * I&M Write alone is permanent (no DCP qualifier) and does not freeze the
 * config name. */
static void test_t12_20_permanent_survives(void)
{
    mem_nvm_t mem;
    memset(&mem, 0, sizeof(mem));
    pn_stack_t *s =
        open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7201);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7202);
    write_im_pattern(s);
    pn_stack_destroy(s);

    s = open_nvm_stack("other", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr, "FAIL: permanent name got '%s'\n", s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, "permanent ip");
    if (!im1_pattern_ok(s) || !im_is(s, PN_INDEX_IM2, 'C', PN_IM2_DATE_LEN) ||
        !im_is(s, PN_INDEX_IM3, 'D', PN_IM3_DESC_LEN) ||
        !im_is(s, PN_INDEX_IM4, 0x11, PN_IM4_SIG_LEN)) {
        fprintf(stderr, "FAIL: permanent I&M1-4 did not survive recreate\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);

    memset(&mem, 0, sizeof(mem));
    s = open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    write_im_pattern(s);
    pn_stack_destroy(s);
    s = open_nvm_stack("other", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "other") != 0) {
        fprintf(stderr, "FAIL: I&M-only save froze name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    if (!im1_pattern_ok(s) || !im_is(s, PN_INDEX_IM4, 0x11, PN_IM4_SIG_LEN)) {
        fprintf(stderr, "FAIL: I&M write did not survive recreate\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

/* BlockQualifier 0 is applied in RAM and is not what the next stack loads.
 * p-net clears the stored field, so a later permanent value is dropped too. */
static void test_t12_20_temporary_does_not(void)
{
    mem_nvm_t mem;
    memset(&mem, 0, sizeof(mem));
    pn_stack_t *s =
        open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_name_qual(s, "temp-name", 0, 0x7301);
    expect(strcmp(s->cfg.station_name, "temp-name") == 0,
           "temporary name is in RAM");
    pn_stack_destroy(s);
    s = open_nvm_stack("other", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    if (s->cfg.station_name[0] != '\0') {
        fprintf(stderr, "FAIL: temporary name survived as '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x0A000001u, 0xFFFFFF00u, 0x0A000001u,
                 "temporary name keeps stored ip");
    pn_stack_destroy(s);

    memset(&mem, 0, sizeof(mem));
    s = open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_ip_qual(s, 0x0A000063u, 0xFFFFFF00u, 0x0A000001u, 0, 0x7302);
    expect(s->cfg.ip == 0x0A000063u, "temporary ip is in RAM");
    pn_stack_destroy(s);
    s = open_nvm_stack("other", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "orig") != 0) {
        fprintf(stderr, "FAIL: temporary ip disturbed name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0, 0, 0, "temporary ip cleared the stored suite");
    pn_stack_destroy(s);

    memset(&mem, 0, sizeof(mem));
    s = open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_name_qual(s, "keep-me", 1, 0x7303);
    set_name_qual(s, "gone", 0, 0x7304);
    expect(strcmp(s->cfg.station_name, "gone") == 0, "temporary replaces RAM");
    pn_stack_destroy(s);
    s = open_nvm_stack("other", 0, 0, 0, 0, &mem, NULL);
    if (!s) {
        return;
    }
    if (s->cfg.station_name[0] != '\0') {
        fprintf(stderr,
                "FAIL: temporary set left stored name '%s' (want empty)\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

/* ResetToFactory drops the stored fields it clears. A new stack must not
 * load the pre-reset name, IP, or I&M. */
static void test_t12_20_reset_erases_store(void)
{
    mem_nvm_t mem;
    memset(&mem, 0, sizeof(mem));
    pn_stack_t *s =
        open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7401);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7402);
    write_im_pattern(s);
    pn_stack_destroy(s);
    s = open_nvm_stack("other", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr, "FAIL: reset setup name got '%s'\n", s->cfg.station_name);
        g_fail = 1;
    }
    set_reset_qual(s, PN_DCP_SUB_CTRL_FACTORY, 1, 0x7403);
    expect(s->cfg.station_name[0] == '\0', "factory reset clears RAM name");
    expect(im_factory_ok(s), "factory reset clears RAM I&M");
    pn_stack_destroy(s);
    s = open_nvm_stack("from-cfg", 0x11111111u, 0xFFFFFF00u, 0x11111101u, 0,
                       &mem, NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "from-cfg") != 0) {
        fprintf(stderr, "FAIL: factory reset left stored name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x11111111u, 0xFFFFFF00u, 0x11111101u,
                 "factory reset dropped stored ip");
    if (!im_factory_ok(s)) {
        fprintf(stderr, "FAIL: factory reset left stored I&M\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);

    /* Mode 1 clears stored I&M and keeps name/IP. */
    memset(&mem, 0, sizeof(mem));
    s = open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7410);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7411);
    write_im_pattern(s);
    set_reset_qual(s, PN_DCP_SUB_CTRL_RESET, 1u << 1, 0x7412);
    pn_stack_destroy(s);
    s = open_nvm_stack("from-cfg", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0,
                       &mem, NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr, "FAIL: mode 1 name got '%s'\n", s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, "mode 1 keeps ip");
    if (!im_factory_ok(s)) {
        fprintf(stderr, "FAIL: mode 1 left stored I&M\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);

    /* Mode 2 clears stored name/IP and keeps I&M. */
    memset(&mem, 0, sizeof(mem));
    s = open_nvm_stack("orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u, 0, &mem,
                       NULL);
    if (!s) {
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7420);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7421);
    write_im_pattern(s);
    set_reset_qual(s, PN_DCP_SUB_CTRL_RESET, 2u << 1, 0x7422);
    pn_stack_destroy(s);
    s = open_nvm_stack("from-cfg", 0x01020304u, 0xFFFF0000u, 0x01020301u, 0,
                       &mem, NULL);
    if (!s) {
        return;
    }
    if (strcmp(s->cfg.station_name, "from-cfg") != 0) {
        fprintf(stderr, "FAIL: mode 2 name got '%s'\n", s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x01020304u, 0xFFFF0000u, 0x01020301u, "mode 2 drops ip");
    if (!im1_pattern_ok(s) || !im_is(s, PN_INDEX_IM4, 0x11, PN_IM4_SIG_LEN)) {
        fprintf(stderr, "FAIL: mode 2 dropped stored I&M\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

/* Stored IP is applied on the next stack when apply_os_ip is set. */
static void test_t12_20_os_ip_on_load(void)
{
    mem_nvm_t mem;
    os_hook_t hook;
    memset(&mem, 0, sizeof(mem));
    memset(&hook, 0, sizeof(hook));
    pn_stack_t *s =
        open_nvm_stack("orig", 0, 0, 0, 1, &mem, &hook);
    if (!s) {
        return;
    }
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7501);
    pn_stack_destroy(s);
    memset(&hook, 0, sizeof(hook));
    s = open_nvm_stack("other", 0x01020304u, 0xFFFF0000u, 0x01020301u, 1, &mem,
                       &hook);
    if (!s) {
        return;
    }
    if (hook.calls != 1 || hook.ev[0].ip != 0xC0A80014u ||
        hook.ev[0].netmask != 0xFFFFFF00u || hook.ev[0].gateway != 0xC0A80001u) {
        fprintf(stderr, "FAIL: power-on did not apply stored IP calls=%d ip=%08x\n",
                hook.calls, hook.calls ? hook.ev[0].ip : 0);
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

static int make_nvm_dir(char *out, size_t cap)
{
    char tmpl[] = "/tmp/pn-nvm-XXXXXX";
    if (!mkdtemp(tmpl)) {
        fprintf(stderr, "FAIL: mkdtemp (%d)\n", errno);
        g_fail = 1;
        return -1;
    }
    snprintf(out, cap, "%s", tmpl);
    return 0;
}

static void rm_nvm_dir(const char *dir)
{
    const char *names[] = {PN_NVM_FILE_IP, PN_NVM_FILE_IM, "pn-ip.bin.tmp",
                           "pn-im.bin.tmp"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        unlink(path);
    }
    rmdir(dir);
}

static int file_exists(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return access(path, F_OK) == 0;
}

static uint32_t test_crc32(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

/* Plant one NVM file. version is written as given so a test can build a
 * different-version record with a matching CRC. */
static int plant_nvm_file(const char *dir, const char *name,
                          const char magic[4], uint16_t version,
                          const uint8_t *payload, uint32_t len)
{
    uint8_t buf[512];
    if (PN_NVM_FILE_HDR_LEN + len + 4u > sizeof(buf)) {
        return -1;
    }
    memcpy(buf, magic, 4);
    pn_wr_le16(buf + 4, version);
    pn_wr_le32(buf + 6, len);
    if (len) {
        memcpy(buf + PN_NVM_FILE_HDR_LEN, payload, len);
    }
    pn_wr_le32(buf + PN_NVM_FILE_HDR_LEN + len,
               test_crc32(buf, PN_NVM_FILE_HDR_LEN + len));
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }
    size_t total = PN_NVM_FILE_HDR_LEN + len + 4u;
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(fd, buf + off, total - off);
        if (w < 0) {
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static char g_logbuf[8192];

static void capture_begin(int *saved, int pfd[2])
{
    fflush(stderr);
    if (pipe(pfd) != 0) {
        pfd[0] = pfd[1] = -1;
        *saved = -1;
        return;
    }
    *saved = dup(STDERR_FILENO);
    dup2(pfd[1], STDERR_FILENO);
}

static void capture_end(int saved, int pfd[2])
{
    fflush(stderr);
    if (saved >= 0) {
        dup2(saved, STDERR_FILENO);
        close(saved);
    }
    if (pfd[1] >= 0) {
        close(pfd[1]);
    }
    size_t n = 0;
    g_logbuf[0] = '\0';
    if (pfd[0] >= 0) {
        ssize_t r;
        while (n + 1 < sizeof(g_logbuf) &&
               (r = read(pfd[0], g_logbuf + n, sizeof(g_logbuf) - 1 - n)) > 0) {
            n += (size_t)r;
        }
        g_logbuf[n] = '\0';
        close(pfd[0]);
    }
}

static pn_stack_t *create_file_stack(const char *dir, const char *name,
                                     uint32_t ip, uint32_t mask, uint32_t gw,
                                     mem_nvm_t *mem)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "%s",
             name ? name : "");
    if (dir && dir[0]) {
        snprintf(cfg.nvm_dir, sizeof(cfg.nvm_dir), "%s", dir);
    }
    cfg.ip = ip;
    cfg.netmask = mask;
    cfg.gateway = gw;
    cfg.input_len = 32;
    cfg.output_len = 8;
    cfg.vendor_id = 0xABCD;
    cfg.device_id = 0x0001;
    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        fprintf(stderr, "FAIL: file stack create\n");
        g_fail = 1;
        return NULL;
    }
    pn_eth_ops_t eops = {.send = capture_send, .recv = NULL, .ctx = NULL};
    pn_stack_set_eth_ops(s, eops);
    if (mem) {
        pn_nvm_ops_t nops = {
            .load = mem_load,
            .save = mem_save,
            .erase = mem_erase,
            .ctx = mem,
        };
        pn_stack_set_nvm_ops(s, &nops);
    }
    return s;
}

static pn_stack_t *open_file_stack(const char *dir, const char *name,
                                   uint32_t ip, uint32_t mask, uint32_t gw,
                                   mem_nvm_t *mem)
{
    pn_stack_t *s = create_file_stack(dir, name, ip, mask, gw, mem);
    if (!s) {
        return NULL;
    }
    if (pn_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: file stack start\n");
        g_fail = 1;
        pn_stack_destroy(s);
        return NULL;
    }
    return s;
}

/* Empty nvm_dir stays RAM-only. A fixed file in the working directory
 * (option C) is not created. */
static void test_t12_20_empty_nvm_dir(void)
{
    char dir[256];
    if (make_nvm_dir(dir, sizeof(dir)) != 0) {
        return;
    }
    char cwd[512];
    if (!getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "FAIL: getcwd\n");
        g_fail = 1;
        rm_nvm_dir(dir);
        return;
    }
    if (chdir(dir) != 0) {
        fprintf(stderr, "FAIL: chdir temp\n");
        g_fail = 1;
        rm_nvm_dir(dir);
        return;
    }
    pn_stack_t *s = open_file_stack("", "orig", 0x0A000001u, 0xFFFFFF00u,
                                    0x0A000001u, NULL);
    if (s) {
        set_name_qual(s, "press-7", 1, 0x7601);
        pn_stack_destroy(s);
    }
    if (chdir(cwd) != 0) {
        fprintf(stderr, "FAIL: chdir back\n");
        g_fail = 1;
    }
    if (file_exists(dir, PN_NVM_FILE_IP) || file_exists(dir, PN_NVM_FILE_IM)) {
        fprintf(stderr, "FAIL: empty nvm_dir wrote a file in the cwd\n");
        g_fail = 1;
    }
    s = open_file_stack("", "other", 0, 0, 0, NULL);
    if (s) {
        if (strcmp(s->cfg.station_name, "other") != 0) {
            fprintf(stderr, "FAIL: empty nvm_dir kept '%s'\n",
                    s->cfg.station_name);
            g_fail = 1;
        }
        pn_stack_destroy(s);
    }
    rm_nvm_dir(dir);
}

/* nvm_dir file backend: values survive a new stack. Injected ops win
 * over files that are already there. */
static void test_t12_20_file_survives(void)
{
    char dir[256];
    if (make_nvm_dir(dir, sizeof(dir)) != 0) {
        return;
    }
    pn_stack_t *s = open_file_stack(dir, "orig", 0x0A000001u, 0xFFFFFF00u,
                                    0x0A000001u, NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7701);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7702);
    write_im_pattern(s);
    pn_stack_destroy(s);
    if (!file_exists(dir, PN_NVM_FILE_IP) || !file_exists(dir, PN_NVM_FILE_IM)) {
        fprintf(stderr, "FAIL: file backend did not write pn-ip.bin/pn-im.bin\n");
        g_fail = 1;
    }
    if (file_exists(dir, "pn-ip.bin.tmp") || file_exists(dir, "pn-im.bin.tmp")) {
        fprintf(stderr, "FAIL: temp NVM file left after save\n");
        g_fail = 1;
    }
    s = open_file_stack(dir, "other", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                        NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr, "FAIL: file backend name got '%s' (want press-7)\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, "file backend ip");
    if (!im1_pattern_ok(s) || !im_is(s, PN_INDEX_IM2, 'C', PN_IM2_DATE_LEN) ||
        !im_is(s, PN_INDEX_IM3, 'D', PN_IM3_DESC_LEN) ||
        !im_is(s, PN_INDEX_IM4, 0x11, PN_IM4_SIG_LEN)) {
        fprintf(stderr, "FAIL: file backend I&M1-4 did not survive recreate\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);

    /* Injected ops are used instead of the files. */
    mem_nvm_t mem;
    memset(&mem, 0, sizeof(mem));
    mem.have = 1;
    mem.img.present = PN_NVM_NAME | PN_NVM_IP;
    snprintf(mem.img.station_name, sizeof(mem.img.station_name), "from-mem");
    mem.img.ip = 0x0A000063u;
    mem.img.netmask = 0xFFFFFF00u;
    mem.img.gateway = 0x0A000001u;
    s = open_file_stack(dir, "other", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                        &mem);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "from-mem") != 0) {
        fprintf(stderr, "FAIL: injected ops lost to file name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x0A000063u, 0xFFFFFF00u, 0x0A000001u,
                 "injected ops ip");
    set_name_qual(s, "mem-only", 1, 0x7703);
    pn_stack_destroy(s);
    s = open_file_stack(dir, "other", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                        NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr,
                "FAIL: injected save changed the file name to '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    pn_stack_destroy(s);

    /* Empty injection starts from config, not from the files. */
    memset(&mem, 0, sizeof(mem));
    s = open_file_stack(dir, "other", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                        &mem);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "other") != 0) {
        fprintf(stderr, "FAIL: empty injection kept file name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x01020304u, 0xFFFF0000u, 0x01020301u,
                 "empty injection ip");
    pn_stack_destroy(s);
    rm_nvm_dir(dir);
}

static void test_t12_20_file_corrupt_and_version(void)
{
    char dir[256];
    if (make_nvm_dir(dir, sizeof(dir)) != 0) {
        return;
    }
    pn_stack_t *s = open_file_stack(dir, "orig", 0x0A000001u, 0xFFFFFF00u,
                                    0x0A000001u, NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7801);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7802);
    write_im_pattern(s);
    pn_stack_destroy(s);

    char ip_path[512];
    snprintf(ip_path, sizeof(ip_path), "%s/%s", dir, PN_NVM_FILE_IP);
    int fd = open(ip_path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "FAIL: corrupt setup could not open pn-ip.bin\n");
        g_fail = 1;
        rm_nvm_dir(dir);
        return;
    }
    if (lseek(fd, 12, SEEK_SET) < 0 || write(fd, "X", 1) != 1) {
        fprintf(stderr, "FAIL: could not flip a byte in pn-ip.bin\n");
        g_fail = 1;
    }
    close(fd);

    int saved = -1;
    int pfd[2] = {-1, -1};
    capture_begin(&saved, pfd);
    s = create_file_stack(dir, "from-cfg", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                          NULL);
    capture_end(saved, pfd);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "from-cfg") != 0) {
        fprintf(stderr, "FAIL: corrupt pn-ip.bin applied name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x01020304u, 0xFFFF0000u, 0x01020301u,
                 "corrupt pn-ip.bin");
    if (!im1_pattern_ok(s)) {
        fprintf(stderr, "FAIL: corrupt IP file dropped a valid I&M file\n");
        g_fail = 1;
    }
    if (!strstr(g_logbuf, "[WARN]") || !strstr(g_logbuf, "nvm")) {
        fprintf(stderr, "FAIL: corrupt file produced no nvm LOG_WARN (%s)\n",
                g_logbuf);
        g_fail = 1;
    }
    pn_stack_destroy(s);

    uint8_t payload[PN_NVM_IP_PAYLOAD_LEN];
    memset(payload, 0, sizeof(payload));
    pn_wr_le32(payload, PN_NVM_NAME | PN_NVM_IP);
    memcpy(payload + 4, "stored-name", 11);
    pn_wr_le32(payload + 4 + PN_STATION_NAME_MAX + 1, 0x0A000063u);
    pn_wr_le32(payload + 4 + PN_STATION_NAME_MAX + 1 + 4, 0xFFFFFF00u);
    pn_wr_le32(payload + 4 + PN_STATION_NAME_MAX + 1 + 8, 0x0A000001u);
    if (plant_nvm_file(dir, PN_NVM_FILE_IP, "PNIP", 2, payload,
                       sizeof(payload)) != 0) {
        fprintf(stderr, "FAIL: could not plant version 2 file\n");
        g_fail = 1;
        rm_nvm_dir(dir);
        return;
    }
    capture_begin(&saved, pfd);
    s = create_file_stack(dir, "from-cfg", 0x11111111u, 0xFFFFFF00u, 0x11111101u,
                          NULL);
    capture_end(saved, pfd);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "from-cfg") != 0) {
        fprintf(stderr, "FAIL: version 2 file applied name '%s'\n",
                s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x11111111u, 0xFFFFFF00u, 0x11111101u, "version 2 file");
    if (!strstr(g_logbuf, "버전")) {
        fprintf(stderr, "FAIL: version file produced no 버전 LOG_WARN (%s)\n",
                g_logbuf);
        g_fail = 1;
    }
    pn_stack_destroy(s);
    rm_nvm_dir(dir);
}

/* ResetToFactory removes the file that matches the mode. */
static void test_t12_20_file_reset_deletes(void)
{
    char dir[256];
    if (make_nvm_dir(dir, sizeof(dir)) != 0) {
        return;
    }
    pn_stack_t *s = open_file_stack(dir, "orig", 0x0A000001u, 0xFFFFFF00u,
                                    0x0A000001u, NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7901);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7902);
    write_im_pattern(s);
    set_reset_qual(s, PN_DCP_SUB_CTRL_RESET, 1u << 1, 0x7903);
    int ip_left = file_exists(dir, PN_NVM_FILE_IP);
    int im_left = file_exists(dir, PN_NVM_FILE_IM);
    pn_stack_destroy(s);
    if (!ip_left || im_left) {
        fprintf(stderr,
                "FAIL: mode 1 files ip=%d im=%d (want ip kept, im deleted)\n",
                ip_left, im_left);
        g_fail = 1;
    }
    s = open_file_stack(dir, "from-cfg", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                        NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr, "FAIL: mode 1 file name got '%s'\n", s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, "mode 1 file ip");
    if (!im_factory_ok(s)) {
        fprintf(stderr, "FAIL: mode 1 file left I&M\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);

    s = open_file_stack(dir, "orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u,
                        NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7911);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7912);
    write_im_pattern(s);
    set_reset_qual(s, PN_DCP_SUB_CTRL_RESET, 2u << 1, 0x7913);
    ip_left = file_exists(dir, PN_NVM_FILE_IP);
    im_left = file_exists(dir, PN_NVM_FILE_IM);
    pn_stack_destroy(s);
    if (ip_left || !im_left) {
        fprintf(stderr,
                "FAIL: mode 2 files ip=%d im=%d (want ip deleted, im kept)\n",
                ip_left, im_left);
        g_fail = 1;
    }
    s = open_file_stack(dir, "from-cfg", 0x01020304u, 0xFFFF0000u, 0x01020301u,
                        NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    if (strcmp(s->cfg.station_name, "from-cfg") != 0) {
        fprintf(stderr, "FAIL: mode 2 file name got '%s'\n", s->cfg.station_name);
        g_fail = 1;
    }
    expect_suite(s, 0x01020304u, 0xFFFF0000u, 0x01020301u, "mode 2 file ip");
    if (!im1_pattern_ok(s) || !im_is(s, PN_INDEX_IM4, 0x11, PN_IM4_SIG_LEN)) {
        fprintf(stderr, "FAIL: mode 2 file dropped I&M\n");
        g_fail = 1;
    }
    pn_stack_destroy(s);

    s = open_file_stack(dir, "orig", 0x0A000001u, 0xFFFFFF00u, 0x0A000001u,
                        NULL);
    if (!s) {
        rm_nvm_dir(dir);
        return;
    }
    set_name_qual(s, "press-7", 1, 0x7921);
    write_im_pattern(s);
    set_reset_qual(s, PN_DCP_SUB_CTRL_FACTORY, 0, 0x7922);
    ip_left = file_exists(dir, PN_NVM_FILE_IP);
    im_left = file_exists(dir, PN_NVM_FILE_IM);
    pn_stack_destroy(s);
    if (ip_left || im_left) {
        fprintf(stderr, "FAIL: factory reset left files ip=%d im=%d\n", ip_left,
                im_left);
        g_fail = 1;
    }
    s = open_file_stack(dir, "from-cfg", 0x11111111u, 0xFFFFFF00u, 0x11111101u,
                        NULL);
    if (s) {
        if (strcmp(s->cfg.station_name, "from-cfg") != 0 || !im_factory_ok(s)) {
            fprintf(stderr, "FAIL: factory reset file still supplies stored values\n");
            g_fail = 1;
        }
        pn_stack_destroy(s);
    }
    rm_nvm_dir(dir);
}

/* A gateway change is delivered to the OS hook, including a change to 0.
 * SIOCDELRT itself is pn_os_install_default_route: the hook replaces
 * pn_os_apply_ip_default, so it cannot see ioctl requests. */
static void test_t12_20_gateway_hook(void)
{
    os_hook_t hook;
    memset(&hook, 0, sizeof(hook));
    pn_stack_t *s = open_nvm_stack("sensor-line1", 0, 0, 0, 1, NULL, &hook);
    if (!s) {
        return;
    }
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80001u, 1, 0x7A01);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0xC0A80101u, 1, 0x7A02);
    set_ip_qual(s, 0xC0A80014u, 0xFFFFFF00u, 0, 1, 0x7A03);
    if (hook.calls != 3 || hook.ev[0].gateway != 0xC0A80001u ||
        hook.ev[1].gateway != 0xC0A80101u || hook.ev[2].gateway != 0 ||
        hook.ev[2].ip != 0xC0A80014u) {
        fprintf(stderr,
                "FAIL: gateway change hook calls=%d gw=%08x %08x %08x\n",
                hook.calls, hook.calls > 0 ? hook.ev[0].gateway : 0,
                hook.calls > 1 ? hook.ev[1].gateway : 0,
                hook.calls > 2 ? hook.ev[2].gateway : 0);
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

typedef struct {
    int n;
    unsigned long req[8];
    uint32_t gw[8];
    int del_errno;
    int add_errno;
} route_rec_t;

static int route_fake(void *ctx, unsigned long req, uint32_t gw)
{
    route_rec_t *r = ctx;
    if (r->n < 8) {
        r->req[r->n] = req;
        r->gw[r->n] = gw;
    }
    r->n++;
    if (req == SIOCDELRT && r->del_errno) {
        return -r->del_errno;
    }
    if (req == SIOCADDRT && r->add_errno) {
        return -r->add_errno;
    }
    return 0;
}

static void test_t12_20_route_replace(void)
{
    const char *table =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        "eth1\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
    uint32_t gws[4];
    int n = pn_os_parse_proc_routes(table, "eth0", gws, 4);
    /* 0100A8C0 is the little-endian /proc form of 192.168.0.1. */
    if (n != 1 || gws[0] != 0xC0A80001u) {
        fprintf(stderr, "FAIL: proc route parse n=%d gw=%08x\n", n,
                n > 0 ? gws[0] : 0);
        g_fail = 1;
    }
    n = pn_os_parse_proc_routes(table, "eth1", gws, 4);
    if (n != 1 || gws[0] != 0xC0A80101u) {
        fprintf(stderr, "FAIL: eth1 default gw n=%d gw=%08x\n", n,
                n > 0 ? gws[0] : 0);
        g_fail = 1;
    }

    route_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    uint32_t prev[2] = {0xC0A80001u, 0xC0A80101u};
    int rc = pn_os_install_default_route("eth0", prev, 2, 0x0A000001u, route_fake,
                                        &rec);
    if (rc != 0 || rec.n != 3 || rec.req[0] != SIOCDELRT ||
        rec.gw[0] != 0xC0A80001u || rec.req[1] != SIOCDELRT ||
        rec.gw[1] != 0xC0A80101u || rec.req[2] != SIOCADDRT ||
        rec.gw[2] != 0x0A000001u) {
        fprintf(stderr,
                "FAIL: route change did not delete then add n=%d rc=%d "
                "req0=%lu gw0=%08x\n",
                rec.n, rc, rec.n > 0 ? rec.req[0] : 0,
                rec.n > 0 ? rec.gw[0] : 0);
        g_fail = 1;
    }

    memset(&rec, 0, sizeof(rec));
    rc = pn_os_install_default_route("eth0", prev, 1, 0, route_fake, &rec);
    if (rc != 0 || rec.n != 1 || rec.req[0] != SIOCDELRT ||
        rec.gw[0] != 0xC0A80001u) {
        fprintf(stderr,
                "FAIL: gateway 0 did not SIOCDELRT the previous route n=%d rc=%d\n",
                rec.n, rc);
        g_fail = 1;
    }

    memset(&rec, 0, sizeof(rec));
    rec.del_errno = ESRCH;
    rc = pn_os_install_default_route("eth0", prev, 1, 0xC0A80001u, route_fake,
                                    &rec);
    if (rc != 0 || rec.n != 2 || rec.req[1] != SIOCADDRT) {
        fprintf(stderr, "FAIL: SIOCDELRT ESRCH aborted the add n=%d rc=%d\n",
                rec.n, rc);
        g_fail = 1;
    }

    memset(&rec, 0, sizeof(rec));
    rec.add_errno = EEXIST;
    rc = pn_os_install_default_route("eth0", NULL, 0, 0xC0A80001u, route_fake,
                                    &rec);
    if (rc != 0 || rec.n != 1 || rec.req[0] != SIOCADDRT) {
        fprintf(stderr, "FAIL: SIOCADDRT EEXIST was an error rc=%d n=%d\n", rc,
                rec.n);
        g_fail = 1;
    }
}

/* T12-22: this station is an IO-Device. Identify.res DeviceRole details
 * are 0x01 (not 0x02 IO-Controller), and a DeviceRole filter matches
 * 0x01 only. docs/protocols/profinet.md D2 and 5.b.4. */
static void test_t12_22_device_role(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "t12-22 role stack");
    if (!s) {
        return;
    }
    uint8_t mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[PN_FRAME_MAX];
    uint8_t role[2] = {0x01, 0x00};
    uint8_t all[4] = {PN_DCP_OPT_ALL, 0xFF, 0x00, 0x00};

    tx_reset();
    size_t flen = dcp_ident_frame(frame, mc, src, 0, all, sizeof(all));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "t12-22 ident all");
    const uint8_t *blocks = NULL;
    uint16_t dlen = 0;
    if (blocks_of_tx(PN_FRAMEID_DCP_ID_RES, &blocks, &dlen, "t12-22 Identify.Res")) {
        expect_blockinfo(blocks, dlen, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ROLE, 0,
                         role, sizeof(role), "t12-22 Identify DeviceRole 0x01");
    }

    uint8_t filt[6];
    filt[0] = PN_DCP_OPT_DEV;
    filt[1] = PN_DCP_SUB_DEV_ROLE;
    pn_wr_be16(filt + 2, 2);
    filt[4] = 0x01;
    filt[5] = 0x00;
    tx_reset();
    flen = dcp_ident_frame(frame, mc, src, 0, filt, sizeof(filt));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "t12-22 role filter 0x01");
    expect(tx_has_fid(PN_FRAMEID_DCP_ID_RES),
           "t12-22 DeviceRole filter 0x01 is answered");

    filt[4] = 0x02;
    tx_reset();
    flen = dcp_ident_frame(frame, mc, src, 0, filt, sizeof(filt));
    expect(pn_stack_handle_eth(s, frame, flen) == 0, "t12-22 role filter 0x02");
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES),
           "t12-22 DeviceRole filter 0x02 is not answered");

    pn_stack_destroy(s);
}

/* Identify.Res unicast to the requester. Xid is DCP header offset 4
 * (Ethernet offset 18). */
static int count_ident_res(const uint8_t mac[6], uint32_t xid)
{
    int n = 0;
    for (int i = 0; i < g_ntx; i++) {
        if (g_txlen[i] < 22 || memcmp(g_tx[i], mac, 6) != 0) {
            continue;
        }
        if (pn_rd_be16(g_tx[i] + 14) != PN_FRAMEID_DCP_ID_RES) {
            continue;
        }
        if (pn_rd_be32(g_tx[i] + 18) != xid) {
            continue;
        }
        n++;
    }
    return n;
}

static void expect_ident_res_n(const uint8_t mac[6], uint32_t xid, int want,
                               const char *what)
{
    int got = count_ident_res(mac, xid);
    if (got != want) {
        fprintf(stderr, "FAIL: %s responses=%d want %d xid=0x%08x\n", what, got,
                want, xid);
        g_fail = 1;
    }
}

static void send_delayed_ident(pn_stack_t *s, const uint8_t src[6], uint32_t xid)
{
    uint8_t mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    uint8_t all[4] = {PN_DCP_OPT_ALL, 0xFF, 0x00, 0x00};
    uint8_t frame[PN_FRAME_MAX];
    /* Default station MAC …:00:01, factor 2 → 1×10 ms. */
    size_t flen =
        dcp_ident_frame_xid(frame, mc, src, 2, xid, all, sizeof(all));
    expect(flen > 0 && pn_stack_handle_eth(s, frame, flen) == 0,
           "t12-22 delayed Identify");
}

static void wait_delayed_ident(pn_stack_t *s)
{
    usleep(40000);
    pn_stack_poll(s);
}

/* T12-22: two delayed Identify requests from different MACs both get a
 * response. A one-slot queue keeps only the second. */
static void test_t12_22_ident_two_macs(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "t12-22 two-mac stack");
    if (!s) {
        return;
    }
    uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
    uint8_t mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};
    tx_reset();
    send_delayed_ident(s, mac_a, 0xA0000001u);
    send_delayed_ident(s, mac_b, 0xB0000002u);
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES), "t12-22 two-mac not immediate");
    wait_delayed_ident(s);
    expect_ident_res_n(mac_a, 0xA0000001u, 1, "t12-22 delayed Identify MAC A");
    expect_ident_res_n(mac_b, 0xB0000002u, 1, "t12-22 delayed Identify MAC B");
    pn_stack_destroy(s);
}

/* T12-22: the same (requester MAC, Xid) again is a retransmission, so
 * exactly one response. A different key queued after it is still answered.
 * One slot keeps only the last request, so the retransmitted key is lost. */
static void test_t12_22_ident_retransmit(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "t12-22 retransmit stack");
    if (!s) {
        return;
    }
    uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x1A};
    uint8_t mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x1B};
    tx_reset();
    send_delayed_ident(s, mac_a, 0x11111111u);
    send_delayed_ident(s, mac_a, 0x11111111u);
    send_delayed_ident(s, mac_b, 0x22222222u);
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES),
           "t12-22 retransmit not immediate");
    wait_delayed_ident(s);
    expect_ident_res_n(mac_a, 0x11111111u, 1,
                       "t12-22 same (MAC, Xid) retransmission");
    expect_ident_res_n(mac_b, 0x22222222u, 1,
                       "t12-22 retransmission still answers the other MAC");
    pn_stack_destroy(s);
}

/* T12-22: four pending responses are kept. The fifth new key is ignored
 * (LOG_WARN) and does not replace the oldest. */
static void test_t12_22_ident_fifth_ignored(void)
{
    pn_stack_t *s = make_dcp_stack();
    expect(s != NULL, "t12-22 fifth stack");
    if (!s) {
        return;
    }
    uint8_t mac[5][6];
    uint32_t xid[5];
    tx_reset();
    for (int i = 0; i < 4; i++) {
        memset(mac[i], 0, 6);
        mac[i][0] = 0x02;
        mac[i][5] = (uint8_t)(0x30 + i);
        xid[i] = 0x30000000u + (uint32_t)i;
        send_delayed_ident(s, mac[i], xid[i]);
    }
    memset(mac[4], 0, 6);
    mac[4][0] = 0x02;
    mac[4][5] = 0x34;
    xid[4] = 0x30000004u;
    int saved = -1;
    int pfd[2] = {-1, -1};
    capture_begin(&saved, pfd);
    send_delayed_ident(s, mac[4], xid[4]);
    capture_end(saved, pfd);
    if (!strstr(g_logbuf, "Identify delay queue full")) {
        fprintf(stderr,
                "FAIL: t12-22 fifth Identify ignored without LOG_WARN\n");
        g_fail = 1;
    }
    expect(!tx_has_fid(PN_FRAMEID_DCP_ID_RES), "t12-22 fifth not immediate");
    wait_delayed_ident(s);
    for (int i = 0; i < 4; i++) {
        char what[64];
        snprintf(what, sizeof(what), "t12-22 delayed Identify slot %d", i);
        expect_ident_res_n(mac[i], xid[i], 1, what);
    }
    expect_ident_res_n(mac[4], xid[4], 0, "t12-22 fifth Identify is ignored");
    pn_stack_destroy(s);
}

int main(void)
{
    test_name_ok();
    test_ident_filter_and_delay();
    test_set_name_and_enforce();
    test_response_blockinfo();
    test_t12_22_device_role();
    test_t12_22_ident_two_macs();
    test_t12_22_ident_retransmit();
    test_t12_22_ident_fifth_ignored();
    test_t12_16_set_rules();
    test_t12_20_os_ip_hook();
    test_t12_20_permanent_survives();
    test_t12_20_temporary_does_not();
    test_t12_20_reset_erases_store();
    test_t12_20_os_ip_on_load();
    test_t12_20_empty_nvm_dir();
    test_t12_20_file_survives();
    test_t12_20_file_corrupt_and_version();
    test_t12_20_file_reset_deletes();
    test_t12_20_gateway_hook();
    test_t12_20_route_replace();
    if (g_fail) {
        fprintf(stderr, "test_pn_dcp: FAILED\n");
        return 1;
    }
    printf("test_pn_dcp: OK\n");
    return 0;
}
