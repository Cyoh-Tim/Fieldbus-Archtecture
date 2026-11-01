/*
 * T12-9: 어댑터 기본값은 자체 HMAC 을 켜면 안 된다.
 *
 * security_class / psk_hex 를 생략한 config 로 fb_open 이 성공해야 하고,
 * 그 장치는 서명 없는 DCP Set(NameOfStation) 과 integrity 블록 없는
 * 표준 Connect 를 받아야 한다. PI Security Class 1 은 프레임에 HMAC 을
 * 넣지 않는다. config 키 security_class=1 과 psk_hex 를 주면 기존
 * vendor integrity extension 은 그대로 서명 없는 Set/Connect 를 거부한다.
 */
#include "fb_api.h"
#include "pn_endian.h"
#include "pn_stack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;
static pn_stack_t *g_stack;

static int mock_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    (void)frame;
    return (int)len;
}

static int mock_recv(void *ctx, uint8_t *frame, size_t cap, int timeout_ms)
{
    (void)ctx;
    (void)frame;
    (void)cap;
    (void)timeout_ms;
    return -EAGAIN;
}

pn_stack_t *__real_pn_stack_create(const pn_cfg_t *cfg);

pn_stack_t *__wrap_pn_stack_create(const pn_cfg_t *cfg)
{
    pn_stack_t *s = __real_pn_stack_create(cfg);
    if (s) {
        pn_eth_ops_t ops = {mock_send, mock_recv, NULL};
        pn_stack_set_eth_ops(s, ops);
        g_stack = s;
    }
    return s;
}

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static int write_file(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        return -1;
    }
    if (fputs(body, f) == EOF) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static const char *k_default_cfg =
    "{\n"
    "  \"protocol\": \"profinet\",\n"
    "  \"device\": {\"name\": \"pn_t12_9\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"iface\": \"mock\",\n"
    "    \"device_name\": \"oracle-dut\",\n"
    "    \"vendor_id\": 43981,\n"
    "    \"device_id\": 1,\n"
    "    \"ip\": \"192.168.0.50\",\n"
    "    \"netmask\": \"255.255.255.0\",\n"
    "    \"input_len\": 32,\n"
    "    \"output_len\": 32,\n"
    "    \"cycle_us\": 8000\n"
    "  },\n"
    "  \"points\": []\n"
    "}\n";

/* security_class 1 은 기존 config 키. psk 없으면 열리면 안 된다. */
static const char *k_class1_no_psk =
    "{\n"
    "  \"protocol\": \"profinet\",\n"
    "  \"device\": {\"name\": \"pn_t12_9\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"iface\": \"mock\",\n"
    "    \"device_name\": \"oracle-dut\",\n"
    "    \"security_class\": 1\n"
    "  },\n"
    "  \"points\": []\n"
    "}\n";

static const char *k_class1_psk =
    "{\n"
    "  \"protocol\": \"profinet\",\n"
    "  \"device\": {\"name\": \"pn_t12_9\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"iface\": \"mock\",\n"
    "    \"device_name\": \"old-name\",\n"
    "    \"security_class\": 1,\n"
    "    \"psk_hex\": "
    "\"2222222222222222222222222222222222222222222222222222222222222222\"\n"
    "  },\n"
    "  \"points\": []\n"
    "}\n";

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

/* integrity 블록(0x0E01) 없는 Connect. 표준 컨트롤러가 보내는 형태. */
static size_t build_plain_connect(uint8_t *pdu)
{
    uint8_t ar[2 + 16 + 2 + 6];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    for (int i = 0; i < 16; i++) {
        ar[2 + i] = (uint8_t)(0xA0 + i);
    }
    pn_wr_be16(ar + 18, 1);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_AR_REQ, ar, sizeof(ar));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    memset(pdu, 0, 80);
    pdu[0] = 4; /* CL RPC. 버전·drep·UUID 를 검사한다. */
    pdu[1] = 0;
    pdu[4] = 0x10;
    static const uint8_t obj[16] = {
        0x00, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xab, 0xcd};
    static const uint8_t iface[16] = {
        0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d};
    memcpy(pdu + 8, obj, 16);
    memcpy(pdu + 24, iface, 16);
    pn_wr_le16(pdu + 68, 0); /* Connect */
    pn_wr_le16(pdu + 74, (uint16_t)sn);
    memcpy(pdu + 80, stub, sn);
    return 80 + sn;
}

static size_t dcp_set_name_frame(uint8_t *out, const uint8_t dst[6],
                                 const uint8_t src[6], const char *name)
{
    size_t nlen = strlen(name);
    uint8_t blk[2 + 64];
    pn_wr_be16(blk, 1);
    memcpy(blk + 2, name, nlen);
    uint8_t blocks[128];
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
    uint8_t pay[256];
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

static fb_runtime_t *open_cfg(const char *dir, const char *name,
                              const char *body, int *rc_out)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (write_file(path, body) != 0) {
        fprintf(stderr, "FAIL: write %s\n", path);
        g_fail = 1;
        if (rc_out) {
            *rc_out = -1;
        }
        return NULL;
    }
    g_stack = NULL;
    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    if (rc_out) {
        *rc_out = rc;
    }
    return rt;
}

static void test_default_accepts_standard(const char *dir)
{
    int rc = 0;
    fb_runtime_t *rt = open_cfg(dir, "default.json", k_default_cfg, &rc);
    if (rc != FB_OK || !rt || !g_stack) {
        fprintf(stderr,
                "FAIL: default config (no security_class, no psk_hex) "
                "fb_open rc=%d (%s), stack=%p\n",
                rc, fb_strerror(rc), (void *)g_stack);
        fprintf(stderr,
                "  expected FB_OK and an open device that accepts a "
                "standard controller\n");
        g_fail = 1;
        fb_close(rt);
        return;
    }
    const pn_cfg_t *cfg = pn_stack_cfg(g_stack);
    if (!cfg || cfg->security_class != 0) {
        fprintf(stderr,
                "FAIL: omitted security_class stored as %d (want 0, "
                "vendor integrity extension off)\n",
                cfg ? cfg->security_class : -1);
        g_fail = 1;
    }

    uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = dcp_set_name_frame(frame, cfg->mac, src, "line-b01");
    expect(pn_stack_handle_eth(g_stack, frame, flen) == 0, "dcp set handle");
    cfg = pn_stack_cfg(g_stack);
    if (!cfg || strcmp(cfg->station_name, "line-b01") != 0) {
        fprintf(stderr,
                "FAIL: unsigned DCP Set name rejected (station_name=%s)\n",
                cfg ? cfg->station_name : "(null)");
        g_fail = 1;
    }

    uint8_t pdu[512];
    size_t plen = build_plain_connect(pdu);
    uint8_t resp[1024];
    size_t rlen = 0;
    int crc = pn_stack_handle_rpc(g_stack, pdu, plen, resp, sizeof(resp),
                                  &rlen);
    if (crc != 0 || pn_stack_ar_up(g_stack) != 1) {
        fprintf(stderr,
                "FAIL: standard Connect without integrity block rejected "
                "(rpc rc=%d ar_up=%d resp_len=%zu)\n",
                crc, g_stack ? pn_stack_ar_up(g_stack) : -1, rlen);
        g_fail = 1;
    }
    fb_close(rt);
}

static void test_explicit_class_still_requires_psk(const char *dir)
{
    int rc = 0;
    fb_runtime_t *rt = open_cfg(dir, "class1.json", k_class1_no_psk, &rc);
    if (rc == FB_OK) {
        fprintf(stderr,
                "FAIL: security_class 1 without psk_hex opened (rc=%d)\n",
                rc);
        g_fail = 1;
        fb_close(rt);
        return;
    }
    expect(rc == FB_ERR_CONFIG, "security_class 1 without psk is config error");
    fb_close(rt);
}

static void test_explicit_class_rejects_unsigned(const char *dir)
{
    int rc = 0;
    fb_runtime_t *rt = open_cfg(dir, "class1psk.json", k_class1_psk, &rc);
    if (rc != FB_OK || !rt || !g_stack) {
        fprintf(stderr,
                "FAIL: security_class 1 + psk_hex fb_open rc=%d (%s)\n", rc,
                fb_strerror(rc));
        g_fail = 1;
        fb_close(rt);
        return;
    }
    const pn_cfg_t *cfg = pn_stack_cfg(g_stack);
    expect(cfg && cfg->security_class == 1, "explicit security_class 1 kept");

    uint8_t src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = dcp_set_name_frame(frame, cfg->mac, src, "new-name");
    expect(pn_stack_handle_eth(g_stack, frame, flen) == 0, "signed-off set");
    cfg = pn_stack_cfg(g_stack);
    if (!cfg || strcmp(cfg->station_name, "old-name") != 0) {
        fprintf(stderr,
                "FAIL: security_class 1 accepted unsigned DCP Set "
                "(station_name=%s)\n",
                cfg ? cfg->station_name : "(null)");
        g_fail = 1;
    }

    uint8_t pdu[512];
    size_t plen = build_plain_connect(pdu);
    uint8_t resp[1024];
    size_t rlen = 0;
    int crc = pn_stack_handle_rpc(g_stack, pdu, plen, resp, sizeof(resp),
                                  &rlen);
    if (crc == 0 && pn_stack_ar_up(g_stack) == 1) {
        fprintf(stderr,
                "FAIL: security_class 1 accepted Connect without integrity "
                "block\n");
        g_fail = 1;
    }
    fb_close(rt);
}

int main(void)
{
    char dir[] = "/tmp/pn_t12_9_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    test_default_accepts_standard(dir);
    if (!g_fail) {
        test_explicit_class_still_requires_psk(dir);
        test_explicit_class_rejects_unsigned(dir);
    }
    if (g_fail) {
        fprintf(stderr, "test_pn_t12_9: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_9: ok\n");
    return 0;
}
