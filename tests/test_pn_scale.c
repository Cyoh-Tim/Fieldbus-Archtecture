/*
 * T2 (PN): scale/offset 는 어댑터 책임 (T0 A안).
 * uint16, scale 0.1 포인트에 fb_write_u32(..., 300) 이면
 * IO 데이터는 원시값 3000 의 빅 엔디안 0B B8 이고, 읽기 왕복은 300.0 이다.
 */
#include "fb_api.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
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

static void hex2(char *dst, size_t dst_len, const uint8_t *b, size_t n)
{
    size_t used = 0;
    dst[0] = '\0';
    for (size_t i = 0; i < n && used + 4 < dst_len; i++) {
        int k = snprintf(dst + used, dst_len - used, "%s%02X", i ? " " : "",
                         b[i]);
        if (k < 0) {
            return;
        }
        used += (size_t)k;
    }
}

/* 스케일 없는 bytes 포인트가 같은 byte_offset 의 입력 이미지를 그대로 읽는다. */
static const char *k_cfg =
    "{\n"
    "  \"protocol\": \"profinet\",\n"
    "  \"device\": {\"name\": \"pn_scale\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"iface\": \"mock\",\n"
    "    \"device_name\": \"sensor-line1\",\n"
    "    \"vendor_id\": 43981,\n"
    "    \"device_id\": 1,\n"
    "    \"ip\": \"192.168.0.10\",\n"
    "    \"netmask\": \"255.255.255.0\",\n"
    "    \"gateway\": \"192.168.0.1\",\n"
    "    \"security_class\": 0,\n"
    "    \"input_len\": 32,\n"
    "    \"output_len\": 8,\n"
    "    \"cycle_us\": 8000\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"status_word\", \"access\": \"read\",\n"
    "     \"data_type\": \"uint16\", \"length\": 2, \"scale\": 0.1,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 1, \"byte_offset\": 0, \"length\": 2}}},\n"
    "    {\"name\": \"status_word_io\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 1, \"byte_offset\": 0, \"length\": 2}}},\n"
    "    {\"name\": \"biased\", \"access\": \"read\",\n"
    "     \"data_type\": \"uint16\", \"length\": 2,\n"
    "     \"scale\": 0.1, \"offset\": 10.0,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 1, \"byte_offset\": 2, \"length\": 2}}},\n"
    "    {\"name\": \"biased_io\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 1, \"byte_offset\": 2, \"length\": 2}}}\n"
    "  ]\n"
    "}\n";

static int read_io(fb_runtime_t *rt, const char *name, uint8_t out[2])
{
    size_t n = 0;
    memset(out, 0, 2);
    int rc = fb_read_bytes(rt, name, out, 2, &n);
    if (rc != FB_OK || n != 2) {
        fprintf(stderr, "FAIL: read %s rc=%d len=%zu\n", name, rc, n);
        g_fail = 1;
        return -1;
    }
    return 0;
}

int main(void)
{
    char dir[] = "/tmp/pn_scale_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/pn.json", dir);

    expect(write_file(path, k_cfg) == 0, "write cfg");

    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    expect(rc == FB_OK && rt != NULL, "fb_open");
    if (rc != FB_OK || !rt) {
        fprintf(stderr, "open: %s\n", fb_strerror(rc));
        return 1;
    }

    rc = fb_write_u32(rt, "status_word", 300);
    expect(rc == FB_OK, "fb_write_u32 status_word 300");
    if (rc != FB_OK) {
        fprintf(stderr, "write: %s\n", fb_strerror(rc));
    }

    uint8_t io[2];
    if (read_io(rt, "status_word_io", io) == 0) {
        char got[16];
        hex2(got, sizeof(got), io, 2);
        if (!(io[0] == 0x0B && io[1] == 0xB8)) {
            fprintf(stderr, "IO data bytes: %s (expected 0B B8)\n", got);
            fprintf(stderr, "FAIL: IO data bytes %s, expected 0B B8\n", got);
            g_fail = 1;
        }
    }

    float eng = 0.0f;
    rc = fb_read_f32(rt, "status_word", &eng);
    expect(rc == FB_OK, "fb_read_f32 status_word");
    if (!(rc == FB_OK && fabsf(eng - 300.0f) < 1e-3f)) {
        fprintf(stderr, "FAIL: read roundtrip %.4f, expected 300.0\n",
                (double)eng);
        g_fail = 1;
    }

    /* offset: eng 310, scale 0.1, offset 10 → raw (310-10)/0.1 = 3000 */
    rc = fb_write_u32(rt, "biased", 310);
    expect(rc == FB_OK, "fb_write_u32 biased 310");
    if (read_io(rt, "biased_io", io) == 0) {
        char got[16];
        hex2(got, sizeof(got), io, 2);
        if (!(io[0] == 0x0B && io[1] == 0xB8)) {
            fprintf(stderr, "FAIL: offset IO data bytes %s, expected 0B B8\n",
                    got);
            g_fail = 1;
        }
    }
    eng = 0.0f;
    rc = fb_read_f32(rt, "biased", &eng);
    if (!(rc == FB_OK && fabsf(eng - 310.0f) < 1e-3f)) {
        fprintf(stderr, "FAIL: offset read roundtrip %.4f, expected 310.0\n",
                (double)eng);
        g_fail = 1;
    }

    fb_close(rt);

    if (g_fail) {
        fprintf(stderr, "test_pn_scale: FAILED\n");
        return 1;
    }
    printf("test_pn_scale: OK\n");
    return 0;
}
