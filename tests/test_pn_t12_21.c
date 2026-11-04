/*
 * T12-21: 예제 config 의 input/output 길이는 GSDML IO 서브모듈(입력 32,
 * 출력 8)과 같아야 하고, 포인트는 그 이미지 안에 들어가야 한다.
 * 주기 이미지는 slot 1 / subslot 1 뿐이다. 같은 byte_offset 이라도
 * 다른 slot/subslot 은 그 이미지를 읽거나 덮어쓰면 안 된다.
 */
#include "cJSON.h"
#include "fb_api.h"

#include <errno.h>
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

static char *read_all(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "FAIL: open %s: %s\n", path, strerror(errno));
        g_fail = 1;
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(stderr, "FAIL: seek %s\n", path);
        g_fail = 1;
        return NULL;
    }
    long n = ftell(f);
    if (n < 0) {
        fclose(f);
        fprintf(stderr, "FAIL: ftell %s\n", path);
        g_fail = 1;
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        fprintf(stderr, "FAIL: rewind %s\n", path);
        g_fail = 1;
        return NULL;
    }
    char *b = malloc((size_t)n + 1);
    if (!b) {
        fclose(f);
        fprintf(stderr, "FAIL: oom\n");
        g_fail = 1;
        return NULL;
    }
    size_t got = fread(b, 1, (size_t)n, f);
    fclose(f);
    b[got] = '\0';
    return b;
}

/* GSDML VirtualSubmoduleItem IOData: Input OctetString 32, Output 8. */
enum { GSDML_INPUT_LEN = 32, GSDML_OUTPUT_LEN = 8 };

static void check_example(const char *path)
{
    char *text = read_all(path);
    if (!text) {
        return;
    }
    cJSON *root = cJSON_Parse(text);
    free(text);
    if (!cJSON_IsObject(root)) {
        fprintf(stderr, "FAIL: %s is not a JSON object\n", path);
        g_fail = 1;
        cJSON_Delete(root);
        return;
    }
    cJSON *params = cJSON_GetObjectItemCaseSensitive(root, "protocol_params");
    cJSON *ilen = cJSON_GetObjectItemCaseSensitive(params, "input_len");
    cJSON *olen = cJSON_GetObjectItemCaseSensitive(params, "output_len");
    int in = cJSON_IsNumber(ilen) ? ilen->valueint : -1;
    int out = cJSON_IsNumber(olen) ? olen->valueint : -1;
    if (in != GSDML_INPUT_LEN || out != GSDML_OUTPUT_LEN) {
        fprintf(stderr,
                "FAIL: %s input_len=%d output_len=%d, GSDML IO submodule is "
                "%d/%d\n",
                path, in, out, GSDML_INPUT_LEN, GSDML_OUTPUT_LEN);
        g_fail = 1;
    }

    cJSON *points = cJSON_GetObjectItemCaseSensitive(root, "points");
    cJSON *p;
    cJSON_ArrayForEach(p, points)
    {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        cJSON *access = cJSON_GetObjectItemCaseSensitive(p, "access");
        cJSON *length = cJSON_GetObjectItemCaseSensitive(p, "length");
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(p, "address");
        cJSON *pn = addr ? cJSON_GetObjectItemCaseSensitive(addr, "profinet")
                         : NULL;
        cJSON *off = pn ? cJSON_GetObjectItemCaseSensitive(pn, "byte_offset")
                        : NULL;
        const char *nm = cJSON_IsString(name) ? name->valuestring : "?";
        const char *ac = cJSON_IsString(access) ? access->valuestring : "read";
        int len = cJSON_IsNumber(length) ? length->valueint : -1;
        int byte_off = cJSON_IsNumber(off) ? off->valueint : -1;
        int cap = (strcmp(ac, "write") == 0) ? out : in;
        if (byte_off < 0 || len < 0 || byte_off > cap ||
            len > cap - byte_off) {
            fprintf(stderr,
                    "FAIL: %s point %s access %s byte_offset %d length %d "
                    "does not fit image %d\n",
                    path, nm, ac, byte_off, len, cap);
            g_fail = 1;
        }
    }
    cJSON_Delete(root);
}

/* slot 0 / subslot 0x8000 is the DAP interface, not the IO image. */
static const char *k_alias_cfg =
    "{\n"
    "  \"protocol\": \"profinet\",\n"
    "  \"device\": {\"name\": \"pn_t12_21\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"iface\": \"mock\",\n"
    "    \"device_name\": \"sensor-line1\",\n"
    "    \"vendor_id\": 43981,\n"
    "    \"device_id\": 1,\n"
    "    \"security_class\": 0,\n"
    "    \"input_len\": 32,\n"
    "    \"output_len\": 8,\n"
    "    \"cycle_us\": 8000\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"io_slot\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 1, \"byte_offset\": 0, \"length\": 2}}},\n"
    "    {\"name\": \"dap_iface\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 0, \"subslot\": 32768,\n"
    "       \"index\": 1, \"byte_offset\": 0, \"length\": 2}}}\n"
    "  ]\n"
    "}\n";

static int read_bytes(fb_runtime_t *rt, const char *name, uint8_t *out,
                      size_t cap, size_t *n)
{
    memset(out, 0, cap);
    *n = 0;
    return fb_read_bytes(rt, name, out, cap, n);
}

static void check_slot_not_aliased(void)
{
    char dir[] = "/tmp/pn_t12_21_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        g_fail = 1;
        return;
    }
    char path[256];
    snprintf(path, sizeof(path), "%s/pn.json", dir);
    expect(write_file(path, k_alias_cfg) == 0, "write alias cfg");

    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    expect(rc == FB_OK && rt != NULL, "fb_open alias cfg");
    if (rc != FB_OK || !rt) {
        fprintf(stderr, "open: %s\n", fb_strerror(rc));
        return;
    }

    const uint8_t io[2] = {0xAA, 0xBB};
    rc = fb_write_bytes(rt, "io_slot", io, sizeof(io));
    expect(rc == FB_OK, "write io_slot");
    if (rc != FB_OK) {
        fprintf(stderr, "write io_slot: %s\n", fb_strerror(rc));
    }

    uint8_t got[2];
    size_t n = 0;
    rc = read_bytes(rt, "io_slot", got, sizeof(got), &n);
    if (!(rc == FB_OK && n == 2 && got[0] == 0xAA && got[1] == 0xBB)) {
        fprintf(stderr,
                "FAIL: io_slot read rc=%d n=%zu bytes %02X %02X, expected "
                "AA BB\n",
                rc, n, got[0], got[1]);
        g_fail = 1;
    }

    uint8_t other[2];
    size_t on = 0;
    rc = read_bytes(rt, "dap_iface", other, sizeof(other), &on);
    if (rc == FB_OK && on == 2 && other[0] == 0xAA && other[1] == 0xBB) {
        fprintf(stderr,
                "FAIL: dap_iface slot 0 subslot 32768 byte_offset 0 read the "
                "IO submodule image (AA BB). slot/subslot ignored\n");
        g_fail = 1;
    }

    const uint8_t clash[2] = {0xCC, 0xDD};
    (void)fb_write_bytes(rt, "dap_iface", clash, sizeof(clash));
    rc = read_bytes(rt, "io_slot", got, sizeof(got), &n);
    if (!(rc == FB_OK && n == 2 && got[0] == 0xAA && got[1] == 0xBB)) {
        fprintf(stderr,
                "FAIL: write to dap_iface changed io_slot to %02X %02X "
                "(rc=%d n=%zu). slot/subslot ignored\n",
                got[0], got[1], rc, n);
        g_fail = 1;
    }

    fb_close(rt);
}

int main(void)
{
    check_example("config/example.profinet.json");
    check_example("config/example.codesys.profinet.json");
    check_example("config/example.fake_sensor.profinet.json");
    check_slot_not_aliased();

    if (g_fail) {
        fprintf(stderr, "test_pn_t12_21: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_21: OK\n");
    return 0;
}
