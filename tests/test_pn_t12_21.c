/*
 * T12-21: 예제 config 의 input/output 길이는 GSDML IO 서브모듈(입력 32,
 * 출력 8)과 같아야 하고, 포인트는 그 이미지 안에 들어가야 한다.
 * 주기 이미지는 slot 1 / subslot 1 뿐이다. 다른 slot/subslot 은
 * 어댑터 설정(init)에서 -EINVAL 로 거부하고 LOG_ERROR 를 남긴다.
 * fb_open 은 그 -EINVAL 을 FB_ERR_CONFIG 로 돌린다.
 * 주기 포인트의 index 는 레코드 번호라 주소로 쓰지 않는다. 필드가
 * 있으면 설정 때 LOG_WARN 을 한 번만 남기고, 읽기/쓰기는 byte_offset
 * 의 주기 이미지를 쓴다. 필드가 없으면 경고하지 않는다.
 */
#include "cJSON.h"
#include "fb_api.h"
#include "protocol_adapter.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

protocol_adapter_t *profinet_adapter_create(void);

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
        cJSON *idx = pn ? cJSON_GetObjectItemCaseSensitive(pn, "index") : NULL;
        const char *nm = cJSON_IsString(name) ? name->valuestring : "?";
        if (idx) {
            fprintf(stderr,
                    "FAIL: %s point %s still has index; cyclic points do not "
                    "use a record index\n",
                    path, nm);
            g_fail = 1;
        }
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

static const char *k_params =
    "{\"iface\":\"mock\",\"device_name\":\"sensor-line1\",\"vendor_id\":43981,"
    "\"device_id\":1,\"security_class\":0,\"input_len\":32,\"output_len\":8,"
    "\"cycle_us\":8000}";

/* index 99 / 7 은 주기 주소가 아니다. 둘 다 있어도 경고는 한 번이다. */
static const char *k_index_cfg =
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
    "    {\"name\": \"wide_index\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 99, \"byte_offset\": 0, \"length\": 2}}},\n"
    "    {\"name\": \"other_index\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"index\": 7, \"byte_offset\": 2, \"length\": 2}}}\n"
    "  ]\n"
    "}\n";

static const char *k_no_index_cfg =
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
    "    {\"name\": \"plain\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 1, \"subslot\": 1,\n"
    "       \"byte_offset\": 0, \"length\": 2}}}\n"
    "  ]\n"
    "}\n";

/* slot 0 / subslot 0x8000 is the DAP interface, not the IO image. */
static const char *k_dap_points =
    "[{\"name\":\"dap_iface\",\"access\":\"read\",\"data_type\":\"bytes\","
    "\"length\":2,\"address\":{\"profinet\":{\"slot\":0,\"subslot\":32768,"
    "\"index\":1,\"byte_offset\":0,\"length\":2}}}]";

static const char *k_bad_sub_points =
    "[{\"name\":\"other_sub\",\"access\":\"read\",\"data_type\":\"bytes\","
    "\"length\":2,\"address\":{\"profinet\":{\"slot\":1,\"subslot\":2,"
    "\"byte_offset\":0,\"length\":2}}}]";

static const char *k_dap_cfg =
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
    "    {\"name\": \"dap_iface\", \"access\": \"read\",\n"
    "     \"data_type\": \"bytes\", \"length\": 2,\n"
    "     \"address\": {\"profinet\": {\"slot\": 0, \"subslot\": 32768,\n"
    "       \"index\": 1, \"byte_offset\": 0, \"length\": 2}}}\n"
    "  ]\n"
    "}\n";

static int line_has(const char *start, const char *end, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t len = (size_t)(end - start);
    if (nlen == 0 || len < nlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= len; i++) {
        if (memcmp(start + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

static int count_profinet(const char *text, const char *level, const char *extra)
{
    char tag[64];
    int n = 0;
    const char *p;
    if (!text) {
        return 0;
    }
    snprintf(tag, sizeof(tag), "[%s][profinet]", level);
    p = text;
    while ((p = strstr(p, tag)) != NULL) {
        const char *eol = strchr(p, '\n');
        if (!eol) {
            eol = p + strlen(p);
        }
        if (!extra || line_has(p, eol, extra)) {
            n++;
        }
        if (*eol == '\0') {
            break;
        }
        p = eol + 1;
    }
    return n;
}

static int capture_start(const char *log_path, int *saved_fd)
{
    int fd;
    fflush(stderr);
    *saved_fd = dup(fileno(stderr));
    if (*saved_fd < 0) {
        return -1;
    }
    fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        close(*saved_fd);
        *saved_fd = -1;
        return -1;
    }
    if (dup2(fd, fileno(stderr)) < 0) {
        close(fd);
        close(*saved_fd);
        *saved_fd = -1;
        return -1;
    }
    close(fd);
    return 0;
}

static void capture_stop(int saved_fd)
{
    fflush(stderr);
    if (saved_fd >= 0) {
        dup2(saved_fd, fileno(stderr));
        close(saved_fd);
    }
}

static int make_dir(char *dir, char *path, size_t path_len, const char *leaf)
{
    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        g_fail = 1;
        return -1;
    }
    snprintf(path, path_len, "%s/%s", dir, leaf);
    return 0;
}

static int roundtrip(fb_runtime_t *rt, const char *name, const uint8_t *bytes,
                     size_t n)
{
    uint8_t got[8];
    size_t got_n = 0;
    int rc;
    if (n > sizeof(got)) {
        return -1;
    }
    rc = fb_write_bytes(rt, name, bytes, n);
    if (rc != FB_OK) {
        return rc;
    }
    rc = fb_read_bytes(rt, name, got, sizeof(got), &got_n);
    if (rc != FB_OK || got_n != n || memcmp(got, bytes, n) != 0) {
        return rc == FB_OK ? -1 : rc;
    }
    return FB_OK;
}

static void check_index_warn_once(void)
{
    char dir[] = "/tmp/pn_t12_21_XXXXXX";
    char path[256];
    char log_path[256];
    int saved = -1;
    int rc;
    int io_rc = -1;
    fb_runtime_t *rt = NULL;
    char *log;
    int warns;

    if (make_dir(dir, path, sizeof(path), "pn.json") != 0) {
        return;
    }
    snprintf(log_path, sizeof(log_path), "%s/log.txt", dir);
    expect(write_file(path, k_index_cfg) == 0, "write index cfg");
    if (capture_start(log_path, &saved) != 0) {
        fprintf(stderr, "FAIL: capture stderr (index)\n");
        g_fail = 1;
        return;
    }
    rc = fb_open(path, &rt);
    if (rc == FB_OK && rt) {
        const uint8_t a[2] = {0xAA, 0xBB};
        const uint8_t b[2] = {0x11, 0x22};
        uint8_t again[2];
        size_t n = 0;
        io_rc = roundtrip(rt, "wide_index", a, sizeof(a));
        if (io_rc == FB_OK) {
            io_rc = roundtrip(rt, "other_index", b, sizeof(b));
        }
        (void)fb_read_bytes(rt, "wide_index", again, sizeof(again), &n);
        (void)fb_read_bytes(rt, "wide_index", again, sizeof(again), &n);
        fb_close(rt);
    }
    capture_stop(saved);

    if (rc != FB_OK) {
        fprintf(stderr, "FAIL: index cfg open rc=%d (%s), index must not be "
                        "an error\n",
                rc, fb_strerror(rc));
        g_fail = 1;
    }
    if (io_rc != FB_OK) {
        fprintf(stderr, "FAIL: index 99/7 did not round-trip on the cyclic "
                        "image (rc=%d). index must be ignored\n",
                io_rc);
        g_fail = 1;
    }
    log = read_all(log_path);
    warns = count_profinet(log, "WARN", "index");
    free(log);
    if (warns != 1) {
        fprintf(stderr,
                "FAIL: cyclic index LOG_WARN count %d, want 1 "
                "(two points with index, repeated reads)\n",
                warns);
        g_fail = 1;
    }
}

static void check_index_absent_is_silent(void)
{
    char dir[] = "/tmp/pn_t12_21_XXXXXX";
    char path[256];
    char log_path[256];
    int saved = -1;
    int rc;
    int io_rc = -1;
    fb_runtime_t *rt = NULL;
    char *log;
    int warns;

    if (make_dir(dir, path, sizeof(path), "pn.json") != 0) {
        return;
    }
    snprintf(log_path, sizeof(log_path), "%s/log.txt", dir);
    expect(write_file(path, k_no_index_cfg) == 0, "write no-index cfg");
    if (capture_start(log_path, &saved) != 0) {
        fprintf(stderr, "FAIL: capture stderr (no index)\n");
        g_fail = 1;
        return;
    }
    rc = fb_open(path, &rt);
    if (rc == FB_OK && rt) {
        const uint8_t a[2] = {0xCC, 0xDD};
        io_rc = roundtrip(rt, "plain", a, sizeof(a));
        fb_close(rt);
    }
    capture_stop(saved);

    if (rc != FB_OK || io_rc != FB_OK) {
        fprintf(stderr, "FAIL: point without index open rc=%d io rc=%d\n", rc,
                io_rc);
        g_fail = 1;
    }
    log = read_all(log_path);
    warns = count_profinet(log, "WARN", "index");
    free(log);
    if (warns != 0) {
        fprintf(stderr, "FAIL: missing index logged LOG_WARN %d times\n",
                warns);
        g_fail = 1;
    }
}

static void check_init_rejects(const char *points_json, const char *what)
{
    char dir[] = "/tmp/pn_t12_21_XXXXXX";
    char path[256];
    int saved = -1;
    int rc = -1;
    protocol_adapter_t *a;
    char *log;
    int errors;

    if (make_dir(dir, path, sizeof(path), "log.txt") != 0) {
        return;
    }
    if (capture_start(path, &saved) != 0) {
        fprintf(stderr, "FAIL: capture stderr (%s)\n", what);
        g_fail = 1;
        return;
    }
    a = profinet_adapter_create();
    if (a && a->init) {
        rc = a->init(a, k_params, points_json);
    }
    if (a && a->destroy) {
        a->destroy(a);
    }
    capture_stop(saved);

    if (rc != -EINVAL) {
        fprintf(stderr, "FAIL: %s init rc=%d, want -EINVAL\n", what, rc);
        g_fail = 1;
    }
    log = read_all(path);
    errors = count_profinet(log, "ERROR", "slot");
    free(log);
    if (errors != 1) {
        fprintf(stderr, "FAIL: %s LOG_ERROR count %d, want 1\n", what, errors);
        g_fail = 1;
    }
}

static void check_open_rejects(void)
{
    char dir[] = "/tmp/pn_t12_21_XXXXXX";
    char path[256];
    char log_path[256];
    int saved = -1;
    int rc;
    fb_runtime_t *rt = NULL;
    char *log;
    int errors;

    if (make_dir(dir, path, sizeof(path), "pn.json") != 0) {
        return;
    }
    snprintf(log_path, sizeof(log_path), "%s/log.txt", dir);
    expect(write_file(path, k_dap_cfg) == 0, "write dap cfg");
    if (capture_start(log_path, &saved) != 0) {
        fprintf(stderr, "FAIL: capture stderr (open dap)\n");
        g_fail = 1;
        return;
    }
    rc = fb_open(path, &rt);
    capture_stop(saved);
    if (rc != FB_ERR_CONFIG || rt != NULL) {
        fprintf(stderr,
                "FAIL: dap slot 0 subslot 32768 open rc=%d (%s), want "
                "FB_ERR_CONFIG\n",
                rc, fb_strerror(rc));
        g_fail = 1;
        if (rt) {
            fb_close(rt);
        }
    }
    log = read_all(log_path);
    errors = count_profinet(log, "ERROR", "slot");
    free(log);
    if (errors != 1) {
        fprintf(stderr, "FAIL: dap open LOG_ERROR count %d, want 1\n", errors);
        g_fail = 1;
    }
}

int main(void)
{
    check_example("config/example.profinet.json");
    check_example("config/example.codesys.profinet.json");
    check_example("config/example.fake_sensor.profinet.json");
    check_index_warn_once();
    check_index_absent_is_silent();
    check_init_rejects(k_dap_points, "slot 0 subslot 32768");
    check_init_rejects(k_bad_sub_points, "slot 1 subslot 2");
    check_open_rejects();

    if (g_fail) {
        fprintf(stderr, "test_pn_t12_21: FAILED\n");
        return 1;
    }
    printf("test_pn_t12_21: OK\n");
    return 0;
}
