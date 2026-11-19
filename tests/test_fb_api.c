#include "fb_api.h"

/* core/ 는 fieldbus 공개 include 가 아니다. T8 은 CMakeLists.txt 를 바꾸지
 * 않으므로 테스트에서만 상대 경로로 config_load 를 호출한다. */
#include "../core/config_loader.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;

static int write_file(const char *path, const char *body);

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

/* [YYYY-MM-DD HH:MM:SS][ERROR][config] <message> */
static int is_config_error_log(const char *buf, const char *message)
{
    int y, mo, d, h, mi, s;
    char level[16];
    char component[16];
    int n = 0;

    if (!buf || !message) {
        return 0;
    }
    if (sscanf(buf, "[%d-%d-%d %d:%d:%d][%15[^]]][%15[^]]] %n", &y, &mo, &d, &h,
               &mi, &s, level, component, &n) < 8 ||
        n <= 0) {
        return 0;
    }
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 ||
        mi < 0 || mi > 59 || s < 0 || s > 60) {
        return 0;
    }
    if (strcmp(level, "ERROR") != 0 || strcmp(component, "config") != 0) {
        return 0;
    }
    return strncmp(buf + n, message, strlen(message)) == 0;
}

/* config_load 가 남기는 stderr 만 임시 파일로 받는다. 호출 후 stderr 는 복구된다. */
static int load_and_capture(const char *dir, const char *path, char *out,
                            size_t outlen, int *rc_out)
{
    char tmpl[64];
    int nw = snprintf(tmpl, sizeof(tmpl), "%s/cap_XXXXXX", dir);
    if (nw < 0 || (size_t)nw >= sizeof(tmpl)) {
        return -1;
    }
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        return -1;
    }
    int saved = dup(fileno(stderr));
    if (saved < 0) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    fflush(stderr);
    if (dup2(fd, fileno(stderr)) < 0) {
        close(saved);
        close(fd);
        unlink(tmpl);
        return -1;
    }

    daemon_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int rc = config_load(path, &cfg);
    if (rc == 0) {
        config_free(&cfg);
    }
    fflush(stderr);
    if (dup2(saved, fileno(stderr)) < 0) {
        close(saved);
        close(fd);
        unlink(tmpl);
        return -1;
    }
    close(saved);

    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    size_t got = 0;
    while (got + 1 < outlen) {
        ssize_t nread = read(fd, out + got, outlen - 1 - got);
        if (nread < 0) {
            close(fd);
            unlink(tmpl);
            return -1;
        }
        if (nread == 0) {
            break;
        }
        got += (size_t)nread;
    }
    out[got] = '\0';
    close(fd);
    unlink(tmpl);
    *rc_out = rc;
    return 0;
}

static void expect_config_error(const char *dir, const char *path,
                                const char *message, const char *what)
{
    char logbuf[512];
    int rc = 0;
    if (load_and_capture(dir, path, logbuf, sizeof(logbuf), &rc) != 0) {
        fprintf(stderr, "FAIL: %s (stderr capture failed)\n", what);
        g_fail = 1;
        return;
    }
    if (rc >= 0 || !is_config_error_log(logbuf, message)) {
        fprintf(stderr, "FAIL: %s (rc=%d) captured stderr:\n%s\n", what, rc,
                logbuf);
        g_fail = 1;
    }
}

/* T8: 파일 없음 / JSON 파싱 실패 / protocol 필드 없음. */
static void test_config_load_error_logs(const char *dir)
{
    char missing[256];
    char badjson[256];
    char noproto[256];
    snprintf(missing, sizeof(missing), "%s/missing.json", dir);
    snprintf(badjson, sizeof(badjson), "%s/badjson.json", dir);
    snprintf(noproto, sizeof(noproto), "%s/noproto.json", dir);

    expect(write_file(badjson, "ad") == 0, "write badjson");
    expect(write_file(noproto, "{\"device\":{\"name\":\"x\"}}\n") == 0,
           "write noproto");

    char open_msg[320];
    snprintf(open_msg, sizeof(open_msg), "파일을 열 수 없음: %s", missing);
    expect_config_error(dir, missing, open_msg, "config log: missing file");
    expect_config_error(dir, badjson, "JSON 파싱 실패: ", "config log: bad json");
    expect_config_error(dir, noproto, "\"protocol\" 필드가 없거나 문자열이 아님",
                        "config log: no protocol");
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

static const char *k_cfg =
    "{\n"
    "  \"protocol\": \"modbus_tcp\",\n"
    "  \"device\": {\"name\": \"fb_api_test\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"role\": \"server\", \"ip\": \"127.0.0.1\", \"port\": 15559,\n"
    "    \"unit_id\": 1, \"max_clients\": 2, \"client_timeout_ms\": 100\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"barcode_value\", \"access\": \"read\",\n"
    "     \"data_type\": \"string\", \"length\": 32,\n"
    "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40001}}},\n"
    "    {\"name\": \"temperature\", \"access\": \"read\",\n"
    "     \"data_type\": \"u16\", \"scale\": 0.1,\n"
    "     \"address\": {\"modbus\": {\"type\": \"4x\", \"start\": 40020}}},\n"
    "    {\"name\": \"count\", \"access\": \"read\",\n"
    "     \"data_type\": \"uint16\",\n"
    "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40030}}},\n"
    "    {\"name\": \"trigger\", \"access\": \"write\",\n"
    "     \"data_type\": \"bool\",\n"
    "     \"address\": {\"modbus\": {\"type\": \"coil\", \"start\": 1}}}\n"
    "  ]\n"
    "}\n";

static const char *k_cfg2 =
    "{\n"
    "  \"protocol\": \"modbus_tcp\",\n"
    "  \"device\": {\"name\": \"fb_api_test_reloaded\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"role\": \"server\", \"ip\": \"127.0.0.1\", \"port\": 15559,\n"
    "    \"unit_id\": 1, \"max_clients\": 2, \"client_timeout_ms\": 100\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"barcode_value\", \"access\": \"read\",\n"
    "     \"data_type\": \"string\", \"length\": 32,\n"
    "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40001}}},\n"
    "    {\"name\": \"count\", \"access\": \"read\",\n"
    "     \"data_type\": \"uint16\",\n"
    "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40030}}}\n"
    "  ]\n"
    "}\n";

int main(void)
{
    expect(fb_api_version() == FB_API_VERSION, "version macro/fn");
    expect(fb_strerror(FB_OK) != NULL && fb_strerror(-999) != NULL,
           "strerror");
    expect(fb_open(NULL, NULL) == FB_ERR_INVAL, "open null");
    expect(fb_poll(NULL) == FB_ERR_INVAL, "poll null");
    expect(fb_close(NULL) == FB_OK, "close null");
    expect(fb_read_bool(NULL, "x", NULL) == FB_ERR_INVAL, "read null");

    char dir[] = "/tmp/fb_api_test_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        return 1;
    }
    char path[256];
    char path2[256];
    char bad[256];
    snprintf(path, sizeof(path), "%s/ok.json", dir);
    snprintf(path2, sizeof(path2), "%s/ok2.json", dir);
    snprintf(bad, sizeof(bad), "%s/bad.json", dir);
    expect(write_file(path, k_cfg) == 0, "write cfg");
    expect(write_file(path2, k_cfg2) == 0, "write cfg2");
    expect(write_file(bad, "{not json") == 0, "write bad");
    test_config_load_error_logs(dir);

    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    expect(rc == FB_OK && rt != NULL, "fb_open");
    if (rc != FB_OK) {
        fprintf(stderr, "open: %s\n", fb_strerror(rc));
        return 1;
    }

    expect(fb_poll(rt) == FB_OK, "poll");

    fb_health_t h;
    memset(&h, 0, sizeof(h));
    expect(fb_health(rt, &h) == FB_OK, "health");
    expect(strcmp(h.protocol, "modbus_tcp") == 0, "protocol name");
    expect(h.generation == 1, "gen 1");
    expect(h.cycle_ms == 8, "cycle");
    expect(h.connected == 1, "connected");

    size_t npts = 0;
    expect(fb_list_points(rt, NULL, 0, &npts) == FB_OK, "list count");
    expect(npts == 4, "4 points");
    fb_point_info_t infos[8];
    memset(infos, 0, sizeof(infos));
    expect(fb_list_points(rt, infos, 8, &npts) == FB_OK, "list fill");
    expect(strcmp(infos[0].name, "barcode_value") == 0, "first name");
    expect(infos[0].access == FB_ACCESS_PLC_READ, "barcode access");
    expect(infos[3].access == FB_ACCESS_PLC_WRITE, "trigger access");

    expect(fb_write_string(rt, "barcode_value", "HELLO") == FB_OK,
           "write barcode");
    char sbuf[64];
    memset(sbuf, 0, sizeof(sbuf));
    expect(fb_read_string(rt, "barcode_value", sbuf, sizeof(sbuf)) == FB_OK,
           "read barcode");
    expect(strcmp(sbuf, "HELLO") == 0, "barcode value");

    char tiny[3];
    expect(fb_read_string(rt, "barcode_value", tiny, sizeof(tiny)) ==
               FB_ERR_NOSPC,
           "string nospc");

    expect(fb_write_f32(rt, "temperature", 25.5f) == FB_OK, "write temp");
    float tf = 0;
    expect(fb_read_f32(rt, "temperature", &tf) == FB_OK, "read temp");
    expect(fabsf(tf - 25.5f) < 0.05f, "temp eng");

    expect(fb_write_u32(rt, "count", 7) == FB_OK, "write count");
    uint32_t cu = 0;
    expect(fb_read_u32(rt, "count", &cu) == FB_OK, "read count");
    expect(cu == 7, "count==7");

    expect(fb_write_bool(rt, "trigger", 1) == FB_ERR_PERM, "write trigger perm");
    int tr = 0;
    expect(fb_read_bool(rt, "trigger", &tr) == FB_OK, "read trigger");

    expect(fb_read_u32(rt, "no_such", &cu) == FB_ERR_NOENT, "noent");
    expect(fb_write_string(rt, "count", "x") == FB_ERR_TYPE, "type");

    uint32_t gen = h.generation;
    expect(fb_reload(rt, bad) != FB_OK, "reload bad");
    memset(&h, 0, sizeof(h));
    expect(fb_health(rt, &h) == FB_OK, "health after bad reload");
    expect(h.generation == gen, "gen unchanged");
    memset(sbuf, 0, sizeof(sbuf));
    expect(fb_read_string(rt, "barcode_value", sbuf, sizeof(sbuf)) == FB_OK &&
               strcmp(sbuf, "HELLO") == 0,
           "old session intact");

    expect(fb_reload(rt, path2) == FB_OK, "reload ok");
    memset(&h, 0, sizeof(h));
    expect(fb_health(rt, &h) == FB_OK, "health after reload");
    expect(h.generation == gen + 1, "gen bumped");
    expect(strcmp(h.device_name, "fb_api_test_reloaded") == 0, "new device");
    npts = 0;
    expect(fb_list_points(rt, NULL, 0, &npts) == FB_OK && npts == 2,
           "reloaded points");
    expect(fb_read_u32(rt, "temperature", &cu) == FB_ERR_NOENT,
           "dropped point");

    expect(fb_start(rt) == FB_OK, "start thread");
    expect(fb_start(rt) == FB_ERR_STATE, "start twice");
    expect(fb_stop(rt) == FB_OK, "stop thread");

    fb_close(rt);

    if (g_fail) {
        fprintf(stderr, "test_fb_api: FAILED\n");
        return 1;
    }
    printf("test_fb_api: OK\n");
    return 0;
}
