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
