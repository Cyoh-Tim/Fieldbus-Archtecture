#include "fb_api.h"

/* core/ 는 fieldbus 공개 include 가 아니다. T8 은 CMakeLists.txt 를 바꾸지
 * 않으므로 테스트에서만 상대 경로로 config_load 를 호출한다. */
#include "../core/config_loader.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
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

/* stderr 를 임시 파일로 돌렸다가 복구한다. 성공 시 *out 에 캡처 내용. */
static int capture_stderr_begin(const char *dir, char *tmpl, size_t tmplen,
                                int *saved_out, int *fd_out)
{
    int nw = snprintf(tmpl, tmplen, "%s/cap_XXXXXX", dir);
    if (nw < 0 || (size_t)nw >= tmplen) {
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
    *saved_out = saved;
    *fd_out = fd;
    return 0;
}

static int capture_stderr_end(char *tmpl, int saved, int fd, char *out,
                              size_t outlen)
{
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
    return 0;
}

static int listen_loopback(int *port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &sl) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

/* core/fb_api.c 의 테스트 전용 심볼. 공개 헤더에는 없다. */
extern void fb_test_set_extra_wake_us(fb_runtime_t *rt, uint32_t us);

static int count_substr(const char *log, const char *needle)
{
    int n = 0;
    if (!log || !needle || !needle[0]) {
        return 0;
    }
    size_t len = strlen(needle);
    for (const char *p = log; (p = strstr(p, needle)) != NULL; p += len) {
        n++;
    }
    return n;
}

/*
 * T7 완료 조건: 인위적인 9ms poll_cycle 이면 경고가 나고, fb_health 로
 * 최대 지연을 µs 로 읽을 수 있다.
 *
 * poll_cycle 을 9ms 로 만드는 방법: Modbus 클라이언트 client_timeout_ms=9,
 * 응답하지 않는 루프백 listen. 읽기 한 번이 select 9ms 후 타임아웃한다.
 * cycle_ms=8 이므로 편차는 약 1ms(1000µs) 이상이다.
 *
 * fb_health_t.reserved[]:
 *   FB_HEALTH_MAX_ELAPSED_US  9ms 폴링의 경과 (9000µs 이상)
 *   FB_HEALTH_MAX_DELAY_US    8ms 사이클을 넘긴 편차 (1000µs 이상)
 *   FB_HEALTH_OVERRUN_COUNT   cycle_warn_us 를 넘긴 지터 횟수
 *   FB_HEALTH_WARN_US         config cycle_warn_us
 * 9ms 폴링은 cycle_warn_us 와 상관없이 마감 놓침 경고를 낸다.
 * 지터 초과 횟수는 편차가 cycle_warn_us 보다 클 때만 올라간다.
 */
static void test_cycle_delay_us(const char *dir, int warn_us, int expect_overrun,
                                const char *what)
{
    int port = 0;
    int lfd = listen_loopback(&port);
    if (lfd < 0 || port <= 0) {
        fprintf(stderr, "FAIL: %s (listen: %s)\n", what, strerror(errno));
        g_fail = 1;
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/t7_%d.json", dir, warn_us);
    char body[1024];
    int nb = snprintf(
        body, sizeof(body),
        "{\n"
        "  \"protocol\": \"modbus_tcp\",\n"
        "  \"device\": {\"name\": \"t7\", \"role\": \"client\"},\n"
        "  \"cycle_ms\": 8,\n"
        "  \"cycle_warn_us\": %d,\n"
        "  \"protocol_params\": {\n"
        "    \"role\": \"client\", \"ip\": \"127.0.0.1\", \"port\": %d,\n"
        "    \"unit_id\": 1, \"client_timeout_ms\": 9\n"
        "  },\n"
        "  \"points\": [\n"
        "    {\"name\": \"count\", \"access\": \"read\",\n"
        "     \"data_type\": \"uint16\",\n"
        "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40001}}}\n"
        "  ]\n"
        "}\n",
        warn_us, port);
    if (nb < 0 || (size_t)nb >= sizeof(body) || write_file(path, body) != 0) {
        fprintf(stderr, "FAIL: %s (config write)\n", what);
        g_fail = 1;
        close(lfd);
        return;
    }

    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    if (rc != FB_OK || !rt) {
        fprintf(stderr, "FAIL: %s (fb_open %s)\n", what, fb_strerror(rc));
        g_fail = 1;
        close(lfd);
        return;
    }

    char tmpl[64];
    int saved = -1;
    int fd = -1;
    char logbuf[8192];
    logbuf[0] = '\0';
    if (capture_stderr_begin(dir, tmpl, sizeof(tmpl), &saved, &fd) != 0) {
        fprintf(stderr, "FAIL: %s (stderr capture)\n", what);
        g_fail = 1;
        fb_close(rt);
        close(lfd);
        return;
    }

    rc = fb_start(rt);
    if (rc != FB_OK) {
        capture_stderr_end(tmpl, saved, fd, logbuf, sizeof(logbuf));
        fprintf(stderr, "FAIL: %s (fb_start %s)\n", what, fb_strerror(rc));
        g_fail = 1;
        fb_close(rt);
        close(lfd);
        return;
    }
    struct timespec pause = {0, 80 * 1000 * 1000L};
    nanosleep(&pause, NULL);
    expect(fb_stop(rt) == FB_OK, "t7 stop");

    if (capture_stderr_end(tmpl, saved, fd, logbuf, sizeof(logbuf)) != 0) {
        fprintf(stderr, "FAIL: %s (stderr restore)\n", what);
        g_fail = 1;
        fb_close(rt);
        close(lfd);
        return;
    }

    int misses = count_substr(logbuf, "사이클 마감 놓침");
    int jitter_logs = count_substr(logbuf, "지터 요약");
    int old_phrase = count_substr(logbuf, "cycle 초과");
    if (misses < 1) {
        fprintf(stderr, "FAIL: %s (no deadline-miss warning) stderr:\n%s\n",
                what, logbuf);
        g_fail = 1;
    }
    if (jitter_logs != 0 || old_phrase != 0) {
        fprintf(stderr,
                "FAIL: %s (jitter logs=%d old phrase=%d; 80ms window should "
                "have neither) stderr:\n%s\n",
                what, jitter_logs, old_phrase, logbuf);
        g_fail = 1;
    }

    fb_health_t h;
    memset(&h, 0, sizeof(h));
    expect(fb_health(rt, &h) == FB_OK, "t7 health");
    uint32_t max_elapsed = h.reserved[FB_HEALTH_MAX_ELAPSED_US];
    uint32_t avg_elapsed = h.reserved[FB_HEALTH_AVG_ELAPSED_US];
    uint32_t max_delay = h.reserved[FB_HEALTH_MAX_DELAY_US];
    uint32_t overruns = h.reserved[FB_HEALTH_OVERRUN_COUNT];
    uint32_t got_warn = h.reserved[FB_HEALTH_WARN_US];
    if (max_elapsed < 9000u || max_elapsed >= 2000000u) {
        fprintf(stderr,
                "FAIL: %s max elapsed us=%u (want 9000..1999999, µs of the "
                "9ms poll)\n",
                what, max_elapsed);
        g_fail = 1;
    }
    if (avg_elapsed == 0u || avg_elapsed > max_elapsed) {
        fprintf(stderr, "FAIL: %s avg elapsed us=%u (max %u)\n", what,
                avg_elapsed, max_elapsed);
        g_fail = 1;
    }
    if (max_delay < 1000u || max_delay >= 2000000u) {
        fprintf(stderr,
                "FAIL: %s max delay us=%u (want >=1000, µs past the 8ms "
                "cycle)\n",
                what, max_delay);
        g_fail = 1;
    }
    if (expect_overrun) {
        if (overruns < 1u) {
            fprintf(stderr, "FAIL: %s overrun count=%u (want >=1)\n", what,
                    overruns);
            g_fail = 1;
        }
    } else if (overruns != 0u) {
        fprintf(stderr, "FAIL: %s overrun count=%u (warn_us=%d, want 0)\n",
                what, overruns, warn_us);
        g_fail = 1;
    }
    if (got_warn != (uint32_t)warn_us) {
        fprintf(stderr, "FAIL: %s warn threshold us=%u (want %d)\n", what,
                got_warn, warn_us);
        g_fail = 1;
    }

    fb_close(rt);
    close(lfd);
}

/* 기상 지연만 기준을 넘고 마감은 지키는 사이클이 이어져도
 * 지터 요약은 1초에 한 번 이하다. */
static void test_jitter_summary_rate(const char *dir)
{
    const char *what = "t7 jitter summary rate";
    int port = 0;
    int lfd = listen_loopback(&port);
    if (lfd < 0 || port <= 0) {
        fprintf(stderr, "FAIL: %s (listen: %s)\n", what, strerror(errno));
        g_fail = 1;
        return;
    }
    close(lfd);

    char path[256];
    snprintf(path, sizeof(path), "%s/t7_jitter.json", dir);
    char body[1024];
    int nb = snprintf(
        body, sizeof(body),
        "{\n"
        "  \"protocol\": \"modbus_tcp\",\n"
        "  \"device\": {\"name\": \"t7jitter\", \"role\": \"server\"},\n"
        "  \"cycle_ms\": 20,\n"
        "  \"cycle_warn_us\": 100,\n"
        "  \"protocol_params\": {\n"
        "    \"role\": \"server\", \"ip\": \"127.0.0.1\", \"port\": %d,\n"
        "    \"unit_id\": 1, \"max_clients\": 1\n"
        "  },\n"
        "  \"points\": [\n"
        "    {\"name\": \"count\", \"access\": \"read\",\n"
        "     \"data_type\": \"uint16\",\n"
        "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40001}}}\n"
        "  ]\n"
        "}\n",
        port);
    if (nb < 0 || (size_t)nb >= sizeof(body) || write_file(path, body) != 0) {
        fprintf(stderr, "FAIL: %s (config write)\n", what);
        g_fail = 1;
        return;
    }

    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    if (rc != FB_OK || !rt) {
        fprintf(stderr, "FAIL: %s (fb_open %s)\n", what, fb_strerror(rc));
        g_fail = 1;
        return;
    }
    /* 200µs 기상 지연. poll 은 짧아서 wake+elapsed 는 20ms 사이클 안이다. */
    fb_test_set_extra_wake_us(rt, 200);

    char tmpl[64];
    int saved = -1;
    int fd = -1;
    char logbuf[32768];
    logbuf[0] = '\0';
    if (capture_stderr_begin(dir, tmpl, sizeof(tmpl), &saved, &fd) != 0) {
        fprintf(stderr, "FAIL: %s (stderr capture)\n", what);
        g_fail = 1;
        fb_close(rt);
        return;
    }
    rc = fb_start(rt);
    if (rc != FB_OK) {
        capture_stderr_end(tmpl, saved, fd, logbuf, sizeof(logbuf));
        fprintf(stderr, "FAIL: %s (fb_start %s)\n", what, fb_strerror(rc));
        g_fail = 1;
        fb_close(rt);
        return;
    }
    struct timespec pause = {2, 300000000L};
    nanosleep(&pause, NULL);
    expect(fb_stop(rt) == FB_OK, "t7 jitter stop");
    if (capture_stderr_end(tmpl, saved, fd, logbuf, sizeof(logbuf)) != 0) {
        fprintf(stderr, "FAIL: %s (stderr restore)\n", what);
        g_fail = 1;
        fb_close(rt);
        return;
    }

    int summaries = count_substr(logbuf, "지터 요약");
    int misses = count_substr(logbuf, "사이클 마감 놓침");
    int old_phrase = count_substr(logbuf, "cycle 초과");
    /* 2.3초 동안 1초 창이 두 번 닫힌다. 경계에서 1~3줄. */
    if (summaries < 1 || summaries > 3) {
        fprintf(stderr, "FAIL: %s jitter summaries=%d (want 1..3) stderr:\n%s\n",
                what, summaries, logbuf);
        g_fail = 1;
    }
    if (misses != 0 || old_phrase != 0) {
        fprintf(stderr,
                "FAIL: %s deadline misses=%d old phrase=%d stderr:\n%s\n", what,
                misses, old_phrase, logbuf);
        g_fail = 1;
    }

    fb_health_t h;
    memset(&h, 0, sizeof(h));
    expect(fb_health(rt, &h) == FB_OK, "t7 jitter health");
    uint32_t overruns = h.reserved[FB_HEALTH_OVERRUN_COUNT];
    uint32_t max_delay = h.reserved[FB_HEALTH_MAX_DELAY_US];
    if (overruns < 20u || (int)overruns <= summaries) {
        fprintf(stderr,
                "FAIL: %s overrun=%u summaries=%d (overruns stay per cycle, "
                "logs do not)\n",
                what, overruns, summaries);
        g_fail = 1;
    }
    if (max_delay < 200u) {
        fprintf(stderr, "FAIL: %s max delay us=%u (want >=200)\n", what,
                max_delay);
        g_fail = 1;
    }
    fb_close(rt);
}

/*
 * A20261003-1: scale 이 있는 uint32/int32 는 native_size 가 4 다.
 * 어댑터가 돌려주는 4바이트 페이로드는 BE float32 공학값이고, 읽기는
 * native 크기와 무관하게 그 비트를 float32 로 해석해야 한다.
 */
static const char *k_scaled32 =
    "{\n"
    "  \"protocol\": \"modbus_tcp\",\n"
    "  \"device\": {\"name\": \"fb_api_scaled32\", \"role\": \"server\"},\n"
    "  \"cycle_ms\": 8,\n"
    "  \"protocol_params\": {\n"
    "    \"role\": \"server\", \"ip\": \"127.0.0.1\", \"port\": 15570,\n"
    "    \"unit_id\": 1, \"max_clients\": 2, \"client_timeout_ms\": 100\n"
    "  },\n"
    "  \"points\": [\n"
    "    {\"name\": \"s_u32\", \"access\": \"read\",\n"
    "     \"data_type\": \"uint32\", \"scale\": 0.1,\n"
    "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40040,\n"
    "       \"byte_order\": \"big\", \"word_order\": \"abcd\"}}},\n"
    "    {\"name\": \"s_i32\", \"access\": \"read\",\n"
    "     \"data_type\": \"int32\", \"scale\": 0.1,\n"
    "     \"address\": {\"modbus\": {\"type\": \"holding\", \"start\": 40042,\n"
    "       \"byte_order\": \"big\", \"word_order\": \"abcd\"}}}\n"
    "  ]\n"
    "}\n";

static void expect_scaled_f32_read(fb_runtime_t *rt, const char *name,
                                   const char *data_type)
{
    fb_point_info_t infos[4];
    size_t npts = 0;
    const fb_point_info_t *info = NULL;
    memset(infos, 0, sizeof(infos));
    expect(fb_list_points(rt, infos, 4, &npts) == FB_OK, "scaled32 list");
    for (size_t i = 0; i < npts; i++) {
        if (strcmp(infos[i].name, name) == 0) {
            info = &infos[i];
        }
    }
    if (!info) {
        fprintf(stderr, "FAIL: scaled %s point missing\n", data_type);
        g_fail = 1;
        return;
    }
    expect(strcmp(info->data_type, data_type) == 0, "scaled32 data_type");
    expect(info->native_type == FB_TYPE_F32, "scaled32 native_type");
    expect((info->flags & FB_POINT_F_SCALED) != 0, "scaled32 flag");
    expect(info->wire_size == 4, "scaled32 wire_size");

    int rc = fb_write_f32(rt, name, 6553.6f);
    if (rc != FB_OK) {
        fprintf(stderr, "FAIL: scaled %s write rc=%d (%s)\n", data_type, rc,
                fb_strerror(rc));
        g_fail = 1;
        return;
    }
    float got = 0.f;
    rc = fb_read_f32(rt, name, &got);
    if (rc != FB_OK || fabsf(got - 6553.6f) >= 0.01f) {
        fprintf(stderr, "FAIL: scaled %s read rc=%d got %.9g (want 6553.6)\n",
                data_type, rc, (double)got);
        g_fail = 1;
    }
}

static void test_scaled_32bit_read(const char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/scaled32.json", dir);
    expect(write_file(path, k_scaled32) == 0, "write scaled32 cfg");

    fb_runtime_t *rt = NULL;
    int rc = fb_open(path, &rt);
    if (rc != FB_OK || !rt) {
        fprintf(stderr, "FAIL: scaled32 open rc=%d (%s)\n", rc,
                fb_strerror(rc));
        g_fail = 1;
        return;
    }
    expect_scaled_f32_read(rt, "s_u32", "uint32");
    expect_scaled_f32_read(rt, "s_i32", "int32");
    fb_close(rt);
}

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

    /* A20261003-1: scale uint32/int32 의 4바이트 BE float32 읽기. */
    test_scaled_32bit_read(dir);

    /* T7: 9ms poll_cycle → 마감 놓침 경고 + fb_health 최대 지연 µs.
     * 지터 기준을 1s 로 올려도 마감 놓침은 남고, 지터 초과 횟수는 0 이다. */
    if (FB_API_VERSION_MINOR < 1) {
        fprintf(stderr, "FAIL: FB_API_VERSION_MINOR=%d (want >=1)\n",
                FB_API_VERSION_MINOR);
        g_fail = 1;
    }
    test_cycle_delay_us(dir, 100, 1, "t7 deadline miss at 100us");
    test_cycle_delay_us(dir, 1000000, 0, "t7 deadline miss, jitter threshold 1s");
    test_jitter_summary_rate(dir);

    if (g_fail) {
        fprintf(stderr, "test_fb_api: FAILED\n");
        return 1;
    }
    printf("test_fb_api: OK\n");
    return 0;
}
