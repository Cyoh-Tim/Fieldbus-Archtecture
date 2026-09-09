#include "ctt.h"
#include "transport.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"

void ctt_failf(ctt_run_t *run, int step, const char *action, const char *fmt,
               ...)
{
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s step=%d action=%s %s",
              run->protocol ? run->protocol : "?",
              run->name ? run->name : run->path, step,
              action ? action : "?", msg);
    run->failures++;
}

void ctt_metrics_set_cycle_ns(ctt_metrics_t *m, uint64_t cycle_ns)
{
    if (!m) {
        return;
    }
    m->cycle_ns = cycle_ns;
    if (cycle_ns) {
        m->late_threshold_ns = cycle_ns + cycle_ns / 2ull; /* 1.5x */
    }
}

void ctt_metrics_note_period(ctt_metrics_t *m, uint64_t dt_ns)
{
    if (!m || dt_ns == 0) {
        return;
    }
    m->period_samples++;
    m->period_sum_ns += dt_ns;
    if (m->period_min_ns == 0 || dt_ns < m->period_min_ns) {
        m->period_min_ns = dt_ns;
    }
    if (dt_ns > m->period_max_ns) {
        m->period_max_ns = dt_ns;
    }
    unsigned ms = (unsigned)(dt_ns / 1000000ull);
    int b = 5;
    if (ms < 4) {
        b = 0;
    } else if (ms < 8) {
        b = 1;
    } else if (ms < 12) {
        b = 2;
    } else if (ms < 16) {
        b = 3;
    } else if (ms < 20) {
        b = 4;
    }
    m->jitter_hist[b]++;

    if (m->cycle_ns > 0) {
        uint64_t jitter =
            dt_ns > m->cycle_ns ? dt_ns - m->cycle_ns : m->cycle_ns - dt_ns;
        if (jitter > m->jitter_max_ns) {
            m->jitter_max_ns = jitter;
        }
        uint64_t late_th = m->late_threshold_ns ? m->late_threshold_ns
                                                : m->cycle_ns + m->cycle_ns / 2ull;
        uint64_t miss_th = m->cycle_ns + m->cycle_ns + m->cycle_ns / 2ull; /* 2.5x */
        if (dt_ns > miss_th) {
            unsigned extra = (unsigned)(dt_ns / m->cycle_ns);
            if (extra > 1u) {
                m->missed_cycles += extra - 1u;
            }
        } else if (dt_ns > late_th) {
            m->late_cycles++;
        }
    }
}

void ctt_metrics_log(const ctt_run_t *run)
{
    const ctt_metrics_t *m = &run->metrics;
    if (m->rtc1_frames == 0 && m->unexpected_frames == 0 && m->ar_drops == 0 &&
        m->period_samples == 0 && m->late_cycles == 0 && m->missed_cycles == 0) {
        return;
    }
    unsigned long long avg_ms = 0;
    if (m->period_samples) {
        avg_ms = (unsigned long long)((m->period_sum_ns / m->period_samples) /
                                      1000000ull);
    }
    LOG_INFO("ctt",
             "metrics protocol=%s scenario=%s bundle_id=%s unexpected=%u "
             "ar_drops=%u rtc1=%u late=%u missed=%u jitter_max_ms=%llu "
             "period_ms min=%llu max=%llu avg=%llu cycle_us=%llu "
             "hist_ms[<4,<8,<12,<16,<20,>=20]=%u,%u,%u,%u,%u,%u",
             run->protocol ? run->protocol : "?",
             run->name ? run->name : run->path,
             run->bundle_id && run->bundle_id[0] ? run->bundle_id : "-",
             m->unexpected_frames, m->ar_drops, m->rtc1_frames, m->late_cycles,
             m->missed_cycles,
             (unsigned long long)(m->jitter_max_ns / 1000000ull),
             (unsigned long long)(m->period_min_ns / 1000000ull),
             (unsigned long long)(m->period_max_ns / 1000000ull), avg_ms,
             (unsigned long long)(m->cycle_ns / 1000ull), m->jitter_hist[0],
             m->jitter_hist[1], m->jitter_hist[2], m->jitter_hist[3],
             m->jitter_hist[4], m->jitter_hist[5]);
}

static int path_ends_with(const char *path, const char *suf)
{
    size_t n = strlen(path);
    size_t m = strlen(suf);
    if (n < m) {
        return 0;
    }
    return strcmp(path + n - m, suf) == 0;
}

static void json_escape(FILE *fp, const char *s)
{
    if (!s) {
        fputs("", fp);
        return;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", fp);
            break;
        case '"':
            fputs("\\\"", fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (*p < 0x20) {
                fprintf(fp, "\\u%04x", *p);
            } else {
                fputc(*p, fp);
            }
            break;
        }
    }
}

int ctt_report_write(const ctt_run_t *run, int verdict, uint64_t duration_ns)
{
    if (!run || !run->opts.report[0]) {
        return 0;
    }
    FILE *fp = fopen(run->opts.report, "w");
    if (!fp) {
        LOG_ERROR("ctt", "failed to write report %s", run->opts.report);
        return -1;
    }
    const ctt_metrics_t *m = &run->metrics;
    const char *verdict_s = verdict == 0 ? "pass" : "fail";
    unsigned long long dur_ms = (unsigned long long)(duration_ns / 1000000ull);
    const char *suite = run->suite_id && run->suite_id[0] ? run->suite_id : "";
    const char *tc = run->bundle_id && run->bundle_id[0] ? run->bundle_id : "";
    const char *name = run->name ? run->name : "";
    const char *proto = run->protocol ? run->protocol : "";
    const char *path = run->path ? run->path : "";
    const char *xport =
        run->opts.transport == CTT_TRANSPORT_AF_PACKET ? "af_packet" : "mock";

    if (path_ends_with(run->opts.report, ".md")) {
        fprintf(fp,
                "# CTT run report (v1)\n\n"
                "> Internal bundle-grade gate **≠** PI / ODVA / Modbus.org / "
                "Mitsubishi certification.\n\n"
                "| Field | Value |\n|-------|-------|\n"
                "| schema | ctt-report/v1 |\n"
                "| suite_id | %s |\n"
                "| tc_id | %s |\n"
                "| name | %s |\n"
                "| protocol | %s |\n"
                "| scenario | %s |\n"
                "| transport | %s |\n"
                "| verdict | **%s** |\n"
                "| failures | %d |\n"
                "| duration_ms | %llu |\n\n"
                "## Metrics\n\n"
                "| Metric | Value |\n|--------|-------|\n"
                "| rtc1_frames | %u |\n"
                "| late_cycles | %u |\n"
                "| missed_cycles | %u |\n"
                "| unexpected_frames | %u |\n"
                "| ar_drops | %u |\n"
                "| period_min_ns | %llu |\n"
                "| period_max_ns | %llu |\n"
                "| jitter_max_ns | %llu |\n"
                "| cycle_ns | %llu |\n"
                "| period_samples | %u |\n"
                "| jitter_hist_ms | %u,%u,%u,%u,%u,%u |\n",
                suite, tc, name, proto, path, xport, verdict_s, run->failures,
                dur_ms, m->rtc1_frames, m->late_cycles, m->missed_cycles,
                m->unexpected_frames, m->ar_drops,
                (unsigned long long)m->period_min_ns,
                (unsigned long long)m->period_max_ns,
                (unsigned long long)m->jitter_max_ns,
                (unsigned long long)m->cycle_ns, m->period_samples,
                m->jitter_hist[0], m->jitter_hist[1], m->jitter_hist[2],
                m->jitter_hist[3], m->jitter_hist[4], m->jitter_hist[5]);
    } else {
        fputs("{\n", fp);
        fputs("  \"schema\": \"ctt-report/v1\",\n", fp);
        fputs("  \"disclaimer\": \"internal bundle-grade gate != PI / ODVA / "
              "Modbus.org / Mitsubishi certification\",\n",
              fp);
        fputs("  \"suite_id\": \"", fp);
        json_escape(fp, suite);
        fputs("\",\n  \"tc_id\": \"", fp);
        json_escape(fp, tc);
        fputs("\",\n  \"name\": \"", fp);
        json_escape(fp, name);
        fputs("\",\n  \"protocol\": \"", fp);
        json_escape(fp, proto);
        fputs("\",\n  \"scenario\": \"", fp);
        json_escape(fp, path);
        fprintf(fp,
                "\",\n  \"transport\": \"%s\",\n"
                "  \"verdict\": \"%s\",\n"
                "  \"failures\": %d,\n"
                "  \"duration_ms\": %llu,\n"
                "  \"metrics\": {\n"
                "    \"rtc1_frames\": %u,\n"
                "    \"late_cycles\": %u,\n"
                "    \"missed_cycles\": %u,\n"
                "    \"unexpected_frames\": %u,\n"
                "    \"ar_drops\": %u,\n"
                "    \"period_min_ns\": %llu,\n"
                "    \"period_max_ns\": %llu,\n"
                "    \"period_sum_ns\": %llu,\n"
                "    \"period_samples\": %u,\n"
                "    \"jitter_max_ns\": %llu,\n"
                "    \"cycle_ns\": %llu,\n"
                "    \"late_threshold_ns\": %llu,\n"
                "    \"jitter_hist_ms\": [%u, %u, %u, %u, %u, %u]\n"
                "  }\n}\n",
                xport, verdict_s, run->failures, dur_ms, m->rtc1_frames,
                m->late_cycles, m->missed_cycles, m->unexpected_frames,
                m->ar_drops, (unsigned long long)m->period_min_ns,
                (unsigned long long)m->period_max_ns,
                (unsigned long long)m->period_sum_ns, m->period_samples,
                (unsigned long long)m->jitter_max_ns,
                (unsigned long long)m->cycle_ns,
                (unsigned long long)m->late_threshold_ns, m->jitter_hist[0],
                m->jitter_hist[1], m->jitter_hist[2], m->jitter_hist[3],
                m->jitter_hist[4], m->jitter_hist[5]);
    }
    fclose(fp);
    LOG_INFO("ctt", "report written %s verdict=%s tc_id=%s", run->opts.report,
             verdict_s, tc[0] ? tc : "-");
    return 0;
}

int ctt_check(ctt_run_t *run, int step, const char *action, int cond,
              const char *fmt, ...)
{
    if (cond) {
        return 0;
    }
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s step=%d action=%s %s",
              run->protocol ? run->protocol : "?",
              run->name ? run->name : run->path, step,
              action ? action : "?", msg);
    run->failures++;
    return -1;
}

int ctt_run_file(const char *path, const ctt_opts_t *opts)
{
    char err[256];
    yaml_node_t *root = yaml_parse_file(path, err, sizeof(err));
    if (!root) {
        LOG_ERROR("ctt", "FAIL yaml load %s: %s", path, err);
        return 1;
    }

    ctt_run_t run;
    memset(&run, 0, sizeof(run));
    run.path = path;
    run.root = root;
    run.name = yaml_cstr(root, "name", path);
    run.protocol = yaml_cstr(root, "protocol", "");
    run.bundle_id = yaml_cstr(root, "bundle_id", NULL);
    if (!run.bundle_id || !run.bundle_id[0]) {
        run.bundle_id = yaml_cstr(root, "id", "");
    }
    run.suite_id = yaml_cstr(root, "suite", "");
    run.started_ns = ctt_now_ns();
    run.af_fd = -1;
    if (opts) {
        run.opts = *opts;
    } else {
        ctt_opts_init(&run.opts);
    }
    ctt_mock_init(&run.mock);

    if (!run.protocol[0]) {
        LOG_ERROR("ctt", "FAIL %s: missing protocol:", path);
        yaml_free(root);
        return 1;
    }

    const ctt_plugin_t *plugin = ctt_plugin_lookup(run.protocol);
    if (!plugin) {
        LOG_ERROR("ctt",
                  "FAIL protocol=%s scenario=%s: unknown plugin "
                  "(implemented: profinet, ethernetip, modbus_tcp, slmp)",
                  run.protocol, run.name);
        yaml_free(root);
        return 1;
    }

    LOG_INFO("ctt",
             "run protocol=%s scenario=%s bundle_id=%s suite=%s file=%s "
             "transport=%s",
             run.protocol, run.name,
             run.bundle_id && run.bundle_id[0] ? run.bundle_id : "-",
             run.suite_id && run.suite_id[0] ? run.suite_id : "-", path,
             run.opts.transport == CTT_TRANSPORT_AF_PACKET ? "af_packet"
                                                          : "mock");

    if (plugin->setup(&run) != 0) {
        LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s: plugin setup",
                  run.protocol, run.name);
        if (plugin->teardown) {
            plugin->teardown(&run);
        }
        run.failures++;
        (void)ctt_report_write(&run, 1, ctt_now_ns() - run.started_ns);
        yaml_free(root);
        return 1;
    }

    const yaml_node_t *steps = yaml_map_get(root, "steps");
    if (!steps || steps->kind != YAML_KIND_SEQ || !steps->child) {
        ctt_failf(&run, 0, "-", "missing steps: sequence");
    } else {
        int idx = 0;
        for (const yaml_node_t *st = steps->child; st; st = st->next) {
            idx++;
            const char *action = yaml_cstr(st, "action", "");
            if (!action[0]) {
                ctt_failf(&run, idx, "-", "step missing action");
                continue;
            }
            LOG_INFO("ctt", "step %d action=%s", idx, action);
            if (plugin->step(&run, st, idx) != 0) {
                /* plugin already logged specifics */
            }
        }
    }

    if (run.opts.transport == CTT_TRANSPORT_MOCK &&
        (run.mock.to_dut.overflow || run.mock.to_ctl.overflow)) {
        ctt_failf(&run, 0, "mock_eth",
                  "ring overflow (unexpected drop) to_dut=%d to_ctl=%d",
                  run.mock.to_dut.overflow, run.mock.to_ctl.overflow);
    }

    ctt_metrics_log(&run);

    if (plugin->teardown) {
        plugin->teardown(&run);
    }

    int rc = run.failures ? 1 : 0;
    uint64_t duration_ns = ctt_now_ns() - run.started_ns;
    if (ctt_report_write(&run, rc, duration_ns) != 0 && rc == 0) {
        rc = 1;
    }
    if (rc == 0) {
        LOG_INFO("ctt", "OK protocol=%s scenario=%s bundle_id=%s", run.protocol,
                 run.name,
                 run.bundle_id && run.bundle_id[0] ? run.bundle_id : "-");
    } else {
        LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s bundle_id=%s failures=%d",
                  run.protocol, run.name,
                  run.bundle_id && run.bundle_id[0] ? run.bundle_id : "-",
                  run.failures);
    }
    yaml_free(root);
    return rc;
}
