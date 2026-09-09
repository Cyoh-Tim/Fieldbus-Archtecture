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
}

void ctt_metrics_log(const ctt_run_t *run)
{
    const ctt_metrics_t *m = &run->metrics;
    if (m->rtc1_frames == 0 && m->unexpected_frames == 0 && m->ar_drops == 0 &&
        m->period_samples == 0) {
        return;
    }
    unsigned long long avg_ms = 0;
    if (m->period_samples) {
        avg_ms = (unsigned long long)((m->period_sum_ns / m->period_samples) /
                                      1000000ull);
    }
    LOG_INFO("ctt",
             "metrics protocol=%s scenario=%s unexpected=%u ar_drops=%u "
             "rtc1=%u period_ms min=%llu max=%llu avg=%llu "
             "hist_ms[<4,<8,<12,<16,<20,>=20]=%u,%u,%u,%u,%u,%u",
             run->protocol ? run->protocol : "?",
             run->name ? run->name : run->path, m->unexpected_frames,
             m->ar_drops, m->rtc1_frames,
             (unsigned long long)(m->period_min_ns / 1000000ull),
             (unsigned long long)(m->period_max_ns / 1000000ull), avg_ms,
             m->jitter_hist[0], m->jitter_hist[1], m->jitter_hist[2],
             m->jitter_hist[3], m->jitter_hist[4], m->jitter_hist[5]);
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
                  "FAIL protocol=%s scenario=%s: plugin not implemented "
                  "(known: profinet, modbus_tcp, slmp; ethernetip/ reserved)",
                  run.protocol, run.name);
        yaml_free(root);
        return 1;
    }

    LOG_INFO("ctt", "run protocol=%s scenario=%s file=%s transport=%s",
             run.protocol, run.name, path,
             run.opts.transport == CTT_TRANSPORT_AF_PACKET ? "af_packet"
                                                          : "mock");

    if (plugin->setup(&run) != 0) {
        LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s: plugin setup",
                  run.protocol, run.name);
        if (plugin->teardown) {
            plugin->teardown(&run);
        }
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
    if (rc == 0) {
        LOG_INFO("ctt", "OK protocol=%s scenario=%s", run.protocol, run.name);
    } else {
        LOG_ERROR("ctt", "FAIL protocol=%s scenario=%s failures=%d",
                  run.protocol, run.name, run.failures);
    }
    yaml_free(root);
    return rc;
}
